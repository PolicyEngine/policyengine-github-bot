"""GitHub webhook handlers."""

import hashlib
import hmac
import re

import logfire
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import ValidationError

from policyengine_github_bot.claude_code import execute_task
from policyengine_github_bot.config import get_settings
from policyengine_github_bot.github_auth import (
    get_github_client,
    get_installation_token,
    get_review_threads,
    reply_to_review_thread,
    resolve_review_thread,
)
from policyengine_github_bot.llm import (
    generate_issue_response,
    generate_pr_rereview,
)
from policyengine_github_bot.models import (
    GitHubPullRequest,
    GitHubUser,
    IssueCommentWebhookPayload,
    IssueWebhookPayload,
    PullRequestWebhookPayload,
)

router = APIRouter()

# Bot username for detecting mentions and own comments
BOT_USERNAME = "policyengine-auto"
BOT_USERNAMES = ["policyengine", "policyengine-auto"]
MENTION_PATTERN = re.compile(r"@(policyengine|policyengine-auto)\b", re.IGNORECASE)


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify the GitHub webhook signature."""
    if not signature.startswith("sha256="):
        prefix = signature[:10] if signature else "empty"
        logfire.warn("Invalid signature format", signature_prefix=prefix)
        return False

    expected = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(f"sha256={expected}", signature)


def contains_mention(text: str | None) -> bool:
    """Check if text contains @policyengine mention."""
    if not text:
        return False
    return bool(MENTION_PATTERN.search(text))


def fetch_claude_md(github, repo_full_name: str) -> str | None:
    """Fetch CLAUDE.md from a repository if it exists."""
    try:
        repo = github.get_repo(repo_full_name)
        contents = repo.get_contents("CLAUDE.md")
        size = len(contents.decoded_content)
        logfire.info(f"[context] {repo_full_name} - loaded CLAUDE.md ({size} bytes)")
        return contents.decoded_content.decode("utf-8")
    except Exception:
        logfire.info(f"[context] {repo_full_name} - no CLAUDE.md")
        return None


def bot_is_in_conversation(github, repo_full_name: str, issue_number: int) -> bool:
    """Check if the bot has already commented on this issue."""
    try:
        repo = github.get_repo(repo_full_name)
        issue = repo.get_issue(issue_number)
        comments = issue.get_comments()

        for comment in comments:
            if comment.user.login.lower() == BOT_USERNAME.lower():
                return True

        return False
    except Exception as e:
        logfire.error(f"[context] {repo_full_name}#{issue_number} - error: {e}")
        return False


def get_conversation_context(github, repo_full_name: str, issue_number: int) -> list[dict]:
    """Get the conversation history for context."""
    try:
        repo = github.get_repo(repo_full_name)
        issue = repo.get_issue(issue_number)
        comments = issue.get_comments()

        context = []
        for comment in comments:
            context.append(
                {
                    "author": comment.user.login,
                    "body": comment.body,
                    "is_bot": comment.user.login.lower() == BOT_USERNAME.lower(),
                }
            )

        return context
    except Exception as e:
        logfire.error(f"[context] {repo_full_name}#{issue_number} - error: {e}")
        return []


@router.post("/webhook")
async def handle_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None),
):
    """Handle incoming GitHub webhooks."""
    settings = get_settings()
    payload = await request.body()

    data = await request.json()

    # Extract key context for logging
    repo = data.get("repository", {}).get("full_name", "unknown")
    sender = data.get("sender", {}).get("login", "unknown")
    action = data.get("action", "")

    logfire.info(
        f"[{x_github_event}] {repo} by @{sender}",
        event=x_github_event,
        action=action,
        repo=repo,
        sender=sender,
    )

    # Verify webhook signature
    if not verify_signature(payload, x_hub_signature_256 or "", settings.github_webhook_secret):
        logfire.error(f"[{x_github_event}] Signature verification failed", event=x_github_event)
        raise HTTPException(status_code=401, detail="Invalid signature")

    if x_github_event == "issues":
        await handle_issue_event(data)
    elif x_github_event == "issue_comment":
        await handle_issue_comment_event(data)
    elif x_github_event == "pull_request":
        await handle_pull_request_event(data)
    elif x_github_event == "pull_request_review":
        await handle_pull_request_review_event(data)
    elif x_github_event == "ping":
        logfire.info("[ping] GitHub ping received", zen=data.get("zen", ""))
        return {"status": "pong"}
    else:
        logfire.info(f"[{x_github_event}] Unhandled event type", event=x_github_event)

    return {"status": "ok"}


async def handle_issue_event(data: dict):
    """Handle issue events - only respond if @policyengine is mentioned."""
    try:
        payload = IssueWebhookPayload.model_validate(data)
    except ValidationError as e:
        logfire.error("[issue] Invalid webhook payload", errors=e.errors())
        return

    repo = payload.repository.full_name
    issue_num = payload.issue.number
    sender = payload.sender.login
    prefix = f"[issue] {repo}#{issue_num} @{sender}"

    # Only respond to newly opened issues
    if payload.action != "opened":
        logfire.info(f"{prefix} - skipped (action={payload.action})")
        return

    # Check if @policyengine is mentioned in title or body
    mentioned_in_title = contains_mention(payload.issue.title)
    mentioned_in_body = contains_mention(payload.issue.body)

    if not mentioned_in_title and not mentioned_in_body:
        logfire.info(f"{prefix} - skipped (no bot mention)")
        return

    logfire.info(f"{prefix} - bot mentioned, will respond")

    if not payload.installation:
        logfire.error(f"{prefix} - no installation ID")
        return

    await respond_to_issue(payload, was_mentioned=True)


async def handle_issue_comment_event(data: dict):
    """Handle issue comment events - respond if mentioned or already in conversation."""
    try:
        payload = IssueCommentWebhookPayload.model_validate(data)
    except ValidationError as e:
        logfire.error("[comment] Invalid webhook payload", errors=e.errors())
        return

    # Check if this is a PR comment (PRs have a pull_request key in the issue)
    is_pr = "pull_request" in data.get("issue", {})
    event_type = "pr_comment" if is_pr else "comment"

    repo = payload.repository.full_name
    issue_num = payload.issue.number
    commenter = payload.comment.user.login
    prefix = f"[{event_type}] {repo}#{issue_num} @{commenter}"

    # Only respond to new comments
    if payload.action != "created":
        logfire.info(f"{prefix} - skipped (action={payload.action})")
        return

    # Ignore our own comments to prevent loops
    if payload.comment.user.login.lower() == BOT_USERNAME.lower():
        logfire.info(f"{prefix} - skipped (own comment)")
        return

    if not payload.installation:
        logfire.error(f"{prefix} - no installation ID")
        return

    # Check if we should respond
    mentioned = contains_mention(payload.comment.body)
    logfire.info(
        f"{prefix} - checking mention",
        body_preview=payload.comment.body[:100] if payload.comment.body else None,
        mentioned=mentioned,
    )

    if not mentioned:
        # Check if we're already in the conversation
        github = get_github_client(payload.installation.id)
        in_conversation = bot_is_in_conversation(
            github,
            payload.repository.full_name,
            payload.issue.number,
        )

        if not in_conversation:
            logfire.info(f"{prefix} - skipped (no mention, not in conversation)")
            return

        logfire.info(f"{prefix} - continuing existing conversation")
    else:
        logfire.info(f"{prefix} - bot mentioned")

    # If this is a PR and we're mentioned, do a review (or re-review if already reviewed)
    if is_pr and mentioned:
        logfire.info(f"{prefix} - triggering PR review")
        await handle_pr_comment_review(payload)
        return

    # Otherwise handle as a normal issue comment
    issue_payload = IssueWebhookPayload(
        action="comment",
        issue=payload.issue,
        repository=payload.repository,
        installation=payload.installation,
        sender=payload.sender,
    )

    await respond_to_issue(
        issue_payload,
        comment_context=payload.comment.body,
        was_mentioned=mentioned,
    )


async def respond_to_issue(
    payload: IssueWebhookPayload,
    comment_context: str | None = None,
    was_mentioned: bool = False,
):
    """Generate and post a response to an issue using Claude Code."""
    repo = payload.repository.full_name
    issue_num = payload.issue.number
    prefix = f"[issue] {repo}#{issue_num}"

    with logfire.span(prefix, repo=repo, issue_number=issue_num):
        github = get_github_client(payload.installation.id)
        gh_repo = github.get_repo(repo)
        gh_issue = gh_repo.get_issue(issue_num)

        request_text = comment_context or payload.issue.body or ""

        # Use Claude Code by default when mentioned
        if was_mentioned:
            await handle_claude_code_request(payload, gh_repo, gh_issue, request_text)
            return

        # For continuing conversations (not mentioned), use simple LLM response
        claude_md = fetch_claude_md(github, repo)
        conversation = get_conversation_context(github, repo, issue_num)
        logfire.info(f"{prefix} - loaded {len(conversation)} previous comments")

        logfire.info(f"{prefix} - generating response...")
        response_text = await generate_issue_response(
            issue=payload.issue,
            repo_context=claude_md,
            conversation=conversation if conversation else None,
        )

        gh_issue.create_comment(response_text)
        logfire.info(f"{prefix} - responded ({len(response_text)} chars)")


ENGINEERING_LABEL = "⚙️ Engineering..."


async def handle_claude_code_request(
    payload: IssueWebhookPayload, gh_repo, gh_issue, request_text: str
):
    """Handle any request using Claude Code - questions, tasks, fixes, etc."""
    repo = payload.repository.full_name
    issue_num = payload.issue.number
    prefix = f"[claude-code] {repo}#{issue_num}"

    with logfire.span(prefix, repo=repo, issue_number=issue_num):
        # Add engineering label to show we're working on it
        try:
            gh_issue.add_to_labels(ENGINEERING_LABEL)
        except Exception as e:
            logfire.warn(f"{prefix} - failed to add label: {e}")

        # Post initial "working on it" comment - Claude Code will update this
        progress_comment = gh_issue.create_comment(
            "⚙️ Working on this..."
        )
        comment_id = progress_comment.id

        try:
            # Get default branch and token
            default_branch = gh_repo.default_branch
            token = get_installation_token(payload.installation.id)

            # Build context for Claude Code
            task = f"""You are responding to a GitHub issue.

Repository: {repo}
Issue #{issue_num}: {payload.issue.title}

Issue description:
{payload.issue.body or "(no description)"}

User request:
{request_text}

Progress updates:
- There's a comment (ID: {comment_id}) that says "⚙️ Working on this..."
- Update this comment as you work to keep the user informed of progress
- Use: `gh api repos/{repo}/issues/comments/{comment_id} -X PATCH -f body="your update"`
- Update when: starting a major step, finding something important, making progress
- Keep updates concise - just a line or two about what you're doing
- Your final update should be your complete response (not a progress update)

Instructions:
- Read the codebase to understand context if needed
- Answer questions, fix bugs, implement features, or do whatever is requested
- If you need to make code changes, create a branch, commit, and open a PR
- Use `gh` CLI for GitHub operations (PRs, issues, etc.)
- Be concise and helpful in your final response"""

            logfire.info(f"{prefix} - executing via Claude Code...")

            result = await execute_task(
                repo_url=f"https://github.com/{repo}",
                base_ref=default_branch,
                task=task,
                issue_number=issue_num,
                token=token,
            )

            # If Claude Code failed, update the comment with error
            if not result.success:
                progress_comment.edit(f"I ran into an issue:\n\n```\n{result.output[:1000]}\n```")

            logfire.info(f"{prefix} - complete (success={result.success}, pr={result.pr_url})")

        except Exception as e:
            # Update progress comment with error
            progress_comment.edit(f"I ran into an issue:\n\n```\n{e}\n```")
            logfire.error(f"{prefix} - error: {e}")

        finally:
            # Remove engineering label when done
            try:
                gh_issue.remove_from_labels(ENGINEERING_LABEL)
            except Exception as e:
                logfire.warn(f"{prefix} - failed to remove label: {e}")


async def handle_pull_request_event(data: dict):
    """Handle pull request events - review if @policyengine-auto is mentioned or requested."""
    try:
        payload = PullRequestWebhookPayload.model_validate(data)
    except ValidationError as e:
        logfire.error("[pr] Invalid webhook payload", errors=e.errors())
        return

    repo = payload.repository.full_name
    pr_num = payload.pull_request.number
    sender = payload.sender.login
    prefix = f"[pr] {repo}#{pr_num} @{sender}"

    # Check if this is a review request for our bot
    if payload.action == "review_requested":
        requested_reviewer = data.get("requested_reviewer", {})
        reviewer_login = requested_reviewer.get("login", "").lower()

        if reviewer_login in [u.lower() for u in BOT_USERNAMES]:
            logfire.info(f"{prefix} - review requested, will review")
            await review_pull_request(payload)
            return

    # Check if mentioned in PR body on open
    if payload.action == "opened":
        if contains_mention(payload.pull_request.body):
            logfire.info(f"{prefix} - bot mentioned in new PR, will review")
            await review_pull_request(payload)
            return

    logfire.info(f"{prefix} - skipped (action={payload.action}, no bot involvement)")


async def handle_pull_request_review_event(data: dict):
    """Handle pull request review events - currently just logging."""
    repo = data.get("repository", {}).get("full_name", "unknown")
    pr_num = data.get("pull_request", {}).get("number", "?")
    action = data.get("action", "")
    reviewer = data.get("review", {}).get("user", {}).get("login", "unknown")
    logfire.info(f"[pr_review] {repo}#{pr_num} @{reviewer} - {action}")


async def review_pull_request(payload: PullRequestWebhookPayload):
    """Review a PR using Claude Code."""
    repo = payload.repository.full_name
    pr_num = payload.pull_request.number
    prefix = f"[review] {repo}#{pr_num}"

    if not payload.installation:
        logfire.error(f"{prefix} - no installation ID")
        return

    with logfire.span(prefix, repo=repo, pr_number=pr_num):
        github = get_github_client(payload.installation.id)
        gh_repo = github.get_repo(repo)
        gh_pr = gh_repo.get_pull(pr_num)

        # Add engineering label to show we're working on it
        try:
            gh_pr.add_to_labels(ENGINEERING_LABEL)
        except Exception as e:
            logfire.warn(f"{prefix} - failed to add label: {e}")

        # Post initial progress comment - Claude Code will update this
        progress_comment = gh_pr.create_issue_comment(
            "⚙️ Reviewing this PR..."
        )
        comment_id = progress_comment.id

        try:
            token = get_installation_token(payload.installation.id)

            # Build review task for Claude Code
            base_ref = payload.pull_request.base["ref"]
            task = f"""You are reviewing pull request #{pr_num} in {repo}.

PR title: {payload.pull_request.title}

PR description:
{payload.pull_request.body or "(no description)"}

Progress updates:
- There's a comment (ID: {comment_id}) that says "⚙️ Reviewing this PR..."
- Update this comment as you work to keep the user informed of progress
- Use: `gh api repos/{repo}/issues/comments/{comment_id} -X PATCH -f body="your update"`
- Update when: starting to read files, finding issues, making fixes
- Keep updates concise - just a line or two about what you're doing

Instructions:
1. Review the changes (use `git diff {base_ref}...HEAD`)
2. Understand what the PR is trying to do and whether it achieves that
3. Look for bugs, edge cases, security issues, and logic errors
4. Check test coverage if relevant

Review guidelines:
- Only leave inline comments on lines with actual issues (bugs, security, logic errors)
- Do NOT comment on things that are fine - mention these briefly in the summary
- If you find issues you can fix, fix them directly (commit to the PR branch)
- Use `gh` CLI to post your review

When posting the review:
- `gh pr review {pr_num} --approve -b "summary"` if good
- `gh pr review {pr_num} --request-changes -b "summary"` if blocking issues
- `gh pr review {pr_num} --comment -b "summary"` for non-blocking feedback

After posting your review, delete the progress comment:
`gh api repos/{repo}/issues/comments/{comment_id} -X DELETE`"""

            logfire.info(f"{prefix} - reviewing via Claude Code...")

            result = await execute_task(
                repo_url=f"https://github.com/{repo}",
                base_ref=payload.pull_request.head["ref"],  # Check out the PR branch
                task=task,
                issue_number=pr_num,
                token=token,
            )

            if not result.success:
                # Update progress comment with error
                progress_comment.edit(
                    f"I tried to review this PR but ran into an issue:\n\n```\n{result.output[:1000]}\n```"
                )

            logfire.info(f"{prefix} - complete (success={result.success})")

        finally:
            # Remove engineering label when done
            try:
                gh_pr.remove_from_labels(ENGINEERING_LABEL)
            except Exception as e:
                logfire.warn(f"{prefix} - failed to remove label: {e}")


def get_pr_diff_and_files(gh_pr, prefix: str) -> tuple[str, list[dict]]:
    """Fetch diff and files changed from a PR."""
    diff = ""
    try:
        diff_parts = []
        for f in gh_pr.get_files():
            if f.patch:
                file_diff = f"File: {f.filename}\n"
                file_diff += f"--- a/{f.filename}\n+++ b/{f.filename}\n"
                file_diff += f.patch
                diff_parts.append(file_diff)
        diff = "\n\n".join(diff_parts)
    except Exception as e:
        logfire.error(f"{prefix} - failed to fetch diff: {e}")

    files_changed = []
    for f in gh_pr.get_files():
        files_changed.append(
            {
                "filename": f.filename,
                "additions": f.additions,
                "deletions": f.deletions,
                "status": f.status,
            }
        )

    return diff, files_changed


async def handle_pr_comment_review(payload: IssueCommentWebhookPayload):
    """Handle a review request on a PR via comment mention.

    If the bot has previously reviewed, do a re-review (check threads).
    Otherwise, do a fresh full review.
    """
    repo = payload.repository.full_name
    pr_num = payload.issue.number
    requester = payload.sender.login

    github = get_github_client(payload.installation.id)
    gh_repo = github.get_repo(repo)
    gh_pr = gh_repo.get_pull(pr_num)

    # Check if bot has previously reviewed this PR
    has_previous_review = False
    try:
        for review in gh_pr.get_reviews():
            if review.user.login.lower() in [u.lower() for u in BOT_USERNAMES]:
                has_previous_review = True
                break
    except Exception as e:
        logfire.error(f"[pr] {repo}#{pr_num} - failed to check previous reviews: {e}")

    if has_previous_review:
        # Do a re-review (check threads, resolve/reply)
        await do_pr_rereview(payload, github, gh_repo, gh_pr)
    else:
        # First time review - do a full review
        logfire.info(f"[review] {repo}#{pr_num} @{requester} - first review via comment")
        pr_payload = PullRequestWebhookPayload(
            action="review_requested",
            pull_request=GitHubPullRequest(
                id=gh_pr.id,
                number=gh_pr.number,
                title=gh_pr.title,
                body=gh_pr.body,
                state=gh_pr.state,
                user=GitHubUser(login=gh_pr.user.login, id=gh_pr.user.id),
                head={"sha": gh_pr.head.sha, "ref": gh_pr.head.ref},
                base={"sha": gh_pr.base.sha, "ref": gh_pr.base.ref},
            ),
            repository=payload.repository,
            installation=payload.installation,
            sender=payload.sender,
        )
        await review_pull_request(pr_payload)


async def do_pr_rereview(payload, github, gh_repo, gh_pr):
    """Perform a re-review on a PR that was previously reviewed."""
    repo = payload.repository.full_name
    pr_num = payload.issue.number
    requester = payload.sender.login
    prefix = f"[re-review] {repo}#{pr_num} @{requester}"

    with logfire.span(prefix, repo=repo, pr_number=pr_num, requester=requester):
        # Fetch CLAUDE.md for context
        claude_md = fetch_claude_md(github, repo)

        # Get diff and files
        diff, files_changed = get_pr_diff_and_files(gh_pr, prefix)
        logfire.info(f"{prefix} - {len(files_changed)} files, {len(diff)} chars diff")

        # Fetch open review threads
        owner, repo_name = repo.split("/")
        all_threads = await get_review_threads(
            payload.installation.id,
            owner,
            repo_name,
            pr_num,
        )
        open_threads = [t for t in all_threads if not t.get("isResolved", False)]
        logfire.info(f"{prefix} - {len(open_threads)} open threads")

        # Build context for re-review
        rereview_context = f"Re-review requested by @{requester}:\n{payload.comment.body}"

        # Build PR model for LLM
        pr_model = GitHubPullRequest(
            id=gh_pr.id,
            number=gh_pr.number,
            title=gh_pr.title,
            body=gh_pr.body,
            state=gh_pr.state,
            user=GitHubUser(login=gh_pr.user.login, id=gh_pr.user.id),
            head={"sha": gh_pr.head.sha, "ref": gh_pr.head.ref},
            base={"sha": gh_pr.base.sha, "ref": gh_pr.base.ref},
        )

        # Generate re-review response
        logfire.info(f"{prefix} - generating re-review...")
        rereview = await generate_pr_rereview(
            pr=pr_model,
            diff=diff,
            files_changed=files_changed,
            open_threads=open_threads,
            rereview_context=rereview_context,
            repo_context=claude_md,
        )

        # Process thread actions
        resolved_count = 0
        replied_count = 0
        for action in rereview.thread_actions:
            idx = action.thread_index
            if 0 <= idx < len(open_threads):
                thread_id = open_threads[idx].get("id")
                if not thread_id:
                    continue

                if action.action.upper() == "RESOLVE":
                    await resolve_review_thread(payload.installation.id, thread_id)
                    resolved_count += 1
                elif action.action.upper() == "REPLY" and action.reply:
                    await reply_to_review_thread(
                        payload.installation.id,
                        thread_id,
                        action.reply,
                    )
                    replied_count += 1

        logfire.info(f"{prefix} - resolved {resolved_count}, replied {replied_count}")

        # Post a new review if there are new comments
        if rereview.new_comments:
            review_comments = []
            for comment in rereview.new_comments:
                review_comments.append(
                    {
                        "path": comment.path,
                        "line": comment.line,
                        "body": comment.body,
                    }
                )

            event = "COMMENT"
            if rereview.approval:
                event_map = {
                    "APPROVE": "APPROVE",
                    "REQUEST_CHANGES": "REQUEST_CHANGES",
                    "COMMENT": "COMMENT",
                }
                event = event_map.get(rereview.approval.upper(), "COMMENT")

            summary = rereview.summary or "Re-review complete."
            logfire.info(f"{prefix} - posting {event} with {len(review_comments)} new comments")
            gh_pr.create_review(
                body=summary,
                event=event,
                comments=review_comments,
            )
        else:
            # No new review, but leave a comment explaining what we did
            logfire.info(f"{prefix} - no new comments, posting summary comment")
            summary_parts = []
            if resolved_count > 0:
                summary_parts.append(f"resolved {resolved_count} thread(s)")
            if replied_count > 0:
                summary_parts.append(f"replied to {replied_count} thread(s)")

            if summary_parts:
                comment_body = f"Re-review complete: {', '.join(summary_parts)}."
            else:
                comment_body = "Re-review complete. No changes needed."

            # Post as an issue comment (not a review)
            gh_repo.get_issue(pr_num).create_comment(comment_body)

        logfire.info(f"{prefix} - done")
