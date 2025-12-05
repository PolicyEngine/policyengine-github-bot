"""GitHub webhook handlers."""

import hashlib
import hmac
import re

import logfire
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import ValidationError

from policyengine_github_bot.claude_code import execute_task, gather_review_context
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
    generate_pr_review,
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


async def classify_request(text: str) -> bool:
    """Use Haiku to classify if a request needs Claude Code.

    Returns True if the request requires codebase access (Claude Code task).
    """
    import anthropic

    logfire.info("[classify] Classifying request", text_preview=text[:100])

    client = anthropic.AsyncAnthropic()

    prompt = f"""Classify this GitHub issue/comment. Does it require codebase access?

Request: {text}

Reply with ONLY "Y" (needs codebase - count files, find code, fix bugs, make changes)
or "N" (no codebase needed - general questions, explanations, advice)."""

    response = await client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1,
        messages=[{"role": "user", "content": prompt}],
    )

    result = response.content[0].text.strip().upper()
    logfire.info("[classify] Result", result=result, needs_codebase=(result == "Y"))
    return result == "Y"


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
    """Generate and post a response to an issue."""
    repo = payload.repository.full_name
    issue_num = payload.issue.number
    prefix = f"[issue] {repo}#{issue_num}"

    with logfire.span(prefix, repo=repo, issue_number=issue_num):
        github = get_github_client(payload.installation.id)
        gh_repo = github.get_repo(repo)
        gh_issue = gh_repo.get_issue(issue_num)

        # Only use Claude Code for task requests when explicitly mentioned
        request_text = comment_context or payload.issue.body or ""
        if was_mentioned and request_text:
            needs_codebase = await classify_request(request_text)
            logfire.info(f"{prefix} - classified request (needs_codebase={needs_codebase})")
            if needs_codebase:
                await handle_task_request(payload, gh_repo, gh_issue, request_text)
                return

        # Otherwise, handle as a normal question/response
        # Fetch CLAUDE.md for context
        claude_md = fetch_claude_md(github, repo)

        # Get conversation history if responding to a comment
        conversation = []
        if comment_context:
            conversation = get_conversation_context(github, repo, issue_num)
            logfire.info(f"{prefix} - loaded {len(conversation)} previous comments")

        # Generate response
        logfire.info(f"{prefix} - generating response...")
        response_text = await generate_issue_response(
            issue=payload.issue,
            repo_context=claude_md,
            conversation=conversation if conversation else None,
        )

        # Post comment
        gh_issue.create_comment(response_text)

        logfire.info(f"{prefix} - responded ({len(response_text)} chars)")


async def handle_task_request(payload: IssueWebhookPayload, gh_repo, gh_issue, request_text: str):
    """Handle a request to perform a task using Claude Code."""
    repo = payload.repository.full_name
    issue_num = payload.issue.number
    prefix = f"[task] {repo}#{issue_num}"

    # Post an acknowledgment
    gh_issue.create_comment("On it! I'll work on this and file a PR if I can make the fix.")

    # Get default branch
    default_branch = gh_repo.default_branch

    # Build task description from issue context
    task = f"""Issue #{issue_num}: {payload.issue.title}

{payload.issue.body or "(no description)"}

Request: {request_text}"""

    # Execute the task
    logfire.info(f"{prefix} - executing task via Claude Code...")
    token = get_installation_token(payload.installation.id)

    result = await execute_task(
        repo_url=f"https://github.com/{repo}",
        base_ref=default_branch,
        task=task,
        issue_number=issue_num,
        token=token,
    )

    # Post result
    if result.success:
        if result.pr_url:
            response = f"Done! I've created a PR: {result.pr_url}"
        else:
            response = f"I've completed the task. Here's what I did:\n\n{result.output[:2000]}"
    else:
        response = (
            f"I wasn't able to complete this task. Here's what happened:\n\n{result.output[:1000]}"
        )

    gh_issue.create_comment(response)
    logfire.info(f"{prefix} - task complete (success={result.success}, pr={result.pr_url})")


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


async def review_pull_request(
    payload: PullRequestWebhookPayload,
    use_claude_code: bool = True,
):
    """Generate and post a PR review."""
    repo = payload.repository.full_name
    pr_num = payload.pull_request.number
    prefix = f"[review] {repo}#{pr_num}"

    if not payload.installation:
        logfire.error(f"{prefix} - no installation ID")
        return

    with logfire.span(prefix, repo=repo, pr_number=pr_num):
        github = get_github_client(payload.installation.id)

        # Fetch CLAUDE.md for context
        claude_md = fetch_claude_md(github, repo)

        # Get PR diff and files
        logfire.info(f"{prefix} - fetching diff and files...")
        gh_repo = github.get_repo(repo)
        gh_pr = gh_repo.get_pull(pr_num)

        diff, files_changed = get_pr_diff_and_files(gh_pr, prefix)

        logfire.info(f"{prefix} - {len(files_changed)} files, {len(diff)} chars diff")

        # Gather enhanced context via Claude Code (optional)
        codebase_context = None
        if use_claude_code:
            try:
                logfire.info(f"{prefix} - gathering codebase context via Claude Code...")
                token = get_installation_token(payload.installation.id)
                codebase_context = await gather_review_context(
                    repo_url=f"https://github.com/{repo}",
                    ref=payload.pull_request.head["ref"],
                    files_changed=[f["filename"] for f in files_changed],
                    pr_title=payload.pull_request.title,
                    pr_body=payload.pull_request.body,
                    token=token,
                )
                logfire.info(f"{prefix} - got {len(codebase_context)} chars context")
            except Exception as e:
                logfire.warn(f"{prefix} - Claude Code failed, continuing without: {e}")

        # Combine contexts
        repo_context = claude_md or ""
        if codebase_context:
            repo_context += f"\n\n## Codebase context (from exploration)\n\n{codebase_context}"
        repo_context = repo_context.strip() or None

        # Generate review
        logfire.info(f"{prefix} - generating review...")
        review = await generate_pr_review(
            pr=payload.pull_request,
            diff=diff,
            files_changed=files_changed,
            repo_context=repo_context,
        )

        # Map approval to GitHub event type
        event_map = {
            "APPROVE": "APPROVE",
            "REQUEST_CHANGES": "REQUEST_CHANGES",
            "COMMENT": "COMMENT",
        }
        event = event_map.get(review.approval.upper(), "COMMENT")

        # Build inline comments for the review
        review_comments = []
        for comment in review.comments:
            review_comments.append(
                {
                    "path": comment.path,
                    "line": comment.line,
                    "body": comment.body,
                }
            )

        # Create a single review with all comments
        logfire.info(f"{prefix} - posting {event} with {len(review_comments)} inline comments")
        if review_comments:
            gh_pr.create_review(
                body=review.summary,
                event=event,
                comments=review_comments,
            )
        else:
            gh_pr.create_review(body=review.summary, event=event)

        logfire.info(f"{prefix} - done ({event})")


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
