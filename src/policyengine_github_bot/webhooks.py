"""GitHub webhook handlers."""

import hashlib
import hmac
import re

import logfire
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import ValidationError

from policyengine_github_bot.config import get_settings
from policyengine_github_bot.github_auth import (
    get_github_client,
    get_review_threads,
    resolve_review_thread,
)
from policyengine_github_bot.llm import generate_issue_response, generate_pr_review
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

    await respond_to_issue(payload)


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

    # If this is a PR and we're mentioned, do a re-review
    if is_pr and mentioned:
        logfire.info(f"{prefix} - triggering PR re-review")
        await handle_pr_rereview(payload)
        return

    # Otherwise handle as a normal issue comment
    issue_payload = IssueWebhookPayload(
        action="comment",
        issue=payload.issue,
        repository=payload.repository,
        installation=payload.installation,
        sender=payload.sender,
    )

    await respond_to_issue(issue_payload, comment_context=payload.comment.body)


async def respond_to_issue(
    payload: IssueWebhookPayload,
    comment_context: str | None = None,
):
    """Generate and post a response to an issue."""
    repo = payload.repository.full_name
    issue_num = payload.issue.number
    prefix = f"[issue] {repo}#{issue_num}"

    with logfire.span(prefix, repo=repo, issue_number=issue_num):
        github = get_github_client(payload.installation.id)

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
        gh_repo = github.get_repo(repo)
        gh_issue = gh_repo.get_issue(issue_num)
        gh_issue.create_comment(response_text)

        logfire.info(f"{prefix} - responded ({len(response_text)} chars)")


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
    rereview_context: str | None = None,
    open_threads: list[dict] | None = None,
):
    """Generate and post a PR review."""
    repo = payload.repository.full_name
    pr_num = payload.pull_request.number
    is_rereview = rereview_context is not None
    review_type = "re-review" if is_rereview else "review"
    prefix = f"[{review_type}] {repo}#{pr_num}"

    if not payload.installation:
        logfire.error(f"{prefix} - no installation ID")
        return

    with logfire.span(prefix, repo=repo, pr_number=pr_num, is_rereview=is_rereview):
        github = get_github_client(payload.installation.id)

        # Fetch CLAUDE.md for context
        claude_md = fetch_claude_md(github, repo)

        # Get PR diff and files
        logfire.info(f"{prefix} - fetching diff and files...")
        gh_repo = github.get_repo(repo)
        gh_pr = gh_repo.get_pull(pr_num)

        # Get the diff - build it from file patches with line number context
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

        # Get files changed
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

        logfire.info(f"{prefix} - {len(files_changed)} files, {len(diff)} chars diff")

        # Generate review
        logfire.info(f"{prefix} - generating review...")
        review = await generate_pr_review(
            pr=payload.pull_request,
            diff=diff,
            files_changed=files_changed,
            repo_context=claude_md,
            rereview_context=rereview_context,
            open_threads=open_threads,
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

        # Resolve threads that the LLM identified as addressed
        if open_threads and review.threads_to_resolve:
            logfire.info(f"{prefix} - resolving {len(review.threads_to_resolve)} threads")
            for idx in review.threads_to_resolve:
                if 0 <= idx < len(open_threads):
                    thread_id = open_threads[idx].get("id")
                    if thread_id:
                        await resolve_review_thread(payload.installation.id, thread_id)

        logfire.info(f"{prefix} - done ({event})")


async def handle_pr_rereview(payload: IssueCommentWebhookPayload):
    """Handle a re-review request on a PR via comment mention."""
    repo = payload.repository.full_name
    pr_num = payload.issue.number
    requester = payload.sender.login
    prefix = f"[re-review] {repo}#{pr_num} @{requester}"

    github = get_github_client(payload.installation.id)

    with logfire.span(prefix, repo=repo, pr_number=pr_num, requester=requester):
        gh_repo = github.get_repo(repo)
        gh_pr = gh_repo.get_pull(pr_num)

        # Fetch previous reviews from the bot to include as context
        previous_reviews = []
        try:
            for review in gh_pr.get_reviews():
                if review.user.login.lower() in [u.lower() for u in BOT_USERNAMES]:
                    previous_reviews.append(
                        {
                            "state": review.state,
                            "body": review.body,
                        }
                    )
            logfire.info(f"{prefix} - found {len(previous_reviews)} previous bot reviews")
        except Exception as e:
            logfire.error(f"{prefix} - failed to fetch previous reviews: {e}")

        # Build PR payload for review
        pr_payload = PullRequestWebhookPayload(
            action="rereview",
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

        # Include the comment that triggered re-review and previous reviews as context
        rereview_context = f"Re-review requested by @{requester}:\n{payload.comment.body}"
        if previous_reviews:
            rereview_context += "\n\nPrevious review(s) from this bot:\n"
            for prev in previous_reviews:
                rereview_context += f"\n[{prev['state']}]: {prev['body']}\n"

        # Fetch open review threads for potential resolution
        owner, repo_name = repo.split("/")
        all_threads = await get_review_threads(
            payload.installation.id,
            owner,
            repo_name,
            pr_num,
        )
        open_threads = [t for t in all_threads if not t.get("isResolved", False)]
        logfire.info(f"{prefix} - {len(open_threads)} open threads to check")

        await review_pull_request(
            pr_payload,
            rereview_context=rereview_context,
            open_threads=open_threads,
        )
