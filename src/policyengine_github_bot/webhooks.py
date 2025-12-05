"""GitHub webhook handlers."""

import hashlib
import hmac
import re

import logfire
from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import ValidationError

from policyengine_github_bot.config import get_settings
from policyengine_github_bot.github_auth import get_github_client
from policyengine_github_bot.llm import generate_issue_response
from policyengine_github_bot.models import IssueCommentWebhookPayload, IssueWebhookPayload

router = APIRouter()

# Bot username for detecting mentions and own comments
BOT_USERNAME = "policyengine"
MENTION_PATTERN = re.compile(r"@policyengine\b", re.IGNORECASE)


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
        logfire.info("Found CLAUDE.md", repo=repo_full_name, size=len(contents.decoded_content))
        return contents.decoded_content.decode("utf-8")
    except Exception as e:
        logfire.info("No CLAUDE.md found", repo=repo_full_name, error=str(e))
        return None


def bot_is_in_conversation(github, repo_full_name: str, issue_number: int) -> bool:
    """Check if the bot has already commented on this issue."""
    try:
        repo = github.get_repo(repo_full_name)
        issue = repo.get_issue(issue_number)
        comments = issue.get_comments()

        for comment in comments:
            if comment.user.login.lower() == BOT_USERNAME.lower():
                logfire.info(
                    "Bot found in conversation",
                    repo=repo_full_name,
                    issue_number=issue_number,
                )
                return True

        return False
    except Exception as e:
        logfire.error(
            "Error checking conversation history",
            repo=repo_full_name,
            issue_number=issue_number,
            error=str(e),
        )
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
        logfire.error(
            "Error fetching conversation context",
            repo=repo_full_name,
            issue_number=issue_number,
            error=str(e),
        )
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

    logfire.info("Webhook received", event=x_github_event, payload_size=len(payload))

    # Verify webhook signature
    if not verify_signature(payload, x_hub_signature_256 or "", settings.github_webhook_secret):
        logfire.error("Webhook signature verification failed", event=x_github_event)
        raise HTTPException(status_code=401, detail="Invalid signature")

    logfire.info("Webhook signature verified", event=x_github_event)

    data = await request.json()

    if x_github_event == "issues":
        await handle_issue_event(data)
    elif x_github_event == "issue_comment":
        await handle_issue_comment_event(data)
    elif x_github_event == "ping":
        logfire.info("Ping received", zen=data.get("zen", ""))
        return {"status": "pong"}
    else:
        logfire.info("Unhandled event type", event=x_github_event)

    return {"status": "ok"}


async def handle_issue_event(data: dict):
    """Handle issue events - only respond if @policyengine is mentioned."""
    try:
        payload = IssueWebhookPayload.model_validate(data)
    except ValidationError as e:
        logfire.error("Invalid issue webhook payload", errors=e.errors())
        return

    logfire.info(
        "Issue event received",
        action=payload.action,
        repo=payload.repository.full_name,
        issue_number=payload.issue.number,
        issue_title=payload.issue.title,
        sender=payload.sender.login,
    )

    # Only respond to newly opened issues
    if payload.action != "opened":
        logfire.info(
            "Ignoring issue event",
            action=payload.action,
            reason="not an 'opened' action",
        )
        return

    # Check if @policyengine is mentioned in title or body
    mentioned_in_title = contains_mention(payload.issue.title)
    mentioned_in_body = contains_mention(payload.issue.body)

    if not mentioned_in_title and not mentioned_in_body:
        logfire.info(
            "Ignoring issue - no @policyengine mention",
            repo=payload.repository.full_name,
            issue_number=payload.issue.number,
        )
        return

    logfire.info(
        "Bot mentioned in new issue",
        repo=payload.repository.full_name,
        issue_number=payload.issue.number,
        mentioned_in_title=mentioned_in_title,
        mentioned_in_body=mentioned_in_body,
    )

    if not payload.installation:
        logfire.error(
            "No installation ID in webhook payload",
            repo=payload.repository.full_name,
            issue_number=payload.issue.number,
        )
        return

    await respond_to_issue(payload)


async def handle_issue_comment_event(data: dict):
    """Handle issue comment events - respond if mentioned or already in conversation."""
    try:
        payload = IssueCommentWebhookPayload.model_validate(data)
    except ValidationError as e:
        logfire.error("Invalid issue_comment webhook payload", errors=e.errors())
        return

    logfire.info(
        "Issue comment event received",
        action=payload.action,
        repo=payload.repository.full_name,
        issue_number=payload.issue.number,
        comment_author=payload.comment.user.login,
    )

    # Only respond to new comments
    if payload.action != "created":
        logfire.info(
            "Ignoring comment event",
            action=payload.action,
            reason="not a 'created' action",
        )
        return

    # Ignore our own comments to prevent loops
    if payload.comment.user.login.lower() == BOT_USERNAME.lower():
        logfire.info(
            "Ignoring own comment",
            repo=payload.repository.full_name,
            issue_number=payload.issue.number,
        )
        return

    if not payload.installation:
        logfire.error(
            "No installation ID in webhook payload",
            repo=payload.repository.full_name,
            issue_number=payload.issue.number,
        )
        return

    # Check if we should respond
    mentioned = contains_mention(payload.comment.body)

    if mentioned:
        logfire.info(
            "Bot mentioned in comment",
            repo=payload.repository.full_name,
            issue_number=payload.issue.number,
        )
    else:
        # Check if we're already in the conversation
        github = get_github_client(payload.installation.id)
        in_conversation = bot_is_in_conversation(
            github,
            payload.repository.full_name,
            payload.issue.number,
        )

        if not in_conversation:
            logfire.info(
                "Ignoring comment - not mentioned and not in conversation",
                repo=payload.repository.full_name,
                issue_number=payload.issue.number,
            )
            return

        logfire.info(
            "Responding to conversation we're part of",
            repo=payload.repository.full_name,
            issue_number=payload.issue.number,
        )

    # Convert to IssueWebhookPayload format for response
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
    with logfire.span(
        "respond_to_issue",
        repo=payload.repository.full_name,
        issue_number=payload.issue.number,
        issue_title=payload.issue.title,
        has_comment_context=comment_context is not None,
    ):
        logfire.info("Authenticating with GitHub", installation_id=payload.installation.id)
        github = get_github_client(payload.installation.id)

        # Fetch CLAUDE.md for context
        with logfire.span("fetch_claude_md", repo=payload.repository.full_name):
            claude_md = fetch_claude_md(github, payload.repository.full_name)

        # Get conversation history if responding to a comment
        conversation = []
        if comment_context:
            with logfire.span("fetch_conversation", issue_number=payload.issue.number):
                conversation = get_conversation_context(
                    github,
                    payload.repository.full_name,
                    payload.issue.number,
                )
                logfire.info(
                    "Fetched conversation context",
                    comment_count=len(conversation),
                )

        # Generate response
        with logfire.span("generate_response", issue_number=payload.issue.number):
            response_text = await generate_issue_response(
                issue=payload.issue,
                repo_context=claude_md,
                conversation=conversation if conversation else None,
            )

        # Post comment
        with logfire.span("post_comment", issue_number=payload.issue.number):
            logfire.info(
                "Posting comment",
                repo=payload.repository.full_name,
                issue_number=payload.issue.number,
                response_length=len(response_text),
            )
            gh_repo = github.get_repo(payload.repository.full_name)
            gh_issue = gh_repo.get_issue(payload.issue.number)
            gh_issue.create_comment(response_text)

        logfire.info(
            "Successfully responded to issue",
            repo=payload.repository.full_name,
            issue_number=payload.issue.number,
        )
