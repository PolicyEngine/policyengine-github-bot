"""GitHub webhook handlers."""

import hashlib
import hmac
import logging

from fastapi import APIRouter, Header, HTTPException, Request

from policyengine_github_bot.config import get_settings
from policyengine_github_bot.github_auth import get_github_client
from policyengine_github_bot.llm import generate_issue_response

logger = logging.getLogger(__name__)
router = APIRouter()


def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify the GitHub webhook signature."""
    if not signature.startswith("sha256="):
        return False

    expected = hmac.new(
        secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(f"sha256={expected}", signature)


def fetch_claude_md(github, repo_full_name: str) -> str | None:
    """Fetch CLAUDE.md from a repository if it exists."""
    try:
        repo = github.get_repo(repo_full_name)
        contents = repo.get_contents("CLAUDE.md")
        return contents.decoded_content.decode("utf-8")
    except Exception:
        return None


@router.post("/webhook")
async def handle_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None),
):
    """Handle incoming GitHub webhooks."""
    settings = get_settings()
    payload = await request.body()

    # Verify webhook signature
    if not verify_signature(payload, x_hub_signature_256 or "", settings.github_webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid signature")

    data = await request.json()

    if x_github_event == "issues":
        await handle_issue_event(data)
    elif x_github_event == "ping":
        return {"status": "pong"}

    return {"status": "ok"}


async def handle_issue_event(data: dict):
    """Handle issue events."""
    action = data.get("action")

    # Only respond to newly opened issues
    if action != "opened":
        return

    issue = data.get("issue", {})
    repo = data.get("repository", {})
    installation = data.get("installation", {})

    issue_title = issue.get("title", "")
    issue_body = issue.get("body", "") or ""
    repo_full_name = repo.get("full_name", "")
    issue_number = issue.get("number")
    installation_id = installation.get("id")

    if not installation_id:
        logger.error("No installation ID in webhook payload")
        return

    logger.info(f"Handling new issue #{issue_number} in {repo_full_name}")

    # Get authenticated GitHub client
    github = get_github_client(installation_id)

    # Fetch CLAUDE.md for context
    claude_md = fetch_claude_md(github, repo_full_name)

    # Generate response
    response_text = generate_issue_response(
        issue_title=issue_title,
        issue_body=issue_body,
        repo_context=claude_md,
    )

    # Post comment
    gh_repo = github.get_repo(repo_full_name)
    gh_issue = gh_repo.get_issue(issue_number)
    gh_issue.create_comment(response_text)

    logger.info(f"Posted response to issue #{issue_number}")
