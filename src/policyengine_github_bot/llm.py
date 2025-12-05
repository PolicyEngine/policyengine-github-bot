"""LLM integration for generating responses using pydantic-ai."""

import logfire
from pydantic_ai import Agent

from policyengine_github_bot.config import get_settings
from policyengine_github_bot.models import (
    GitHubIssue,
    GitHubPullRequest,
    IssueResponse,
    PRReviewResponse,
)

BASE_SYSTEM_PROMPT = """You are PolicyEngine's GitHub bot.

Be concise. Avoid unnecessary preamble or filler.
Use sentence case everywhere (not Title Case).
Be friendly but professional. Don't be overly formal.
If you need more information, ask specific clarifying questions."""


def get_issue_agent(repo_context: str | None = None) -> Agent[None, IssueResponse]:
    """Create an agent for responding to GitHub issues."""
    settings = get_settings()

    system = BASE_SYSTEM_PROMPT + "\n\nYou respond to issues with helpful, accurate information."
    if repo_context:
        system += f"\n\nRepository context:\n{repo_context}"

    return Agent(
        f"anthropic:{settings.anthropic_model}",
        output_type=IssueResponse,
        system_prompt=system,
    )


def get_pr_review_agent(repo_context: str | None = None) -> Agent[None, PRReviewResponse]:
    """Create an agent for reviewing pull requests."""
    settings = get_settings()

    system = (
        BASE_SYSTEM_PROMPT
        + """

You review pull requests. When reviewing:
1. Check that the change does what the PR description says
2. Look for bugs, edge cases, and potential issues
3. Consider test coverage - are new features tested?
4. Flag any security concerns
5. Note if documentation needs updating
6. Be constructive - suggest improvements, don't just criticise
7. Focus on substance over style (assume formatters handle style)

For approval field, use exactly one of: APPROVE, REQUEST_CHANGES, or COMMENT"""
    )

    if repo_context:
        system += f"\n\nRepository context:\n{repo_context}"

    return Agent(
        f"anthropic:{settings.anthropic_model}",
        output_type=PRReviewResponse,
        system_prompt=system,
    )


async def generate_issue_response(
    issue: GitHubIssue,
    repo_context: str | None = None,
    conversation: list[dict] | None = None,
) -> str:
    """Generate a response to a GitHub issue using Claude."""
    logfire.info(
        "Generating issue response",
        issue_number=issue.number,
        issue_title=issue.title,
        has_repo_context=repo_context is not None,
        conversation_length=len(conversation) if conversation else 0,
    )

    agent = get_issue_agent(repo_context)

    prompt = f"""Please respond to this GitHub issue:

Title: {issue.title}

Body:
{issue.body or "(no body provided)"}"""

    if conversation:
        prompt += "\n\nConversation history:\n"
        for comment in conversation:
            role = "You" if comment["is_bot"] else comment["author"]
            prompt += f"\n{role}:\n{comment['body']}\n"

    prompt += "\n\nProvide a helpful response."

    result = await agent.run(prompt)

    logfire.info(
        "Generated response",
        issue_number=issue.number,
        response_length=len(result.output.content),
    )

    return result.output.content


async def generate_pr_review(
    pr: GitHubPullRequest,
    diff: str,
    files_changed: list[dict],
    repo_context: str | None = None,
) -> PRReviewResponse:
    """Generate a PR review using Claude."""
    logfire.info(
        "Generating PR review",
        pr_number=pr.number,
        pr_title=pr.title,
        files_changed=len(files_changed),
        diff_length=len(diff),
        has_repo_context=repo_context is not None,
    )

    agent = get_pr_review_agent(repo_context)

    files_summary = "\n".join(
        f"- {f['filename']} (+{f.get('additions', 0)}/-{f.get('deletions', 0)})"
        for f in files_changed
    )

    prompt = f"""Please review this pull request:

Title: {pr.title}

Description:
{pr.body or "(no description provided)"}

Files changed:
{files_summary}

Diff:
```
{diff}
```

Provide a thorough but concise review."""

    result = await agent.run(prompt)

    logfire.info(
        "Generated PR review",
        pr_number=pr.number,
        approval=result.output.approval,
        comment_count=len(result.output.comments),
    )

    return result.output
