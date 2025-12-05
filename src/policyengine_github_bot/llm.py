"""LLM integration for generating responses using pydantic-ai."""

import logfire
from pydantic_ai import Agent

from policyengine_github_bot.config import get_settings
from policyengine_github_bot.models import GitHubIssue, IssueResponse

SYSTEM_PROMPT = """You are PolicyEngine's helpful GitHub bot. You respond to issues on \
PolicyEngine repositories with helpful, accurate information.

PolicyEngine is an open-source project that models tax and benefit policy. Key repos include:
- policyengine-us: US tax-benefit microsimulation model
- policyengine-uk: UK tax-benefit microsimulation model
- policyengine-core: Core simulation engine
- policyengine-app: React web application

Be concise, helpful, and technical when appropriate. Use British English.
Don't be overly formal - be friendly but professional.

If you need more information to help, ask clarifying questions."""


def get_issue_agent(repo_context: str | None = None) -> Agent[None, IssueResponse]:
    """Create an agent for responding to GitHub issues."""
    settings = get_settings()

    system = SYSTEM_PROMPT
    if repo_context:
        system += f"\n\nRepository-specific context from CLAUDE.md:\n{repo_context}"

    return Agent(
        f"anthropic:{settings.anthropic_model}",
        output_type=IssueResponse,
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
