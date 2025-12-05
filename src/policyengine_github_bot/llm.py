"""LLM integration for generating responses."""

import anthropic

from policyengine_github_bot.config import get_settings


def get_anthropic_client() -> anthropic.Anthropic:
    """Get an Anthropic client."""
    settings = get_settings()
    return anthropic.Anthropic(api_key=settings.anthropic_api_key)


def generate_issue_response(
    issue_title: str,
    issue_body: str,
    repo_context: str | None = None,
) -> str:
    """Generate a response to a GitHub issue using Claude."""
    settings = get_settings()
    client = get_anthropic_client()

    system_prompt = (
        "You are PolicyEngine's helpful GitHub bot. You respond to issues on "
        "PolicyEngine repositories with helpful, accurate information.\n\n"
        "PolicyEngine is an open-source project that models tax and benefit policy. "
        "Key repos include:\n"
        "- policyengine-us: US tax-benefit microsimulation model\n"
        "- policyengine-uk: UK tax-benefit microsimulation model\n"
        "- policyengine-core: Core simulation engine\n"
        "- policyengine-app: React web application\n\n"
        "Be concise, helpful, and technical when appropriate. Use British English. "
        "Don't be overly formal - be friendly but professional."
    )

    if repo_context:
        system_prompt += f"\n\nRepository-specific context from CLAUDE.md:\n{repo_context}"

    user_message = f"""Please respond to this GitHub issue:

Title: {issue_title}

Body:
{issue_body}

Provide a helpful response. If you need more information to help, ask clarifying questions."""

    response = client.messages.create(
        model=settings.anthropic_model,
        max_tokens=2048,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}],
    )

    return response.content[0].text
