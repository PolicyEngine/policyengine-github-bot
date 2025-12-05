"""LLM integration for generating responses using pydantic-ai."""

import logfire
from pydantic_ai import Agent

from policyengine_github_bot.config import get_settings
from policyengine_github_bot.models import (
    GitHubIssue,
    GitHubPullRequest,
    IssueResponse,
    PRReReviewResponse,
    PRReviewResponse,
)

# Instrument pydantic-ai with logfire for tracing LLM calls
logfire.instrument_pydantic_ai()

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

IMPORTANT: You MUST provide inline comments on specific lines of code.
- Each comment needs: path (file path), line (line number in the new file), body (your comment)
- The line number should be from the RIGHT side of the diff (the new version)
- Look at @@ hunk headers for line numbers (e.g. @@ -10,5 +12,7 @@ means new lines start at 12)
- Add comments for: bugs, potential issues, suggestions, questions about the code
- Don't comment on trivial style issues

For approval field:
- APPROVE: The code is good to merge. Use this when changes are correct and complete.
- REQUEST_CHANGES: There are issues that MUST be fixed before merging (bugs, security issues, \
missing tests for new functionality, broken logic).
- COMMENT: You have feedback but it's not blocking (suggestions, questions, minor improvements).

When re-reviewing after changes, check if previous concerns were addressed."""
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

Diff (with line numbers from @@ headers showing new file line positions):
```diff
{diff}
```

Provide a thorough but concise review. Include inline comments on specific lines where you have \
feedback. Use the line numbers from the RIGHT side of the diff (the + lines in the new version). \
Each inline comment should reference a specific file path and line number."""

    result = await agent.run(prompt)

    logfire.info(
        "Generated PR review",
        pr_number=pr.number,
        approval=result.output.approval,
        comment_count=len(result.output.comments),
    )

    return result.output


def get_pr_rereview_agent(
    repo_context: str | None = None,
) -> Agent[None, PRReReviewResponse]:
    """Create an agent for re-reviewing pull requests."""
    settings = get_settings()

    system = (
        BASE_SYSTEM_PROMPT
        + """

You are re-reviewing a pull request after changes were made. Your job is to:
1. Check if previous review comments have been addressed
2. Decide what to do with each open thread
3. Only add NEW comments if there are genuinely new issues

For each open thread, you must decide:
- RESOLVE: The issue has been fixed. Use this when the code change addresses the concern.
- REPLY: The issue is NOT fixed or needs follow-up. Provide a reply explaining why.

IMPORTANT: Do NOT post a whole new review unless there are genuinely NEW issues to comment on.
- If all threads are resolved and no new issues, just resolve threads (no new_comments needed)
- If threads need replies, reply to them (no new_comments needed)
- Only use new_comments for issues on lines NOT already covered by existing threads

Be concise in replies. Examples:
- "Fixed, thanks!"
- "This still needs attention - the edge case for X isn't handled."
- "Good improvement, but consider also handling Y."
"""
    )

    if repo_context:
        system += f"\n\nRepository context:\n{repo_context}"

    return Agent(
        f"anthropic:{settings.anthropic_model}",
        output_type=PRReReviewResponse,
        system_prompt=system,
    )


async def generate_pr_rereview(
    pr: GitHubPullRequest,
    diff: str,
    files_changed: list[dict],
    open_threads: list[dict],
    rereview_context: str,
    repo_context: str | None = None,
) -> PRReReviewResponse:
    """Generate a re-review response for a PR."""
    logfire.info(
        "Generating PR re-review",
        pr_number=pr.number,
        pr_title=pr.title,
        open_thread_count=len(open_threads),
    )

    agent = get_pr_rereview_agent(repo_context)

    files_summary = "\n".join(
        f"- {f['filename']} (+{f.get('additions', 0)}/-{f.get('deletions', 0)})"
        for f in files_changed
    )

    # Build thread list for the prompt
    threads_text = ""
    for i, thread in enumerate(open_threads):
        comments = thread.get("comments", {}).get("nodes", [])
        if comments:
            first = comments[0]
            author = first.get("author", {}).get("login", "unknown")
            body = first.get("body", "(no body)")
            threads_text += f"\n[Thread {i}] by @{author}:\n{body}\n"

    prompt = f"""Re-review this pull request.

Title: {pr.title}

Description:
{pr.body or "(no description provided)"}

Files changed:
{files_summary}

Current diff:
```diff
{diff}
```

Context for this re-review:
{rereview_context}

Open threads that need your attention:
{threads_text}

For each thread above, decide whether to RESOLVE it (if fixed) or REPLY (if not fixed).
Only add new_comments if there are genuinely NEW issues not covered by existing threads."""

    result = await agent.run(prompt)

    logfire.info(
        "Generated PR re-review",
        pr_number=pr.number,
        thread_actions=len(result.output.thread_actions),
        new_comments=len(result.output.new_comments),
    )

    return result.output
