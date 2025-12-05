"""Claude Code integration for enhanced codebase analysis."""

import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import logfire

from policyengine_github_bot.repo import clone_repo, get_temp_repo_dir


@dataclass
class TaskResult:
    """Result from executing a Claude Code task."""

    output: str
    success: bool
    pr_url: str | None = None


def run_claude_code(
    prompt: str,
    workdir: Path,
    timeout: int = 300,
) -> str:
    """Run Claude Code CLI in a directory and return output.

    Args:
        prompt: The prompt to send to Claude Code
        workdir: Working directory for Claude Code to operate in
        timeout: Timeout in seconds (default 5 minutes)

    Returns:
        The output from Claude Code
    """
    logfire.info(f"[claude-code] Running in {workdir}")

    result = subprocess.run(
        ["claude", "-p", prompt, "--output-format", "text", "--dangerously-skip-permissions"],
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=timeout,
    )

    if result.returncode != 0:
        logfire.error(f"[claude-code] Failed: {result.stderr}")
        raise RuntimeError(f"Claude Code failed: {result.stderr}")

    logfire.info(f"[claude-code] Complete ({len(result.stdout)} chars)")
    return result.stdout


def run_claude_code_streaming(
    prompt: str,
    workdir: Path,
) -> Iterator[str]:
    """Run Claude Code CLI and stream output line by line.

    Args:
        prompt: The prompt to send to Claude Code
        workdir: Working directory for Claude Code to operate in

    Yields:
        Lines of output from Claude Code
    """
    logfire.info(f"[claude-code] Starting streaming in {workdir}")

    proc = subprocess.Popen(
        ["claude", "-p", prompt, "--dangerously-skip-permissions"],
        cwd=workdir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    yield from proc.stdout

    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(f"Claude Code exited with code {proc.returncode}")

    logfire.info("[claude-code] Streaming complete")


async def gather_review_context(
    repo_url: str,
    ref: str,
    files_changed: list[str],
    pr_title: str,
    pr_body: str | None = None,
    token: str | None = None,
) -> str:
    """Use Claude Code to gather codebase context for a PR review.

    Clones the repo to a temp directory, runs Claude Code to explore,
    then cleans up.

    Args:
        repo_url: HTTPS URL of the repository
        ref: Branch or commit to checkout
        files_changed: List of file paths being changed
        pr_title: Title of the pull request
        pr_body: Body/description of the pull request
        token: GitHub token for private repos

    Returns:
        Context string to include in the review prompt
    """
    files_list = "\n".join(f"- {f}" for f in files_changed[:20])  # Limit for prompt size
    if len(files_changed) > 20:
        files_list += f"\n- ... and {len(files_changed) - 20} more files"

    prompt = f"""I'm reviewing a pull request. Help me understand the context.

PR title: {pr_title}

PR description:
{pr_body or "(no description)"}

Files changed:
{files_list}

Please explore this codebase and provide context that would help review this PR:

1. What do the changed files do? (brief summary of each)
2. What other code depends on or calls into these files?
3. Are there similar patterns elsewhere that should stay consistent?
4. Any repo conventions I should know about? (check for CLAUDE.md, README, etc.)

Be concise - bullet points, key facts only. No preamble."""

    with get_temp_repo_dir() as tmpdir:
        repo_path = await clone_repo(
            repo_url=repo_url,
            target_dir=tmpdir,
            ref=ref,
            token=token,
        )
        return run_claude_code(prompt, repo_path)


async def execute_task(
    repo_url: str,
    base_ref: str,
    task: str,
    issue_number: int | None = None,
    token: str | None = None,
    timeout: int = 600,
) -> TaskResult:
    """Use Claude Code to execute a task in a repository.

    This is for tasks that modify code - fixing bugs, implementing features,
    filing PRs, etc. Claude Code will have full access to make changes.

    Args:
        repo_url: HTTPS URL of the repository
        base_ref: Branch to start from (usually main/master)
        task: Description of what to do
        issue_number: Related issue number (for branch naming, PR linking)
        token: GitHub token for auth (required for pushing)
        timeout: Timeout in seconds (default 10 minutes)

    Returns:
        TaskResult with output, success status, and PR URL if created
    """
    import re

    branch_suffix = f"issue-{issue_number}" if issue_number else "bot-task"
    pr_ref = f" that references issue #{issue_number}" if issue_number else ""

    prompt = f"""You are working on a task for the PolicyEngine GitHub bot.

Task: {task}

Instructions:
1. Understand what needs to be done
2. Make the necessary code changes
3. Create a new branch named 'bot/{branch_suffix}' from the current branch
4. Commit your changes with a clear message
5. Push the branch and create a pull request{pr_ref}

Important:
- Be concise in commit messages and PR descriptions
- Only make changes directly related to the task
- If you can't complete the task, explain why
- Use `gh` CLI for GitHub operations (creating PRs, etc.)

When done, output a summary of what you did and include the PR URL if you created one."""

    with get_temp_repo_dir() as tmpdir:
        try:
            repo_path = await clone_repo(
                repo_url=repo_url,
                target_dir=tmpdir,
                ref=base_ref,
                token=token,
            )

            # Configure git for commits
            subprocess.run(
                ["git", "config", "user.email", "bot@policyengine.org"],
                cwd=repo_path,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "PolicyEngine Bot"],
                cwd=repo_path,
                check=True,
            )

            output = run_claude_code(prompt, repo_path, timeout=timeout)

            # Try to extract PR URL from output
            pr_url = None
            pr_match = re.search(r"https://github\.com/[^\s]+/pull/\d+", output)
            if pr_match:
                pr_url = pr_match.group(0)

            logfire.info(
                "[claude-code] Task completed",
                pr_url=pr_url,
                output_length=len(output),
            )

            return TaskResult(output=output, success=True, pr_url=pr_url)

        except Exception as e:
            logfire.error(f"[claude-code] Task failed: {e}")
            return TaskResult(output=str(e), success=False)
