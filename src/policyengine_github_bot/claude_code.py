"""Claude Code integration for enhanced codebase analysis."""

import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import logfire

from policyengine_github_bot.repo import clone_repo, get_temp_repo_dir

PLUGIN_REPO_URL = "https://github.com/PolicyEngine/policyengine-claude"


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
    env: dict | None = None,
) -> str:
    """Run Claude Code CLI in a directory, stream output to logfire, and return result.

    Args:
        prompt: The prompt to send to Claude Code
        workdir: Working directory for Claude Code to operate in
        timeout: Timeout in seconds (default 5 minutes)
        env: Optional environment variables (e.g. for GH_TOKEN)

    Returns:
        The output from Claude Code
    """
    import select
    import time

    logfire.info(f"[claude-code] Running in {workdir}")

    proc = subprocess.Popen(
        [
            "claude",
            "-p",
            prompt,
            "--output-format",
            "text",
            "--allowedTools",
            "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch",
        ],
        cwd=workdir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )

    output_lines = []
    start_time = time.time()

    try:
        while True:
            # Check timeout
            if time.time() - start_time > timeout:
                proc.kill()
                raise TimeoutError(f"Claude Code timed out after {timeout}s")

            # Check if process has finished
            retcode = proc.poll()
            if retcode is not None:
                # Process finished, read any remaining output
                for line in proc.stdout:
                    output_lines.append(line)
                    logfire.info("[claude-code] output", line=line.rstrip())
                break

            # Try to read a line (non-blocking on unix via select)
            ready, _, _ = select.select([proc.stdout], [], [], 0.1)
            if ready:
                line = proc.stdout.readline()
                if line:
                    output_lines.append(line)
                    logfire.info("[claude-code] output", line=line.rstrip())

    except Exception as e:
        proc.kill()
        raise e

    if proc.returncode != 0:
        output = "".join(output_lines)
        logfire.error(f"[claude-code] Failed with code {proc.returncode}")
        raise RuntimeError(f"Claude Code failed (exit {proc.returncode}): {output[-500:]}")

    output = "".join(output_lines)
    logfire.info(f"[claude-code] Complete ({len(output)} chars)")
    return output


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
        [
            "claude",
            "-p",
            prompt,
            "--allowedTools",
            "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch",
        ],
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


async def capture_learnings(
    task_context: str,
    task_output: str,
    source_repo: str,
    token: str | None = None,
    timeout: int = 300,
) -> str | None:
    """Reflect on a completed task and file a PR to the plugin repo if there are learnings.

    Args:
        task_context: Description of the task that was performed
        task_output: Output from the task execution
        source_repo: The repo where the task was performed
        token: GitHub token for auth
        timeout: Timeout in seconds

    Returns:
        PR URL if one was created, None otherwise
    """
    import asyncio
    import os
    import re

    prompt = f"""You just helped with a task in {source_repo}:

Task: {task_context[:500]}

You should consider whether there's anything you learned that would help future Claude Code sessions working on PolicyEngine repositories. This could include:
- Patterns or conventions specific to this repo
- Common gotchas or edge cases
- Useful context about how components interact
- Testing or debugging tips

If there's something worth adding to the PolicyEngine Claude plugin (policyengine-claude), file a PR. The plugin contains skills, agents, and documentation that help Claude Code work effectively on PolicyEngine repos.

If there's nothing significant to add, just say "No learnings to capture" and stop.

If filing a PR:
- Create branch 'bot/learnings-{source_repo.split("/")[-1]}'
- Keep changes minimal and focused
- Commit and push, then create PR with `gh pr create`

Be selective - only file a PR if it would genuinely help future sessions."""

    with logfire.span("[claude-code] Capturing learnings", source_repo=source_repo):
        with get_temp_repo_dir() as tmpdir:
            try:
                repo_path = await clone_repo(
                    repo_url=PLUGIN_REPO_URL,
                    target_dir=tmpdir,
                    ref="main",
                    token=token,
                )

                subprocess.run(
                    ["git", "config", "user.email", "bot@policyengine.org"],
                    cwd=repo_path,
                    check=True,
                )
                subprocess.run(
                    ["git", "config", "user.name", "policyengine-bot"],
                    cwd=repo_path,
                    check=True,
                )

                env = os.environ.copy()
                if token:
                    env["GH_TOKEN"] = token

                output = await asyncio.to_thread(
                    run_claude_code, prompt, repo_path, timeout, env
                )

                # Check if a PR was created
                pr_match = re.search(r"https://github\.com/[^\s]+/pull/\d+", output)
                if pr_match:
                    pr_url = pr_match.group(0)
                    logfire.info("[claude-code] Filed learnings PR", pr_url=pr_url)
                    return pr_url

                logfire.info("[claude-code] No learnings to capture")
                return None

            except Exception as e:
                logfire.warning(f"[claude-code] Failed to capture learnings: {e}")
                return None


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
    prompt = f"""Reviewing PR: {pr_title}

{pr_body or "(no description)"}

Files: {", ".join(files_changed[:10])}{f" (+{len(files_changed) - 10} more)" if len(files_changed) > 10 else ""}

Explore the codebase and tell me:
- What these files do (one line each)
- What depends on them
- Any patterns to keep consistent
- Relevant conventions (check CLAUDE.md, README)

Reply as a human would - short sentences, no headers, no preamble."""

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

    Claude Code has full access to the codebase and can answer questions,
    make changes, create PRs, etc.

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
    import os
    import re

    branch_suffix = f"issue-{issue_number}" if issue_number else "bot-task"

    prompt = f"""{task}

If making changes: branch 'bot/{branch_suffix}', commit, push, create PR with `gh pr create`.

Your response will be posted as a GitHub comment. Write like a human - be direct, no unnecessary headers or formatting. Just say what you did or found."""

    with logfire.span(
        "[claude-code] Executing task",
        repo_url=repo_url,
        issue_number=issue_number,
        timeout=timeout,
    ):
        with get_temp_repo_dir() as tmpdir:
            try:
                repo_path = await clone_repo(
                    repo_url=repo_url,
                    target_dir=tmpdir,
                    ref=base_ref,
                    token=token,
                )

                # Configure git for commits (author info)
                subprocess.run(
                    ["git", "config", "user.email", "bot@policyengine.org"],
                    cwd=repo_path,
                    check=True,
                )
                subprocess.run(
                    ["git", "config", "user.name", "policyengine-bot"],
                    cwd=repo_path,
                    check=True,
                )

                # Set up environment with GitHub token for gh CLI
                env = os.environ.copy()
                if token:
                    env["GH_TOKEN"] = token

                import asyncio

                output = await asyncio.to_thread(run_claude_code, prompt, repo_path, timeout, env)

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

                # Capture learnings in background (don't block the response)
                asyncio.create_task(
                    capture_learnings(
                        task_context=task,
                        task_output=output,
                        source_repo=repo_url,
                        token=token,
                    )
                )

                return TaskResult(output=output, success=True, pr_url=pr_url)

            except Exception as e:
                logfire.error(f"[claude-code] Task failed: {e}")
                return TaskResult(output=str(e), success=False)
