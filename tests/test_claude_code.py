"""Tests for Claude Code integration."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from policyengine_github_bot.claude_code import (
    TaskResult,
    execute_task,
    gather_review_context,
    run_claude_code,
    run_claude_code_streaming,
)
from policyengine_github_bot.repo import clone_repo, get_temp_repo_dir


class TestRunClaudeCode:
    def test_run_claude_code_success(self, tmp_path: Path):
        """Test successful Claude Code execution."""
        with patch("policyengine_github_bot.claude_code.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="This is the analysis output",
                stderr="",
            )

            result = run_claude_code("Analyse this code", tmp_path)

            assert result == "This is the analysis output"
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert call_args[0][0] == [
                "claude",
                "-p",
                "Analyse this code",
                "--output-format",
                "text",
                "--allowedTools",
                "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch",
            ]
            assert call_args[1]["cwd"] == tmp_path

    def test_run_claude_code_failure(self, tmp_path: Path):
        """Test Claude Code failure raises RuntimeError."""
        with patch("policyengine_github_bot.claude_code.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="Something went wrong",
            )

            with pytest.raises(RuntimeError, match="Claude Code failed"):
                run_claude_code("Analyse this code", tmp_path)

    def test_run_claude_code_timeout(self, tmp_path: Path):
        """Test custom timeout is passed through."""
        with patch("policyengine_github_bot.claude_code.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="output", stderr="")

            run_claude_code("prompt", tmp_path, timeout=600)

            call_args = mock_run.call_args
            assert call_args[1]["timeout"] == 600


class TestRunClaudeCodeStreaming:
    def test_streaming_yields_lines(self, tmp_path: Path):
        """Test streaming yields output lines."""
        with patch("policyengine_github_bot.claude_code.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.stdout = iter(["line 1\n", "line 2\n", "line 3\n"])
            mock_proc.wait.return_value = None
            mock_proc.returncode = 0
            mock_popen.return_value = mock_proc

            lines = list(run_claude_code_streaming("prompt", tmp_path))

            assert lines == ["line 1\n", "line 2\n", "line 3\n"]

    def test_streaming_raises_on_failure(self, tmp_path: Path):
        """Test streaming raises on non-zero exit."""
        with patch("policyengine_github_bot.claude_code.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.stdout = iter([])
            mock_proc.wait.return_value = None
            mock_proc.returncode = 1
            mock_popen.return_value = mock_proc

            with pytest.raises(RuntimeError, match="exited with code 1"):
                list(run_claude_code_streaming("prompt", tmp_path))


class TestCloneRepo:
    async def test_clone_repo_success(self, tmp_path: Path):
        """Test successful repo clone."""
        with patch("policyengine_github_bot.repo.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            result = await clone_repo(
                "https://github.com/policyengine/test-repo",
                tmp_path,
                ref="main",
            )

            assert result == tmp_path / "test-repo"
            mock_run.assert_called_once()
            cmd = mock_run.call_args[0][0]
            assert "git" in cmd
            assert "clone" in cmd
            assert "--depth" in cmd
            assert "20" in cmd
            assert "--branch" in cmd
            assert "main" in cmd

    async def test_clone_repo_with_token(self, tmp_path: Path):
        """Test clone with auth token."""
        with patch("policyengine_github_bot.repo.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            await clone_repo(
                "https://github.com/policyengine/test-repo",
                tmp_path,
                token="ghp_secret123",
            )

            cmd = mock_run.call_args[0][0]
            # Token should be in the URL
            assert any("x-access-token:ghp_secret123@" in arg for arg in cmd)

    async def test_clone_repo_failure(self, tmp_path: Path):
        """Test clone failure raises RuntimeError."""
        with patch("policyengine_github_bot.repo.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=128,
                stdout="",
                stderr="fatal: repository not found",
            )

            with pytest.raises(RuntimeError, match="Failed to clone"):
                await clone_repo("https://github.com/policyengine/nonexistent", tmp_path)

    async def test_clone_repo_custom_depth(self, tmp_path: Path):
        """Test clone with custom depth."""
        with patch("policyengine_github_bot.repo.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            await clone_repo(
                "https://github.com/policyengine/test-repo",
                tmp_path,
                depth=5,
            )

            cmd = mock_run.call_args[0][0]
            depth_idx = cmd.index("--depth")
            assert cmd[depth_idx + 1] == "5"


class TestGetTempRepoDir:
    def test_temp_dir_created_and_cleaned(self):
        """Test temp directory is created and cleaned up."""
        with get_temp_repo_dir() as tmpdir:
            path = Path(tmpdir)
            assert path.exists()
            assert path.is_dir()
            assert "policyengine-bot-" in path.name

        # Should be cleaned up after context exits
        assert not path.exists()


class TestGatherReviewContext:
    async def test_gather_context_full_flow(self):
        """Test full context gathering flow."""
        with (
            patch("policyengine_github_bot.claude_code.clone_repo") as mock_clone,
            patch("policyengine_github_bot.claude_code.run_claude_code") as mock_run,
            patch("policyengine_github_bot.claude_code.get_temp_repo_dir") as mock_temp,
        ):
            # Set up mocks
            mock_temp.return_value.__enter__ = MagicMock(return_value="/tmp/test")
            mock_temp.return_value.__exit__ = MagicMock(return_value=False)
            mock_clone.return_value = Path("/tmp/test/repo")
            mock_run.return_value = "Analysis: this code does X and Y"

            result = await gather_review_context(
                repo_url="https://github.com/policyengine/test",
                ref="feature-branch",
                files_changed=["src/main.py", "src/utils.py"],
                pr_title="Add new feature",
                pr_body="This PR adds a cool feature",
                token="ghp_token",
            )

            assert result == "Analysis: this code does X and Y"
            mock_clone.assert_called_once()
            mock_run.assert_called_once()

            # Check prompt contains key info
            prompt = mock_run.call_args[0][0]
            assert "Add new feature" in prompt
            assert "src/main.py" in prompt
            assert "src/utils.py" in prompt

    async def test_gather_context_limits_files_list(self):
        """Test that file list is limited to prevent huge prompts."""
        with (
            patch("policyengine_github_bot.claude_code.clone_repo") as mock_clone,
            patch("policyengine_github_bot.claude_code.run_claude_code") as mock_run,
            patch("policyengine_github_bot.claude_code.get_temp_repo_dir") as mock_temp,
        ):
            mock_temp.return_value.__enter__ = MagicMock(return_value="/tmp/test")
            mock_temp.return_value.__exit__ = MagicMock(return_value=False)
            mock_clone.return_value = Path("/tmp/test/repo")
            mock_run.return_value = "output"

            # Pass 30 files
            files = [f"src/file{i}.py" for i in range(30)]

            await gather_review_context(
                repo_url="https://github.com/policyengine/test",
                ref="main",
                files_changed=files,
                pr_title="Big change",
            )

            prompt = mock_run.call_args[0][0]
            # Should show first 20 and mention "10 more"
            assert "file19.py" in prompt
            assert "file20.py" not in prompt
            assert "10 more files" in prompt


class TestExecuteTask:
    async def test_execute_task_success_with_pr(self):
        """Test successful task execution that creates a PR."""
        with (
            patch("policyengine_github_bot.claude_code.clone_repo") as mock_clone,
            patch("policyengine_github_bot.claude_code.run_claude_code") as mock_run,
            patch("policyengine_github_bot.claude_code.get_temp_repo_dir") as mock_temp,
            patch("policyengine_github_bot.claude_code.subprocess.run") as mock_subprocess,
        ):
            mock_temp.return_value.__enter__ = MagicMock(return_value="/tmp/test")
            mock_temp.return_value.__exit__ = MagicMock(return_value=False)
            mock_clone.return_value = Path("/tmp/test/repo")
            mock_subprocess.return_value = MagicMock(returncode=0)
            mock_run.return_value = """Done! Created PR at https://github.com/org/repo/pull/123"""

            result = await execute_task(
                repo_url="https://github.com/org/repo",
                base_ref="main",
                task="Fix the bug",
                issue_number=42,
                token="ghp_token",
            )

            assert result.success
            assert result.pr_url == "https://github.com/org/repo/pull/123"
            assert "Done!" in result.output

    async def test_execute_task_failure(self):
        """Test task execution that fails."""
        with (
            patch("policyengine_github_bot.claude_code.clone_repo") as mock_clone,
            patch("policyengine_github_bot.claude_code.get_temp_repo_dir") as mock_temp,
        ):
            mock_temp.return_value.__enter__ = MagicMock(return_value="/tmp/test")
            mock_temp.return_value.__exit__ = MagicMock(return_value=False)
            mock_clone.side_effect = RuntimeError("Clone failed")

            result = await execute_task(
                repo_url="https://github.com/org/repo",
                base_ref="main",
                task="Fix the bug",
            )

            assert not result.success
            assert "Clone failed" in result.output

    async def test_execute_task_configures_git(self):
        """Test that git is configured for commits."""
        with (
            patch("policyengine_github_bot.claude_code.clone_repo") as mock_clone,
            patch("policyengine_github_bot.claude_code.run_claude_code") as mock_run,
            patch("policyengine_github_bot.claude_code.get_temp_repo_dir") as mock_temp,
            patch("policyengine_github_bot.claude_code.subprocess.run") as mock_subprocess,
        ):
            mock_temp.return_value.__enter__ = MagicMock(return_value="/tmp/test")
            mock_temp.return_value.__exit__ = MagicMock(return_value=False)
            mock_clone.return_value = Path("/tmp/test/repo")
            mock_subprocess.return_value = MagicMock(returncode=0)
            mock_run.return_value = "Done"

            await execute_task(
                repo_url="https://github.com/org/repo",
                base_ref="main",
                task="Fix bug",
            )

            # Should configure git email and name
            git_calls = [call[0][0] for call in mock_subprocess.call_args_list]
            assert any("user.email" in str(call) for call in git_calls)
            assert any("user.name" in str(call) for call in git_calls)


