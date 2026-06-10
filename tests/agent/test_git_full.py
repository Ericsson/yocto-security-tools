# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.git — revert_unauthorized_changes and run_git_display."""
from unittest.mock import MagicMock, patch

from cve_agent.git import (
    revert_unauthorized_changes,
    run_git_display,
    run_git_stdout,
)


class TestRunGitCapture:
    def test_missing_cwd(self, tmp_path):
        assert run_git_stdout(["status"], tmp_path / "gone") == ""

    @patch("subprocess.run")
    def test_failure(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=128, stdout="error")
        assert run_git_stdout(["status"], tmp_path) == ""


class TestRunGitDisplay:
    @patch("subprocess.run")
    def test_calls_no_pager(self, mock_run, tmp_path):
        run_git_display(["log"], tmp_path)
        cmd = mock_run.call_args[0][0]
        assert "--no-pager" in cmd


class TestRevertUnauthorizedChanges:
    @patch("cve_agent.git.run_git_stdout")
    @patch("subprocess.run")
    def test_reverts_working_tree(self, mock_run, mock_git, tmp_path):
        """Working tree changes are no longer reverted (ephemeral)."""
        mock_git.side_effect = [
            "feature",               # rev-parse --abbrev-ref HEAD
            "",                      # diff --name-only original-version..HEAD (no committed)
        ]
        revert_unauthorized_changes(tmp_path, {"a.c"})
        checkout_calls = [c for c in mock_run.call_args_list
                          if "checkout" in str(c)]
        assert len(checkout_calls) == 0

    @patch("cve_agent.git.run_git_stdout")
    @patch("subprocess.run")
    def test_removes_untracked(self, mock_run, mock_git, tmp_path):
        """Untracked files are no longer removed (ephemeral)."""
        mock_git.side_effect = [
            "feature",               # rev-parse --abbrev-ref HEAD
            "",                      # diff --name-only original-version..HEAD (no committed)
        ]
        untracked = tmp_path / "new_file.txt"
        untracked.write_text("junk")
        revert_unauthorized_changes(tmp_path, set())
        assert untracked.exists()

    @patch("cve_agent.git.run_git_stdout")
    @patch("subprocess.run")
    def test_skips_devtool_branch_no_cve_branch(self, mock_run, mock_git, tmp_path):
        mock_git.side_effect = [
            "devtool",   # rev-parse --abbrev-ref HEAD
            "* devtool\n  main",  # branch --list (no CVE branch found)
        ]
        revert_unauthorized_changes(tmp_path, set())
        reset_calls = [c for c in mock_run.call_args_list if "--soft" in str(c)]
        assert len(reset_calls) == 0

    @patch("cve_agent.git.run_git_stdout")
    @patch("subprocess.run")
    def test_reverts_committed_unauthorized(self, mock_run, mock_git, tmp_path):
        # Create the unauthorized file so unlink works
        (tmp_path / "bad.c").write_text("bad")
        mock_git.side_effect = [
            "feature",   # rev-parse --abbrev-ref HEAD
            "a.c\nbad.c",  # diff --name-only original-version..HEAD
            "commit msg",  # log -1 --format=%B
        ]
        # cat-file -e returns non-zero (file didn't exist at base)
        mock_run.return_value = MagicMock(returncode=1)
        revert_unauthorized_changes(tmp_path, {"a.c"})
        # Should have done soft reset
        reset_calls = [c for c in mock_run.call_args_list if "--soft" in str(c)]
        assert len(reset_calls) >= 1

    @patch("cve_agent.git.run_git_stdout")
    @patch("subprocess.run")
    def test_restores_file_from_base(self, mock_run, mock_git, tmp_path):
        mock_git.side_effect = [
            "feature",   # rev-parse --abbrev-ref HEAD
            "bad.c",     # diff --name-only original-version..HEAD
            "msg",       # log -1 --format=%B
        ]
        # cat-file -e returns 0 (file exists at base)
        mock_run.return_value = MagicMock(returncode=0)
        revert_unauthorized_changes(tmp_path, set())
        checkout_calls = [c for c in mock_run.call_args_list
                          if "original-version" in str(c) and "checkout" in str(c)]
        assert len(checkout_calls) >= 1

    @patch("cve_agent.git.run_git_stdout")
    @patch("subprocess.run")
    def test_keeps_new_file_in_allowed(self, mock_run, mock_git, tmp_path):
        """Files in the allowed set but not in baseline are now kept."""
        (tmp_path / "new.c").write_text("created by agent")
        mock_git.side_effect = [
            "feature",   # rev-parse --abbrev-ref HEAD
            "a.c\nnew.c",  # diff --name-only original-version..HEAD
        ]
        revert_unauthorized_changes(tmp_path, {"a.c", "new.c"})
        # new.c is in allowed set, so it should NOT be reverted
        reset_calls = [c for c in mock_run.call_args_list if "--soft" in str(c)]
        assert len(reset_calls) == 0
