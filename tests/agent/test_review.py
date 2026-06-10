# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.review — approval gate and change review."""
from pathlib import Path
from unittest.mock import patch

from cve_agent import AgentConfig
from cve_agent.review import (
    _display_changes,
    _save_review_diff,
    amend_commit_with_summary,
    build_change_summary,
    request_approval,
)


def _make_config(**kwargs):
    defaults = dict(cve_id="CVE-2025-0001", cve_info_path=Path("/tmp/c.json"))
    defaults.update(kwargs)
    return AgentConfig(**defaults)


class TestRequestApproval:
    @patch("cve_agent.review.amend_commit_with_summary")
    @patch("cve_agent.review.build_change_summary", return_value="summary")
    def test_trust_mode_auto_approves(self, mock_summary, mock_amend):
        cfg = _make_config(trust_mode=True)
        action, feedback = request_approval(Path("/ws"), "abc123", cfg)
        assert action == "approved"
        assert feedback == ""
        mock_amend.assert_called_once()

    @patch("cve_agent.review._display_changes")
    @patch("cve_agent.review._save_review_diff", return_value=Path("/tmp/d.diff"))
    @patch("cve_agent.review.amend_commit_with_summary")
    @patch("cve_agent.review.build_change_summary", return_value="summary")
    @patch("builtins.input", return_value="y")
    def test_approve_yes(self, *_):
        cfg = _make_config()
        action, feedback = request_approval(Path("/ws"), "abc123", cfg)
        assert action == "approved"

    @patch("cve_agent.review._display_changes")
    @patch("cve_agent.review._save_review_diff", return_value=Path("/tmp/d.diff"))
    @patch("cve_agent.review.build_change_summary", return_value="summary")
    @patch("builtins.input", return_value="n")
    def test_approve_no(self, *_):
        cfg = _make_config()
        action, _ = request_approval(Path("/ws"), "abc123", cfg)
        assert action == "rejected"

    @patch("cve_agent.review._display_changes")
    @patch("cve_agent.review._save_review_diff", return_value=Path("/tmp/d.diff"))
    @patch("cve_agent.review.build_change_summary", return_value="summary")
    @patch("builtins.input", side_effect=["e", "fix the thing"])
    def test_approve_edit(self, *_):
        cfg = _make_config()
        action, feedback = request_approval(Path("/ws"), "abc123", cfg)
        assert action == "edit"
        assert feedback == "fix the thing"

    @patch("cve_agent.review._display_changes")
    @patch("cve_agent.review._save_review_diff", return_value=Path("/tmp/d.diff"))
    @patch("cve_agent.review.build_change_summary", return_value="summary")
    @patch("builtins.input", side_effect=["invalid", "y"])
    @patch("cve_agent.review.amend_commit_with_summary")
    def test_approve_retry_on_invalid(self, *_):
        cfg = _make_config()
        action, _ = request_approval(Path("/ws"), "abc123", cfg)
        assert action == "approved"


class TestBuildChangeSummary:
    @patch("cve_agent.review.run_git_stdout", return_value="")
    @patch("cve_agent.review.get_changed_files")
    def test_no_deviations(self, mock_files, mock_git):
        mock_files.side_effect = [{"a.c"}, {"a.c"}]
        result = build_change_summary(Path("/ws"), "abc123")
        assert "no deviations" in result

    @patch("cve_agent.review.run_git_stdout", return_value="some diff")
    @patch("cve_agent.review.get_changed_files")
    def test_adapted_files(self, mock_files, mock_git):
        mock_files.side_effect = [{"a.c", "b.c"}, {"a.c"}]
        result = build_change_summary(Path("/ws"), "abc123")
        assert "adapted from upstream" in result

    @patch("cve_agent.review.run_git_stdout", return_value="")
    @patch("cve_agent.review.get_changed_files")
    def test_omitted_files(self, mock_files, mock_git):
        mock_files.side_effect = [{"a.c", "b.c"}, {"a.c"}]
        result = build_change_summary(Path("/ws"), "abc123")
        assert "omitted from backport" in result


class TestAmendCommit:
    @patch("cve_agent.review.run_git_stdout",
           return_value="Changes from upstream commit abc123456789 already here")
    def test_skip_if_already_present(self, mock_git):
        amend_commit_with_summary(Path("/ws"), "abc123456789abcdef", "summary")

    @patch("subprocess.run")
    @patch("cve_agent.review.run_git_stdout", return_value="Fix CVE\n\nCVE: CVE-2025-0001")
    def test_strips_cve_block_and_appends(self, mock_git, mock_run):
        amend_commit_with_summary(Path("/ws"), "def456", "my summary")
        mock_run.assert_called_once()
        msg = mock_run.call_args[1].get("args", mock_run.call_args[0][0])
        assert "my summary" in msg[-1]

    @patch("subprocess.run")
    @patch("cve_agent.review.run_git_stdout",
           return_value="Fix CVE\n\nBackport-Resolution: adapted")
    def test_preserves_kiro_notes(self, mock_git, mock_run):
        amend_commit_with_summary(Path("/ws"), "def456", "summary")
        mock_run.assert_called_once()
        msg = mock_run.call_args[0][0][-1]
        assert "Backport-Resolution" in msg
        assert "summary" not in msg


class TestSaveReviewDiff:
    @patch("cve_agent.review.run_git_stdout", return_value="diff content")
    @patch("cve_agent.review.get_changed_files", return_value={"a.c"})
    def test_saves_diff_file(self, mock_files, mock_git, tmp_path):
        agent_dir = tmp_path / "agent"
        agent_dir.mkdir()
        with patch("cve_agent.review.get_agent_dir", return_value=agent_dir):
            result = _save_review_diff(Path("/ws"), "abc123456789")
        assert result.exists()
        content = result.read_text()
        assert "UPSTREAM COMMIT" in content
        assert "BACKPORTED DIFF" in content

    @patch("cve_agent.review.run_git_stdout", return_value="diff content")
    @patch("cve_agent.review.get_changed_files", return_value=set())
    def test_saves_diff_no_upstream_files(self, mock_files, mock_git, tmp_path):
        agent_dir = tmp_path / "agent"
        agent_dir.mkdir()
        with patch("cve_agent.review.get_agent_dir", return_value=agent_dir):
            result = _save_review_diff(Path("/ws"), "abc123456789")
        assert result.exists()


class TestDisplayChanges:
    @patch("cve_agent.review.get_agent_dir")
    @patch("cve_agent.review.run_git_display")
    @patch("cve_agent.review.get_changed_files")
    def test_display_with_upstream_files(self, mock_files, mock_display, mock_dir, tmp_path):
        mock_files.return_value = {"a.c"}
        mock_dir.return_value = tmp_path
        _display_changes(Path("/ws"), "abc123", "summary", "CVE-2025-0001")

    @patch("cve_agent.review.get_agent_dir")
    @patch("cve_agent.review.run_git_display")
    @patch("cve_agent.review.get_changed_files")
    def test_display_no_upstream_files(self, mock_files, mock_display, mock_dir, tmp_path):
        mock_files.return_value = set()
        mock_dir.return_value = tmp_path
        _display_changes(Path("/ws"), "abc123", "summary", "CVE-2025-0001")

    @patch("cve_agent.review.get_agent_dir")
    @patch("cve_agent.review.run_git_display")
    @patch("cve_agent.review.get_changed_files")
    def test_display_with_ai_log(self, mock_files, mock_display, mock_dir, tmp_path):
        mock_files.return_value = set()
        mock_dir.return_value = tmp_path
        log = tmp_path / "busybox-CVE-2025-0001-ai-changes.log"
        log.write_text("AI did things")
        _display_changes(tmp_path / "busybox", "abc123", "summary", "CVE-2025-0001")
