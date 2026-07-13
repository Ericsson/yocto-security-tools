# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.session — kiro-cli session management and audit log."""
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from cve_agent.backend import SessionResult
from cve_agent.kiro_backend import KiroBackend
from cve_agent.session import (
    _build_deviation_section,
    _extract_diff_hunks,
    _format_diff_lines,
    _get_backport_note,
    _hunk_lines,
    _log_session_end,
    _log_session_start,
    _split_diff_by_file,
    _write_audit_log,
    check_resolution_state,
    guarded_session,
)

_kiro = KiroBackend()


def _spawn_kiro_cli(context_file, workspace_path, model, timeout, interactive=False):
    """Compat wrapper for tests — delegates to KiroBackend."""
    result = _kiro.run_session(
        f"Read {context_file}", workspace_path, set(), model, timeout, interactive)
    return not result.resolved


def run_kiro_session(context_file, workspace_path, allowed,
                     model="claude-sonnet-4.6", timeout=300, interactive=False):
    """Compat wrapper for tests — delegates to KiroBackend."""
    result = _kiro.run_session(
        f"Read {context_file}", workspace_path, allowed, model, timeout, interactive)
    return result


class TestCheckResolutionState:
    def test_missing_workspace(self, tmp_path):
        assert check_resolution_state(tmp_path / "gone") is True

    @patch("subprocess.run")
    def test_no_conflicts(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="M  file.c\n")
        assert check_resolution_state(Path("/ws")) is True

    @patch("subprocess.run")
    def test_with_conflicts(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stdout="UU file.c\n")
        assert check_resolution_state(tmp_path) is False

    @patch("subprocess.run")
    def test_git_error(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=128, stdout="")
        assert check_resolution_state(tmp_path) is False


class TestExtractDiffHunks:
    def test_extracts_diff(self):
        output = "commit abc\nAuthor: x\n\n    msg\n\ndiff --git a/f b/f\n+line"
        assert _extract_diff_hunks(output) == "diff --git a/f b/f\n+line"

    def test_no_diff(self):
        assert _extract_diff_hunks("commit abc\nno diff here") == ""


class TestHunkLines:
    def test_filters_headers(self):
        diff = "--- a/f\n+++ b/f\n@@ -1 +1 @@\n-old\n+new\n context"
        result = _hunk_lines(diff)
        assert "--- a/f" not in '\n'.join(result)
        assert "+++ b/f" not in '\n'.join(result)
        assert not any(l.startswith("@@") for l in result)
        assert "-old" in result
        assert "+new" in result


class TestFormatDiffLines:
    def test_marks_additions_and_removals(self):
        diff = "+added\n-removed\n context"
        result = _format_diff_lines(diff)
        assert any("|>>" in l for l in result)
        assert any("|<<" in l for l in result)
        assert any("|  " in l for l in result)

    def test_skips_header_markers(self):
        diff = "+++ b/file\n--- a/file\n+real"
        result = _format_diff_lines(diff)
        assert sum("|>>" in l for l in result) == 1


class TestSplitDiffByFile:
    def test_splits_multi_file(self):
        diff = (
            "diff --git a/x.c b/x.c\n+line1\n"
            "diff --git a/y.c b/y.c\n+line2"
        )
        result = _split_diff_by_file(diff)
        assert "x.c" in result
        assert "y.c" in result

    def test_empty_diff(self):
        assert _split_diff_by_file("") == {}


class TestGetBackportNote:
    @patch("cve_agent.session.run_git_stdout",
           return_value="Fix CVE\n\nBackport-Resolution: adapted code")
    def test_finds_note(self, _):
        assert "Backport-Resolution" in _get_backport_note(Path("/ws"))

    @patch("cve_agent.session.run_git_stdout", return_value="Fix CVE\n\nSigned-off-by: x")
    def test_no_note(self, _):
        assert _get_backport_note(Path("/ws")) == ""


class TestBuildDeviationSection:
    def test_builds_section(self):
        lines = _build_deviation_section("a.c", "+new", "-old", "adapted")
        text = '\n'.join(lines)
        assert "a.c" in text
        assert "Differences from upstream" in text
        assert "Full upstream diff" in text
        assert "adapted" in text

    def test_no_backport_note(self):
        lines = _build_deviation_section("a.c", "+new", "-old", "")
        text = '\n'.join(lines)
        assert "rationale" not in text


class TestSpawnKiroCli:
    @patch("subprocess.run")
    def test_normal_run(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout='')
        result = _spawn_kiro_cli(Path("/ctx.md"), Path("/ws"), "model", 300)
        assert result is False

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 300))
    def test_timeout(self, _):
        assert _spawn_kiro_cli(Path("/ctx.md"), Path("/ws"), "model", 300) is True

    @patch("subprocess.run", side_effect=[FileNotFoundError, MagicMock(returncode=0, stdout="")])
    def test_not_found(self, _):
        assert _spawn_kiro_cli(Path("/ctx.md"), Path("/ws"), "model", 300) is False

    @patch("subprocess.run", side_effect=[KeyboardInterrupt, MagicMock(returncode=0, stdout="")])
    def test_keyboard_interrupt(self, _):
        assert _spawn_kiro_cli(Path("/ctx.md"), Path("/ws"), "model", 300) is False


class TestRunKiroSession:
    @patch("subprocess.run")
    def test_resolved(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout='')
        result = run_kiro_session(Path("/ctx"), Path("/ws"), {"a.c"})
        assert result.resolved is True

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 300))
    def test_timed_out(self, _):
        result = run_kiro_session(Path("/ctx"), Path("/ws"), {"a.c"})
        assert result.resolved is False


class TestGuardedKiroSession:
    @patch("cve_agent.session._write_audit_log")
    @patch("cve_agent.session.revert_unauthorized_changes")
    @patch("cve_agent.session.remove_scope_hook")
    @patch("cve_agent.kiro_backend.KiroBackend.run_session",
           return_value=SessionResult(resolved=True, duration=1.0))
    @patch("cve_agent.session.install_scope_hook")
    @patch("cve_agent.session.run_git_stdout", return_value="")
    @patch("cve_agent.session.get_changed_files", return_value={"a.c"})
    @patch("cve_agent.session.get_all_upstream_shas", return_value=["abc123"])
    def test_full_flow(self, m_shas, m_files, m_git, m_hook, m_session,
                       m_unhook, m_revert, m_audit, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        result = guarded_session(
            Path("/ctx"), ws, "abc123", {"hashes": ["abc123"]}, "model", 300, "CVE-1"
        )
        assert result.resolved is True

    @patch("cve_agent.session.remove_scope_hook")
    @patch("cve_agent.kiro_backend.KiroBackend.run_session",
           return_value=SessionResult(resolved=False, duration=1.0))
    @patch("cve_agent.session.install_scope_hook")
    @patch("cve_agent.session.run_git_stdout", return_value="")
    @patch("cve_agent.session.get_changed_files", return_value={"a.c"})
    @patch("cve_agent.session.get_all_upstream_shas", return_value=["abc123"])
    def test_workspace_gone(self, m_shas, m_files, m_git, m_hook, m_session,
                            m_unhook, tmp_path):
        ws = tmp_path / "ws_gone"
        result = guarded_session(
            Path("/ctx"), ws, "abc123", {}, "model", 300, "CVE-1"
        )
        assert result.resolved is False


class TestWriteAuditLog:
    @patch("cve_agent.session._get_backport_note", return_value="adapted")
    @patch("cve_agent.session.run_git_stdout", return_value="")
    def test_no_deviations(self, mock_git, mock_note, tmp_path):
        agent_dir = tmp_path / "agent"
        agent_dir.mkdir()
        with patch("cve_agent.session.get_agent_dir", return_value=agent_dir):
            _write_audit_log(Path("/ws"), "busybox", "CVE-1", ["abc"], {}, "HEAD~1")
        log = agent_dir / "busybox-CVE-1-ai-changes.log"
        assert log.exists()
        assert "Empty cherry-pick" in log.read_text()

    @patch("cve_agent.session._get_backport_note", return_value="")
    @patch("cve_agent.session.run_git_stdout",
           return_value="diff --git a/a.c b/a.c\n+new line")
    def test_with_deviations(self, mock_git, mock_note, tmp_path):
        agent_dir = tmp_path / "agent"
        agent_dir.mkdir()
        upstream_diffs = {"a.c": "diff --git a/a.c b/a.c\n-old line"}
        with patch("cve_agent.session.get_agent_dir", return_value=agent_dir):
            _write_audit_log(Path("/ws"), "busybox", "CVE-1", ["abc"], upstream_diffs, "HEAD~1")
        log = agent_dir / "busybox-CVE-1-ai-changes.log"
        assert "deviation" in log.read_text().lower()

    @patch("cve_agent.session._get_backport_note", return_value="")
    def test_new_file_filtered(self, mock_note, tmp_path):
        """Files not in baseline (new-file creations) are excluded from deviations."""
        agent_dir = tmp_path / "agent"
        agent_dir.mkdir()
        new_file_diff = "diff --git a/new.c b/new.c\nnew file mode 100644\n+entire file"
        existing_diff = "diff --git a/a.c b/a.c\n+changed line"

        def fake_git(args, cwd=None):
            # diff original-version..HEAD returns both files
            if args[:1] == ['diff'] and 'original-version..HEAD' in ' '.join(args):
                if '--name-only' in args:
                    return "a.c\nnew.c"
                return f"{existing_diff}\n{new_file_diff}"
            # ls-tree: a.c exists in baseline, new.c does not
            if args[:1] == ['ls-tree']:
                return "100644 blob abc\ta.c" if 'a.c' in args else ""
            return "a.c\nnew.c"

        upstream_diffs = {
            "a.c": "diff --git a/a.c b/a.c\n-old line",
            "new.c": "diff --git a/new.c b/new.c\n-something",
        }
        with patch("cve_agent.session.get_agent_dir", return_value=agent_dir), \
             patch("cve_agent.session.run_git_stdout", side_effect=fake_git):
            _write_audit_log(Path(tmp_path / "ws"), "busybox", "CVE-1",
                             ["abc"], upstream_diffs, "HEAD~1")
        log_text = (agent_dir / "busybox-CVE-1-ai-changes.log").read_text()
        assert "a.c" in log_text
        assert "new.c" not in log_text


class TestLogSessionStartEnd:
    def test_log_start(self, tmp_path):
        _log_session_start(tmp_path, Path("/ctx.md"))
        log = tmp_path / "sessions.log"
        assert "SESSION START" in log.read_text()

    def test_log_end(self, tmp_path):
        _log_session_end(tmp_path, True, 5.0)
        log = tmp_path / "sessions.log"
        content = log.read_text()
        assert "RESOLVED" in content
        assert "5.0s" in content

    def test_log_end_unresolved(self, tmp_path):
        _log_session_end(tmp_path, False, 3.0)
        assert "UNRESOLVED" in (tmp_path / "sessions.log").read_text()
