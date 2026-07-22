# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.interdiff — optional patchutils integration."""
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from cve_agent.interdiff import _ensure_trailing_newline, generate_interdiff

UPSTREAM = "diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n@@ -1 +1 @@\n-old\n+new\n"
BACKPORT = "diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n@@ -1 +1 @@\n-old\n+new2\n"


class TestEnsureTrailingNewline:
    def test_adds_newline_when_missing(self):
        assert _ensure_trailing_newline("abc") == "abc\n"

    def test_leaves_single_trailing_newline_unchanged(self):
        assert _ensure_trailing_newline("abc\n") == "abc\n"

    def test_does_not_add_second_newline(self):
        result = _ensure_trailing_newline("abc\n")
        assert not result.endswith("\n\n")

    def test_empty_string_gets_newline(self):
        assert _ensure_trailing_newline("") == "\n"


class TestGenerateInterdiff:
    @patch("cve_agent.interdiff.shutil.which", return_value=None)
    @patch("cve_agent.interdiff.subprocess.run")
    def test_binary_missing_returns_none(self, mock_run, mock_which):
        result = generate_interdiff(UPSTREAM, BACKPORT)
        assert result is None
        mock_run.assert_not_called()

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    @patch("cve_agent.interdiff.subprocess.run")
    def test_empty_backport_returns_none(self, mock_run, mock_which):
        result = generate_interdiff(UPSTREAM, "")
        assert result is None
        mock_run.assert_not_called()

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    @patch("cve_agent.interdiff.subprocess.run")
    def test_empty_upstream_returns_none(self, mock_run, mock_which):
        result = generate_interdiff("   ", BACKPORT)
        assert result is None
        mock_run.assert_not_called()

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    @patch("cve_agent.interdiff.subprocess.run")
    def test_success_returns_stdout(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="-old\n+new2\n", stderr=""
        )
        result = generate_interdiff(UPSTREAM, BACKPORT)
        assert result == "-old\n+new2\n"
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args[0] == "interdiff"
        assert len(args) == 3

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    @patch("cve_agent.interdiff.subprocess.run")
    def test_nonzero_exit_returns_none(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="error"
        )
        result = generate_interdiff(UPSTREAM, BACKPORT)
        assert result is None

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    @patch("cve_agent.interdiff.subprocess.run")
    def test_empty_stdout_returns_none(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = generate_interdiff(UPSTREAM, BACKPORT)
        assert result is None

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    @patch("cve_agent.interdiff.subprocess.run",
           side_effect=subprocess.SubprocessError("boom"))
    def test_subprocess_error_returns_none(self, mock_run, mock_which):
        result = generate_interdiff(UPSTREAM, BACKPORT)
        assert result is None

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    @patch("cve_agent.interdiff.subprocess.run", side_effect=OSError("boom"))
    def test_os_error_returns_none(self, mock_run, mock_which):
        result = generate_interdiff(UPSTREAM, BACKPORT)
        assert result is None

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    def test_temp_files_cleaned_up(self, mock_which):
        created_paths = []

        def fake_run(cmd, **kwargs):
            # cmd = ['interdiff', old_path, new_path]
            created_paths.extend(cmd[1:3])
            return MagicMock(returncode=0, stdout="delta\n", stderr="")

        with patch("cve_agent.interdiff.subprocess.run", side_effect=fake_run):
            result = generate_interdiff(UPSTREAM, BACKPORT)

        assert result == "delta\n"
        assert len(created_paths) == 2
        for path in created_paths:
            assert not Path(path).exists()

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    def test_temp_files_cleaned_up_on_failure(self, mock_which):
        created_paths = []

        def fake_run(cmd, **kwargs):
            created_paths.extend(cmd[1:3])
            raise OSError("boom")

        with patch("cve_agent.interdiff.subprocess.run", side_effect=fake_run):
            result = generate_interdiff(UPSTREAM, BACKPORT)

        assert result is None
        assert len(created_paths) == 2
        for path in created_paths:
            assert not Path(path).exists()

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    def test_temp_files_always_end_with_newline(self, mock_which):
        """Regression: run_git_stdout() strips trailing newlines before
        callers pass patch text in. If the temp files written for
        interdiff lack a trailing newline, interdiff's parser corrupts
        the last hunk (stray control chars, spurious 'No newline at end
        of file' markers) instead of producing a clean delta."""
        captured_contents = []

        def fake_run(cmd, **kwargs):
            for path in cmd[1:3]:
                captured_contents.append(Path(path).read_text(encoding="utf-8"))
            return MagicMock(returncode=0, stdout="delta\n", stderr="")

        stripped_upstream = UPSTREAM.rstrip("\n")
        stripped_backport = BACKPORT.rstrip("\n")
        assert not stripped_upstream.endswith("\n")
        assert not stripped_backport.endswith("\n")

        with patch("cve_agent.interdiff.subprocess.run", side_effect=fake_run):
            result = generate_interdiff(stripped_upstream, stripped_backport)

        assert result == "delta\n"
        assert len(captured_contents) == 2
        for content in captured_contents:
            assert content.endswith("\n")
            assert not content.endswith("\n\n")

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    def test_temp_files_not_double_newlined_when_already_terminated(self, mock_which):
        captured_contents = []

        def fake_run(cmd, **kwargs):
            for path in cmd[1:3]:
                captured_contents.append(Path(path).read_text(encoding="utf-8"))
            return MagicMock(returncode=0, stdout="delta\n", stderr="")

        with patch("cve_agent.interdiff.subprocess.run", side_effect=fake_run):
            generate_interdiff(UPSTREAM, BACKPORT)

        for content in captured_contents:
            assert not content.endswith("\n\n")
