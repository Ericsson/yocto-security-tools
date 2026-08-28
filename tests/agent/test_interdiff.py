# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.interdiff — optional patchutils integration."""
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from cve_agent.interdiff import (
    InterdiffArtifacts,
    _ensure_trailing_newline,
    generate_interdiff,
    generate_interdiff_artifacts,
    repair_whitespace_damage,
)

UPSTREAM = "diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n@@ -1 +1 @@\n-old\n+new\n"
BACKPORT = "diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n@@ -1 +1 @@\n-old\n+new2\n"


class TestRepairWhitespaceDamage:
    """interdiff rejects a patch whose context lines lost their leading space.

    Several patches carried in OE layers are damaged that way (e.g. oe-core's
    less CVE-2024-32487.patch), which used to make every comparison against
    them either impossible or pure whitespace noise.
    """

    def test_wellformed_patch_unchanged(self):
        assert repair_whitespace_damage(UPSTREAM) == UPSTREAM

    def test_is_idempotent(self):
        damaged = "@@ -1,3 +1,3 @@\nctx\n-old\n+new\n"
        once = repair_whitespace_damage(damaged)
        assert repair_whitespace_damage(once) == once

    def test_restores_space_on_damaged_context_line(self):
        damaged = "--- a/f.c\n+++ b/f.c\n@@ -1,2 +1,2 @@\n\tctx\n-old\n+new\n"
        assert repair_whitespace_damage(damaged) == (
            "--- a/f.c\n+++ b/f.c\n@@ -1,2 +1,2 @@\n \tctx\n-old\n+new\n"
        )

    def test_restores_space_on_emptied_blank_context_line(self):
        damaged = "@@ -1,3 +1,3 @@\n ctx\n\n-old\n+new\n"
        # The blank line is a context line inside the hunk, so it must be
        # re-prefixed; the empty string after the trailing newline is not.
        assert repair_whitespace_damage(damaged) == "@@ -1,3 +1,3 @@\n ctx\n \n-old\n+new\n"

    def test_trailing_empty_line_never_prefixed(self):
        # Deliberately inconsistent counts (claims 9 lines, has 3): the
        # end-of-file empty string must still be left alone.
        damaged = "@@ -1,9 +1,9 @@\n ctx\n-old\n+new\n"
        assert repair_whitespace_damage(damaged).endswith("+new\n")

    def test_leaves_git_signature_alone(self):
        damaged = "@@ -1,2 +1,2 @@\n ctx\n-old\n+new\n--\n2.40.0\n"
        assert repair_whitespace_damage(damaged).endswith("--\n2.40.0\n")

    def test_leaves_metadata_between_hunks_alone(self):
        text = ("@@ -1,2 +1,2 @@\n ctx\n-old\n+new\n"
                "diff --git a/g.c b/g.c\nindex 1..2 100644\n"
                "--- a/g.c\n+++ b/g.c\n@@ -1,2 +1,2 @@\n ctx2\n-a\n+b\n")
        assert repair_whitespace_damage(text) == text

    def test_no_newline_marker_does_not_consume_budget(self):
        text = "@@ -1,2 +1,2 @@\n ctx\n-old\n\\ No newline at end of file\n+new\n"
        assert repair_whitespace_damage(text) == text

    def test_hunk_header_without_counts_means_one_line(self):
        text = "@@ -1 +1 @@\n-old\n+new\nnot a context line\n"
        assert repair_whitespace_damage(text) == text


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
    @patch("cve_agent.interdiff.subprocess.run")
    def test_allow_empty_distinguishes_equivalent_from_failed(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        assert generate_interdiff(UPSTREAM, BACKPORT, allow_empty=True) == ""

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    @patch("cve_agent.interdiff.subprocess.run")
    def test_allow_empty_still_none_on_failure(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="boom")
        assert generate_interdiff(UPSTREAM, BACKPORT, allow_empty=True) is None

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


class TestGenerateInterdiffArtifacts:
    @patch("cve_agent.interdiff.shutil.which", return_value=None)
    @patch("cve_agent.interdiff.subprocess.run")
    def test_binary_missing_returns_none(self, mock_run, mock_which):
        assert generate_interdiff_artifacts(UPSTREAM, BACKPORT) is None
        mock_run.assert_not_called()

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    @patch("cve_agent.interdiff.subprocess.run")
    def test_success_returns_artifacts_with_command_and_paths(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(returncode=0, stdout="-old\n+new2\n", stderr="")
        result = generate_interdiff_artifacts(UPSTREAM, BACKPORT)
        assert isinstance(result, InterdiffArtifacts)
        assert result.output == "-old\n+new2\n"
        assert result.command.startswith("interdiff ")
        assert str(result.old_patch_path) in result.command
        assert str(result.new_patch_path) in result.command

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    @patch("cve_agent.interdiff.subprocess.run")
    def test_nonzero_exit_returns_none(self, mock_run, mock_which):
        mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        assert generate_interdiff_artifacts(UPSTREAM, BACKPORT) is None

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    def test_temp_files_cleaned_up_when_no_keep_dir(self, mock_which):
        def fake_run(cmd, **kwargs):
            return MagicMock(returncode=0, stdout="delta\n", stderr="")

        with patch("cve_agent.interdiff.subprocess.run", side_effect=fake_run):
            result = generate_interdiff_artifacts(UPSTREAM, BACKPORT)

        assert result is not None
        assert not result.old_patch_path.exists()
        assert not result.new_patch_path.exists()

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    def test_keep_files_dir_persists_both_patches(self, mock_which, tmp_path):
        keep_dir = tmp_path / "interdiff-out"

        def fake_run(cmd, **kwargs):
            return MagicMock(returncode=0, stdout="delta\n", stderr="")

        with patch("cve_agent.interdiff.subprocess.run", side_effect=fake_run):
            result = generate_interdiff_artifacts(
                UPSTREAM, BACKPORT, keep_files_dir=keep_dir
            )

        assert result is not None
        assert result.old_patch_path == keep_dir / "upstream.patch"
        assert result.new_patch_path == keep_dir / "backport.patch"
        assert result.old_patch_path.exists()
        assert result.new_patch_path.exists()
        assert result.old_patch_path.read_text(encoding="utf-8") == UPSTREAM
        assert result.new_patch_path.read_text(encoding="utf-8") == BACKPORT

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    def test_keep_files_dir_command_uses_persisted_paths(self, mock_which, tmp_path):
        keep_dir = tmp_path / "interdiff-out"
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["argv"] = cmd
            return MagicMock(returncode=0, stdout="delta\n", stderr="")

        with patch("cve_agent.interdiff.subprocess.run", side_effect=fake_run):
            result = generate_interdiff_artifacts(
                UPSTREAM, BACKPORT, keep_files_dir=keep_dir
            )

        assert result is not None
        assert result.command == " ".join(captured["argv"])
        assert result.command == (
            f"interdiff {keep_dir / 'upstream.patch'} {keep_dir / 'backport.patch'}"
        )

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    def test_keep_files_dir_not_removed_on_nonzero_exit(self, mock_which, tmp_path):
        """Even on failure, callers who asked to keep files should not lose
        them silently — but since no concise delta is produced we still
        return None; the persisted directory is left in place for
        troubleshooting rather than being cleaned up."""
        keep_dir = tmp_path / "interdiff-out"

        def fake_run(cmd, **kwargs):
            return MagicMock(returncode=1, stdout="", stderr="error")

        with patch("cve_agent.interdiff.subprocess.run", side_effect=fake_run):
            result = generate_interdiff_artifacts(
                UPSTREAM, BACKPORT, keep_files_dir=keep_dir
            )

        assert result is None
        assert (keep_dir / "upstream.patch").exists()
        assert (keep_dir / "backport.patch").exists()

    @patch("cve_agent.interdiff.shutil.which", return_value="/usr/bin/interdiff")
    def test_generate_interdiff_wraps_artifacts_output(self, mock_which, tmp_path):
        keep_dir = tmp_path / "interdiff-out"

        def fake_run(cmd, **kwargs):
            return MagicMock(returncode=0, stdout="delta\n", stderr="")

        with patch("cve_agent.interdiff.subprocess.run", side_effect=fake_run):
            result = generate_interdiff(UPSTREAM, BACKPORT, keep_files_dir=keep_dir)

        assert result == "delta\n"
        assert (keep_dir / "upstream.patch").exists()
