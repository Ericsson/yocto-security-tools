# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector.workflow — workflow functions."""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cve_corrector.cherry_pick import (
    apply_series,
    apply_single_commits,
    cherry_pick_to_devtool,
    find_least_conflict_commit,
)
from cve_corrector.git_ops import (
    copy_missing_files_from_devtool,
    detect_strip_level,
    get_repo_subdir,
)
from cve_corrector.meta_layer import create_layer_commit
from cve_corrector.ptest import compare_ptest_results
from cve_corrector.recipe_ops import sort_cve_lines_in_recipe
from cve_corrector.state import (
    BuildError,
    ConflictError,
    MetadataError,
    PtestError,
    WorkflowState,
)
from cve_corrector.ui import (
    print_build_failure_instructions,
    print_conflict_instructions,
    print_edit_instructions,
)
from cve_corrector.workflow import (
    _handle_failed_series,
    _handle_no_clean_apply,
    _log_ptest_debug_conf,
    _make_should_run,
    _run_build_step,
    _run_ptest_step,
    continue_from_conflict,
    save_progress,
    save_workflow_state,
)
from cve_corrector.workspace import (
    _alternate_protocol_url,
    _fetch_remote,
    setup_upstream_remote,
)


def _state(tmp_path, **kwargs):
    ws = tmp_path / "build" / "workspace" / "sources" / "busybox"
    ws.mkdir(parents=True)
    defaults = dict(
        workspace_path=ws, cve_id="CVE-2025-0001", recipe="busybox",
        commit_hash="abc123", hash_details=[],
        meta_layer=tmp_path / "meta", skip_build=True, skip_ptest=True,
        ptest_before=None, series_state=None,
    )
    defaults.update(kwargs)
    return WorkflowState(**defaults)


class TestSaveWorkflowState:
    @patch("cve_corrector.bitbake_ops.get_build_path")
    def test_saves(self, mock_build_path, tmp_path):
        mock_build_path.return_value = tmp_path
        state = _state(tmp_path)
        save_workflow_state(state)
        state_dir = tmp_path / "workspace" / "cve_corrector"
        assert (state_dir / "busybox.json").exists()


class TestSaveProgress:
    @patch("cve_corrector.state.save_workflow_state")
    def test_sets_step(self, mock_save, tmp_path):
        state = _state(tmp_path)
        save_progress(state, "build_after_patch")
        assert state.current_step == "build_after_patch"
        mock_save.assert_called_once()


class TestPrintConflictInstructions:
    def test_basic(self, capsys, tmp_path):
        print_conflict_instructions(tmp_path, "busybox")
        out = capsys.readouterr().out
        assert "CONFLICT DETECTED" in out
        assert "busybox" in out

    def test_with_series(self, capsys, tmp_path):
        series = {"commits": ["a", "b", "c"], "applied_commits": ["a"],
                  "remaining_commits": ["c"], "failed_at": "bbbbbbbbbb"}
        print_conflict_instructions(tmp_path, "busybox", series)
        out = capsys.readouterr().out
        assert "1/3" in out


class TestPrintEditInstructions:
    def test_basic(self, capsys, tmp_path):
        print_edit_instructions(tmp_path, "busybox", "abc123def456")
        out = capsys.readouterr().out
        assert "EDIT MODE" in out
        assert "abc123de" in out


class TestPrintBuildFailureInstructions:
    def test_basic(self, capsys, tmp_path):
        print_build_failure_instructions(tmp_path, "libxml2")
        out = capsys.readouterr().out
        assert "BUILD FAILED" in out
        assert "libxml2" in out
        assert str(tmp_path) in out
        assert "devtool build libxml2" in out
        assert "git commit --amend" in out
        assert "cve-corrector --continue" in out


class TestComparePtestResults:
    def test_same(self):
        assert compare_ptest_results("PASSED: 10, FAILED: 0", "PASSED: 10, FAILED: 0")

    def test_increased(self):
        assert not compare_ptest_results("PASSED: 10, FAILED: 0", "PASSED: 9, FAILED: 1")

    def test_decreased(self):
        assert compare_ptest_results("PASSED: 10, FAILED: 2", "PASSED: 11, FAILED: 1")

    def test_missing_counts(self):
        assert compare_ptest_results("no data", "no data")


class TestSortCveLinesInRecipe:
    def test_sorts(self, tmp_path):
        bb = tmp_path / "foo.bb"
        bb.write_text('SRC_URI = "\\\n  file://CVE-2025-0001-2.patch \\\n  file://CVE-2025-0001-1.patch"\n')
        sort_cve_lines_in_recipe("CVE-2025-0001", tmp_path)
        lines = bb.read_text().splitlines()
        cve_lines = [l for l in lines if "CVE-2025-0001-" in l]
        assert cve_lines == sorted(cve_lines)

    def test_already_sorted(self, tmp_path):
        bb = tmp_path / "foo.bb"
        content = 'SRC_URI = "\\\n  file://CVE-2025-0001-1.patch \\\n  file://CVE-2025-0001-2.patch"\n'
        bb.write_text(content)
        sort_cve_lines_in_recipe("CVE-2025-0001", tmp_path)
        assert bb.read_text() == content


class TestGetRepoSubdir:
    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_no_subdir(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="meson.build\nsrc\n")
        assert get_repo_subdir(Path("/ws")) is None

    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_with_subdir(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="expat\noe-local-files\n"),
            MagicMock(returncode=0, stdout="CMakeLists.txt\nsrc\n"),
        ]
        assert get_repo_subdir(Path("/ws")) == "expat"

    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_python_project_not_monorepo(self, mock_run):
        """Python project with ancillary launcher/ dir should not be detected as monorepo."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="setup.cfg\nsetuptools\nlauncher\nlauncher.c\ndocs\n"
        )
        assert get_repo_subdir(Path("/ws")) is None

    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_git_error(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        assert get_repo_subdir(Path("/ws")) is None


class TestDetectStripLevel:
    def test_normal(self, tmp_path):
        p = tmp_path / "0001.patch"
        p.write_text("diff --git a/src/file.c b/src/file.c\n+line\n")
        assert detect_strip_level([p]) == 1

    def test_monorepo(self, tmp_path):
        p = tmp_path / "0001.patch"
        p.write_text("diff --git a/subprojects/gst/file.c b/subprojects/gst/file.c\n")
        assert detect_strip_level([p]) == 3

    def test_empty(self):
        assert detect_strip_level([]) == 1


class TestMakeShouldRun:
    def test_no_current_step(self, tmp_path):
        state = _state(tmp_path)
        should_run = _make_should_run(state)
        assert should_run("build_after_patch")
        assert should_run("finish")

    def test_resume_from_finish(self, tmp_path):
        state = _state(tmp_path, current_step="finish")
        should_run = _make_should_run(state)
        assert not should_run("build_after_patch")
        assert should_run("finish")


class TestCopyMissingFilesFromDevtool:
    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_copies_missing(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="a.c\nb.c\nconfigure\n"),
            MagicMock(returncode=0, stdout="a.c\nb.c\n"),
            # git ls-tree -r HEAD (symlink detection) — no symlinks
            MagicMock(returncode=0,
                      stdout="100644 blob abc123\ta.c\n"
                             "100644 blob def456\tb.c\n"),
            MagicMock(returncode=0),  # checkout
            MagicMock(returncode=0),  # reset
        ]
        copy_missing_files_from_devtool(Path("/ws"))

    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_nothing_missing(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="a.c\n"),
            MagicMock(returncode=0, stdout="a.c\n"),
            # git ls-tree -r HEAD (symlink detection) — no symlinks
            MagicMock(returncode=0, stdout="100644 blob abc123\ta.c\n"),
        ]
        copy_missing_files_from_devtool(Path("/ws"))

    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_git_error(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        copy_missing_files_from_devtool(Path("/ws"))  # should not crash
        assert mock_run.called


class TestApplySingleCommits:
    @patch("cve_corrector.cherry_pick.try_cherry_pick", return_value=True)
    @patch("cve_corrector.cherry_pick.is_bad_object", return_value=False)
    @patch("cve_corrector.cherry_pick.run_cmd_capture",
           return_value=MagicMock(stdout="other stuff"))
    def test_success(self, *_):
        ok, h = apply_single_commits(Path("/ws"), ["abc"])
        assert ok and h == "abc"

    @patch("cve_corrector.cherry_pick.run_cmd_capture",
           return_value=MagicMock(stdout="abc12345 already here"))
    def test_already_applied(self, _):
        ok, h = apply_single_commits(Path("/ws"), ["abc12345"])
        assert ok

    @patch("cve_corrector.cherry_pick.run_cmd")
    @patch("cve_corrector.cherry_pick.try_cherry_pick", return_value=False)
    @patch("cve_corrector.cherry_pick.is_bad_object", return_value=False)
    @patch("cve_corrector.cherry_pick.run_cmd_capture",
           return_value=MagicMock(stdout=""))
    def test_all_fail(self, *_):
        ok, h = apply_single_commits(Path("/ws"), ["abc"])
        assert not ok

    @patch("cve_corrector.cherry_pick.is_bad_object", return_value=True)
    @patch("cve_corrector.cherry_pick.run_cmd_capture",
           return_value=MagicMock(stdout=""))
    def test_bad_objects_skipped(self, *_):
        ok, h = apply_single_commits(Path("/ws"), ["abc"])
        assert not ok


class TestFindLeastConflictCommit:
    @patch("cve_corrector.cherry_pick.run_cmd")
    @patch("cve_corrector.cherry_pick.run_cmd_capture")
    @patch("cve_corrector.cherry_pick.is_bad_object", return_value=False)
    def test_finds_best(self, mock_bad, mock_capture, mock_cmd):
        mock_capture.side_effect = [
            MagicMock(stdout="a.c\nb.c\n"),  # 2 conflicts for first
            MagicMock(stdout="a.c\nb.c\n"),  # diff-tree for first (source files)
            MagicMock(stdout="a.c\n"),  # 1 conflict for second
            MagicMock(stdout="a.c\n"),  # diff-tree for second (source files)
        ]
        best, count = find_least_conflict_commit(Path("/ws"), ["h1", "h2"])
        assert best == "h2"
        assert count == 1


class TestCherryPickToDevtool:
    """Tests for cherry_pick_to_devtool — format-patch and fallback logic."""

    @patch("cve_corrector.cherry_pick.run_cmd")
    @patch("cve_corrector.cherry_pick.run_cmd_capture")
    @patch("cve_corrector.cherry_pick.get_repo_subdir", return_value=None)
    @patch("cve_corrector.cherry_pick.git_clean_workspace")
    def test_formats_only_cve_commits(self, mock_clean, mock_subdir,
                                       mock_capture, mock_cmd, tmp_path):
        """format-patch runs per CVE commit, skipping ones already on devtool."""
        state = _state(tmp_path)

        mock_capture.side_effect = [
            # git cherry devtool CVE original-version
            MagicMock(returncode=0, stdout="+ h1\n- h2\n+ h3\n"),
            MagicMock(returncode=0, stdout=""),  # format-patch h1
            MagicMock(returncode=0, stdout=""),  # format-patch h3
        ]
        from cve_corrector.state import AlreadyAppliedError
        with patch("cve_corrector.cherry_pick.handle_empty_cherry_pick"):
            with pytest.raises(AlreadyAppliedError):
                cherry_pick_to_devtool(state)

        fmt_calls = [c[0][0] for c in mock_capture.call_args_list
                     if 'format-patch' in c[0][0]]
        assert len(fmt_calls) == 2
        assert fmt_calls[0][-1] == 'h1'
        assert fmt_calls[1][-1] == 'h3'
        assert '--start-number' in fmt_calls[1]
        assert 'h2' not in [c[-1] for c in fmt_calls]

    @patch("cve_corrector.cherry_pick.run_cmd")
    @patch("cve_corrector.cherry_pick.run_cmd_capture")
    @patch("cve_corrector.cherry_pick.get_repo_subdir", return_value=None)
    @patch("cve_corrector.cherry_pick.git_clean_workspace")
    def test_falls_back_to_cherry_pick(self, mock_clean, mock_subdir,
                                        mock_capture, mock_cmd, tmp_path):
        """When git am fails at all levels, falls back to direct cherry-pick."""
        state = _state(tmp_path)
        patch_content = "From abc\nSubject: fix\n\ndiff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n@@ -1 +1 @@\n-old\n+new\n"
        patch_dir_path = tmp_path / "patches"
        patch_dir_path.mkdir()
        (patch_dir_path / "0001-fix.patch").write_text(patch_content)

        mock_cmd.return_value = 0  # git checkout devtool succeeds

        am_fail = MagicMock(returncode=1, stderr="error: patch failed")
        cherry_pick_ok = MagicMock(returncode=0)
        mock_capture.side_effect = [
            MagicMock(returncode=0, stdout="+ commit1\n"),  # git cherry
            MagicMock(returncode=0, stdout="patched"),  # format-patch
            am_fail,  # git am -p1
            am_fail,  # git am -p1 --3way
            am_fail,  # git am -p2
            am_fail,  # git am -p2 --3way
            am_fail,  # git am -p3
            am_fail,  # git am -p3 --3way
            cherry_pick_ok,  # cherry-pick commit1
        ]

        with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
            mock_tmpdir.return_value.__enter__ = lambda s: str(patch_dir_path)
            mock_tmpdir.return_value.__exit__ = MagicMock(return_value=False)
            cherry_pick_to_devtool(state)

        # Verify cherry-pick was attempted as fallback
        cherry_pick_calls = [c for c in mock_capture.call_args_list
                             if 'cherry-pick' in str(c) and 'abort' not in str(c)]
        assert len(cherry_pick_calls) >= 1

    @patch("cve_corrector.cherry_pick.run_cmd")
    @patch("cve_corrector.cherry_pick.run_cmd_capture")
    @patch("cve_corrector.cherry_pick.get_repo_subdir", return_value=None)
    @patch("cve_corrector.cherry_pick.git_clean_workspace")
    def test_no_commits_to_transfer(self, mock_clean, mock_subdir,
                                    mock_capture, mock_cmd, tmp_path):
        """All commits already on devtool -> already applied, no format-patch."""
        state = _state(tmp_path)

        mock_capture.side_effect = [
            MagicMock(returncode=0, stdout="- h1\n- h2\n"),  # git cherry
        ]
        from cve_corrector.state import AlreadyAppliedError
        with patch("cve_corrector.cherry_pick.handle_empty_cherry_pick"):
            with pytest.raises(AlreadyAppliedError):
                cherry_pick_to_devtool(state)

        assert not [c for c in mock_capture.call_args_list
                    if 'format-patch' in c[0][0]]

    @patch("cve_corrector.cherry_pick.save_progress")
    @patch("cve_corrector.cherry_pick.run_cmd")
    @patch("cve_corrector.cherry_pick.run_cmd_capture")
    @patch("cve_corrector.cherry_pick.get_repo_subdir", return_value=None)
    @patch("cve_corrector.cherry_pick.git_clean_workspace")
    def test_git_apply_rolls_back_partial_series(self, mock_clean, mock_subdir,
                                                 mock_capture, mock_cmd,
                                                 mock_save, tmp_path):
        """A series that git-applies only partially is rolled back, not kept."""
        state = _state(tmp_path)
        patch_content = ("From abc\nSubject: fix\n\ndiff --git a/f.c b/f.c\n"
                         "--- a/f.c\n+++ b/f.c\n@@ -1 +1 @@\n-old\n+new\n")
        patch_dir_path = tmp_path / "patches"
        patch_dir_path.mkdir()
        (patch_dir_path / "0001-fix.patch").write_text(patch_content)
        (patch_dir_path / "0002-fix.patch").write_text(patch_content)

        mock_cmd.return_value = 0
        fail = MagicMock(returncode=1, stderr="error: patch failed")
        ok = MagicMock(returncode=0, stdout="")
        mock_capture.side_effect = [
            MagicMock(returncode=0, stdout="+ c1\n+ c2\n"),  # git cherry
            ok, ok,                    # format-patch c1, c2
            fail, fail, fail, fail, fail, fail,  # git am at p1/p2/p3 (+3way)
            fail,                      # cherry-pick c1 fails
            MagicMock(returncode=0, stdout="oldhead\n"),  # rev-parse HEAD
            ok,                        # git apply patch 1
            ok,                        # git commit patch 1
            fail, fail, fail,          # git apply patch 2 (all variants)
        ]

        from cve_corrector.state import PatchError
        with patch("tempfile.TemporaryDirectory") as mock_tmpdir:
            mock_tmpdir.return_value.__enter__ = lambda s: str(patch_dir_path)
            mock_tmpdir.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(PatchError):
                cherry_pick_to_devtool(state)

        reset_calls = [c for c in mock_cmd.call_args_list
                       if c[0][0][:3] == ['git', 'reset', '--hard']]
        assert reset_calls and reset_calls[-1][0][0][-1] == 'oldhead'
        mock_save.assert_called_once()


class TestHandleFailedSeries:
    @patch("cve_corrector.workflow.run_cmd")
    def test_exits_conflict(self, mock_cmd, tmp_path):
        series = {"commits": ["a", "b"], "failed_at": "bbbbbbbb",
                  "applied_commits": ["a"], "remaining_commits": []}
        state = _state(tmp_path)
        make_state = MagicMock(return_value=state)
        with patch("cve_corrector.workflow.save_workflow_state"):
            with pytest.raises(ConflictError):
                _handle_failed_series(state.workspace_path, series, make_state, "busybox")


class TestHandleNoCleanApply:
    @patch("cve_corrector.workflow.find_least_conflict_commit", return_value=("abc", 2))
    @patch("cve_corrector.workflow.run_cmd")
    def test_with_hashes(self, mock_cmd, mock_find, tmp_path):
        make_state = MagicMock(return_value=_state(tmp_path))
        with patch("cve_corrector.workflow.save_workflow_state"):
            with pytest.raises(ConflictError):
                _handle_no_clean_apply(Path("/ws"), ["abc"], [], make_state, "r")

    def test_no_hashes_no_series(self, tmp_path):
        with pytest.raises(ConflictError):
            _handle_no_clean_apply(Path("/ws"), [], [], MagicMock(), "r")


class TestCreateLayerCommit:
    def test_invalid_meta_layer(self):
        create_layer_commit(None, "r", "CVE-1")
        create_layer_commit(Path("/nonexistent"), "r", "CVE-1")

    @patch("cve_corrector.meta_layer.get_build_path")
    @patch("subprocess.run")
    @patch("cve_corrector.meta_layer.run_cmd", return_value=0)
    @patch("cve_corrector.git_ops.get_git_user_info", return_value=("A", "a@b.c"))
    def test_creates_commit(self, mock_info, mock_cmd, mock_subrun, mock_bp, tmp_path):
        mock_bp.return_value = tmp_path
        meta = tmp_path / "meta"
        meta.mkdir()
        mock_subrun.return_value = MagicMock(returncode=0, stdout="")
        create_layer_commit(meta, "busybox", "CVE-1", skip_confirm=True)

    @patch("cve_corrector.meta_layer.get_build_path")
    @patch("subprocess.run")
    @patch("cve_corrector.meta_layer.run_cmd", return_value=0)
    @patch("cve_corrector.git_ops.get_git_user_info", return_value=("A", "a@b.c"))
    def test_user_cancels(self, mock_info, mock_cmd, mock_subrun, mock_bp, tmp_path):
        mock_bp.return_value = tmp_path
        meta = tmp_path / "meta"
        meta.mkdir()
        mock_subrun.return_value = MagicMock(returncode=0, stdout="")
        with patch("builtins.input", return_value="n"):
            create_layer_commit(meta, "busybox", "CVE-1")

    @patch("cve_corrector.meta_layer.get_build_path")
    @patch("subprocess.run")
    @patch("cve_corrector.meta_layer.run_cmd", return_value=0)
    @patch("cve_corrector.git_ops.get_git_user_info", return_value=("A", "a@b.c"))
    def test_used_commits_filters_urls(self, mock_info, mock_cmd, mock_subrun, mock_bp,
                                       tmp_path, caplog):
        """Only URLs for used commits appear in the commit message."""
        mock_bp.return_value = tmp_path
        meta = tmp_path / "meta"
        meta.mkdir()
        mock_subrun.return_value = MagicMock(returncode=0, stdout="")
        hash_details = [
            {'hash': 'aaa', 'url': 'https://github.com/org/repo/commit/aaa'},
            {'hash': 'bbb', 'url': 'https://github.com/org/repo/commit/bbb'},
            {'hash': 'ccc', 'url': 'https://github.com/org/repo/commit/ccc'},
        ]
        import logging
        with caplog.at_level(logging.INFO, logger="cve_corrector"):
            create_layer_commit(meta, "openssl", "CVE-2026-31789", skip_confirm=True,
                                hash_details=hash_details, used_commits=['aaa'])
        logged = "\n".join(caplog.messages)
        assert 'commit/aaa' in logged
        assert 'commit/bbb' not in logged
        assert 'commit/ccc' not in logged

    @patch("cve_corrector.meta_layer.get_build_path")
    @patch("subprocess.run")
    @patch("cve_corrector.meta_layer.run_cmd", return_value=0)
    @patch("cve_corrector.git_ops.get_git_user_info", return_value=("A", "a@b.c"))
    def test_annotates_fix_source(self, mock_info, mock_cmd, mock_subrun, mock_bp,
                                  tmp_path, caplog):
        """Each fix URL is annotated with a single preferred source."""
        mock_bp.return_value = tmp_path
        meta = tmp_path / "meta"
        meta.mkdir()
        mock_subrun.return_value = MagicMock(returncode=0, stdout="")
        hash_details = [
            # Multiple sources -> highest priority (cvelistv5 over debian) wins.
            {'hash': 'aaa', 'url': 'https://github.com/org/repo/commit/aaa',
             'source': 'debian, cvelistv5'},
            # Same URL reported by ubuntu and debian -> debian preferred, one line.
            {'hash': 'bbb', 'url': 'https://github.com/org/repo/commit/bbb',
             'source': 'ubuntu'},
            {'hash': 'bbb', 'url': 'https://github.com/org/repo/commit/bbb',
             'source': 'debian'},
            # osv is a public shipped source and should be shown.
            {'hash': 'ccc', 'url': 'https://github.com/org/repo/commit/ccc',
             'source': 'osv'},
            # Proprietary source paired with a public one -> public one shown.
            {'hash': 'ddd', 'url': 'https://github.com/org/repo/commit/ddd',
             'source': 'bdba, debian'},
            # Proprietary-only source -> no annotation, URL still listed.
            {'hash': 'eee', 'url': 'https://github.com/org/repo/commit/eee',
             'source': 'bdba'},
        ]
        import logging
        with caplog.at_level(logging.INFO, logger="cve_corrector"):
            create_layer_commit(meta, "openssl", "CVE-2026-31789", skip_confirm=True,
                                hash_details=hash_details)
        logged = "\n".join(caplog.messages)
        assert 'commit/aaa [cvelistv5]' in logged
        assert 'commit/bbb [debian]' in logged
        assert 'commit/ccc [osv]' in logged
        assert 'commit/ddd [debian]' in logged
        # Proprietary sources are never disclosed.
        assert 'bdba' not in logged
        # Proprietary-only reference is listed without a source annotation.
        assert 'commit/eee\n' in logged
        assert 'commit/eee [' not in logged
        # Only a single source is shown per reference.
        assert 'cvelistv5, debian' not in logged
        # The bbb URL must appear on a single merged line, not duplicated.
        assert logged.count('commit/bbb') == 1

    @patch("cve_corrector.meta_layer.get_build_path")
    @patch("subprocess.run")
    @patch("cve_corrector.meta_layer.run_cmd", return_value=0)
    @patch("cve_corrector.git_ops.get_git_user_info", return_value=("A", "a@b.c"))
    def test_templated_source_references(self, mock_info, mock_cmd, mock_subrun,
                                         mock_bp, tmp_path, caplog):
        """A References section lists templated tracker URLs per public source."""
        mock_bp.return_value = tmp_path
        meta = tmp_path / "meta"
        meta.mkdir()
        mock_subrun.return_value = MagicMock(returncode=0, stdout="")
        cve = "CVE-2026-56115"
        hash_details = [
            {'hash': 'aaa', 'url': 'https://github.com/org/repo/commit/aaa',
             'source': 'debian'},
            {'hash': 'bbb', 'url': 'https://github.com/org/repo/commit/bbb',
             'source': 'ubuntu, osv'},
            # Proprietary source must not produce a reference URL.
            {'hash': 'ccc', 'url': 'https://github.com/org/repo/commit/ccc',
             'source': 'bdba'},
        ]
        import logging
        with caplog.at_level(logging.INFO, logger="cve_corrector"):
            create_layer_commit(meta, "openssl", cve, skip_confirm=True,
                                hash_details=hash_details)
        logged = "\n".join(caplog.messages)
        # NVD is always present as the canonical record.
        assert f'https://nvd.nist.gov/vuln/detail/{cve}' in logged
        assert f'https://security-tracker.debian.org/tracker/{cve}' in logged
        assert f'https://ubuntu.com/security/{cve}' in logged
        assert f'https://osv.dev/list?q={cve}' in logged
        # No proprietary tracker reference is emitted.
        assert 'bdba' not in logged

    @patch("cve_corrector.meta_layer.get_build_path")
    @patch("subprocess.run")
    @patch("cve_corrector.meta_layer.run_cmd", return_value=0)
    @patch("cve_corrector.git_ops.get_git_user_info", return_value=("A", "a@b.c"))
    def test_references_nvd_only_without_details(self, mock_info, mock_cmd,
                                                 mock_subrun, mock_bp, tmp_path,
                                                 caplog):
        """With no fix metadata, only the canonical NVD reference is listed."""
        mock_bp.return_value = tmp_path
        meta = tmp_path / "meta"
        meta.mkdir()
        mock_subrun.return_value = MagicMock(returncode=0, stdout="")
        cve = "CVE-2026-52846"
        import logging
        with caplog.at_level(logging.INFO, logger="cve_corrector"):
            create_layer_commit(meta, "openssl", cve, skip_confirm=True)
        logged = "\n".join(caplog.messages)
        assert f'https://nvd.nist.gov/vuln/detail/{cve}' in logged
        assert 'security-tracker.debian.org' not in logged
        assert 'ubuntu.com/security' not in logged
        assert 'osv.dev' not in logged

    @patch("cve_corrector.meta_layer.get_build_path")
    @patch("subprocess.run")
    @patch("cve_corrector.meta_layer.run_cmd", return_value=0)
    @patch("cve_corrector.meta_layer.get_git_user_info", return_value=("A", "a@b.c"))
    def test_no_signoff_by_default(self, mock_info, mock_cmd, mock_subrun, mock_bp,
                                   tmp_path, caplog):
        """Default behavior must not fabricate a Signed-off-by / DCO certification."""
        mock_bp.return_value = tmp_path
        meta = tmp_path / "meta"
        meta.mkdir()
        mock_subrun.return_value = MagicMock(returncode=0, stdout="")
        import logging
        with caplog.at_level(logging.INFO, logger="cve_corrector"):
            create_layer_commit(meta, "busybox", "CVE-1", skip_confirm=True)
        logged = "\n".join(caplog.messages)
        assert "Signed-off-by" not in logged
        mock_info.assert_not_called()

    @patch("cve_corrector.meta_layer.get_build_path")
    @patch("subprocess.run")
    @patch("cve_corrector.meta_layer.run_cmd", return_value=0)
    @patch("cve_corrector.meta_layer.get_git_user_info", return_value=("A", "a@b.c"))
    def test_signoff_opt_in(self, mock_info, mock_cmd, mock_subrun, mock_bp,
                            tmp_path, caplog):
        mock_bp.return_value = tmp_path
        meta = tmp_path / "meta"
        meta.mkdir()
        mock_subrun.return_value = MagicMock(returncode=0, stdout="")
        import logging
        with caplog.at_level(logging.INFO, logger="cve_corrector"):
            create_layer_commit(meta, "busybox", "CVE-1", skip_confirm=True,
                                sign_off=True)
        logged = "\n".join(caplog.messages)
        assert "Signed-off-by: A <a@b.c>" in logged


class TestCreateLayerCommitStagesRecipeFile:
    """Regression test: the recipe's .bb file must be staged even when its
    directory is not named after the recipe (e.g. 'acl' lives under
    recipes-support/attr/, not recipes-support/acl/).
    """

    @staticmethod
    def _git(args, cwd):
        import subprocess
        subprocess.run(["git", *args], cwd=cwd, check=True,
                       capture_output=True)

    @patch("cve_corrector.meta_layer.get_layerseries_corename", return_value=None)
    @patch("cve_corrector.meta_layer.get_build_path")
    @patch("cve_corrector.git_ops.get_git_user_info", return_value=("A", "a@b.c"))
    def test_bb_file_staged_when_dir_differs_from_recipe(self, mock_info, mock_bp,
                                                          mock_corename, tmp_path):
        meta = tmp_path / "meta"
        meta.mkdir()
        self._git(["init"], cwd=meta)
        self._git(["config", "user.email", "a@b.c"], cwd=meta)
        self._git(["config", "user.name", "A"], cwd=meta)

        recipe_dir = meta / "meta" / "recipes-support" / "attr"
        recipe_dir.mkdir(parents=True)
        bb_file = recipe_dir / "acl_2.3.2.bb"
        bb_file.write_text('SRC_URI = "http://example.com/acl.tar.gz"\n')
        self._git(["add", "-A"], cwd=meta)
        self._git(["commit", "-m", "initial"], cwd=meta)

        # Simulate devtool finish: append a new patch reference to the .bb
        # file and drop the new patch under a same-named subdirectory.
        bb_file.write_text(
            'SRC_URI = "http://example.com/acl.tar.gz \\\n'
            '           file://CVE-2026-54369.patch"\n')
        patch_dir = recipe_dir / "acl"
        patch_dir.mkdir()
        (patch_dir / "CVE-2026-54369.patch").write_text(
            "--- a/f\n+++ b/f\n---\n")

        mock_bp.return_value = tmp_path

        create_layer_commit(meta, "acl", "CVE-2026-54369", skip_confirm=True)

        committed = subprocess_run(
            ["git", "show", "--stat", "HEAD"], cwd=meta)
        assert "acl_2.3.2.bb" in committed
        assert "CVE-2026-54369.patch" in committed


def subprocess_run(args, cwd):
    import subprocess
    return subprocess.run(args, cwd=cwd, check=True,
                          capture_output=True, text=True).stdout


class TestContinueFromConflict:
    @patch("cve_corrector.workflow.get_state_dir")
    def test_no_state(self, mock_dir, tmp_path):
        mock_dir.return_value = tmp_path
        with pytest.raises(MetadataError):
            continue_from_conflict()

    @patch("cve_corrector.workflow.run_cmd")
    @patch("cve_corrector.workflow.run_cmd_capture")
    @patch("cve_corrector.workflow.get_state_dir")
    def test_resumes(self, mock_dir, mock_capture, mock_cmd, tmp_path):
        mock_dir.return_value = tmp_path
        ws = tmp_path / "build" / "workspace" / "sources" / "busybox"
        ws.mkdir(parents=True)
        state_data = {
            "workspace_path": str(ws), "cve_id": "CVE-1", "recipe": "busybox",
            "commit_hash": "abc", "hash_details": [], "meta_layer": str(tmp_path),
            "skip_build": True, "skip_ptest": True, "ptest_before": None,
            "series_state": None, "current_step": None, "skip_confirm": False,
        }
        (tmp_path / "busybox.json").write_text(json.dumps(state_data))
        mock_capture.return_value = MagicMock(stdout="")
        state = continue_from_conflict()
        assert state.cve_id == "CVE-1"
        assert state.current_step == "cherry_pick_to_devtool"

    @patch("cve_corrector.workflow.run_cmd")
    @patch("cve_corrector.workflow.run_cmd_capture")
    @patch("cve_corrector.workflow.get_state_dir")
    def test_conflicts_still_present(self, mock_dir, mock_capture, mock_cmd, tmp_path):
        mock_dir.return_value = tmp_path
        ws = tmp_path / "build" / "workspace" / "sources" / "busybox"
        ws.mkdir(parents=True)
        state_data = {
            "workspace_path": str(ws), "cve_id": "CVE-1", "recipe": "busybox",
            "commit_hash": "abc", "hash_details": [], "meta_layer": str(tmp_path),
            "skip_build": True, "skip_ptest": True, "ptest_before": None,
            "series_state": None, "current_step": None, "skip_confirm": False,
        }
        (tmp_path / "busybox.json").write_text(json.dumps(state_data))
        mock_capture.return_value = MagicMock(stdout="UU file.c")
        with pytest.raises(ConflictError):
            continue_from_conflict()

    @patch("cve_corrector.workflow.run_cmd")
    @patch("cve_corrector.workflow.run_cmd_capture")
    @patch("cve_corrector.workflow.get_state_dir")
    def test_untracked_files_do_not_block_resume(self, mock_dir, mock_capture,
                                                  mock_cmd, tmp_path):
        """Untracked/modified build artifacts should not trigger ConflictError."""
        mock_dir.return_value = tmp_path
        ws = tmp_path / "build" / "workspace" / "sources" / "openssh"
        ws.mkdir(parents=True)
        state_data = {
            "workspace_path": str(ws), "cve_id": "CVE-2024-39894",
            "recipe": "openssh", "commit_hash": "abc", "hash_details": [],
            "meta_layer": str(tmp_path), "skip_build": True, "skip_ptest": True,
            "ptest_before": None, "series_state": None,
            "current_step": None, "skip_confirm": False,
        }
        (tmp_path / "openssh.json").write_text(json.dumps(state_data))
        # Simulate untracked build artifacts (no U markers)
        mock_capture.return_value = MagicMock(stdout="?? config.log\n?? config.status\nM  Makefile\n")
        state = continue_from_conflict()
        assert state.cve_id == "CVE-2024-39894"

    @patch("cve_corrector.workflow.run_cmd")
    @patch("cve_corrector.workflow.run_cmd_capture")
    @patch("cve_corrector.workflow.get_state_dir")
    def test_preserves_step_when_past_cherry_pick(self, mock_dir, mock_capture,
                                                   mock_cmd, tmp_path):
        """When saved step is ptest_after_patch, don't reset to cherry_pick_to_devtool."""
        mock_dir.return_value = tmp_path
        ws = tmp_path / "build" / "workspace" / "sources" / "busybox"
        ws.mkdir(parents=True)
        state_data = {
            "workspace_path": str(ws), "cve_id": "CVE-2026-26157",
            "recipe": "busybox", "commit_hash": "abc", "hash_details": [],
            "meta_layer": str(tmp_path), "skip_build": True, "skip_ptest": True,
            "ptest_before": None, "series_state": None,
            "current_step": "ptest_after_patch", "skip_confirm": False,
        }
        (tmp_path / "busybox.json").write_text(json.dumps(state_data))
        mock_capture.return_value = MagicMock(stdout="")
        state = continue_from_conflict()
        assert state.current_step == "ptest_after_patch"


class TestRunBuildStep:
    @patch("cve_corrector.workflow.run_cmd", return_value=0)
    @patch("cve_corrector.workflow.run_cmd_capture")
    @patch("cve_corrector.workflow.copy_missing_files_from_devtool")
    def test_success(self, mock_copy, mock_capture, mock_cmd, tmp_path):
        state = _state(tmp_path, skip_build=False)
        _run_build_step(state)

    def test_skip(self, tmp_path):
        state = _state(tmp_path, skip_build=True)
        _run_build_step(state)  # no crash

    @patch("cve_corrector.workflow.save_progress")
    @patch("cve_corrector.workflow.run_cmd")
    @patch("cve_corrector.workflow.run_cmd_capture")
    @patch("cve_corrector.workflow.copy_missing_files_from_devtool")
    def test_failure(self, mock_copy, mock_capture, mock_cmd, mock_save, tmp_path):
        # clean ok, bitbake -c clean ok, devtool build fails
        mock_cmd.side_effect = [0, 1]
        state = _state(tmp_path, skip_build=False)
        with pytest.raises(BuildError):
            _run_build_step(state)


class TestRunPtestStep:
    def test_skip(self, tmp_path):
        state = _state(tmp_path, skip_ptest=True)
        assert _run_ptest_step(state) is None

    @patch("cve_corrector.workflow.run_ptest", return_value="PASSED: 5, FAILED: 0")
    def test_success(self, _, tmp_path):
        state = _state(tmp_path, skip_ptest=False)
        result = _run_ptest_step(state)
        assert "PASSED" in result

    @patch("cve_corrector.workflow.save_progress")
    @patch("cve_corrector.workflow.run_ptest", return_value="PASSED: 4, FAILED: 1")
    def test_regression(self, mock_ptest, mock_save, tmp_path):
        state = _state(tmp_path, skip_ptest=False, ptest_before="PASSED: 5, FAILED: 0")
        with pytest.raises(PtestError):
            _run_ptest_step(state)

    @patch("cve_corrector.workflow.save_progress")
    @patch("cve_corrector.workflow.run_ptest", return_value=None)
    def test_ptest_fails_with_before(self, mock_ptest, mock_save, tmp_path):
        state = _state(tmp_path, skip_ptest=False, ptest_before="PASSED: 5, FAILED: 0")
        with pytest.raises(PtestError):
            _run_ptest_step(state)


class TestLogPtestDebugConf:
    """Tests for _log_ptest_debug_conf helper."""

    def test_logs_when_debug_conf_exists(self, tmp_path, monkeypatch):
        """Logs the debug conf path when the file exists and BBPATH is set."""
        monkeypatch.setenv("BBPATH", str(tmp_path))
        conf_dir = tmp_path / "conf"
        conf_dir.mkdir()
        debug_conf = conf_dir / "local.conf.ptest-debug"
        debug_conf.write_text("# debug config\n")
        # Should not raise; just logs
        _log_ptest_debug_conf()

    def test_noop_when_no_bbpath(self, monkeypatch):
        """Does nothing when BBPATH is not set (no crash)."""
        monkeypatch.delenv("BBPATH", raising=False)
        _log_ptest_debug_conf()

    def test_noop_when_file_missing(self, tmp_path, monkeypatch):
        """Does nothing when the debug file doesn't exist."""
        monkeypatch.setenv("BBPATH", str(tmp_path))
        (tmp_path / "conf").mkdir()
        _log_ptest_debug_conf()


class TestApplySeries:
    @patch("cve_corrector.cherry_pick.run_cmd", return_value=0)
    @patch("cve_corrector.cherry_pick.is_bad_object", return_value=False)
    def test_success(self, *_):
        series = [{"pull_url": "http://pr/1", "commits": ["a", "b"]}]
        ok, h, partial = apply_series(Path("/ws"), series)
        assert ok and h == "b"

    @patch("cve_corrector.cherry_pick.run_cmd")
    @patch("cve_corrector.cherry_pick.is_bad_object", return_value=False)
    def test_failure_with_partial(self, mock_bad, mock_cmd, tmp_path):
        mock_cmd.side_effect = [1, 0, 0]  # cherry-pick fails, abort, reset
        ws = tmp_path / "ws"
        ws.mkdir()
        git_dir = ws / ".git"
        git_dir.mkdir()
        commit_a = "a" * 40
        commit_b = "b" * 40
        # Make it fail at commit_b so commit_a counts as applied
        (git_dir / "CHERRY_PICK_HEAD").write_text(commit_b)
        series = [{"pull_url": "http://pr/1", "commits": [commit_a, commit_b]}]
        ok, h, partial = apply_series(ws, series)
        assert not ok
        assert partial is not None
        assert partial["failed_at"] == commit_b
        assert partial["applied_commits"] == [commit_a]

    @patch("cve_corrector.cherry_pick.is_bad_object", return_value=True)
    def test_all_bad_objects(self, _):
        series = [{"pull_url": "http://pr/1", "commits": ["a"]}]
        ok, h, partial = apply_series(Path("/ws"), series)
        assert not ok


class TestSetupUpstreamRemoteSeriesFallback:
    @patch("cve_corrector.workspace.run_cmd", return_value=0)
    @patch("cve_corrector.workspace.run_cmd_capture")
    @patch("cve_corrector.workspace.find_mirror_repo", return_value=None)
    @patch("cve_corrector.workspace.get_upstream_check_uri", return_value=None)
    @patch("cve_corrector.workspace.get_recipe_src_uri_git", return_value=None)
    def test_deduces_from_series_pull_url(self, mock_src, mock_check, mock_mirror, mock_capture, mock_cmd, tmp_path):
        """When hash_details is empty, deduce upstream from series pull_url."""
        ws = tmp_path / "ws"
        ws.mkdir()
        mock_capture.side_effect = [
            MagicMock(stdout=""),  # git remote (no upstream)
        ]
        setup_upstream_remote(
            ws, None, tmp_path, "libsolv", hash_details=[],
            series=[{"pull_url": "https://github.com/openSUSE/libsolv/pull/616",
                     "commits": ["c5b5db52"]}])
        # Should have called git remote add with the deduced URL
        mock_cmd.assert_any_call(
            ['git', 'remote', 'add', 'upstream',
             'https://github.com/openSUSE/libsolv'],
            cwd=ws)

    @patch("cve_corrector.workspace.run_cmd", return_value=0)
    @patch("cve_corrector.workspace.run_cmd_capture")
    @patch("cve_corrector.workspace.find_mirror_repo", return_value=None)
    @patch("cve_corrector.workspace.get_upstream_check_uri", return_value=None)
    @patch("cve_corrector.workspace.get_recipe_src_uri_git", return_value=None)
    def test_hash_details_takes_priority(self, mock_src, mock_check, mock_mirror, mock_capture, mock_cmd, tmp_path):
        """hash_details URLs are tried before series pull_url."""
        ws = tmp_path / "ws"
        ws.mkdir()
        mock_capture.side_effect = [
            MagicMock(stdout=""),  # git remote
        ]
        setup_upstream_remote(
            ws, None, tmp_path, "libsolv",
            hash_details=[{"hash": "abc", "url": "https://github.com/other/repo/commit/abc"}],
            series=[{"pull_url": "https://github.com/openSUSE/libsolv/pull/616",
                     "commits": ["c5b5db52"]}])
        mock_cmd.assert_any_call(
            ['git', 'remote', 'add', 'upstream',
             'https://github.com/other/repo'],
            cwd=ws)

    @patch("cve_corrector.workspace.find_mirror_repo", return_value=None)
    @patch("cve_corrector.workspace.get_upstream_check_uri", return_value=None)
    @patch("cve_corrector.workspace.get_recipe_src_uri_git", return_value=None)
    def test_returns_none_when_no_urls(self, mock_src, mock_check, mock_mirror, tmp_path):
        """Returns None when neither hash_details nor series have URLs."""
        ws = tmp_path / "ws"
        ws.mkdir()
        result = setup_upstream_remote(
            ws, None, tmp_path, "libsolv", hash_details=[], series=[])
        assert result is None


class TestSetupUpstreamRemoteMismatchWarning:
    """The patch-deduced upstream must be compared against the recipe SRC_URI
    even when SRC_URI is used as the fetch source (regression: CVE-2026-42250,
    fix commit in bzip2 repo while recipe SRC_URI points to bzip2-tests)."""

    @patch("cve_corrector.workspace.logger")
    @patch("cve_corrector.workspace.run_cmd", return_value=0)
    @patch("cve_corrector.workspace.run_cmd_capture")
    @patch("cve_corrector.workspace.find_mirror_repo", return_value=None)
    @patch("cve_corrector.workspace.get_recipe_src_uri_git",
           return_value="git://sourceware.org/git/bzip2-tests.git")
    def test_warns_when_patch_repo_differs_from_src_uri(
            self, mock_src, mock_mirror, mock_capture, mock_cmd, mock_logger,
            tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        mock_capture.return_value = MagicMock(stdout="")  # git remote: no upstream
        setup_upstream_remote(
            ws, None, tmp_path, "bzip2",
            hash_details=[{
                "hash": "35d122a3df8b0cc4082a4d89fdc6ee99f375fe67",
                "url": ("https://sourceware.org/cgit/bzip2/commit/"
                        "?id=35d122a3df8b0cc4082a4d89fdc6ee99f375fe67"),
            }])
        warned = any(
            "differs from recipe SRC_URI" in str(c.args[0])
            for c in mock_logger.warning.call_args_list)
        assert warned, "expected supply-chain mismatch warning"

    @patch("cve_corrector.workspace.logger")
    @patch("cve_corrector.workspace.run_cmd", return_value=0)
    @patch("cve_corrector.workspace.run_cmd_capture")
    @patch("cve_corrector.workspace.find_mirror_repo", return_value=None)
    @patch("cve_corrector.workspace.get_recipe_src_uri_git",
           return_value="https://github.com/openssl/openssl.git")
    def test_no_warning_when_patch_repo_matches(
            self, mock_src, mock_mirror, mock_capture, mock_cmd, mock_logger,
            tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        mock_capture.return_value = MagicMock(stdout="")
        setup_upstream_remote(
            ws, None, tmp_path, "openssl",
            hash_details=[{
                "hash": "abc1234",
                "url": "https://github.com/openssl/openssl/commit/abc1234",
            }])
        warned = any(
            "differs from recipe SRC_URI" in str(c.args[0])
            for c in mock_logger.warning.call_args_list)
        assert not warned, "did not expect a mismatch warning for matching repos"


class TestSetupUpstreamRemoteFixSource:
    """On a repo mismatch, the deduced fix repo is added as a secondary
    'upstream-fix' remote and fetched so fix commits/tags are reachable."""

    @patch("cve_corrector.workspace.run_cmd", return_value=0)
    @patch("cve_corrector.workspace.run_cmd_capture")
    @patch("cve_corrector.workspace.find_mirror_repo", return_value=None)
    @patch("cve_corrector.workspace.get_recipe_src_uri_git",
           return_value="git://sourceware.org/git/bzip2-tests.git")
    def test_adds_and_fetches_fix_remote(
            self, mock_src, mock_mirror, mock_capture, mock_cmd, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        mock_capture.return_value = MagicMock(stdout="")  # git remote listings
        setup_upstream_remote(
            ws, None, tmp_path, "bzip2",
            hash_details=[{
                "hash": "35d122a3df8b0cc4082a4d89fdc6ee99f375fe67",
                "url": ("https://sourceware.org/cgit/bzip2/commit/"
                        "?id=35d122a3df8b0cc4082a4d89fdc6ee99f375fe67"),
            }])
        mock_cmd.assert_any_call(
            ['git', 'remote', 'add', 'upstream-fix',
             'https://sourceware.org/git/bzip2'], cwd=ws)
        mock_cmd.assert_any_call(
            ['git', 'fetch', 'upstream-fix', '--tags', '--progress'], cwd=ws)

    @patch("cve_corrector.workspace.run_cmd", return_value=0)
    @patch("cve_corrector.workspace.run_cmd_capture")
    @patch("cve_corrector.workspace.find_mirror_repo", return_value=None)
    @patch("cve_corrector.workspace.get_recipe_src_uri_git",
           return_value="https://github.com/openssl/openssl.git")
    def test_no_fix_remote_when_repos_match(
            self, mock_src, mock_mirror, mock_capture, mock_cmd, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        mock_capture.return_value = MagicMock(stdout="")
        setup_upstream_remote(
            ws, None, tmp_path, "openssl",
            hash_details=[{
                "hash": "abc1234",
                "url": "https://github.com/openssl/openssl/commit/abc1234",
            }])
        fix_calls = [
            c for c in mock_cmd.call_args_list
            if len(c.args) and isinstance(c.args[0], list)
            and 'upstream-fix' in c.args[0]]
        assert not fix_calls, "should not add a fix remote when repos match"


class TestProtocolFallback:
    """Fetches retry over an alternate transport when the first fails
    (regression: relocated OE SDK breaks https via a bad http.sslCAInfo)."""

    def test_alternate_https_to_git(self):
        assert (_alternate_protocol_url("https://sourceware.org/git/bzip2")
                == "git://sourceware.org/git/bzip2")

    def test_alternate_git_to_https(self):
        assert (_alternate_protocol_url("git://sourceware.org/git/bzip2.git")
                == "https://sourceware.org/git/bzip2.git")

    def test_alternate_local_path_none(self):
        assert _alternate_protocol_url("/mirrors/bzip2.git") is None

    @patch("cve_corrector.workspace.run_cmd")
    def test_fetch_retries_with_git_protocol(self, mock_cmd, tmp_path):
        # https fetch fails (128), set-url succeeds, git:// fetch succeeds.
        mock_cmd.side_effect = [128, 0, 0]
        ok = _fetch_remote(tmp_path, "upstream-fix",
                           "https://sourceware.org/git/bzip2")
        assert ok is True
        mock_cmd.assert_any_call(
            ['git', 'remote', 'set-url', 'upstream-fix',
             'git://sourceware.org/git/bzip2'], cwd=tmp_path)

    @patch("cve_corrector.workspace.run_cmd")
    def test_fetch_succeeds_first_try_no_retry(self, mock_cmd, tmp_path):
        mock_cmd.return_value = 0
        ok = _fetch_remote(tmp_path, "upstream",
                           "git://sourceware.org/git/bzip2-tests.git")
        assert ok is True
        assert mock_cmd.call_count == 1  # no set-url / retry

    @patch("cve_corrector.workspace.run_cmd")
    def test_fetch_fails_both_protocols(self, mock_cmd, tmp_path):
        mock_cmd.side_effect = [128, 0, 128]  # fetch, set-url, retry-fetch
        ok = _fetch_remote(tmp_path, "upstream-fix",
                           "https://sourceware.org/git/bzip2")
        assert ok is False


class TestPremirrorFallback:
    """Tests for premirror fallback in setup_upstream_remote."""

    @patch("cve_corrector.workspace.run_cmd")
    @patch("cve_corrector.workspace.run_cmd_capture")
    @patch("cve_corrector.workspace.get_recipe_src_uri_git",
           return_value="https://github.com/libexpat/libexpat")
    @patch("cve_corrector.workspace.get_upstream_check_uri", return_value=None)
    def test_premirror_fallback_on_fetch_failure(
        self, mock_check_uri, mock_src_uri, mock_capture, mock_cmd, tmp_path
    ):
        """When premirror fetch fails, falls back to original upstream URL."""
        ws = tmp_path / "workspace"
        ws.mkdir()

        # Mock responses for run_cmd_capture:
        # 1. git remote -> no upstream
        mock_capture.return_value = MagicMock(
            returncode=0, stdout="origin\n", stderr=""
        )

        # run_cmd calls: premirror fetches fail, original URL fetch succeeds
        fetch_attempt = [0]

        def run_cmd_effect(cmd, **kwargs):
            cmd_str = ' '.join(cmd) if isinstance(cmd, list) else cmd
            if 'fetch' in cmd_str:
                fetch_attempt[0] += 1
                # First two fetch attempts fail (premirror + alt protocol)
                # Third fetch attempt succeeds (original URL)
                if fetch_attempt[0] <= 2:
                    return 128
                return 0
            return 0

        mock_cmd.side_effect = run_cmd_effect

        result = setup_upstream_remote(
            ws, None, None, "libexpat", [],
            premirror="https://git.example.com/mirror"
        )

        # Should succeed via fallback
        assert result is not None

        # Verify premirror URL was tried first (git remote add with premirror URL)
        add_calls = [c for c in mock_cmd.call_args_list
                     if 'remote' in str(c) and 'add' in str(c)]
        assert any('git.example.com' in str(c) for c in add_calls)

        # Verify fallback to original URL (git remote set-url)
        set_url_calls = [c for c in mock_cmd.call_args_list
                         if 'set-url' in str(c)]
        assert any('github.com/libexpat/libexpat' in str(c) for c in set_url_calls)
