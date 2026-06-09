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
from cve_corrector.ui import print_conflict_instructions, print_edit_instructions
from cve_corrector.workflow import (
    _handle_failed_series,
    _handle_no_clean_apply,
    _make_should_run,
    _run_build_step,
    _run_ptest_step,
    continue_from_conflict,
    save_progress,
    save_workflow_state,
)
from cve_corrector.workspace import setup_upstream_remote


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
            MagicMock(returncode=0),  # checkout
            MagicMock(returncode=0),  # reset
        ]
        copy_missing_files_from_devtool(Path("/ws"))

    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_nothing_missing(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="a.c\n"),
            MagicMock(returncode=0, stdout="a.c\n"),
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
        """format-patch should only include CVE commits, not devtool prep."""
        state = _state(tmp_path)

        mock_capture.side_effect = [
            MagicMock(returncode=0, stdout="5\n"),  # rev-list --count original-version..CVE
            MagicMock(returncode=0, stdout="3\n"),  # rev-list --count original-version..devtool
            MagicMock(returncode=0, stdout=""),  # format-patch (produces no patches)
        ]
        from cve_corrector.state import AlreadyAppliedError
        with patch("cve_corrector.cherry_pick.handle_empty_cherry_pick"):
            with pytest.raises(AlreadyAppliedError):
                cherry_pick_to_devtool(state)

        # Verify format-patch uses -2 (5 total - 3 devtool = 2 CVE commits)
        fmt_call = mock_capture.call_args_list[2]
        assert '-2' in fmt_call[0][0]

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
            MagicMock(returncode=0, stdout="3\n"),  # rev-list --count total
            MagicMock(returncode=0, stdout="2\n"),  # rev-list --count devtool
            MagicMock(returncode=0, stdout="patched"),  # format-patch
            am_fail,  # git am -p1
            am_fail,  # git am -p1 --3way
            am_fail,  # git am -p2
            am_fail,  # git am -p2 --3way
            am_fail,  # git am -p3
            am_fail,  # git am -p3 --3way
            MagicMock(returncode=0, stdout="commit1\n"),  # rev-list for fallback
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
    def test_minimum_one_commit(self, mock_clean, mock_subdir,
                                 mock_capture, mock_cmd, tmp_path):
        """Even if devtool count >= total, at least 1 commit is formatted."""
        state = _state(tmp_path)

        mock_capture.side_effect = [
            MagicMock(returncode=0, stdout="2\n"),  # rev-list --count total
            MagicMock(returncode=0, stdout="5\n"),  # rev-list --count devtool (more!)
            MagicMock(returncode=0, stdout=""),  # format-patch
        ]
        from cve_corrector.state import AlreadyAppliedError
        with patch("cve_corrector.cherry_pick.handle_empty_cherry_pick"):
            with pytest.raises(AlreadyAppliedError):
                cherry_pick_to_devtool(state)

        fmt_call = mock_capture.call_args_list[2]
        assert '-1' in fmt_call[0][0]


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
    def test_dirty_tracked_files_not_treated_as_conflicts(self, mock_dir, mock_capture, mock_cmd, tmp_path):
        """Modified tracked files (e.g. autotools configure) should not block --continue."""
        mock_dir.return_value = tmp_path
        ws = tmp_path / "build" / "workspace" / "sources" / "dropbear"
        ws.mkdir(parents=True)
        state_data = {
            "workspace_path": str(ws), "cve_id": "CVE-1", "recipe": "dropbear",
            "commit_hash": "abc", "hash_details": [], "meta_layer": str(tmp_path),
            "skip_build": True, "skip_ptest": True, "ptest_before": None,
            "series_state": None, "current_step": None, "skip_confirm": False,
        }
        (tmp_path / "dropbear.json").write_text(json.dumps(state_data))
        # Porcelain output with modified files but no conflict markers
        mock_capture.return_value = MagicMock(stdout=" M configure\n M config.guess\n")
        state = continue_from_conflict()
        assert state.cve_id == "CVE-1"

    @patch("cve_corrector.workflow.run_cmd")
    @patch("cve_corrector.workflow.run_cmd_capture")
    @patch("cve_corrector.workflow.get_state_dir")
    def test_dd_conflict_detected(self, mock_dir, mock_capture, mock_cmd, tmp_path):
        """DD (both deleted) should be treated as a conflict."""
        mock_dir.return_value = tmp_path
        ws = tmp_path / "build" / "workspace" / "sources" / "pkg"
        ws.mkdir(parents=True)
        state_data = {
            "workspace_path": str(ws), "cve_id": "CVE-2", "recipe": "pkg",
            "commit_hash": "abc", "hash_details": [], "meta_layer": str(tmp_path),
            "skip_build": True, "skip_ptest": True, "ptest_before": None,
            "series_state": None, "current_step": None, "skip_confirm": False,
        }
        (tmp_path / "pkg.json").write_text(json.dumps(state_data))
        mock_capture.return_value = MagicMock(stdout="DD deleted.c\n M other.c\n")
        with pytest.raises(ConflictError):
            continue_from_conflict()


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
