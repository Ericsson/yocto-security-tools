# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector.git_ops — git operations."""
from pathlib import Path
from unittest.mock import MagicMock, patch

from cve_corrector.git_ops import (
    _cherry_pick_monorepo,
    checkout_version,
    detect_monorepo_subproject,
    get_git_user_info,
    is_bad_object,
    try_cherry_pick,
)


class TestGetGitUserInfo:
    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_returns_info(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="John Doe\n"),
            MagicMock(returncode=0, stdout="john@example.com\n"),
        ]
        name, email = get_git_user_info()
        assert name == "John Doe"
        assert email == "john@example.com"

    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_defaults_on_failure(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        name, email = get_git_user_info()
        assert name == "Unknown"
        assert email == "unknown@example.com"


class TestDetectMonorepoSubproject:
    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_detected(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        result = detect_monorepo_subproject(Path("/repo"), "v1.0", "gst-plugins-good")
        assert result == "subprojects/gst-plugins-good"

    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_not_detected(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        assert detect_monorepo_subproject(Path("/repo"), "v1.0", "simple") is None


class TestCheckoutVersion:
    @patch("cve_corrector.git_ops.run_cmd", return_value=0)
    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_success(self, mock_capture, mock_cmd):
        mock_capture.return_value = MagicMock(stdout="v1.0\nv2.0\n")
        assert checkout_version(Path("/repo"), "2.0", "cve-branch") is True

    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_no_matching_tag(self, mock_capture):
        mock_capture.return_value = MagicMock(stdout="v1.0\n")
        assert checkout_version(Path("/repo"), "9.9", "cve-branch") is False

    @patch("cve_corrector.git_ops.run_cmd", return_value=0)
    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_subproject(self, mock_capture, mock_cmd):
        mock_capture.side_effect = [
            MagicMock(stdout="v1.0\n"),  # git tag
            MagicMock(returncode=0, stdout="tree-sha\n"),  # rev-parse tag:subproject
            MagicMock(returncode=0, stdout="commit-sha\n"),  # rev-parse tag^{commit}
            MagicMock(returncode=0, stdout="new-commit\n"),  # commit-tree
        ]
        assert checkout_version(Path("/repo"), "1.0", "cve", subproject="sub/proj") is True

    @patch("cve_corrector.git_ops.run_cmd", return_value=1)
    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_checkout_fails(self, mock_capture, mock_cmd):
        mock_capture.return_value = MagicMock(stdout="v1.0\n")
        assert checkout_version(Path("/repo"), "1.0", "cve") is False


class TestIsBadObject:
    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_good_object(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        assert is_bad_object(Path("/repo"), "abc123") is False

    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_bad_object_after_fetch(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=1),  # first cat-file
            MagicMock(returncode=0),  # fetch
            MagicMock(returncode=1),  # second cat-file
        ]
        assert is_bad_object(Path("/repo"), "abc123") is True

    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_bad_then_good_after_fetch(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=1),  # first cat-file
            MagicMock(returncode=0),  # fetch
            MagicMock(returncode=0),  # second cat-file
        ]
        assert is_bad_object(Path("/repo"), "abc123") is False


class TestTryCherryPick:
    @patch("cve_corrector.git_ops.run_cmd", return_value=0)
    def test_success_first_try(self, mock_cmd):
        assert try_cherry_pick(Path("/repo"), "abc123") is True

    @patch("cve_corrector.git_ops.run_cmd_capture")
    @patch("cve_corrector.git_ops.run_cmd", return_value=1)
    def test_fallback_merge_parent(self, mock_cmd, mock_capture):
        mock_capture.side_effect = [
            MagicMock(returncode=0),  # cherry-pick --abort
            MagicMock(returncode=0, stdout="tree abc\nparent 111\nparent 222\n"),  # cat-file -p
            MagicMock(returncode=0),  # cherry-pick -m 1
        ]
        assert try_cherry_pick(Path("/repo"), "abc123") is True

    @patch("cve_corrector.git_ops.run_cmd_capture")
    @patch("cve_corrector.git_ops.run_cmd", return_value=1)
    def test_no_merge_parent_fallback_for_non_merge(self, mock_cmd, mock_capture):
        mock_capture.side_effect = [
            MagicMock(returncode=0),  # cherry-pick --abort
            MagicMock(returncode=0, stdout="tree abc\nparent 111\n"),  # cat-file -p (1 parent)
        ]
        assert try_cherry_pick(Path("/repo"), "abc123") is False

    @patch("cve_corrector.git_ops.run_cmd_capture")
    @patch("cve_corrector.git_ops.run_cmd", return_value=1)
    def test_merge_parent_fallback_fails(self, mock_cmd, mock_capture):
        mock_capture.side_effect = [
            MagicMock(returncode=0),  # cherry-pick --abort
            MagicMock(returncode=0, stdout="tree abc\nparent 111\nparent 222\n"),  # cat-file -p
            MagicMock(returncode=1),  # cherry-pick -m 1 fails
            MagicMock(returncode=0),  # cherry-pick --abort
        ]
        assert try_cherry_pick(Path("/repo"), "abc123") is False

    @patch("cve_corrector.git_ops.run_cmd_capture")
    @patch("cve_corrector.git_ops.run_cmd", return_value=1)
    def test_all_fail(self, mock_cmd, mock_capture):
        mock_capture.side_effect = [
            MagicMock(returncode=0),  # cherry-pick --abort
            MagicMock(returncode=0, stdout="tree abc\nparent 111\nparent 222\n"),  # cat-file -p
            MagicMock(returncode=1),  # cherry-pick -m 1 fails
            MagicMock(returncode=0),  # cherry-pick --abort
        ]
        assert try_cherry_pick(Path("/repo"), "abc123") is False


class TestCherryPickMonorepo:
    @patch("subprocess.run")
    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_success(self, mock_capture, mock_subrun):
        mock_capture.return_value = MagicMock(
            returncode=0, stdout="diff a/subprojects/gst/file.c b/subprojects/gst/file.c")
        mock_subrun.return_value = MagicMock(returncode=0)
        assert _cherry_pick_monorepo(Path("/repo"), "abc", "subprojects/gst") is True

    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_format_patch_fails(self, mock_capture):
        mock_capture.return_value = MagicMock(returncode=1, stdout="")
        assert _cherry_pick_monorepo(Path("/repo"), "abc", "sub") is False

    @patch("subprocess.run")
    @patch("cve_corrector.git_ops.run_cmd_capture")
    def test_3way_fallback(self, mock_capture, mock_subrun):
        mock_capture.side_effect = [
            MagicMock(returncode=0, stdout="diff content"),  # format-patch
            MagicMock(returncode=0),  # am --abort
        ]
        mock_subrun.side_effect = [
            MagicMock(returncode=1),  # first am fails
            MagicMock(returncode=0),  # 3way succeeds
        ]
        assert _cherry_pick_monorepo(Path("/repo"), "abc", "sub") is True
