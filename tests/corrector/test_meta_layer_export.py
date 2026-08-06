# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector.meta_layer._export_commit_patch and the
LAYERSERIES_CORENAMES-based --subject-prefix used when exporting a patch
for mailing-list submission.
"""
from pathlib import Path
from unittest.mock import MagicMock, patch

from cve_corrector.bitbake_ops import get_layerseries_corename
from cve_corrector.meta_layer import _export_commit_patch, write_cve_status


class TestGetLayerseriesCorename:
    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_returns_corename(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="scarthgap\n")
        assert get_layerseries_corename() == "scarthgap"
        mock_run.assert_called_once_with(
            ['bitbake-getvar', 'LAYERSERIES_CORENAMES', '--value'])

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_multiple_corenames_uses_last(self, mock_run):
        """LAYERSERIES_CORENAMES may list multiple names; the current
        release is the last one."""
        mock_run.return_value = MagicMock(returncode=0, stdout="kirkstone scarthgap\n")
        assert get_layerseries_corename() == "scarthgap"

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_command_failure_returns_none(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert get_layerseries_corename() is None

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_empty_output_returns_none(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="\n")
        assert get_layerseries_corename() is None


class TestExportCommitPatch:
    @patch("cve_corrector.meta_layer.get_layerseries_corename")
    @patch("cve_corrector.meta_layer.get_build_path")
    @patch("cve_corrector.meta_layer.run_cmd_capture")
    def test_includes_subject_prefix_when_corename_available(
            self, mock_run, mock_bp, mock_corename, tmp_path):
        mock_bp.return_value = tmp_path
        mock_corename.return_value = "scarthgap"
        mock_run.return_value = MagicMock(returncode=0, stdout="0001-fix.patch\n")

        meta = tmp_path / "meta"
        _export_commit_patch(meta)

        args, kwargs = mock_run.call_args
        cmd = args[0]
        assert '--subject-prefix' in cmd
        idx = cmd.index('--subject-prefix')
        assert cmd[idx + 1] == 'scarthgap][PATCH'
        assert kwargs.get("cwd") == meta

    @patch("cve_corrector.meta_layer.get_layerseries_corename")
    @patch("cve_corrector.meta_layer.get_build_path")
    @patch("cve_corrector.meta_layer.run_cmd_capture")
    def test_omits_subject_prefix_when_corename_unavailable(
            self, mock_run, mock_bp, mock_corename, tmp_path):
        mock_bp.return_value = tmp_path
        mock_corename.return_value = None
        mock_run.return_value = MagicMock(returncode=0, stdout="0001-fix.patch\n")

        meta = tmp_path / "meta"
        _export_commit_patch(meta)

        args, _ = mock_run.call_args
        cmd = args[0]
        assert '--subject-prefix' not in cmd

    @patch("cve_corrector.meta_layer.get_layerseries_corename")
    @patch("cve_corrector.meta_layer.get_build_path")
    @patch("cve_corrector.meta_layer.run_cmd_capture")
    def test_logs_warning_on_format_patch_failure(
            self, mock_run, mock_bp, mock_corename, tmp_path, caplog):
        import logging
        mock_bp.return_value = tmp_path
        mock_corename.return_value = "scarthgap"
        mock_run.return_value = MagicMock(returncode=1, stdout="")

        meta = tmp_path / "meta"
        with caplog.at_level(logging.WARNING, logger="cve_corrector"):
            _export_commit_patch(meta)
        assert any("Failed to export patch" in r.message for r in caplog.records)


class TestWriteCveStatusSignoff:
    """write_cve_status must not fabricate a Signed-off-by trailer unless
    explicitly requested — the tool cannot know whether the resolved git
    identity represents a human who has reviewed this specific change."""

    def _meta_layer_with_recipe(self, tmp_path, recipe="busybox"):
        meta = tmp_path / "meta"
        recipe_dir = meta / "recipes-core" / recipe
        recipe_dir.mkdir(parents=True)
        recipe_file = recipe_dir / f"{recipe}_1.36.bb"
        recipe_file.write_text('SUMMARY = "busybox"\n')
        return meta, recipe_file

    @staticmethod
    def _capturing_run_cmd(captured):
        def _run_cmd(cmd, cwd=None):
            if cmd[:2] == ['git', 'commit']:
                msg_file = cmd[cmd.index('-F') + 1]
                captured.append(Path(msg_file).read_text())
            return 0
        return _run_cmd

    @patch("cve_corrector.meta_layer._export_commit_patch")
    @patch("cve_corrector.meta_layer.get_git_user_info", return_value=("A", "a@b.c"))
    def test_no_signoff_by_default(self, mock_info, mock_export, tmp_path):
        meta, recipe_file = self._meta_layer_with_recipe(tmp_path)
        captured = []
        with patch("cve_corrector.recipe_ops._find_recipe_file",
                   return_value=recipe_file), \
             patch("cve_corrector.meta_layer.run_cmd",
                  side_effect=self._capturing_run_cmd(captured)):
            write_cve_status(meta, "busybox", "CVE-1", "not applicable",
                             skip_confirm=True)
        assert captured and "Signed-off-by" not in captured[0]
        mock_info.assert_not_called()

    @patch("cve_corrector.meta_layer._export_commit_patch")
    @patch("cve_corrector.meta_layer.get_git_user_info", return_value=("A", "a@b.c"))
    def test_signoff_opt_in(self, mock_info, mock_export, tmp_path):
        meta, recipe_file = self._meta_layer_with_recipe(tmp_path)
        captured = []
        with patch("cve_corrector.recipe_ops._find_recipe_file",
                   return_value=recipe_file), \
             patch("cve_corrector.meta_layer.run_cmd",
                  side_effect=self._capturing_run_cmd(captured)):
            write_cve_status(meta, "busybox", "CVE-1", "not applicable",
                             skip_confirm=True, sign_off=True)
        assert captured and "Signed-off-by: A <a@b.c>" in captured[0]
