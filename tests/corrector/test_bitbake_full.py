# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector.bitbake_ops — build path, cleanup, meta-layer."""
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cve_corrector.bitbake_ops import (
    cleanup_workspace,
    deduce_meta_layer_from_recipe,
    find_mirror_repo,
    get_build_path,
    get_state_dir,
    resolve_meta_layer,
)
from cve_corrector.recipe_ops import update_recipe_patch


class TestGetBuildPath:
    def test_from_bbpath(self, tmp_path):
        with patch.dict(os.environ, {"BBPATH": str(tmp_path)}):
            assert get_build_path() == tmp_path

    def test_no_bbpath(self):
        with patch.dict(os.environ, {}, clear=True), pytest.raises(SystemExit):
            get_build_path()

    def test_colon_separated(self, tmp_path):
        with patch.dict(os.environ, {"BBPATH": f"{tmp_path}:/other"}):
            assert get_build_path() == tmp_path


class TestGetStateDir:
    @patch("cve_corrector.bitbake_ops.get_build_path")
    def test_creates_dir(self, mock_bp, tmp_path):
        mock_bp.return_value = tmp_path
        state_dir = get_state_dir()
        assert state_dir.exists()
        assert state_dir == tmp_path / "workspace" / "cve_corrector"


class TestCleanupWorkspace:
    def test_removes_workspace(self, tmp_path):
        ws = tmp_path / "workspace"
        ws.mkdir()
        (ws / "file").write_text("x")
        cleanup_workspace(str(tmp_path))
        assert not ws.exists()

    def test_removes_tmp_dirs(self, tmp_path):
        for d in ("tmp", "tmp-glibc"):
            (tmp_path / d).mkdir()
        cleanup_workspace(str(tmp_path), full=True)
        assert not (tmp_path / "tmp").exists()
        assert not (tmp_path / "tmp-glibc").exists()

    def test_cleans_bblayers_conf(self, tmp_path):
        conf = tmp_path / "conf"
        conf.mkdir()
        bblayers = conf / "bblayers.conf"
        workspace_path = tmp_path / "workspace"
        bblayers.write_text(f"BBLAYERS = \"\\\n  /path/to/meta \\\n  {workspace_path} \\\n\"\n")
        cleanup_workspace(str(tmp_path))
        assert str(workspace_path) not in bblayers.read_text()

    def test_handles_missing_dirs(self, tmp_path):
        cleanup_workspace(str(tmp_path))  # no crash


class TestFindMirrorRepo:
    def test_alias_lookup(self, tmp_path):
        (tmp_path / "glib").mkdir()
        assert find_mirror_repo(tmp_path, "glib-2.0") == tmp_path / "glib"

    def test_hash_details_url(self, tmp_path):
        (tmp_path / "myrepo").mkdir()
        details = [{"url": "https://github.com/org/myrepo/commit/abc"}]
        assert find_mirror_repo(tmp_path, "unknown", details) == tmp_path / "myrepo"


class TestDeduceMetaLayer:
    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_finds_layer(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="/home/build/meta-oe/recipes-core/busybox/busybox_1.36.bb\n")
        result = deduce_meta_layer_from_recipe("busybox")
        assert result == Path("/home/build/meta-oe")

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_no_match(self, mock_run):
        mock_run.return_value = MagicMock(stdout="no recipes found\n")
        assert deduce_meta_layer_from_recipe("nonexistent") is None


class TestResolveMetaLayer:
    def test_absolute_existing(self, tmp_path):
        layer = tmp_path / "meta-oe"
        layer.mkdir()
        assert resolve_meta_layer(layer) == layer

    def test_from_bblayers_conf(self, tmp_path):
        conf = tmp_path / "conf"
        conf.mkdir()
        layer = tmp_path / "meta-oe"
        layer.mkdir()
        bblayers = conf / "bblayers.conf"
        # Use space-separated format (no quotes around path) to match regex
        bblayers.write_text(f'BBLAYERS = \\\n  {layer} \\\n')
        with patch.dict(os.environ, {"BBPATH": str(tmp_path)}):
            result = resolve_meta_layer(Path("meta-oe"))
        assert result == layer

    def test_no_bbpath(self):
        with patch.dict(os.environ, {}, clear=True):
            result = resolve_meta_layer(Path("meta-oe"))
            assert result == Path("meta-oe")


class TestUpdateRecipePatch:
    def test_empty_patch_name(self, capsys):
        update_recipe_patch("foo", "new.patch", "", None)
        assert "Warning" in capsys.readouterr().out

    @patch("cve_corrector.recipe_ops.run_cmd_capture")
    def test_fallback_to_bitbake(self, mock_run, tmp_path):
        mock_run.side_effect = [
            MagicMock(stdout=f"{tmp_path}/foo.bb\n"),
            MagicMock(stdout=""),
        ]
        bb = tmp_path / "foo.bb"
        bb.write_text('SRC_URI = "file://old.patch"\n')
        update_recipe_patch("foo", "new.patch", "old.patch")
        assert "new.patch" in bb.read_text()
