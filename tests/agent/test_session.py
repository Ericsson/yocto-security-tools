# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.session — resolution state checking."""
from unittest.mock import MagicMock
from unittest.mock import patch as mock_patch

from cve_agent.session import check_resolution_state


def test_check_resolution_no_conflicts(tmp_path):
    ws = tmp_path / "repo"
    ws.mkdir()
    result = MagicMock(returncode=0, stdout=" M file.c\n")
    with mock_patch("subprocess.run", return_value=result):
        assert check_resolution_state(ws) is True


def test_check_resolution_with_conflicts(tmp_path):
    ws = tmp_path / "repo"
    ws.mkdir()
    result = MagicMock(returncode=0, stdout="UU file.c\n")
    with mock_patch("subprocess.run", return_value=result):
        assert check_resolution_state(ws) is False


def test_check_resolution_missing_workspace(tmp_path):
    assert check_resolution_state(tmp_path / "nonexistent") is True


# --- Tests for _expand_path_variants ---

from cve_agent.session import _expand_path_variants


def test_expand_strips_subprojects_prefix(tmp_path):
    """subprojects/<name>/path should expand to path when it exists in workspace."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "gst" / "isomp4").mkdir(parents=True)
    (ws / "gst" / "isomp4" / "qtdemux.c").write_text("")
    allowed = {"subprojects/gst-plugins-good/gst/isomp4/qtdemux.c"}
    expanded = _expand_path_variants(allowed, ws)
    assert "gst/isomp4/qtdemux.c" in expanded


def test_expand_keeps_original(tmp_path):
    """Original paths are always kept in the expanded set."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    allowed = {"subprojects/foo/bar.c", "src/main.c"}
    expanded = _expand_path_variants(allowed, ws)
    assert "subprojects/foo/bar.c" in expanded
    assert "src/main.c" in expanded


def test_expand_src_prefix(tmp_path):
    """src/foo.c expands to foo.c when it exists at workspace root."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "main.c").write_text("")
    allowed = {"src/main.c"}
    expanded = _expand_path_variants(allowed, ws)
    assert "main.c" in expanded


def test_expand_adds_src_prefix(tmp_path):
    """foo.c expands to src/foo.c when that path exists in workspace."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    (ws / "src").mkdir()
    (ws / "src" / "main.c").write_text("")
    allowed = {"main.c"}
    expanded = _expand_path_variants(allowed, ws)
    assert "src/main.c" in expanded


def test_expand_no_false_positives(tmp_path):
    """Don't add variants for files that don't exist in workspace."""
    ws = tmp_path / "workspace"
    ws.mkdir()
    allowed = {"subprojects/foo/bar.c", "src/missing.c"}
    expanded = _expand_path_variants(allowed, ws)
    assert "bar.c" not in expanded
    assert "missing.c" not in expanded
