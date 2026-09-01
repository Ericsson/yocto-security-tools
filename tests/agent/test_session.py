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


def test_expand_finds_file_moved_between_branches(tmp_path):
    """A stable branch keeping a file at another path is still in scope.

    libsoup 3.x holds websocket sources in libsoup/websocket/; the 2.4 branch
    that the libsoup-2.4 recipe builds keeps them flat in libsoup/. Scope
    derived from a 3.x commit named a path absent from the 2.4 tree, so the
    agent could not edit the one file it needed (CVE-2024-52532).
    """
    ws = tmp_path / "workspace"
    (ws / "libsoup").mkdir(parents=True)
    (ws / "libsoup" / "soup-websocket-connection.c").write_text("")
    allowed = {"libsoup/websocket/soup-websocket-connection.c"}
    expanded = _expand_path_variants(allowed, ws)
    assert "libsoup/soup-websocket-connection.c" in expanded
    # The upstream path is still kept, so the hook accepts either spelling.
    assert "libsoup/websocket/soup-websocket-connection.c" in expanded


def test_expand_ignores_ambiguous_basename(tmp_path):
    """An ambiguous basename must not silently widen scope to the wrong file."""
    ws = tmp_path / "workspace"
    (ws / "a").mkdir(parents=True)
    (ws / "b").mkdir(parents=True)
    (ws / "a" / "Makefile").write_text("")
    (ws / "b" / "Makefile").write_text("")
    expanded = _expand_path_variants({"upstream/dir/Makefile"}, ws)
    assert "a/Makefile" not in expanded
    assert "b/Makefile" not in expanded


def test_expand_does_not_search_when_path_already_exists(tmp_path):
    """An existing upstream path needs no moved-file search."""
    ws = tmp_path / "workspace"
    (ws / "libsoup" / "websocket").mkdir(parents=True)
    (ws / "libsoup" / "websocket" / "conn.c").write_text("")
    # A decoy at another path must not be pulled into scope.
    (ws / "other").mkdir()
    (ws / "other" / "conn.c").write_text("")
    expanded = _expand_path_variants({"libsoup/websocket/conn.c"}, ws)
    assert "other/conn.c" not in expanded


def test_expand_skips_git_directory_when_searching(tmp_path):
    """A match inside .git is not a source file and must be ignored."""
    ws = tmp_path / "workspace"
    (ws / ".git").mkdir(parents=True)
    (ws / ".git" / "config.c").write_text("")
    expanded = _expand_path_variants({"src/config.c"}, ws)
    assert ".git/config.c" not in expanded
