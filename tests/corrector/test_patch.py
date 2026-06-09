# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector.patch_ops — patch metadata injection."""
from unittest.mock import MagicMock
from unittest.mock import patch as mock_patch

from cve_corrector.patch_ops import modify_patch

MINIMAL_PATCH = """\
From abc123 Mon Sep 17 00:00:00 2001
Subject: Fix something

Some description.
---
 file.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/file.c b/file.c
"""


def test_modify_patch_inserts_metadata(tmp_path):
    p = tmp_path / "test.patch"
    p.write_text(MINIMAL_PATCH)
    with mock_patch("cve_corrector.patch_ops.get_git_user_info",
                    return_value=("Test User", "test@example.com")):
        modify_patch(p, "CVE-2025-0001", "https://example.com/commit/abc")
    content = p.read_text()
    assert "CVE: CVE-2025-0001" in content
    assert "Upstream-Status: Backport [https://example.com/commit/abc]" in content
    assert "Signed-off-by: Test User <test@example.com>" in content
    # Metadata should appear before the --- separator
    assert content.index("CVE: CVE-2025-0001") < content.index("\n---\n")


def test_modify_patch_idempotent(tmp_path):
    p = tmp_path / "test.patch"
    p.write_text(MINIMAL_PATCH)
    with mock_patch("cve_corrector.patch_ops.get_git_user_info",
                    return_value=("Test User", "test@example.com")):
        modify_patch(p, "CVE-2025-0001", "https://example.com/commit/abc")
        first = p.read_text()
        modify_patch(p, "CVE-2025-0001", "https://example.com/commit/abc")
        second = p.read_text()
    assert first == second


def test_modify_patch_no_separator(tmp_path):
    p = tmp_path / "test.patch"
    p.write_text("Subject: no separator\n\nsome content\n")
    import pytest
    with mock_patch("cve_corrector.patch_ops.get_git_user_info",
                    return_value=("Test User", "test@example.com")):
        with pytest.raises(ValueError, match="No line containing '---'"):
            modify_patch(p, "CVE-2025-0001", "https://example.com/commit/abc")


def test_modify_patch_preserves_diff(tmp_path):
    p = tmp_path / "test.patch"
    p.write_text(MINIMAL_PATCH)
    diff_section = MINIMAL_PATCH[MINIMAL_PATCH.index("---"):]
    with mock_patch("cve_corrector.patch_ops.get_git_user_info",
                    return_value=("Test User", "test@example.com")):
        modify_patch(p, "CVE-2025-0001", "https://example.com/commit/abc")
    content = p.read_text()
    assert content.endswith(diff_section)


# --- Tests for update_patches_with_metadata recipe scoping ---

from cve_corrector.patch_ops import update_patches_with_metadata


def _make_state(tmp_path, recipe="busybox"):
    """Create a minimal WorkflowState-like object for testing."""
    from cve_corrector.state import WorkflowState
    meta = tmp_path / "meta"
    meta.mkdir()
    return WorkflowState(
        workspace_path=tmp_path / "ws",
        cve_id="CVE-2025-0001",
        recipe=recipe,
        commit_hash="abc123",
        hash_details=[{"hash": "abc123", "url": "https://example.com/commit/abc123"}],
        meta_layer=meta,
        skip_build=True,
        skip_ptest=True,
        ptest_before=None,
        series_state=None,
    )


@mock_patch("cve_corrector.recipe_ops._find_recipe_file")
@mock_patch("cve_corrector.patch_ops.update_recipe_patch")
@mock_patch("cve_corrector.patch_ops.run_cmd_capture")
@mock_patch("cve_corrector.patch_ops.modify_patch")
def test_scopes_patches_to_recipe_dir(mock_modify, mock_capture, mock_update, mock_find, tmp_path):
    """Only patches in the recipe's directory are processed, not other recipes'."""
    state = _make_state(tmp_path, recipe="busybox")
    # Create patch file
    recipe_dir = state.meta_layer / "recipes-core" / "busybox"
    recipe_dir.mkdir(parents=True)
    patch_own = recipe_dir / "files" / "CVE-2025-0001.patch"
    patch_own.parent.mkdir(parents=True)
    patch_own.write_text(MINIMAL_PATCH)

    mock_find.return_value = recipe_dir / "busybox_1.36.bb"

    mock_capture.return_value = MagicMock(
        returncode=0,
        stdout=(
            "recipes-core/busybox/files/CVE-2025-0001.patch\n"
            "recipes-devtools/python/python3-pip/CVE-2025-9999.patch\n"
        )
    )

    update_patches_with_metadata(state)

    # Only the busybox patch should be modified, not python3-pip's
    assert mock_modify.call_count == 1
    called_path = mock_modify.call_args[0][0]
    assert "busybox" in str(called_path)


@mock_patch("cve_corrector.recipe_ops._find_recipe_file")
@mock_patch("cve_corrector.patch_ops.run_cmd_capture")
@mock_patch("cve_corrector.patch_ops.modify_patch")
def test_no_patches_when_all_from_other_recipes(mock_modify, mock_capture, mock_find, tmp_path):
    """When no patches belong to the current recipe, nothing is modified."""
    state = _make_state(tmp_path, recipe="busybox")
    recipe_dir = state.meta_layer / "recipes-core" / "busybox"
    recipe_dir.mkdir(parents=True)

    mock_find.return_value = recipe_dir / "busybox_1.36.bb"

    mock_capture.return_value = MagicMock(
        returncode=0,
        stdout="recipes-devtools/python/python3-pip/CVE-2025-9999.patch\n"
    )

    update_patches_with_metadata(state)
    mock_modify.assert_not_called()
