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


# --- Tests for prerequisite-aware CVE tagging ---

from cve_corrector.patch_ops import (
    _cherry_picked_sha,
    _compute_cve_tag_flags,
    _extract_patch_subject,
    _normalize_subject,
)

_FIX_PATCH = """\
From aaa111 Mon Sep 17 00:00:00 2001
Subject: [PATCH] net: fix use-after-free in foo()

The real CVE fix.
---
 net/foo.c | 2 +-
"""

_PREREQ_PATCH = """\
From bbb222 Mon Sep 17 00:00:00 2001
Subject: [PATCH] net: add foo_helper() infrastructure

Prerequisite introducing the helper the fix calls.

(cherry picked from commit deadbeefcafe1234)
---
 net/foo.c | 8 ++++++++
"""


def test_modify_patch_prerequisite_omits_cve_tag(tmp_path):
    """A prerequisite patch gets Upstream-Status but NOT a CVE tag."""
    p = tmp_path / "prereq.patch"
    p.write_text(_PREREQ_PATCH)
    with mock_patch("cve_corrector.patch_ops.get_git_user_info",
                    return_value=("Test User", "test@example.com")):
        modify_patch(p, "CVE-2025-0001", "https://example.com/commit/bbb",
                     include_cve_tag=False)
    content = p.read_text()
    assert "CVE: CVE-2025-0001" not in content
    assert "Upstream-Status: Backport [https://example.com/commit/bbb]" in content
    assert "Signed-off-by: Test User <test@example.com>" in content


def test_modify_patch_prerequisite_idempotent(tmp_path):
    """Re-running on a prerequisite (already has Upstream-Status) is a no-op."""
    p = tmp_path / "prereq.patch"
    p.write_text(_PREREQ_PATCH)
    with mock_patch("cve_corrector.patch_ops.get_git_user_info",
                    return_value=("Test User", "test@example.com")):
        modify_patch(p, "CVE-2025-0001", "https://example.com/commit/bbb",
                     include_cve_tag=False)
        first = p.read_text()
        modify_patch(p, "CVE-2025-0001", "https://example.com/commit/bbb",
                     include_cve_tag=False)
        second = p.read_text()
    assert first == second
    assert "CVE: CVE-2025-0001" not in second


def test_extract_patch_subject_strips_patch_prefix():
    assert _extract_patch_subject(_FIX_PATCH) == "net: fix use-after-free in foo()"


def test_normalize_subject_collapses_whitespace_and_case():
    assert _normalize_subject("Net:  Fix   FOO") == "net: fix foo"


def test_cherry_picked_sha_extracts_origin():
    assert _cherry_picked_sha(_PREREQ_PATCH) == "deadbeefcafe1234"
    assert _cherry_picked_sha(_FIX_PATCH) is None


def _write_patches(meta_layer, names_and_text):
    rels = []
    for name, text in names_and_text:
        path = meta_layer / name
        path.write_text(text)
        rels.append(name)
    return rels


def test_compute_flags_series_state_tags_all(tmp_path):
    """Known PR series keep the existing all-CVE tagging (unchanged)."""
    state = _make_state(tmp_path)
    state.series_state = {"commits": ["a", "b"]}
    rels = _write_patches(state.meta_layer,
                          [("0001.patch", _FIX_PATCH), ("0002.patch", _PREREQ_PATCH)])
    assert _compute_cve_tag_flags(state, rels) == [True, True]


def test_compute_flags_single_patch_tags_all(tmp_path):
    """A lone patch is always the fix — tagged with CVE."""
    state = _make_state(tmp_path)
    rels = _write_patches(state.meta_layer, [("0001.patch", _FIX_PATCH)])
    assert _compute_cve_tag_flags(state, rels) == [True]


def test_compute_flags_prerequisite_only_fix_tagged(tmp_path):
    """Agent-added prerequisite (no series, >1 patch): only the fix patch
    whose subject matches the fix commit gets the CVE tag."""
    state = _make_state(tmp_path)
    rels = _write_patches(state.meta_layer,
                          [("0001-prereq.patch", _PREREQ_PATCH),
                           ("0002-fix.patch", _FIX_PATCH)])
    with mock_patch("cve_corrector.patch_ops._git_commit_subject",
                    return_value="net: fix use-after-free in foo()"):
        flags = _compute_cve_tag_flags(state, rels)
    assert flags == [False, True]


def test_compute_flags_no_subject_match_falls_back_to_all(tmp_path):
    """If the fix subject matches no patch, fall back to tagging all so the
    fix never silently loses its CVE tag."""
    state = _make_state(tmp_path)
    rels = _write_patches(state.meta_layer,
                          [("0001.patch", _PREREQ_PATCH), ("0002.patch", _FIX_PATCH)])
    with mock_patch("cve_corrector.patch_ops._git_commit_subject",
                    return_value="totally different subject not in any patch"):
        flags = _compute_cve_tag_flags(state, rels)
    assert flags == [True, True]


def test_compute_flags_unknown_fix_subject_falls_back_to_all(tmp_path):
    """If the fix commit subject can't be resolved, tag all patches."""
    state = _make_state(tmp_path)
    rels = _write_patches(state.meta_layer,
                          [("0001.patch", _PREREQ_PATCH), ("0002.patch", _FIX_PATCH)])
    with mock_patch("cve_corrector.patch_ops._git_commit_subject",
                    return_value=None):
        flags = _compute_cve_tag_flags(state, rels)
    assert flags == [True, True]
