# Copyright (C) 2026 Triet Hoang <triet.hoang.dev@gmail.com>
# SPDX-License-Identifier: MIT
"""Tests for shared format-patch metadata and parsing helpers."""
import pytest

from shared.patch import (
    annotate_patch_text,
    cherry_picked_sha,
    extract_patch_subject,
    git_commit_subject,
    modify_patch,
    normalize_subject,
)

PATCH = """\
From abc123 Mon Sep 17 00:00:00 2001
Subject: [PATCH] net: fix issue

Fix description.
---
 file.c | 1 +
diff --git a/file.c b/file.c
"""


def test_annotate_patch_text_adds_fix_metadata_and_is_idempotent():
    annotated = annotate_patch_text(PATCH, "CVE-2025-0001", "https://example/commit/abc")

    assert "CVE: CVE-2025-0001\n" in annotated
    assert "Upstream-Status: Backport [https://example/commit/abc]\n" in annotated
    assert annotate_patch_text(annotated, "CVE-2025-0001", "unused") == annotated
    assert annotated.endswith(PATCH[PATCH.index("---\n"):])


def test_annotate_patch_text_leaves_prerequisite_without_cve_tag():
    annotated = annotate_patch_text(
        PATCH, "CVE-2025-0001", "https://example/commit/abc", include_cve_tag=False)

    assert "CVE: CVE-2025-0001" not in annotated
    assert "Upstream-Status: Backport [https://example/commit/abc]" in annotated


def test_annotate_patch_text_ignores_metadata_like_diff_content():
    patch = PATCH + "CVE: CVE-2025-0001\nUpstream-Status: unrelated\n"

    annotated = annotate_patch_text(patch, "CVE-2025-0001", "https://example/commit/abc")

    assert annotated.count("CVE: CVE-2025-0001") == 2
    assert "Upstream-Status: Backport [https://example/commit/abc]" in annotated


def test_modify_patch_adds_requested_signoff_to_existing_metadata(tmp_path):
    patch_file = tmp_path / "fix.patch"
    patch_file.write_text(annotate_patch_text(PATCH, "CVE-2025-0001", "upstream"))

    modify_patch(
        patch_file, "CVE-2025-0001", "upstream",
        sign_off_identity=("Test Author", "test@example.invalid"))

    content = patch_file.read_text()
    assert content.count("CVE: CVE-2025-0001") == 1
    assert content.count("Upstream-Status:") == 1
    assert "Signed-off-by: Test Author <test@example.invalid>" in content


def test_patch_subject_and_commit_helpers():
    folded = PATCH.replace(
        "Subject: [PATCH] net: fix issue\n",
        "Subject: [PATCH v2] net: fix\n issue\n")

    assert extract_patch_subject(folded) == "net: fix issue"
    assert normalize_subject("Net:  Fix   ISSUE") == "net: fix issue"
    assert cherry_picked_sha("(cherry picked from commit deadbeef1234567)") == "deadbeef1234567"
    assert cherry_picked_sha(PATCH) is None


def test_git_commit_subject_missing_workspace_returns_none(tmp_path):
    assert git_commit_subject(tmp_path / "missing", "abc123") is None


def test_annotate_patch_text_requires_separator():
    with pytest.raises(ValueError, match="No line containing '---'"):
        annotate_patch_text("Subject: no separator\n", "CVE-2025-0001", "upstream")
