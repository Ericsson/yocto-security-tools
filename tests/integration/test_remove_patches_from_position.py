# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for test_utils.remove_patches_from_position.

Regression coverage for a one-patch-per-statement scoping bug: recipes that
declare each patch on its own self-closing ``SRC_URI += "file://..."`` line
(e.g. glib-networking) reset the "found target" tracking at the end of that
statement, so a later patch declared on the *next* SRC_URI line -- one that
assumed the removed patch was already applied -- was never recognized as
"subsequent" and was left behind. The orphaned patch then fails to apply on
its own (reproduced against glib-networking's CVE-2025-60018.patch /
CVE-2025-60019.patch, which both touch gtlscertificate-openssl.c and only
apply in that order), breaking `devtool modify` before the CVE workflow
under test even starts.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_utils import remove_patches_from_position  # noqa: E402


def test_subsequent_patch_on_separate_src_uri_statement_is_removed(tmp_path):
    """A dependent patch declared on its own later SRC_URI += line must be
    treated as "subsequent" to the removed patch, not left behind."""
    recipe = tmp_path / "recipe.bb"
    recipe.write_text(
        'SUMMARY = "test recipe"\n'
        'SRC_URI += "file://run-ptest"\n'
        'SRC_URI += "file://eagain.patch"\n'
        'SRC_URI += "file://CVE-2025-60018.patch"\n'
        'SRC_URI += "file://CVE-2025-60019.patch"\n'
    )

    removed = remove_patches_from_position(str(recipe), "CVE-2025-60018.patch")

    assert removed == ["CVE-2025-60018.patch", "CVE-2025-60019.patch"]
    content = recipe.read_text()
    assert "CVE-2025-60018.patch" not in content
    assert "CVE-2025-60019.patch" not in content
    assert "eagain.patch" in content, "earlier, unrelated patch must survive"


def test_multiline_src_uri_block_unaffected(tmp_path):
    """Baseline: a single multi-line SRC_URI block still removes the target
    and everything after it within that block, exactly as before."""
    recipe = tmp_path / "recipe.bb"
    recipe.write_text(
        'SUMMARY = "test recipe"\n'
        'SRC_URI = "file://a.patch \\\n'
        '           file://CVE-2024-1111.patch \\\n'
        '           file://CVE-2024-2222.patch \\\n'
        '           file://z.patch"\n'
    )

    removed = remove_patches_from_position(str(recipe), "CVE-2024-1111.patch")

    assert removed == ["CVE-2024-1111.patch", "CVE-2024-2222.patch", "z.patch"]
    content = recipe.read_text()
    assert "a.patch" in content
    assert "CVE-2024-1111.patch" not in content
    assert "CVE-2024-2222.patch" not in content


def test_no_subsequent_patches_returns_only_target(tmp_path):
    """A target patch with nothing declared after it removes just itself."""
    recipe = tmp_path / "recipe.bb"
    recipe.write_text(
        'SUMMARY = "test recipe"\n'
        'SRC_URI += "file://eagain.patch"\n'
        'SRC_URI += "file://CVE-2025-60018.patch"\n'
    )

    removed = remove_patches_from_position(str(recipe), "CVE-2025-60018.patch")

    assert removed == ["CVE-2025-60018.patch"]
    assert "eagain.patch" in recipe.read_text()
