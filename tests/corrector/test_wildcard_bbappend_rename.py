# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the wildcard-bbappend rename guard used by the --bbappend flow.

Regression coverage for: --bbappend created a new version-pinned bbappend
even when a matching wildcard (``recipe_%.bbappend``) already existed,
hijacking/narrowing a bbappend that was meant to apply to every recipe
version.
"""
from cve_corrector.workflow import (
    _existing_wildcard_bbappends,
    _rename_new_wildcard_bbappends,
)


def test_pre_existing_wildcard_bbappend_is_not_renamed(tmp_path):
    """A wildcard bbappend that already existed before this run must be
    left as-is — devtool merges new content into it in place, and it may
    carry content (e.g. an earlier CVE fix) meant for every version.
    """
    recipe_dir = tmp_path / "recipes-test" / "foo"
    recipe_dir.mkdir(parents=True)
    wildcard = recipe_dir / "foo_%.bbappend"
    wildcard.write_text(
        'FILESEXTRAPATHS:prepend := "${THISDIR}/${PN}:"\n'
        'SRC_URI += "file://CVE-2025-0001.patch"\n'
    )

    pre_existing = _existing_wildcard_bbappends(tmp_path, "foo")
    assert wildcard in pre_existing

    # Simulate devtool merging new content into the same wildcard file
    # (it does not create a new file when one already matches).
    wildcard.write_text(
        wildcard.read_text() + 'SRC_URI += "file://CVE-2026-99999.patch"\n')

    _rename_new_wildcard_bbappends(tmp_path, "foo", "1.2.3", pre_existing)

    assert wildcard.exists(), "pre-existing wildcard bbappend must not be renamed"
    assert not (recipe_dir / "foo_1.2.3.bbappend").exists()
    assert "CVE-2025-0001.patch" in wildcard.read_text()
    assert "CVE-2026-99999.patch" in wildcard.read_text()


def test_newly_created_wildcard_bbappend_is_renamed(tmp_path):
    """A wildcard bbappend that did NOT exist before this run (i.e. one
    devtool just created) is renamed to a version-pinned name, preserving
    existing --bbappend behavior for the first CVE fix on a recipe.
    """
    recipe_dir = tmp_path / "recipes-test" / "foo"
    recipe_dir.mkdir(parents=True)

    pre_existing = _existing_wildcard_bbappends(tmp_path, "foo")
    assert pre_existing == set()

    # Simulate devtool creating a brand new wildcard bbappend.
    new_wildcard = recipe_dir / "foo_%.bbappend"
    new_wildcard.write_text('SRC_URI += "file://CVE-2026-99999.patch"\n')

    _rename_new_wildcard_bbappends(tmp_path, "foo", "1.2.3", pre_existing)

    assert not new_wildcard.exists()
    versioned = recipe_dir / "foo_1.2.3.bbappend"
    assert versioned.exists()
    assert "CVE-2026-99999.patch" in versioned.read_text()


def test_no_rename_without_version(tmp_path):
    """No renaming happens when state.version is unset."""
    recipe_dir = tmp_path / "recipes-test" / "foo"
    recipe_dir.mkdir(parents=True)
    wildcard = recipe_dir / "foo_%.bbappend"
    wildcard.write_text('SRC_URI += "file://CVE-2026-99999.patch"\n')

    _rename_new_wildcard_bbappends(tmp_path, "foo", None, set())

    assert wildcard.exists()


def test_no_rename_without_meta_layer():
    """No error and no-op when meta_layer is None."""
    assert _existing_wildcard_bbappends(None, "foo") == set()
    _rename_new_wildcard_bbappends(None, "foo", "1.2.3", set())
