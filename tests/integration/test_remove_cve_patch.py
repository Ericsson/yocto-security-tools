# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for test_utils.remove_cve_patch.

Regression coverage for a scoping bug: remove_cve_patch only searched
oe_dir's meta/** tree, so any CVE whose patch lives in a sibling
meta-openembedded layer (meta-oe, meta-networking, meta-python,
meta-filesystems -- each its own layer root, not nested under a shared
meta/ like openembedded-core) was unconditionally reported NOTFOUND, even
though the patch and recipe both existed and the CVE metadata was correct.
This caused the full-roster test run to classify every meta-openembedded
CVE as METADATA_ERROR/SKIP.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_utils import remove_cve_patch  # noqa: E402


def _write_recipe(path: Path, patch_filename: str):
    path.write_text(
        'SUMMARY = "test recipe"\n'
        'LICENSE = "MIT"\n'
        f'SRC_URI = "file://{patch_filename}"\n'
    )


def test_remove_cve_patch_finds_patch_in_extra_root(tmp_path, capsys):
    """A CVE patch living only under a meta-openembedded-style extra root
    (not nested under oe_dir/meta/) must be found and removed, not
    reported NOTFOUND."""
    oe_dir = tmp_path / "openembedded-core"
    (oe_dir / "meta" / "recipes-core").mkdir(parents=True)

    meta_oe = tmp_path / "meta-openembedded" / "meta-oe"
    recipe_dir = meta_oe / "recipes-extended" / "indent" / "indent"
    recipe_dir.mkdir(parents=True)
    patch = recipe_dir / "CVE-2024-0911.patch"
    patch.write_text("Upstream-Status: Backport\nCVE: CVE-2024-0911\n")
    recipe_bb = meta_oe / "recipes-extended" / "indent" / "indent_2.2.13.bb"
    _write_recipe(recipe_bb, "CVE-2024-0911.patch")

    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    remove_cve_patch(str(oe_dir), "CVE-2024-0911", str(log_dir),
                      extra_roots=[str(meta_oe)])
    out = capsys.readouterr().out

    assert "NOTFOUND" not in out
    assert "PATCH:" in out
    assert not patch.exists(), "patch should have been removed"
    assert "CVE-2024-0911.patch" not in recipe_bb.read_text()


def test_remove_cve_patch_without_extra_roots_still_notfound(tmp_path, capsys):
    """Without extra_roots, a patch outside oe_dir is still correctly
    reported NOTFOUND -- confirms the fix is additive, not a silent
    behavior change for callers that don't pass extra_roots."""
    oe_dir = tmp_path / "openembedded-core"
    (oe_dir / "meta" / "recipes-core").mkdir(parents=True)

    meta_oe = tmp_path / "meta-openembedded" / "meta-oe"
    recipe_dir = meta_oe / "recipes-extended" / "indent" / "indent"
    recipe_dir.mkdir(parents=True)
    patch = recipe_dir / "CVE-2024-0911.patch"
    patch.write_text("Upstream-Status: Backport\nCVE: CVE-2024-0911\n")

    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    remove_cve_patch(str(oe_dir), "CVE-2024-0911", str(log_dir))
    out = capsys.readouterr().out

    assert "NOTFOUND" in out
    assert patch.exists(), "patch outside oe_dir must not be touched"


def test_remove_cve_patch_still_finds_patch_in_oe_dir(tmp_path, capsys):
    """Baseline: a patch under oe_dir/meta/ (the original, only-supported
    case) still works exactly as before."""
    oe_dir = tmp_path / "openembedded-core"
    recipe_dir = oe_dir / "meta" / "recipes-core" / "busybox"
    recipe_dir.mkdir(parents=True)
    patch = recipe_dir / "CVE-2024-5678.patch"
    patch.write_text("Upstream-Status: Backport\nCVE: CVE-2024-5678\n")
    recipe_bb = recipe_dir / "busybox_1.36.bb"
    _write_recipe(recipe_bb, "CVE-2024-5678.patch")

    log_dir = tmp_path / "logs"
    log_dir.mkdir()

    remove_cve_patch(str(oe_dir), "CVE-2024-5678", str(log_dir))
    out = capsys.readouterr().out

    assert "NOTFOUND" not in out
    assert not patch.exists()


def _two_recipe_tree(tmp_path: Path):
    """libsoup / libsoup-2.4 layout: one dir, both patched for one CVE."""
    oe_dir = tmp_path / "openembedded-core"
    recipes = oe_dir / "meta" / "recipes-support" / "libsoup"
    patches = {}
    bbs = {}
    for pn, subdir, version in (("libsoup", "libsoup-3.4.4", "3.4.4"),
                                ("libsoup-2.4", "libsoup-2.4", "2.74.3")):
        (recipes / subdir).mkdir(parents=True)
        patches[pn] = recipes / subdir / "CVE-2025-4945.patch"
        patches[pn].write_text("Upstream-Status: Backport\nCVE: CVE-2025-4945\n")
        bbs[pn] = recipes / f"{pn}_{version}.bb"
        _write_recipe(bbs[pn], "CVE-2025-4945.patch")
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    return oe_dir, log_dir, patches, bbs


def test_compound_roster_key_removes_only_its_recipe(tmp_path, capsys):
    """A ``<cve-id>+<recipe>`` key must find the real CVE's patch.

    The full key was used as the search string, so every second recipe
    patched for a CVE (25 roster entries) was reported NOTFOUND and skipped.
    """
    oe_dir, log_dir, patches, bbs = _two_recipe_tree(tmp_path)

    remove_cve_patch(str(oe_dir), "CVE-2025-4945+libsoup-2.4", str(log_dir),
                     prefix="full",
                     only_patches=[str(patches["libsoup-2.4"])])
    out = capsys.readouterr().out

    assert "NOTFOUND" not in out
    assert not patches["libsoup-2.4"].exists()
    assert "CVE-2025-4945.patch" not in bbs["libsoup-2.4"].read_text()
    # The other recipe's patch and SRC_URI entry are untouched.
    assert patches["libsoup"].exists()
    assert "CVE-2025-4945.patch" in bbs["libsoup"].read_text()
    # The reference copy is saved under the roster key the harness iterates on.
    assert (log_dir / "full_CVE-2025-4945+libsoup-2.4_CVE-2025-4945.patch").exists()


def test_plain_key_still_removes_every_recipe(tmp_path, capsys):
    """Plain keys keep the historical all-recipes removal."""
    oe_dir, log_dir, patches, bbs = _two_recipe_tree(tmp_path)

    remove_cve_patch(str(oe_dir), "CVE-2025-4945", str(log_dir))
    capsys.readouterr()

    assert not any(path.exists() for path in patches.values())
    assert all("CVE-2025-4945.patch" not in bb.read_text() for bb in bbs.values())


def test_roster_entry_scope_and_entry_metadata(tmp_path):
    import json

    from test_utils import roster_entry_scope, write_entry_metadata

    metadata = tmp_path / "meta.json"
    entry = {"name": "krb5", "discovered_from": ["/l/krb5/CVE-2024-3596.patch"]}
    metadata.write_text(json.dumps({"CVE-2024-3596": {"name": "hostapd"},
                                    "CVE-2024-3596+krb5": entry}))

    assert roster_entry_scope(str(metadata), "CVE-2024-3596") == (None, None)
    assert roster_entry_scope(str(metadata), "CVE-2024-3596+krb5") == (
        "krb5", ["/l/krb5/CVE-2024-3596.patch"])

    out = tmp_path / "entry.json"
    write_entry_metadata(str(metadata), "CVE-2024-3596+krb5", str(out))
    assert json.loads(out.read_text()) == {"CVE-2024-3596": entry}
