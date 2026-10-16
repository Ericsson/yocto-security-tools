# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for discover_cves_from_layers._deduce_recipe.

Regression coverage for a mis-deduction bug: patches living in a recipe's
own subdirectory (e.g. gstreamer1.0-plugins-good/) were resolved to the
*parent* directory's name (gstreamer) whenever that subdirectory held no
.bb of its own and the parent held every sibling recipe's .bb flatly
(gstreamer1.0_X.bb, gstreamer1.0-plugins-good_X.bb, ...). This fed a wrong
recipe name into cve_corrector's `devtool modify <recipe>`, which fails
with "Unable to find any recipe file matching" since "gstreamer" is not a
real recipe.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from discover_cves_from_layers import _deduce_recipe, discover  # noqa: E402


def test_deduce_recipe_subdir_shares_parent_bb_directory(tmp_path):
    """gstreamer1.0-plugins-good/<patch> must resolve to
    'gstreamer1.0-plugins-good', not the flat parent 'gstreamer'."""
    layer_root = tmp_path / "openembedded-core"
    recipe_dir = layer_root / "meta" / "recipes-multimedia" / "gstreamer"
    subdir = recipe_dir / "gstreamer1.0-plugins-good"
    subdir.mkdir(parents=True)
    (recipe_dir / "gstreamer1.0_1.22.12.bb").touch()
    (recipe_dir / "gstreamer1.0-plugins-good_1.22.12.bb").touch()
    (recipe_dir / "gstreamer1.0-plugins-base_1.22.12.bb").touch()
    patch = subdir / "0022-jpegdec-fix.patch"
    patch.touch()

    assert _deduce_recipe(patch, layer_root) == "gstreamer1.0-plugins-good"


def test_deduce_recipe_subdir_without_matching_bb_falls_back_to_ancestor(tmp_path):
    """A subdirectory that does NOT match any sibling .bb stem (e.g. a
    generic 'files' directory) still resolves to the ancestor holding the
    .bb, preserving the original behavior for the common case."""
    layer_root = tmp_path / "openembedded-core"
    recipe_dir = layer_root / "meta" / "recipes-core" / "dropbear"
    files_dir = recipe_dir / "files"
    files_dir.mkdir(parents=True)
    (recipe_dir / "dropbear_2022.83.bb").touch()
    patch = files_dir / "CVE-2024-1234.patch"
    patch.touch()

    assert _deduce_recipe(patch, layer_root) == "dropbear"


def test_deduce_recipe_patch_directly_in_recipe_dir(tmp_path):
    """A patch sitting directly alongside the .bb (no subdirectory at all)
    still resolves correctly."""
    layer_root = tmp_path / "openembedded-core"
    recipe_dir = layer_root / "meta" / "recipes-core" / "busybox"
    recipe_dir.mkdir(parents=True)
    (recipe_dir / "busybox_1.36.bb").touch()
    patch = recipe_dir / "CVE-2024-5678.patch"
    patch.touch()

    assert _deduce_recipe(patch, layer_root) == "busybox"


def test_deduce_recipe_no_bb_anywhere_returns_none(tmp_path):
    layer_root = tmp_path / "openembedded-core"
    recipe_dir = layer_root / "meta" / "recipes-core" / "orphan"
    recipe_dir.mkdir(parents=True)
    patch = recipe_dir / "CVE-2024-0000.patch"
    patch.touch()

    assert _deduce_recipe(patch, layer_root) is None


def test_deduce_recipe_lone_bb_with_different_stem_is_preferred(tmp_path):
    """Regression for CVE-2024-53849 (editorconfig-core-c): a directory
    named after the project, holding exactly one recipe file whose stem
    differs from the directory name, has no sibling to disambiguate
    against — the lone .bb's own stem is the real recipe name, not the
    directory name. Previously this returned 'editorconfig' (the
    directory), which devtool rejected with "Unable to find any recipe
    file matching 'editorconfig'" since the actual recipe is
    editorconfig-core-c_0.12.6.bb."""
    layer_root = tmp_path / "meta-openembedded"
    recipe_dir = layer_root / "meta-oe" / "recipes-devtools" / "editorconfig"
    files_dir = recipe_dir / "files"
    files_dir.mkdir(parents=True)
    (recipe_dir / "editorconfig-core-c_0.12.6.bb").touch()
    patch = files_dir / "CVE-2024-53849_1.patch"
    patch.touch()

    assert _deduce_recipe(patch, layer_root) == "editorconfig-core-c"


def test_deduce_recipe_lone_bb_matching_directory_name_unaffected(tmp_path):
    """When the lone .bb's stem already matches the directory name, behavior
    is unchanged (returns the directory/stem, same value either way)."""
    layer_root = tmp_path / "openembedded-core"
    recipe_dir = layer_root / "meta" / "recipes-core" / "busybox"
    files_dir = recipe_dir / "files"
    files_dir.mkdir(parents=True)
    (recipe_dir / "busybox_1.36.1.bb").touch()
    patch = files_dir / "CVE-2024-1234.patch"
    patch.touch()

    assert _deduce_recipe(patch, layer_root) == "busybox"


def _write_patch(path: Path, cve_id: str, upstream_sha: str | None,
                  from_header_sha: str, upstream_url: str | None = None) -> None:
    """Write a minimal OE-style patch file with a git format-patch header
    and, optionally, an Upstream-Status Backport trailer."""
    url = upstream_url or (
        f"https://gitlab.gnome.org/GNOME/example/-/commit/{upstream_sha}"
        if upstream_sha else None)
    upstream_line = f"Upstream-Status: Backport [{url}]\n" if url else ""
    path.write_text(
        f"From {from_header_sha} Mon Sep 17 00:00:00 2001\n"
        "From: Example Dev <dev@example.com>\n"
        "Date: Mon, 1 Jan 2024 00:00:00 +0000\n"
        "Subject: [PATCH] Fix something\n\n"
        f"CVE: {cve_id}\n"
        f"{upstream_line}"
        "Signed-off-by: Example Dev <dev@example.com>\n"
        "---\n"
        " file.c | 1 +\n"
        " 1 file changed, 1 insertion(+)\n"
    )


def test_discover_single_commit_header_hash_excluded_when_url_hash_present(tmp_path):
    """Regression for the CVE-2025-32051/CVE-2025-31181 GIT_ERROR bug:
    cve_corrector requires every hash listed in `hashes` to resolve
    upstream (workspace.py's canonical-fetch check treats the list as a
    set of mandatory commits, not independent fallbacks). A patch's
    `From <sha>` git-format-patch header is frequently a local/rebased
    commit that was never pushed upstream, so leaking it into `hashes`
    alongside a resolvable Upstream-Status hash made the whole CVE
    unresolvable even though the real fix commit was present and correct.
    The header hash must be dropped whenever a URL-derived hash exists."""
    layer_root = tmp_path / "openembedded-core"
    recipe_dir = layer_root / "meta" / "recipes-support" / "libsoup"
    recipe_dir.mkdir(parents=True)
    (recipe_dir / "libsoup_3.4.4.bb").touch()

    real_upstream_sha = "0713ba4a719da938dc8facc89fca99cd0aa3069f"
    bogus_header_sha = "dc5db30989f385303c79ec3188c52e33f6f5886e"
    patch = recipe_dir / "CVE-2025-32051-1.patch"
    _write_patch(patch, "CVE-2025-32051", real_upstream_sha, bogus_header_sha)

    result = discover([layer_root])

    entry = result["CVE-2025-32051"]
    assert entry["hashes"] == [real_upstream_sha]
    assert bogus_header_sha not in entry["hashes"]


def test_discover_header_hash_used_only_when_no_url_hash_found(tmp_path):
    """Last-resort behavior is preserved: when a patch has no parsable
    Upstream-Status Backport trailer at all, the From-header hash is the
    only candidate and must still be returned."""
    layer_root = tmp_path / "openembedded-core"
    recipe_dir = layer_root / "meta" / "recipes-core" / "example"
    recipe_dir.mkdir(parents=True)
    (recipe_dir / "example_1.0.bb").touch()

    header_sha = "2d9e68278aece7e971815d9c3ec297c5e9bc51bd"
    patch = recipe_dir / "CVE-2024-9999.patch"
    _write_patch(patch, "CVE-2024-9999", upstream_sha=None,
                 from_header_sha=header_sha)

    result = discover([layer_root])

    entry = result["CVE-2024-9999"]
    assert entry["hashes"] == [header_sha]


def test_discover_chain_still_excludes_header_hash_duplicating_chain_member(tmp_path):
    """Existing chain behavior (len(url_based) > 1) is unaffected: a
    header hash that duplicates a chain member is excluded from `hashes`
    (it would re-apply a chain commit as a standalone alternative), while
    a header hash that is NOT part of the chain remains a last-resort
    standalone candidate, as the code already documents."""
    layer_root = tmp_path / "openembedded-core"
    recipe_dir = layer_root / "meta" / "recipes-support" / "libsoup"
    recipe_dir.mkdir(parents=True)
    (recipe_dir / "libsoup_3.4.4.bb").touch()

    sha1 = "0713ba4a719da938dc8facc89fca99cd0aa3069f"
    sha2 = "79cfd65c9bd8024cd45dd725c284766329873709"
    # bogus1 duplicates sha1 itself (simulating a header SHA that is
    # identical to one of the chain's own Upstream-Status commits) and
    # must be excluded; a header hash with no relation to the chain is
    # kept as a last-resort candidate.
    patch1 = recipe_dir / "CVE-2025-32051-1.patch"
    patch2 = recipe_dir / "CVE-2025-32051-2.patch"
    _write_patch(patch1, "CVE-2025-32051", sha1, from_header_sha=sha1)
    _write_patch(patch2, "CVE-2025-32051", sha2, from_header_sha=sha2)

    result = discover([layer_root])

    entry = result["CVE-2025-32051"]
    assert entry["series"] == [{
        "pull_url": "oe_patch:CVE-2025-32051-1.patch",
        "commits": [sha1, sha2],
    }]
    assert entry["hashes"] == []
