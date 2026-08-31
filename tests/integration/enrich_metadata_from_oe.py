#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Recover upstream fix commits from the CVE patches already in OE-Core.

Fallback for CVEs that ``cve-metadata-extractor`` cannot resolve from the
public trackers (Debian/OSV/CVEList/NVD/UCT). A recipe that already carries a
backported fix records the upstream commit in its patch file, in two places of
very different quality:

1. The URL in ``Upstream-Status: Backport [<url>]``. A maintainer wrote this
   deliberately to name the upstream commit, so it is cherry-pickable.
2. The ``From <sha> Mon Sep 17 00:00:00 2001`` header that ``git format-patch``
   writes. This is only as good as the tree the patch was generated from — it is
   frequently a local or rebased commit that does not exist upstream, so
   cherry-picking it fails. Measured on the 15 CVEs added for the balanced
   roster: leading with header SHAs turned 5 clean runs into 5 conflicts,
   whereas the URL form applied cleanly. It is therefore a **last resort**,
   used only when nothing else yields a hash.

:func:`find_hashes_from_oe` returns URL-derived hashes first for that reason.
Callers that already have tracker-derived hashes should keep those first and
treat these as additional candidates.

Updates a cve-metadata JSON file in place for CVEs that have no hashes.
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from shared.url_parser import extract_commit_hash  # noqa: E402

UPSTREAM_RE = re.compile(
    r'Upstream-Status:\s*Backport\s*\[([^\]]+)\]', re.IGNORECASE)
# git format-patch's first line: "From <40-hex> Mon Sep 17 00:00:00 2001".
# Anchored to line start so a "From: <author>" line can never match.
FROM_HEADER_RE = re.compile(r'^From ([0-9a-f]{7,40}) ', re.MULTILINE)


def _cve_patches(cve_id: str, meta_dir: Path) -> list[Path]:
    """Patch files in the meta layer whose name mentions ``cve_id``."""
    return sorted(meta_dir.rglob(f"*{cve_id}*.patch"))


def find_hashes_from_patch_headers(cve_id: str, meta_dir: Path) -> list[dict]:
    """Extract upstream SHAs from the ``From <sha>`` header of OE patches.

    Args:
        cve_id: CVE identifier, used to match patch filenames.
        meta_dir: Root of an OE meta layer to search recursively.

    Returns:
        One dict per distinct SHA, in file order, tagged
        ``source='oe_patch_header'``.
    """
    results: list[dict] = []
    seen: set[str] = set()
    for patch in _cve_patches(cve_id, meta_dir):
        text = patch.read_text(encoding="utf-8", errors="ignore")
        for sha in FROM_HEADER_RE.findall(text):
            if sha not in seen:
                seen.add(sha)
                results.append({'hash': sha, 'url': None,
                                'source': 'oe_patch_header',
                                'patch': patch.name})
    return results


def find_hashes_from_upstream_status(cve_id: str, meta_dir: Path) -> list[dict]:
    """Extract upstream SHAs from ``Upstream-Status: Backport [<url>]``.

    Args:
        cve_id: CVE identifier, used to match patch filenames.
        meta_dir: Root of an OE meta layer to search recursively.

    Returns:
        One dict per distinct SHA, tagged ``source='oe_patch'``.
    """
    results: list[dict] = []
    seen: set[str] = set()
    for patch in _cve_patches(cve_id, meta_dir):
        text = patch.read_text(encoding="utf-8", errors="ignore")
        for m in UPSTREAM_RE.finditer(text):
            url = m.group(1)
            h = extract_commit_hash(url)
            if h and h not in seen:
                seen.add(h)
                results.append({'hash': h, 'url': url, 'source': 'oe_patch',
                                'patch': patch.name})
    return results


def find_hashes_from_oe(cve_id: str, meta_dir: Path) -> list[dict]:
    """Collect upstream SHAs for ``cve_id`` from OE-Core's own patches.

    ``Upstream-Status: Backport [<url>]`` hashes come first because they are
    cherry-pickable; ``From``-header SHAs follow as a last resort (see module
    docstring for the measurement behind that ordering).

    Args:
        cve_id: CVE identifier, used to match patch filenames.
        meta_dir: Root of an OE meta layer to search recursively.

    Returns:
        Deduplicated hash dicts, most reliable first. Empty if the CVE has no
        patch in this layer.
    """
    url_based = find_hashes_from_upstream_status(cve_id, meta_dir)
    seen = {h['hash'] for h in url_based}
    extra = [h for h in find_hashes_from_patch_headers(cve_id, meta_dir)
             # A short From-header sha and a full URL sha can be the same
             # commit; treat a prefix match as already covered.
             if not any(h['hash'].startswith(s) or s.startswith(h['hash'])
                        for s in seen)]
    return url_based + extra


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <cve-metadata.json> <oe-meta-dir>")
        sys.exit(1)

    metadata_path = Path(sys.argv[1])
    meta_dir = Path(sys.argv[2])

    with open(metadata_path) as f:
        data = json.load(f)

    updated = 0
    for cve_id, entry in sorted(data.items()):
        if entry.get('hashes'):
            continue
        found = find_hashes_from_oe(cve_id, meta_dir)
        if found:
            entry['hashes'] = [h['hash'] for h in found]
            entry['hash_details'] = found
            updated += 1
            sources = ', '.join(sorted({h['source'] for h in found}))
            print(f"  {cve_id}: {len(found)} hash(es) from OE patches "
                  f"({sources})")

    if updated:
        with open(metadata_path, 'w') as f:
            json.dump(data, f, indent=2)
            f.write('\n')
        print(f"\nUpdated {updated} CVEs in {metadata_path}")
    else:
        print("No new hashes found.")


if __name__ == '__main__':
    main()
