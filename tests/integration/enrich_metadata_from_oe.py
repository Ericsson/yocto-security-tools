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

Updates a cve-metadata JSON file in place. By default only CVEs with no
hashes are filled in; ``--correct-existing`` additionally repairs CVEs whose
recorded hashes do not include the commit OE-Core actually backported, which
is the only way to catch a tracker naming a release commit, a fork's commit,
or the commit that introduced the flaw.
"""
import argparse
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


def _covers(recorded: list[str], candidate: str) -> bool:
    """Check whether ``candidate`` is already represented in ``recorded``.

    A short From-header sha and a full URL sha can name the same commit, so a
    prefix match either way counts as covered.
    """
    cand = candidate.lower()
    return any(cand.startswith(r.lower()) or r.lower().startswith(cand)
               for r in recorded if r)


def missing_upstream_hashes(cve_id: str, entry: dict,
                            meta_dir: Path) -> list[dict]:
    """Ground-truth hashes for ``cve_id`` that ``entry`` does not already have.

    Only ``Upstream-Status: Backport [<url>]`` hashes are considered. A
    maintainer wrote those deliberately to name the upstream commit, which
    makes them the one authoritative source available offline — unlike tracker
    data, which can name a release commit, a commit from a different fork, or
    even the commit that *introduced* the flaw.

    Args:
        cve_id: CVE identifier.
        entry: The metadata entry, read for its existing ``hashes``.
        meta_dir: Root of an OE meta layer to search recursively.

    Returns:
        Hash dicts absent from ``entry['hashes']``, in patch order. Empty when
        the entry already covers them or the CVE has no patch in this layer.
    """
    recorded = entry.get('hashes') or []
    return [h for h in find_hashes_from_upstream_status(cve_id, meta_dir)
            if not _covers(recorded, h['hash'])]


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('metadata', type=Path, help='cve-metadata JSON to update in place')
    parser.add_argument('meta_dir', type=Path, help='OE meta layer to search')
    parser.add_argument(
        '--correct-existing', action='store_true',
        help="Also fix CVEs that already have hashes but are missing the "
             "commit OE-Core's own Upstream-Status names. The ground-truth "
             "hash is prepended, so cve-corrector tries it first, and the "
             "tracker hashes are kept as fallbacks.")
    args = parser.parse_args()

    metadata_path, meta_dir = args.metadata, args.meta_dir

    with open(metadata_path) as f:
        data = json.load(f)

    updated = corrected = 0
    for cve_id, entry in sorted(data.items()):
        if not entry.get('hashes'):
            found = find_hashes_from_oe(cve_id, meta_dir)
            if found:
                url_based = [h for h in found if h['source'] == 'oe_patch']
                entry['hash_details'] = found
                # Same reasoning as the correction path below: several
                # Upstream-Status patches are an ordered chain, not a set of
                # alternatives. Header-only SHAs are excluded from the series --
                # they are frequently local/rebased commits that do not exist
                # upstream (see module docstring), so they belong in `hashes`
                # as last-resort candidates rather than in a chain that must
                # apply in full.
                if len(url_based) > 1:
                    entry['series'] = [{
                        'pull_url': f"oe_patch:{url_based[0]['patch']}",
                        'commits': [h['hash'] for h in url_based],
                    }]
                    entry['hashes'] = [h['hash'] for h in found]
                    kind = f"{len(url_based)}-commit series"
                else:
                    entry['hashes'] = [h['hash'] for h in found]
                    kind = f"{len(found)} hash(es)"
                updated += 1
                sources = ', '.join(sorted({h['source'] for h in found}))
                print(f"  {cve_id}: {kind} from OE patches ({sources})")
            continue

        if not args.correct_existing:
            continue
        # The entry has hashes, but none of them is the commit the maintainer
        # actually backported -- so every one of them is a wrong guess. This is
        # not hypothetical: u-boot's CVE-2025-24857 carried only a 2017 release
        # bump, and wpa-supplicant's CVE-2024-3596 carried 28 commits from
        # FreeRADIUS, a different project entirely.
        missing = missing_upstream_hashes(cve_id, entry, meta_dir)
        if not missing:
            continue
        commits = [h['hash'] for h in missing]
        if len(commits) > 1:
            # More than one patch means an ordered, dependent chain, and it
            # must be recorded as a series: cve-corrector treats `hashes` as
            # *alternatives* and stops at the first that applies, which for a
            # chain leaves a partial fix. binutils' CVE-2025-1153 is the clear
            # case -- three patches where the third reverts part of the first,
            # so applying only the first is worse than applying none.
            #
            # Order comes from the patch filenames, which is how OE itself
            # applies them (binutils: 0019-CVE-2025-1153-1.patch ..
            # 0021-CVE-2025-1153-3.patch, listed in that order in SRC_URI).
            entry['series'] = [{
                'pull_url': f"oe_patch:{missing[0]['patch']}",
                'commits': commits,
            }] + list(entry.get('series') or [])
            entry['hash_details'] = missing + list(entry.get('hash_details') or [])
            corrected += 1
            print(f"  {cve_id}: added {len(commits)}-commit SERIES from "
                  f"Upstream-Status ({', '.join(h[:12] for h in commits)})")
        else:
            entry['hashes'] = commits + list(entry['hashes'])
            entry['hash_details'] = missing + list(entry.get('hash_details') or [])
            corrected += 1
            print(f"  {cve_id}: prepended ground-truth hash "
                  f"{commits[0][:12]} from Upstream-Status")

    if updated or corrected:
        with open(metadata_path, 'w') as f:
            json.dump(data, f, indent=2)
            f.write('\n')
        print(f"\nFilled {updated} CVEs with no hashes; "
              f"corrected {corrected} with wrong ones, in {metadata_path}")
    else:
        print("No new hashes found.")


if __name__ == '__main__':
    main()
