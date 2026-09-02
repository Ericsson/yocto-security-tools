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


def _series_covers_chain(entry: dict, chain: list[str]) -> bool:
    """Check whether ``entry`` already records ``chain`` as one ordered series.

    ``hashes`` cannot satisfy this no matter what they contain: cve-corrector
    treats them as *alternatives* and stops at the first that applies, so a
    dependent chain listed there still yields a partial fix.

    Args:
        entry: The metadata entry, read for its existing ``series``.
        chain: Ordered upstream SHAs, as OE-Core applies them.

    Returns:
        True when some existing series covers every commit in ``chain``.
    """
    for series in entry.get('series') or []:
        recorded = list(series.get('commits') or [])
        if all(_covers(recorded, h) for h in chain):
            return True
    return False


def missing_upstream_hashes(cve_id: str, entry: dict,
                            meta_dir: Path) -> list[dict]:
    """Ground-truth hashes for ``cve_id`` that ``entry`` does not already have.

    Only ``Upstream-Status: Backport [<url>]`` hashes are considered. A
    maintainer wrote those deliberately to name the upstream commit, which
    makes them the one authoritative source available offline — unlike tracker
    data, which can name a release commit, a commit from a different fork, or
    even the commit that *introduced* the flaw.

    Commits already recorded in a ``series`` count as present: they are being
    applied as part of a chain, and re-adding them to ``hashes`` would offer
    each one to the corrector as a standalone alternative.

    Args:
        cve_id: CVE identifier.
        entry: The metadata entry, read for its existing ``hashes``/``series``.
        meta_dir: Root of an OE meta layer to search recursively.

    Returns:
        Hash dicts absent from ``entry``, in patch order. Empty when the entry
        already covers them or the CVE has no patch in this layer.
    """
    recorded = list(entry.get('hashes') or [])
    for series in entry.get('series') or []:
        recorded.extend(series.get('commits') or [])
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
        # The entry has hashes, but they may not include the commit the
        # maintainer actually backported -- so they can be wrong guesses. This
        # is not hypothetical: u-boot's CVE-2025-24857 carried only a 2017
        # release bump, and wpa-supplicant's CVE-2024-3596 carried 28 commits
        # from FreeRADIUS, a different project entirely.
        #
        # The chain is every Upstream-Status commit OE-Core ships for this CVE,
        # in the order OE applies it. That -- not the subset the entry happens
        # to be missing -- is what decides series vs hashes: when OE ships
        # `-pre1` plus the fix, the two are a dependent pair even if the entry
        # already lists one of them. Keying off the missing subset instead
        # recorded setuptools' CVE-2025-47273 as three *alternatives*; the
        # prerequisite refactor and the real fix then each failed to apply
        # alone, and the least-conflict fallback shipped the refactor as the
        # security fix.
        chain_details = find_hashes_from_upstream_status(cve_id, meta_dir)
        chain = [h['hash'] for h in chain_details]
        missing = missing_upstream_hashes(cve_id, entry, meta_dir)
        is_chain = len(chain) > 1
        needs_series = is_chain and not _series_covers_chain(entry, chain)
        # A chain commit must not also sit in `hashes`. For a metadata-driven
        # series the corrector leaves require_all_commits False, so a failed
        # series falls back to apply_single_commits over `hashes` -- which would
        # offer exactly the partial fix the chain exists to prevent
        # (CVE-2025-1153's first commit is partly reverted by its third). This
        # is checked even when the series is already correct, to clean up
        # entries an earlier run left leaking.
        leaked = [h for h in (entry.get('hashes') or []) if _covers(chain, h)] \
            if is_chain else []
        if not missing and not needs_series and not leaked:
            continue
        if is_chain:
            if needs_series:
                entry['series'] = [{
                    'pull_url': f"oe_patch:{chain_details[0]['patch']}",
                    'commits': chain,
                }] + list(entry.get('series') or [])
            if leaked:
                entry['hashes'] = [h for h in entry['hashes']
                                   if not _covers(chain, h)]
            if missing:
                entry['hash_details'] = missing + list(entry.get('hash_details') or [])
            corrected += 1
            what = (f"added {len(chain)}-commit SERIES" if needs_series
                    else f"de-duplicated {len(leaked)} chain commit(s) from hashes")
            print(f"  {cve_id}: {what} from Upstream-Status "
                  f"({', '.join(h[:12] for h in chain)})")
        else:
            commits = [h['hash'] for h in missing]
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
