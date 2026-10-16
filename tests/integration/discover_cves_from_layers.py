# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Discover CVEs directly from the patches already carried by OE layers.

Scans one or more OE meta layers (e.g. openembedded-core, meta-openembedded)
for ``*.patch`` files naming a CVE — either in the filename or via a ``CVE:``
body tag — and builds a fresh ``cve-metadata.json`` from what each patch's own
``Upstream-Status: Backport [<url>]`` trailer says, the same ground-truth
source ``enrich_metadata_from_oe.py`` uses for an existing roster's entries.
Unlike that script, this one *discovers* the CVE ID/recipe pairing itself
instead of requiring the caller to already know it, so it can build a roster
far larger than any one tracker-derived input file — entirely offline, no
tracker network calls.

A CVE commonly has more than one patch file across both layers (sequential
numbered patches for one recipe, or the same CVE fixed independently in two
different recipes/layers). Patches naming the same CVE on the DIFFERENT
recipes are kept as separate entries (``<cve-id>`` for the first recipe seen,
``<cve-id>+<recipe>`` for each additional one) rather than merged, since they
are unrelated fixes that happen to share a CVE ID.

Usage:
    python3 discover_cves_from_layers.py <output.json> <layer_dir> [<layer_dir> ...]
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from shared.url_parser import extract_commit_hash  # noqa: E402

CVE_FILENAME_RE = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
CVE_TAG_RE = re.compile(r'^CVE:\s*(CVE-\d{4}-\d+)', re.IGNORECASE | re.MULTILINE)
UPSTREAM_RE = re.compile(
    r'Upstream-Status:\s*Backport\s*\[([^\]]+)\]', re.IGNORECASE)
FROM_HEADER_RE = re.compile(r'^From ([0-9a-f]{7,40}) ', re.MULTILINE)

# Patch files live at .../recipes-<category>/<recipe>/[<recipe-subdir>/]files/<patch>
# or directly under .../recipes-<category>/<recipe>/. The recipe name is the
# directory two or three levels above the patch, whichever actually holds a
# matching .bb/.inc/.bbappend file.
_RECIPE_GLOB_SUFFIXES = ('.bb', '.inc', '.bbappend')


def _cve_ids_in_patch(path: Path) -> set[str]:
    """CVE IDs this patch names, via filename or ``CVE:`` body tag."""
    ids = {m.group(0).upper() for m in CVE_FILENAME_RE.finditer(path.name)}
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return ids
    ids.update(m.group(1).upper() for m in CVE_TAG_RE.finditer(text))
    return ids


def _deduce_recipe(path: Path, layer_root: Path) -> str | None:
    """Walk up from a patch file to the directory holding its recipe file.

    A patch's immediate parent directory is usually the real recipe name
    (e.g. ``gstreamer1.0-plugins-good/0022-....patch``), but that directory
    often has no ``.bb`` of its own — all the sibling recipes in a package
    group (gstreamer1.0, gstreamer1.0-plugins-good, -base, -bad, ...) share
    one flat parent directory (``gstreamer/``) holding every ``.bb``. Walking
    straight up to that ancestor and returning *its* name (``gstreamer``,
    not a real recipe) silently mis-deduces the recipe for every patch
    living in one of those subdirectories.

    So: before climbing past a subdirectory with no ``.bb``, check whether
    its own name matches the stem (version suffix stripped) of a ``.bb`` one
    level up. If so, that subdirectory name *is* the real recipe name.

    A second, narrower mismatch: a directory named after the project/package
    (not a package group) that holds exactly one recipe file whose own stem
    differs from the directory name — e.g.
    ``editorconfig/files/CVE-2024-53849_1.patch`` sits under
    ``editorconfig/editorconfig-core-c_0.12.6.bb``. There is no sibling
    recipe to disambiguate against here, so the lone ``.bb``'s own stem
    (``editorconfig-core-c``) is the real recipe name, not the directory
    name (``editorconfig``) — returning the latter fed ``devtool modify
    editorconfig`` a name with no matching recipe at all ("Unable to find
    any recipe file matching"). This only applies when exactly one recipe
    file is present; a directory sharing several sibling recipes' ``.bb``
    files keeps returning its own name, as above.
    """
    child_name = path.parent.name
    for ancestor in path.parents:
        try:
            ancestor.relative_to(layer_root)
        except ValueError:
            break
        for suffix in _RECIPE_GLOB_SUFFIXES:
            recipe_files = list(ancestor.glob(f'*{suffix}'))
            if not recipe_files:
                continue
            if child_name != ancestor.name:
                stems = {re.sub(r'_[^_]*$', '', f.stem) for f in recipe_files}
                if child_name in stems:
                    return child_name
            if len(recipe_files) == 1:
                lone_stem = re.sub(r'_[^_]*$', '', recipe_files[0].stem)
                if lone_stem != ancestor.name:
                    return lone_stem
            return ancestor.name
        if ancestor == layer_root:
            break
    return None


def _extract_hashes(path: Path) -> list[dict]:
    """Upstream-Status hashes first, From-header hashes as last resort."""
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except OSError:
        return []
    results = []
    seen = set()
    for m in UPSTREAM_RE.finditer(text):
        url = m.group(1)
        h = extract_commit_hash(url)
        if h and h not in seen:
            seen.add(h)
            results.append({'hash': h, 'url': url, 'source': 'oe_patch',
                            'patch': path.name})
    for h in FROM_HEADER_RE.findall(text):
        if h not in seen:
            seen.add(h)
            results.append({'hash': h, 'url': None,
                            'source': 'oe_patch_header', 'patch': path.name})
    return results


def discover(layer_dirs: list[Path]) -> dict:
    """Scan ``layer_dirs`` and build a cve-metadata dict.

    Returns:
        Dict keyed by CVE ID (or ``<cve-id>+<recipe>`` for a second distinct
        recipe under the same CVE ID), each value matching the schema
        cve_corrector/cve_agent read: name, version, hashes, hash_details,
        patches, patch_details, series, references.
    """
    # cve_id -> recipe -> list[Path] (patches for that recipe, patch order)
    by_cve: dict[str, dict[str, list[Path]]] = {}

    for layer_dir in layer_dirs:
        layer_dir = layer_dir.resolve()
        for patch in sorted(layer_dir.rglob('*.patch')):
            cve_ids = _cve_ids_in_patch(patch)
            if not cve_ids:
                continue
            recipe = _deduce_recipe(patch, layer_dir) or patch.parent.name
            for cve_id in cve_ids:
                by_cve.setdefault(cve_id, {}).setdefault(recipe, []).append(patch)

    result: dict[str, dict] = {}
    for cve_id, by_recipe in sorted(by_cve.items()):
        for index, (recipe, patches) in enumerate(sorted(by_recipe.items())):
            key = cve_id if index == 0 else f"{cve_id}+{recipe}"
            all_hashes: list[dict] = []
            for patch in patches:
                all_hashes.extend(_extract_hashes(patch))

            url_based = [h for h in all_hashes if h['source'] == 'oe_patch']
            header_based = [h for h in all_hashes if h['source'] == 'oe_patch_header']

            def _dedup(hash_dicts: list[dict]) -> list[dict]:
                seen_local: set[str] = set()
                out = []
                for h in hash_dicts:
                    if h['hash'] not in seen_local:
                        seen_local.add(h['hash'])
                        out.append(h)
                return out

            url_based = _dedup(url_based)
            # A chain commit must not also sit in plain `hashes`: cve_corrector
            # treats `hashes` entries as independent alternatives and stops at
            # the first that applies, so leaking a chain member in there would
            # let a partial fix apply on its own — the exact failure mode
            # enrich_metadata_from_oe.py's module docstring documents for
            # CVE-2025-1153. Build a single ordered list instead: every
            # Upstream-Status hash first (most reliable, in patch order),
            # then any From-header hash not already covered by one of them.
            is_chain = len(url_based) > 1
            if is_chain:
                chain_hashes = {h['hash'] for h in url_based}
                header_based = [h for h in header_based
                                if h['hash'] not in chain_hashes]
            else:
                # Non-chain case: cve_corrector requires every hash in
                # `hashes` to resolve (see workspace.py's canonical-fetch
                # check), it does not try them as independent fallbacks.
                # A From-header SHA is frequently a local/rebased commit
                # that never existed upstream (module docstring in
                # enrich_metadata_from_oe.py), so pairing it with a
                # resolvable Upstream-Status hash in the same list makes
                # that CVE fail outright even though the real fix is right
                # there. Only fall back to header hashes when no
                # Upstream-Status hash was found at all.
                if url_based:
                    header_based = []
            dedup_hashes = _dedup(url_based + header_based)

            entry: dict = {
                'name': recipe.lower(),
                'version': None,
                'cvss3_score': None,
                'hashes': [h['hash'] for h in dedup_hashes],
                'hash_details': dedup_hashes,
                'patches': [h['url'] for h in url_based if h['url']],
                'patch_details': [{'url': h['url'], 'source': 'oe_patch'}
                                  for h in url_based if h['url']],
                'references': [],
                'series': [],
                'discovered_from': sorted({str(p) for p in patches}),
            }
            if is_chain:
                # The chain's own commits are recorded in `series`, not
                # `hashes` — see the comment above. Header-only hashes (never
                # part of the chain) remain in `hashes` as last-resort
                # standalone candidates.
                entry['series'] = [{
                    'pull_url': f"oe_patch:{patches[0].name}",
                    'commits': [h['hash'] for h in url_based],
                }]
                entry['hashes'] = [h['hash'] for h in header_based]
                entry['hash_details'] = url_based + header_based
            result[key] = entry

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('output', type=Path, help='Output cve-metadata JSON path')
    parser.add_argument('layer_dirs', type=Path, nargs='+',
                        help='One or more OE meta layer roots to scan')
    args = parser.parse_args()

    for layer_dir in args.layer_dirs:
        if not layer_dir.is_dir():
            parser.error(f"not a directory: {layer_dir}")

    data = discover(args.layer_dirs)

    with_hashes = sum(1 for e in data.values() if e['hashes'])
    with_series = sum(1 for e in data.values() if e['series'])
    print(f"Discovered {len(data)} CVE entries from "
          f"{', '.join(str(d) for d in args.layer_dirs)}")
    print(f"  With at least one upstream hash: {with_hashes}")
    print(f"  Multi-commit series: {with_series}")
    print(f"  No hash found (header-only or unparsed Upstream-Status): "
          f"{len(data) - with_hashes}")

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write('\n')
    print(f"Wrote {args.output}")


if __name__ == '__main__':
    main()
