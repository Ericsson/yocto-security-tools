#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Extract commit hashes from OE-Core patches with Upstream-Status: Backport.

Updates tests/integration/cve-metadata.json for CVEs that have no hashes
but have patches in the OE meta layer.
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from shared.url_parser import extract_commit_hash  # noqa: E402

UPSTREAM_RE = re.compile(
    r'Upstream-Status:\s*Backport\s*\[([^\]]+)\]', re.IGNORECASE)


def find_hashes_from_oe(cve_id: str, meta_dir: Path) -> list[dict]:
    """Search meta layer for patches matching a CVE and extract hashes."""
    results = []
    for patch in meta_dir.rglob(f"*{cve_id}*.patch"):
        text = patch.read_text(encoding="utf-8", errors="ignore")
        for m in UPSTREAM_RE.finditer(text):
            url = m.group(1)
            h = extract_commit_hash(url)
            if h:
                results.append({'hash': h, 'url': url, 'source': 'oe_patch'})
    return results


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
            print(f"  {cve_id}: {len(found)} hash(es) from OE patches")

    if updated:
        with open(metadata_path, 'w') as f:
            json.dump(data, f, indent=2)
            f.write('\n')
        print(f"\nUpdated {updated} CVEs in {metadata_path}")
    else:
        print("No new hashes found.")


if __name__ == '__main__':
    main()
