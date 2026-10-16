# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Filter a discovered cve-metadata JSON down to entries whose patch(es) live
in a layer currently enabled in bblayers.conf.

Reads each entry's ``discovered_from`` paths (written by
discover_cves_from_layers.py) and keeps only entries where every one of those
paths falls under an allowed layer root.

Usage:
    python3 filter_metadata_by_layers.py <input.json> <output.json> <layer_root> [<layer_root> ...]
"""
import json
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) < 4:
        print(f"Usage: {sys.argv[0]} <input.json> <output.json> "
              "<layer_root> [<layer_root> ...]", file=sys.stderr)
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])
    layer_roots = [Path(p).resolve() for p in sys.argv[3:]]

    with open(input_path) as f:
        data = json.load(f)

    kept = {}
    dropped = 0
    for cve_id, entry in data.items():
        paths = entry.get('discovered_from') or []
        if not paths:
            dropped += 1
            continue
        in_scope = all(
            any(Path(p).resolve().is_relative_to(root) for root in layer_roots)
            for p in paths
        )
        if in_scope:
            kept[cve_id] = entry
        else:
            dropped += 1

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(kept, f, indent=2, sort_keys=True)
        f.write('\n')

    print(f"Kept {len(kept)} entries (patches under allowed layers)")
    print(f"Dropped {dropped} entries (patches outside allowed layers)")
    print(f"Wrote {output_path}")


if __name__ == '__main__':
    main()
