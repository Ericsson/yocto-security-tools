<!-- SPDX-License-Identifier: MIT -->
# tools/

Standalone, dev-only scripts for ad-hoc analysis. Nothing here is part of the
installed `yocto-security-tools` package or its runtime dependencies — see
`AGENTS.md` ("Minimize Dependencies") for why `requests`/`packaging` are the
only runtime deps.

## plot_source_distribution.py

Analyzes the source distribution and complementarity of a `cve-metadata.json`
file produced by `cve-metadata-extractor` (optionally enriched with
additional closed sources not part of the extractor's own registry).
Generates 7 PNG charts:

| File | Shows |
|------|-------|
| `coverage_by_source.png` | How many CVEs each source contributed data for, split into CVEs with an actual fix-commit hash vs. CVEs with only patch/reference data |
| `coverage_by_source_upstream_only.png` | Same as above, but restricted to public upstream sources only. Any source name not registered by `cve_metadata_extractor`'s own `SOURCE_REGISTRY` is excluded from the underlying data *before* plotting, not just hidden — the generated PNG contains no trace of it |
| `upstream_vs_combined_gain.png` | How much closed enrichment sources improve coverage *on top of* upstream alone — CVEs with any data, CVEs with a fix-commit hash, and distinct fix-commit hashes, each compared upstream-only vs. upstream+closed. Sets are unioned across sources so overlapping contributions aren't double-counted, giving a real "how much do we gain" answer rather than a sum of individual sources' unique contributions |
| `volume_by_source.png` | Raw hash/patch entry volume contributed per source |
| `overlap_cve_level.png` | Pairwise Jaccard overlap — did both sources say *something* about the same CVE |
| `overlap_hash_level.png` | Pairwise Jaccard overlap — did both sources point to the *identical* fix commit |
| `unique_contribution.png` | Fix-commit hashes found by only one source, exactly one other source (with that source named), or 3+ sources — shows what's lost if a source is dropped, and which other source it most overlaps with |

Any source name found in the input file that is not registered by
`cve_metadata_extractor`'s own `SOURCE_REGISTRY` (see `UPSTREAM_SOURCES` in
the script) is treated as closed enrichment data and visually
distinguished (orange color) from public upstream sources in every chart,
with a caption note. The script never hardcodes the name of any specific
closed source — whatever source names actually appear in the input
`cve-metadata.json` are read and labeled as-is; the internal/upstream
distinction is derived entirely from `cve_metadata_extractor`'s actual
registered sources, not from a fixed list of vendor names.

`UPSTREAM_SOURCES` in the script is derived directly from
`cve_metadata_extractor`'s actual `SOURCE_REGISTRY` (debian.py, osv.py,
ubuntu.py, uct.py, cvelistv5.py) — not from a manually maintained list — so
the upstream-only chart stays correct if a new source module is ever added
to the extractor.

`nvd` is merged into `cvelistv5` before any metric is computed: NVD mirrors
CVEListV5 data, and the two show 100% CVE-level and hash-level overlap in
practice. Keeping them as separate rows/bars would double-count the same
underlying data and hide that the combined pair still contributes a small
amount (~6% of its hashes in a sample run) that no other source reports.
See `MERGED_SOURCES` in the script to add/adjust merges.

### Usage

Requires `matplotlib`, which is intentionally **not** a runtime dependency of
this project. Install it in your virtualenv first:

```bash
pip install matplotlib==3.10.1
python3 tools/plot_source_distribution.py cve-metadata.json --output-dir plots/
```

The script also prints a text summary (CVE coverage, hash/patch counts per
source) to stdout before generating the charts.
