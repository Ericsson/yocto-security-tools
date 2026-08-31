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

## plot_benchmark_results.py

Plots a `cve-agent` model benchmark run — the `agent_results.csv` /
`judge_results.csv` pair written by `tests/benchmark/run_benchmark.sh` (see
`tests/benchmark/README.md` for the CSV schemas). Generates 6 PNG charts:

| File | Shows |
|------|-------|
| `outcome_by_model.png` | Stacked run outcomes per model, with each model's reference-equivalent rate called out |
| `bucket_by_model.png` | The raw `diff_bucket` distribution per model — the textual-distance signal *before* the judge reclassifies a large-but-equivalent diff as a success. Read against `outcome_by_model.png` to see how much of a model's apparent divergence is cosmetic |
| `cost_by_model.png` | Total credits, average credits per run, and credits per *usable* backport (total credits divided by reference-equivalent results) |
| `quality_vs_cost.png` | Average credits per run vs. reference-equivalent rate, one point per model — the price/accuracy tradeoff |
| `effort_by_model.png` | Average wall-clock duration and average tool-call count. A high call count next to a low equivalent rate is thrashing, not thoroughness |
| `outcome_matrix.png` | Per-CVE × per-model outcome grid. A weak *column* is a weak model; a uniformly bad *row* is a CVE (or a reference patch) that defeats every model, which is a property of the roster rather than a model result |

The central metric is the **outcome collapse** in `classify_outcome`: neither
CSV column answers "did the model do the job?" on its own. `diff_bucket`
measures how far the generated patch drifted textually from the human
reference backport, and the judge verdict says whether that drift is
behavioral. So a `major` diff judged `stylistic` counts as **equivalent**,
while a `partial` diff judged `meaningful` does not. Each run collapses to
exactly one of: `equivalent`, `divergent` (judged `meaningful`), `unjudged`,
`no-patch` (exit 0 but the corrector bailed before producing a patch), or
`failed` (non-zero exit or `TIMEOUT`).

A model with zero equivalent backports has an *undefined* credits-per-usable
ratio, not an infinite one; that bar is drawn full-width in the failure color
and labeled, so "cheap but useless" cannot be misread as "cheap".

Charts use the Okabe-Ito palette (distinguishable under the common forms of
color blindness) and every bar and cell is annotated with its value or a
glyph, so no chart depends on hue alone being read correctly.

### Usage

Requires `matplotlib`, which is intentionally **not** a runtime dependency of
this project. Install it in your virtualenv first:

```bash
pip install matplotlib==3.10.1
python3 tools/plot_benchmark_results.py \
    tests/benchmark/test-results/bench_20260828_145923
```

PNGs are written into the results directory by default; use `--output-dir` to
send them elsewhere. The script also prints the same figures as a text table
(plus a per-CVE equivalent rate across models) to stdout, so a run can be
quoted into a report without opening the images.

The pure data layer (`classify_outcome`, `aggregate`, `rank_models`,
`build_matrix`) is covered by `tests/tools/test_plot_benchmark_results.py`.
Those tests do not import matplotlib — the plotting functions import it
lazily for exactly that reason — so they run in CI without adding a
dependency.
