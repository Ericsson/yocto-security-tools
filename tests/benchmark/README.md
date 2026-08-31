<!-- SPDX-License-Identifier: MIT -->
# CVE Agent Model Benchmark

Runs `cve-agent` across a fixed roster of CVEs and a selection of models,
then (optionally) an AI judge pass on the diffs that came out
moderately/majorly different from the human reference backport, or that
partially overlap it (judged on the shared files only). Produces
`agent_results.csv`, `judge_results.csv`, and (via
`generate_benchmark_report.py`) a markdown summary.

## Prerequisites

- A Yocto build environment (OE-Core checkout + `oe-init-build-env` sourced)
- Git mirror directory with upstream repos (for offline cherry-pick)
- `pip install -e .` (this project installed)
- `kiro-cli` on `PATH`, authenticated

**This benchmark depends on and sources `tests/integration/test_common.sh`**
directly, reusing its `reset_oe_tree`, `setup_cve_branch`, `run_cve_corrector`,
and `compare_patches_detailed` functions rather than reimplementing them.
That means it inherits `test_common.sh`'s environment-variable requirements
below, and any change to that script's function signatures affects this
benchmark too.

## Required Environment Variables

```bash
export OE_DIR=/path/to/openembedded-core    # OE-Core git checkout
export BUILD_DIR=/path/to/build             # Yocto build directory
export MIRROR_DIR=/path/to/upstream-git     # Git mirrors of upstream repos
```

Optional (see `tests/integration/test_common.sh`):
```bash
export BUILDTOOLS_ENV=/path/to/environment-setup-x86_64-pokysdk-linux
```

## Running

Three committed rosters ship, none regenerated, so every run tests the exact
same CVEs regardless of environment or when it's run:

| `--roster` | File | CVEs | Composition |
|---|---|---|---|
| `default` | `benchmark-roster.json` | 7 | 1 medium, 6 hard |
| `balanced` | `benchmark-roster-balanced.json` | 20 | 6 easy, 6 medium, 8 hard |
| `extended` | `benchmark-roster-extended.json` | 40 | 6 easy, 10 medium, 24 hard |

They are **nested** — `default` ⊂ `balanced` ⊂ `extended`, with shared entries
carrying identical recorded stats — so results from any of them stay directly
comparable, including with previous `default` runs. Cost rises with size
(roughly 2.9x and 5.7x the default), which is why the larger two are opt-in;
see [Run cost by roster](#run-cost-by-roster) before starting one.

`balanced` is the one to reach for when the default roster is too narrow to
draw conclusions from but a 40-CVE run is too expensive: it is the only roster
with an even tier split, so it measures conflict resolution and clean-apply
regressions in comparable proportion.

See [Roster files](#roster-files) below for what is in each and how to change them.

```bash
# Runs the default model set through cve-agent against the default (7-CVE)
# roster, then judges.
./run_benchmark.sh

# The same, against the 20-CVE balanced roster (~2.9x the cost) or the 40-CVE
# extended one (~5.7x):
./run_benchmark.sh --roster balanced
./run_benchmark.sh --roster extended

# Preview the plan (row counts, cost-weight) without touching git/OE state
# or invoking cve-agent/the judge:
./run_benchmark.sh --dry-run
./run_benchmark.sh --roster balanced --dry-run

# Re-verify a roster's cached stats against the current OE-Core state
# (re-probes with cve-corrector, no AI cost). Does NOT add, remove, or
# reorder roster CVEs -- only refreshes their recorded exit_code/diff_lines/
# conflict_markers/tier in the selected roster file:
./run_benchmark.sh --retier
./run_benchmark.sh --roster extended --retier

# A specific model selection:
./run_benchmark.sh --models claude-opus-5,claude-sonnet-4.8

# List the roster CVEs as numbered cases (in run order), then run only some
# of them -- handy to avoid an expensive recipe (e.g. skip glib/binutils), to
# re-run a single case, or to work through a larger roster in affordable
# slices instead of committing to a full run:
./run_benchmark.sh --list-cases
./run_benchmark.sh --run-case 3                          # just case 3
./run_benchmark.sh --run-case 1 2 3                      # the first three cases
./run_benchmark.sh --roster balanced --run-case 13 14 15

# Skip the judge phase entirely (no prompt, no cost, nothing runs):
./run_benchmark.sh --skip-judge

# Resume an interrupted run (reuses its agent_results.csv/judge_results.csv):
./run_benchmark.sh --resume test-results/bench_20260814_120000
```

## Flags

| Flag | Effect |
|------|--------|
| `--roster <default\|balanced\|extended\|path>` | Which committed roster to run (default: `default`, 7 CVEs; `balanced` is 20, `extended` is 40, and they nest). A path selects an arbitrary roster JSON. The chosen roster is logged at startup so a run's provenance is recorded. |
| `--retier` | Re-probes the selected roster's CVEs with cve-corrector (no AI cost) and updates their recorded stats/tier in that roster file in place. Never changes which CVEs are in the roster. Preserves the author-supplied `recipe` and `series_len`. |
| `--models <default\|full\|comma-list>` | Model selection for phase 1 (default: `default`) |
| `--list-cases` | List the roster CVEs as numbered cases (in run order: easy→medium→hard, alphabetical within a tier) and exit, without running anything. |
| `--run-case <N...>` | Run only the given 1-based case number(s) from `--list-cases` (space-separated, e.g. `--run-case 1 2 3`). Scopes the agent run, the cost estimate, and `--retier`; the judge phase follows whatever was run. |
| `--dry-run` | Print the planned run (rows, cost-weight) without invoking cve-agent, without running the judge, and without prompting for confirmation |
| `--skip-judge` | Phase 2 (the judge pass) does not run at all |
| `--resume <dir>` | Reuse an existing `test-results/bench_*` directory and its CSVs, skipping any `(cve_id, model)` pair already present |

`--full` was removed along with dynamic per-tier candidate selection — each
roster is a fixed set of CVEs, so there is no "per tier count" left to inflate.
Use `--roster extended` to run more CVEs. Passing `--full` now fails with an
explanation instead of silently doing something unexpected.

## `--no-knowledge` is automatic

`run_benchmark.sh` always passes `--no-knowledge` to every `cve-agent`
invocation. You do not need to (and should not) pass it yourself — the
benchmark measures each model's unaided backporting performance, so
knowledge-base lookups and saves are disabled for every run it makes.

## Cost visibility

Before phase 1 (and phase 2, which shares the same confirmation — there is
only one y/N prompt for the whole run, skipped entirely under `--dry-run`),
the script prints:

- **Relative cost weight** — `sum(model multipliers) * planned CVE count`
  across the selected models and all three tiers. This is a **relative**
  figure for comparing model selections against each other before a run —
  **not a prediction of actual credits that will be spent**.
- **Projected remaining cost** (resume only, when `agent_results.csv`
  already has rows) — `observed average credits per run so far * remaining
  runs`. This is a projection **based on data already observed in this
  run**, not a credit prediction either.

## CSV Schemas

### Per-model artifact files

Because the roster runs every CVE against multiple models, the patch-comparison
artifacts are keyed by **both** CVE and model so one model's run never
overwrites another's:

- `<cve>_<model>_differences.txt` — the human-readable comparison report
- `<cve>_<model>_differences_diff.patch` — the per-file unified diff the judge reads
- `generated_<cve>_<model>_<file>.patch` — the patch(es) the model generated, archived before the OE tree is reset

(`compare_patches_detailed` writes the first two per-CVE; the benchmark renames
them per-model right after reading the bucket/diff_lines.)

### `agent_results.csv`

```
cve_id,tier,model,exit_status,credits,duration_s,commands,diff_bucket,diff_lines
```

- `exit_status` — `0` for a clean cve-agent run, `TIMEOUT`, or the raw exit code
- `credits` — parsed from cve-agent's kiro-cli output (`cve_agent.metrics.parse_kiro_credits`); empty if unavailable
- `duration_s` — wall-clock seconds measured by the script
- `commands` — tool-call count from the captured log (`bench_lib.count_tool_calls`)
- `diff_bucket` — `identical` / `minor` / `moderate` / `major` / `partial` / `file-mismatch`, same line thresholds as `tests/integration/generate_differences_report.py`. `partial` means the generated and reference patch sets overlap but aren't identical filesets (some files shared, some missing/extra); the judge then evaluates only the shared files (`bench_lib.scope_diff_to_common_files`). `file-mismatch` is reserved for fully disjoint filesets, which stay unjudged.
- `diff_lines` — changed-line count from `compare_patches_detailed`. For a `partial` row this is scoped to the shared files only (counted over `bench_lib.scope_diff_to_common_files`), matching what the judge evaluates; for all other buckets it is the whole-patch divergence.

### `judge_results.csv`

```
cve_id,model,judgment,reason,judge_credits,scope
```

- `judgment` — `meaningful` or `stylistic`, from the fixed judge model (`claude-opus-4.8`, deliberately not part of the benchmarked roster); or one of two verdicts recorded without a judge call: `structural-only` for a `partial` overlap whose shared files were identical, and `comment-only` when every remaining changed line was a comment (see the report note)
- `reason` — the judge's own one-or-two-sentence justification, flattened to a single line and capped at `bench_lib.JUDGE_REASON_MAX_CHARS`. Free-form prose, so rows are written with `csv.writer` and must be read with a CSV parser rather than `cut -d,`
- `judge_credits` — credits spent on that one judge call; empty if unavailable (and always empty for `structural-only` and `comment-only`, which make no call)
- `scope` — `full` when the verdict covers the whole patch (moderate/major rows), or `partial` when it covers only the shared files of a partial overlap

Comment-only changes are stripped from the diff before it reaches the judge
(`bench_lib.strip_comment_only_changes`): a reworded, added, or dropped comment
is not a behavioral difference. The comment syntax is picked per file from the
diff headers — `//` and `/* … */` for C-like sources, `#` for shell/Python/make
— and block-comment state is tracked per diff side so C pointer code such as
`*p++ = *s++;` is never mistaken for a comment continuation. Note that
`diff_lines` and `diff_bucket` in `agent_results.csv` still count comment lines;
only the judge ignores them.

### Roster files

```json
{
  "CVE-2024-XXXXX": {
    "tier": "easy",
    "recipe": "busybox",
    "exit_code": 0,
    "diff_lines": 3,
    "series_len": 1,
    "conflict_markers": 0
  }
}
```

Three roster files are committed, all in this schema and all selected with
`--roster`:

- `tests/benchmark/benchmark-roster.json` — the default, 7 CVEs.
- `tests/benchmark/benchmark-roster-balanced.json` — 20 CVEs, even tier split.
- `tests/benchmark/benchmark-roster-extended.json` — 40 CVEs, the full pool.

They nest: `default` ⊂ `balanced` ⊂ `extended`. Each is the entire, fixed
candidate pool for a run. Every benchmark run reads exactly the CVEs in the
selected file; there is no regenerable cache or candidate probing involved in
normal use.

Every entry's `tier`/`exit_code`/`diff_lines`/`series_len`/`conflict_markers`
is real measured data, not an estimate: captured from a live `cve-corrector`
probe against openembedded-core (scarthgap), plus the historical bulk run in
`tests/integration/test-results/bulk_20260626_081658/`. Refresh with
`--retier`, which re-probes without any AI cost and writes back to whichever
roster `--roster` selected. Note that `--retier` rewrites the file with
`json.dump(sort_keys=True)`, so the entries come back alphabetized regardless
of how they were ordered before.

`conflict_markers` (count of git's `CONFLICT (content):` marker from the
probe log; `0` for a clean or non-content-conflict failure, e.g. a merge
commit the corrector's cherry-pick strategy can't handle) is a rough
difficulty signal used when a roster is assembled, to spread the `hard`
entries across the real complexity range instead of picking several CVEs that
all happen to be similarly easy or all similarly brutal.

`tests/benchmark/test_benchmark_roster.py` validates **all three** files:
schema completeness, tier agreement with `score_tier`, zero markers on clean
entries, the nesting chain, and that shared entries carry identical stats in
every file that contains them.

#### Default roster (7 CVEs)

The cheap, established roster — 1 medium, 6 hard — used by
`bench_20260828_145923` and every earlier run. Keep it for quick model
comparisons and for continuity with historical results.

| CVE | Tier | Recipe | `conflict_markers` | Why |
|---|---|---|---|---|
| `CVE-2026-0990` | medium | libxml2 | – | Clean, 3-commit dependent series |
| `CVE-2024-6345` | hard | python3-setuptools | 2 | Structural failure (merge commit, not a content conflict) — low end |
| `CVE-2024-32487` | hard | less | 2 | Single-file genuine conflict — low-mid |
| `CVE-2025-47183` | hard | gstreamer1.0-plugins-good | 1 | Moderate conflict |
| `CVE-2025-47203` | hard | dropbear | 7 | Moderate-high conflict |
| `CVE-2026-26158` | hard | busybox | 3 | 2-commit dependent series (shared fix with CVE-2026-26157) + genuine conflict, plus a post-apply ptest failure — cheap to rebuild |
| `CVE-2025-1153` | hard | binutils | 45 | Sprawling, multi-file conflict — high end |

#### Balanced roster (20 CVEs)

6 `easy`, 6 `medium`, 8 `hard` across 20 distinct recipes — no recipe repeats.
A superset of the default roster and a subset of the extended one, so it slots
into the same comparison. This is the roster to use when the default 7 are too
few to conclude anything from (a one-run swing there is 14 percentage points)
but 40 CVEs is more budget than the question deserves.

The even split is the point: the `hard` entries measure conflict resolution,
while the 6 `easy` entries measure that a model does not *break* a cherry-pick
that already applies cleanly — a regression the default roster cannot detect at
all, since it contains no easy entries.

| Tier | CVE | Recipe | `conflict_markers` |
|---|---|---|---|
| easy | `CVE-2024-24856` | acpica | – |
| easy | `CVE-2024-5569` | python3-zipp | – |
| easy | `CVE-2024-8006` | libpcap | – |
| easy | `CVE-2025-11687` | gi-docgen | – |
| easy | `CVE-2025-46805` | screen | – |
| easy | `CVE-2025-46836` | net-tools | – |
| medium | `CVE-2024-37535` | vte | – |
| medium | `CVE-2024-47615` | gstreamer1.0-plugins-base | – |
| medium | `CVE-2025-32051` | libsoup | – |
| medium | `CVE-2025-68121` | go-runtime | – |
| medium | `CVE-2026-0990` | libxml2 | – |
| medium | `CVE-2026-23865` | freetype | – |
| hard | `CVE-2026-27135` | nghttp2 | 0 |
| hard | `CVE-2025-47183` | gstreamer1.0-plugins-good | 1 |
| hard | `CVE-2024-32487` | less | 2 |
| hard | `CVE-2024-6345` | python3-setuptools | 2 |
| hard | `CVE-2026-26158` | busybox | 3 |
| hard | `CVE-2025-47203` | dropbear | 7 |
| hard | `CVE-2026-39881` | vim-tiny | 20 |
| hard | `CVE-2025-1153` | binutils | 45 |

Composition notes:

- The 8 `hard` entries are the default roster's 6 plus two picked to fill gaps
  the default set leaves: `CVE-2026-27135` is a 0-marker *structural* failure
  (a distinct failure mode from a content clash), and `CVE-2026-39881` fills
  the empty 8–40 marker band. Markers now run 0, 1, 2, 2, 3, 7, 20, 45.
- 5 of the 6 `medium` entries are dependent commit series (`series_len` 2–3);
  `CVE-2025-68121` is the exception, medium because of a 129-line diff, so the
  tier is not testing only one mechanism.
- The 6 `easy` entries are every easy entry the extended roster contains.

#### Extended roster (40 CVEs)

24 `hard`, 10 `medium`, 6 `easy` across 35 distinct recipes, and a superset of
the default roster. Composition, and the reasoning behind it:

- **24 hard** (`exit_code != 0`, so `cve-agent` actually invokes the AI).
  This is the only tier where models differentiate: in
  `bench_20260828_145923` every failed run and every `meaningful` judge
  verdict landed on a hard entry. They are spread deliberately across the
  real conflict-complexity range — `conflict_markers` of
  0, 0, 0, 0, 3, 3, 3, 3, 3, 4, 5, 6, 7, 9, 10, 10, 12, 20, 21, 29, 34, 38,
  39, 52 — so the roster is not several CVEs that all happen to be similarly
  easy or all similarly brutal. The four 0-marker entries are *structural*
  failures (e.g. a merge commit the cherry-pick strategy cannot handle),
  which is a genuinely different failure mode from a content clash.
- **10 medium** — every medium candidate the source data contained. This is
  the scarcest tier because it needs a clean apply that is still non-trivial:
  9 of the 10 are dependent commit series (`series_len` 2–3) and one is a
  129-line single-commit diff.
- **6 easy** — a control group. They measure that a model does not *break* a
  cherry-pick that already applies cleanly, which no hard entry can test.

| Tier | CVE | Recipe | `conflict_markers` |
|---|---|---|---|
| easy | `CVE-2024-24856` | acpica | – |
| easy | `CVE-2024-5569` | python3-zipp | – |
| easy | `CVE-2024-8006` | libpcap | – |
| easy | `CVE-2025-11687` | gi-docgen | – |
| easy | `CVE-2025-46805` | screen | – |
| easy | `CVE-2025-46836` | net-tools | – |
| medium | `CVE-2024-12087` | rsync | – |
| medium | `CVE-2024-37535` | vte | – |
| medium | `CVE-2024-47615` | gstreamer1.0-plugins-base | – |
| medium | `CVE-2025-3887` | gstreamer1.0-plugins-bad | – |
| medium | `CVE-2025-32051` | libsoup | – |
| medium | `CVE-2025-65018` | libpng | – |
| medium | `CVE-2025-68121` | go-runtime | – |
| medium | `CVE-2025-9301` | cmake | – |
| medium | `CVE-2026-0990` | libxml2 | – |
| medium | `CVE-2026-23865` | freetype | – |
| hard | `CVE-2024-6345` | python3-setuptools | 0 |
| hard | `CVE-2025-24857` | u-boot-tools | 0 |
| hard | `CVE-2025-6052` | glib-2.0 | 0 |
| hard | `CVE-2026-27135` | nghttp2 | 0 |
| hard | `CVE-2024-32487` | less | 3 |
| hard | `CVE-2024-39689` | python3-certifi | 3 |
| hard | `CVE-2024-52532` | libsoup-2.4 | 3 |
| hard | `CVE-2024-7537` | ofono | 3 |
| hard | `CVE-2026-26158` | busybox | 3 |
| hard | `CVE-2026-24049` | python3-wheel | 4 |
| hard | `CVE-2026-21441` | python3-urllib3 | 5 |
| hard | `CVE-2025-47183` | gstreamer1.0-plugins-good | 6 |
| hard | `CVE-2025-50181` | python3-urllib3 | 7 |
| hard | `CVE-2026-25068` | alsa-lib | 9 |
| hard | `CVE-2025-47273` | python3-setuptools | 10 |
| hard | `CVE-2026-27459` | python3-pyopenssl | 10 |
| hard | `CVE-2025-47203` | dropbear | 12 |
| hard | `CVE-2026-39881` | vim-tiny | 20 |
| hard | `CVE-2025-4674` | go-runtime | 21 |
| hard | `CVE-2026-26007` | python3-cryptography | 29 |
| hard | `CVE-2025-1176` | binutils | 34 |
| hard | `CVE-2025-64505` | libpng | 38 |
| hard | `CVE-2024-6387` | openssh | 39 |
| hard | `CVE-2025-1153` | binutils | 52 |

(`conflict_markers` is meaningless for a clean run, so `--retier` records it
as `0` for every `easy`/`medium` entry; shown as `–` above.)

**Selection rules.** Candidates were mined from the historical bulk run in
`tests/integration/test-results/bulk_20260626_081658/` (289 CVEs, 235 of them
non-skipped), and every field is measured from that run's logs rather than
estimated. A candidate had to pass all of:

1. **Mirror resolves** — the probe log contains `Found mirror:`. Directory-name
   guessing against `$MIRROR_DIR` is unreliable, since mirror names don't
   always match recipe names (`gst-plugins-good`, not
   `gstreamer1.0-plugins-good`).
2. **Not a mirror gap** — `bench_lib.is_mirror_gap_only` is false. A cherry-pick
   that fails only because the mirror lacks the commit fails identically for
   every model and measures nothing.
3. **Agent-recoverable failure**, for hard entries — the corrector failed with
   a recoverable exit code (1 conflict, 3 ptest, 4 build). A
   `DEVTOOL_ERROR`/`PATCH_ERROR`/`METADATA_ERROR` failure is unrecoverable, so
   `cve-agent` gives up without ever consulting the model.
4. **At most 2 CVEs per recipe**, so no single recipe biases the result. Only
   5 recipes appear twice (binutils, go-runtime, libpng, python3-setuptools,
   python3-urllib3); the other 30 appear once.
5. **At most 20 credits** per CVE in the source run. Not binding on this data
   — the most expensive candidate in the whole pool was `CVE-2024-6387` at
   12.40 credits — but it is the rule to apply when adding entries, so one
   pathological CVE cannot dominate a run's cost.
6. **Cheapest first within a complexity bin**, using the source run's measured
   duration, so the roster does not stack slow recipes needlessly.

The mining method was validated against the default 7-CVE roster: it
reproduced the recorded `recipe` and `exit_code` for all 6 of its entries
present in the bulk run, and its `conflict_markers` (3 / 52 / 6 / 12 / 0) match
the values this README documented for them before the default roster's last
`--retier`. The default roster's marker counts differ slightly because they
come from a later probe against a newer OE-Core — which is expected, and is
exactly what `--retier` is for. The two rosters intentionally keep the shared
entries byte-identical across all three files, so refresh them together.

**Refresh before trusting the numbers.** These values describe OE-Core as of
the source run. Run `./run_benchmark.sh --retier` (no AI cost) to re-probe them
against your current checkout before reading much into the tiers. `--retier`
recomputes `exit_code`/`diff_lines`/`conflict_markers`/`tier` but preserves the
author-supplied `recipe` and `series_len`, and never changes which CVEs are in
the roster.

**Changing a roster.** Edit the relevant JSON file directly. To pick new
candidates with real data instead of guessing, use `bench_lib.score_tier` /
`is_mirror_gap_only` / `count_conflict_markers` against either a fresh probe
log (`setup_cve_branch` + `run_cve_corrector` from `test_common.sh`, as
`--retier` does) or an existing historical bulk-run log
(`tests/integration/test-results/bulk_*/`), and apply the six rules above.
`tests/benchmark/test_benchmark_roster.py` enforces the mechanical parts —
schema, tier agreement with `score_tier`, zero markers on clean runs, the
2-per-recipe cap, the hard tier still spanning 0 to ≥30 markers, and the
nesting chain (`default` ⊆ `balanced` ⊆ `extended`) with identical stats on
shared entries. If you add a CVE to a smaller roster, add it to every larger
one too, or the nesting test will fail.

#### Run cost by roster

Cost tracks the **hard** entry count, not the CVE count: only hard entries
reach `cve-agent`'s AI at all, since easy and medium ones are resolved by
`cve-corrector` alone. That makes the balanced roster unusually good value —
2.9x the runs of the default roster for roughly 1.35x the credits.

| | default (7) | balanced (20) | extended (40) |
|---|---|---|---|
| Hard entries (AI-consuming) | 6 | 8 | 24 |
| Agent invocations, 5 models | 35 | 100 | 200 |
| Credits, per sonnet-class model | ~16 | ~21 | ~63 |
| Credits, whole default model set | ~63 | **~85** | **~254** |
| Wall clock, sequential, 5 models | ~11 h | **~15 h** | **~44 h** |

Credit estimates scale the source run's measured mean of 2.62 credits per hard
entry by each model's `MODELS` multiplier. Wall clock combines each roster's
measured corrector durations with the benchmark's own observed ~645 s mean per
agent run. Both are estimates from prior runs, **not** predictions. For
reference, the completed 7-CVE, 5-model run `bench_20260828_145923` actually
spent 95.75 credits against its ~63 estimate, because its roster is 6/7 hard
and two models burned credits on retries before failing — so treat these as
lower bounds.

Use `--run-case` to work through a roster in affordable slices rather than
committing to a full run, and `--models` to narrow the model set:

```bash
./run_benchmark.sh --roster balanced --list-cases          # 20 numbered cases
./run_benchmark.sh --roster balanced --run-case 1 2 3 4 5 6    # the 6 easy ones
./run_benchmark.sh --roster extended --models claude-opus-5,claude-sonnet-4.8 \
    --run-case 17 18 19
```

## Report

```bash
python3 generate_benchmark_report.py test-results/bench_20260814_120000
```

Produces `benchmark_report.md` (or `-o <path>`) with a per-model summary
(total credits, avg duration, avg commands, run count), a per-tier bucket
distribution table, and a meaningful-vs-stylistic split for the judged
moderate/major/partial subset.

## Files

- `run_benchmark.sh` — main entry point (`--retier`, phase 1, phase 2)
- `bench_lib.py` — pure-Python helpers (tiering score, mirror-gap/conflict-marker detection, cost weight, tool-call counting, judge call, CSV filtering)
- `generate_benchmark_report.py` — markdown report generator
- `benchmark-roster.json` — the default committed roster, 7 CVEs (see [Roster files](#roster-files) above)
- `benchmark-roster-balanced.json` — the balanced committed roster, 20 CVEs (6/6/8)
- `benchmark-roster-extended.json` — the extended committed roster, 40 CVEs (the full pool)
- `test_benchmark_roster.py` — integrity tests for all three roster files
