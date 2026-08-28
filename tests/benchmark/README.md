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

The benchmark always runs the fixed 7-CVE roster in `benchmark-roster.json`
(1 medium, 6 hard) — committed, not regenerated — so every run tests
the exact same CVEs regardless of environment or when it's run. See
[Fixed roster](#fixed-roster) below for what's in it and how to change it.

```bash
# Runs the default model set through cve-agent against the fixed roster,
# then judges.
./run_benchmark.sh

# Preview the plan (row counts, cost-weight) without touching git/OE state
# or invoking cve-agent/the judge:
./run_benchmark.sh --dry-run

# Re-verify the roster's cached stats against the current OE-Core state
# (re-probes with cve-corrector, no AI cost). Does NOT add, remove, or
# reorder roster CVEs -- only refreshes their recorded exit_code/diff_lines/
# conflict_markers/tier:
./run_benchmark.sh --retier

# A specific model selection:
./run_benchmark.sh --models claude-sonnet-5,minimax-m2.5

# List the roster CVEs as numbered cases (in run order), then run only some
# of them -- handy to avoid an expensive recipe (e.g. skip glib/binutils) or
# to re-run a single case:
./run_benchmark.sh --list-cases
./run_benchmark.sh --run-case 3          # just case 3
./run_benchmark.sh --run-case 1 2 3      # the first three cases

# Skip the judge phase entirely (no prompt, no cost, nothing runs):
./run_benchmark.sh --skip-judge

# Resume an interrupted run (reuses its agent_results.csv/judge_results.csv):
./run_benchmark.sh --resume test-results/bench_20260814_120000
```

## Flags

| Flag | Effect |
|------|--------|
| `--retier` | Re-probes the 8 roster CVEs with cve-corrector (no AI cost) and updates their recorded stats/tier in `benchmark-roster.json` in place. Never changes which CVEs are in the roster. |
| `--models <default\|full\|comma-list>` | Model selection for phase 1 (default: `default`) |
| `--list-cases` | List the roster CVEs as numbered cases (in run order: easy→medium→hard, alphabetical within a tier) and exit, without running anything. |
| `--run-case <N...>` | Run only the given 1-based case number(s) from `--list-cases` (space-separated, e.g. `--run-case 1 2 3`). Scopes the agent run, the cost estimate, and `--retier`; the judge phase follows whatever was run. |
| `--dry-run` | Print the planned run (rows, cost-weight) without invoking cve-agent, without running the judge, and without prompting for confirmation |
| `--skip-judge` | Phase 2 (the judge pass) does not run at all |
| `--resume <dir>` | Reuse an existing `test-results/bench_*` directory and its CSVs, skipping any `(cve_id, model)` pair already present |

`--full` was removed along with dynamic per-tier candidate selection — the
roster is a fixed 7 CVEs, so there is no "per tier count" left to inflate.
Passing `--full` now fails with an explanation instead of silently doing
something unexpected.

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

### `benchmark-roster.json`

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

Committed at `tests/benchmark/benchmark-roster.json` — the entire, fixed
candidate pool. Every benchmark run reads exactly these CVEs; there is no
regenerable cache or candidate probing involved in normal use.

Every entry's `tier`/`exit_code`/`diff_lines`/`series_len`/`conflict_markers`
is real measured data, not an estimate: captured from a live `cve-corrector`
probe against openembedded-core (scarthgap), plus the historical bulk run in
`tests/integration/test-results/bulk_20260626_081658/`. Refresh it with
`--retier`, which re-probes without any AI cost. Note that `--retier`
rewrites the file with `json.dump(sort_keys=True)`, so the entries come back
alphabetized regardless of how they were ordered before.

`conflict_markers` (count of git's `CONFLICT (content):` marker from the
probe log; `0` for a clean or non-content-conflict failure, e.g. a merge
commit the corrector's cherry-pick strategy can't handle) is a rough
difficulty signal used only when this roster was assembled, to spread the
`hard` entries across the real complexity range (`0` to `45` in the current
roster) instead of picking several CVEs that all happen to be similarly
easy or all similarly brutal.

#### Fixed roster

The current 7 CVEs, and why each was picked (see `bench_lib.is_mirror_gap_only`
/ `count_conflict_markers` / `score_tier` for how the underlying signals are
computed):

| CVE | Tier | Recipe | conflict_markers | Why |
|---|---|---|---|---|
| `CVE-2025-4373` | easy | glib-2.0 | – | Clean, single-commit, small diff |
| `CVE-2026-0990` | medium | libxml2 | – | Clean, 3-commit dependent series |
| `CVE-2024-6345` | hard | python3-setuptools | 0 | Structural failure (merge commit, not a content conflict) — low end |
| `CVE-2024-32487` | hard | less | 3 | Single-file genuine conflict — low-mid |
| `CVE-2025-47183` | hard | gstreamer1.0-plugins-good | 6 | Moderate conflict |
| `CVE-2025-47203` | hard | dropbear | 12 | Moderate-high conflict |
| `CVE-2025-1153` | hard | binutils | 52 | Sprawling, multi-file conflict — high end |
| `CVE-2026-26158` | hard | busybox | 5 | 2-commit dependent series (shared fix with CVE-2026-26157) + genuine conflict, plus a post-apply ptest failure — cheap to rebuild |

**Changing the roster.** Edit `benchmark-roster.json` directly. To pick new
candidates with real data instead of guessing, use `bench_lib.score_tier` /
`is_mirror_gap_only` / `count_conflict_markers` against either a fresh probe
log (`setup_cve_branch` + `run_cve_corrector` from `test_common.sh`, as
`--retier` does) or an existing historical bulk-run log
(`tests/integration/test-results/bulk_*/`). Verify the CVE's upstream mirror
actually resolves (grep the probe log for `Found mirror:`) before adding it
— directory-name guessing against `$MIRROR_DIR` is unreliable, since mirror
directory names don't always match recipe names (e.g. `gst-plugins-good`,
not `gstreamer1.0-plugins-good`).

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
- `benchmark-roster.json` — the fixed, committed CVE roster (see [Fixed roster](#fixed-roster) above)
