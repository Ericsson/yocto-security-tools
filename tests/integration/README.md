# Integration Tests

End-to-end tests that run `cve-corrector` and `cve-agent` against a real
Yocto/OE-Core checkout. These require a full build environment and are not
run in CI.

> **Comparison warning:** `test_cve_corrector.sh` is the historical
> `resume-compatible-legacy` runner. Its cumulative resume output must not be
> reported as a standalone backend/model comparison. New crossover,
> baseline-health, fallback-policy, and stability campaigns use
> `cve_agent.evaluation`; see
> [the evaluation guide](../../docs/evaluation-harness.md).

## Prerequisites

- A Yocto build environment (OE-Core checkout + `oe-init-build-env` sourced)
- Git mirror directory with upstream repos (for offline cherry-pick)
- `pip install -e .` (this project installed)

## Required Environment Variables

```bash
export OE_DIR=/path/to/openembedded-core    # OE-Core git checkout
export BUILD_DIR=/path/to/build             # Yocto build directory
export MIRROR_DIR=/path/to/upstream-git     # Git mirrors of upstream repos
```

Optional:
```bash
export BUILDTOOLS_ENV=/path/to/environment-setup-x86_64-pokysdk-linux
export AGENT_BACKEND=openai-qwen3.8-l40s  # backend or named native profile
export AGENT_MODEL=local-model            # optional model override
```

## Running

```bash
# All test cases
./test_cve_corrector_cases.sh

# Single test
./test_cve_corrector_cases.sh --test 2

# Agent cases (6, 7, 11, 13) with the Claude Code backend
# (requires an authenticated `claude` CLI on PATH)
AGENT_BACKEND=claude ./test_cve_corrector_cases.sh --test 6

# Bulk full-mode campaign with a named local OpenAI-compatible profile
CVE_METADATA="$PWD/test-cve-metadata-agent.json" \
AGENT_BACKEND=openai-qwen3.8-l40s \
./test_cve_corrector.sh --full-only

# Bulk campaign for the slow local reasoning model: the same runner with the
# medium-effort profile, --session-timeout 1800 and TEST_TIMEOUT=7200 preset
# (see the header of run_qwen_campaign.sh; every value can be overridden)
./run_qwen_campaign.sh --full-only --resume "$PWD/test-results/resume-seed"

# Bulk run plus a second ground-truth round against metadata enriched from
# OE-Core's own Upstream-Status patches (see "Bulk runner modes" below)
./test_cve_corrector.sh --enriched-round
```

The agent test cases run whichever backend `AGENT_BACKEND` selects; any
backend registered with `cve_agent` works (`kiro`, `claude`, or a plugin
from `extra/`). `cve-agent` itself verifies the backend CLI is available
before starting and exits with a clear error if not.

The bulk runner invokes the selected backend only after `cve-corrector`
returns a recoverable conflict, build, ptest, or patch error. Clean automatic
backports do not invoke the agent. Its resume-compatible output is therefore
an end-to-end pipeline result rather than a pure model-capability score.

### Bulk runner modes

`test_cve_corrector.sh` always runs `$CVE_METADATA` once per CVE in two modes
(unless `--full-only` is given): `skip-build-ptest` (corrector only, no
build/ptest) and `full`.

`--agent-only` skips `cve-corrector`'s own cherry-pick/build/ptest attempt
entirely and invokes `cve-agent` directly for every CVE (implies
`--full-only`, since the skipped `skip-build-ptest` round never reaches the
agent anyway). Use this when you already know from a prior run which CVEs
need the agent — e.g. resuming with a different backend/model against a set
of CVEs previously marked `SECURITY_REVIEW_REQUIRED` — and want to skip the
corrector-only attempt that would otherwise run first on every CVE.

`--enriched-round` adds a second pass over the *same* CVE list, using a
corrected copy of `$CVE_METADATA` instead of the original. The copy is
produced with `enrich_metadata_from_oe.py --correct-existing` against
`${OE_DIR}/meta` — the same ground-truth recovery the model benchmark's
roster files rely on (see
[`tests/benchmark/README.md`](../benchmark/README.md#roster-files)). That
script finds the commit each OE-Core patch itself names in its
`Upstream-Status: Backport [<url>]` line and prepends it ahead of whatever the
public trackers (Debian/OSV/CVEList/NVD/UCT) guessed, so this round measures
`cve-corrector` against the hash OE-Core actually backported rather than a
tracker's possibly-wrong guess (tracker data can name a release commit, a
different fork's commit, or even the commit that introduced the flaw — see
the script's module docstring for real examples).

The enriched round runs as `skip-build-ptest-enriched` and `full-enriched`,
writing to `results_skip-build-ptest-enriched.csv` / `results_full-enriched.csv`
and separate per-CVE logs, so it never overwrites or mixes with round 1's
output in the same `$LOG_DIR`. The copy itself, and a log of what the
enrichment changed, are written to `enriched-cve-metadata.json` and
`enrich_metadata.log` in `$LOG_DIR`. `$CVE_METADATA` itself is never modified.

```bash
# Round 1 only (default; unchanged from before --enriched-round existed)
./test_cve_corrector.sh

# Round 1, then round 2 against the Upstream-Status-corrected metadata
./test_cve_corrector.sh --enriched-round

# Combine with --full-only to skip the skip-build-ptest pass in both rounds
./test_cve_corrector.sh --enriched-round --full-only
```

For live pytest smoke tests of the Claude backend that do **not** need a
Yocto build environment, see `tests/agent/test_claude_live.py`:

```bash
CLAUDE_LIVE_TESTS=1 pytest -m live -v
```

### Comparing two models' bulk campaigns

`compare_campaigns.py` reproduces a model-vs-model comparison in three
resumable steps. Model A's run already exists (here `test-results/qwen`):

```bash
# 1. Start model B's run from the rows no model can influence (direct
#    success, skipped, failed before the AI); every agent CVE is left out
./compare_campaigns.py seed test-results/qwen test-results/opus

# 2. Let model B attempt every remaining CVE (OE_DIR, BUILD_DIR and
#    CVE_METADATA as for model A's run)
AGENT_BACKEND=kiro AGENT_MODEL=claude-opus-5.5 \
    ./test_cve_corrector.sh --agent-only --resume "$PWD/test-results/opus"

# 3. Judge both runs' review-required and agent-resolved patches with each
#    judge (resumable; --dry-run shows how many calls it would make)
./compare_campaigns.py judge test-results/qwen test-results/opus \
    -j claude-opus-5.5 -j claude-sonnet-5.5 -j claude-opus-4.6

# 4. Draw the charts
./compare_campaigns.py plot -a "Qwen3.8-27B=test-results/qwen" \
    -b "Claude Opus 5.5=test-results/opus" \
    -j claude-opus-5.5 -j claude-sonnet-5.5 -j claude-opus-4.6 \
    -o test-results/qwen-vs-opus
```

`seed` records the copied CVEs in `<run-b>/seeded-from.txt`. Each judge writes
`<run>/judge-<model>/judge_results.csv`. `plot` writes:

- `outcomes.png`: each model's outcome families over all CVEs
  (`tools/plot_model_outcome_comparison.py`)
- `judge_comparison.png`: the majority verdict of the judges for every CVE
  either model produced a patch for; a side that failed counts as "failed
  to generate a patch" (`tools/plot_model_judge_comparison.py`)
- `judge_agreement_<model>.png`: how often the judges agree, per run
  (`tools/plot_judge_agreement.py`)
- `attempted-by-both.txt`: the CVEs neither run copied from the other

The verdicts measure similarity to the human reference patch, not
correctness; see "Judging a bulk integration run" in
`tests/benchmark/README.md`.

## Test Cases

| # | Scenario | CVE | Expected |
|---|----------|-----|----------|
| 1 | Multi-patch + removed subsequent | CVE-2024-12086 | exit 0 |
| 2 | Single patch (clean cherry-pick) | CVE-2025-5915 | exit 0 |
| 3 | Multiple patches (series) | CVE-2026-25210 | exit 0 |
| 4 | Conflict | CVE-2026-2903 | exit 1 |
| 5 | Single patch with ptest | CVE-2023-42363 | exit 0 |
| 6 | Agent conflict+ptest | CVE-2026-26157 | exit 14 (correct fix deviates from upstream; see script comment) |
| 7 | Build-fix | CVE-2024-0684 | exit 0 (corrector-only; regression test for the gnulib submodule fix) |
| 8 | Missing autotools files | CVE-2024-0684 | exit 0 |
| 9 | Monorepo subprojects strip | CVE-2024-47539 | exit 0 |
| 10 | Single-patch SRC_URI += removal | CVE-2024-39689 | exit 1 |
| 11 | Agent conflict + devtool finish recovery | CVE-2024-39894 | exit 14 (conflicting line is only an OpenBSD version stamp; see script comment) |
| 12 | Skip-build-ptest baseline | CVE-2024-44331 | exit 0 |
| 13 | Agent resolution | CVE-2024-44331 | exit 14 (workspace removed before semantic validation could run; see script comment) |
| 14 | Binutils underscore tag | CVE-2024-53589 | exit 0 |
| 15 | Cross-recipe shared patch removal | CVE-2025-32909 | exit 1 |
| 16 | Ignored untracked files cleanup | CVE-2025-46802 | exit 0 |
| 17 | Monorepo build verification | CVE-2024-47539 | exit 0 |

## Files

- `test_cve_corrector_cases.sh` — Main test runner
- `test_cve_corrector.sh` — Bulk runner over `$CVE_METADATA`; see
  [Bulk runner modes](#bulk-runner-modes) for `--enriched-round`
- `compare_campaigns.py` — Seed, judge and plot a two-model campaign
  comparison; see [Comparing two models' bulk campaigns](#comparing-two-models-bulk-campaigns)
- `test_common.sh` — Shared helper functions
- `test_utils.py` — Python utilities (patch removal, comparison)
- `enrich_metadata_from_oe.py` — Recovers/corrects ground-truth upstream
  commit hashes from OE-Core's own `Upstream-Status: Backport [<url>]`
  patches; used standalone or via `test_cve_corrector.sh --enriched-round`
- `test-cve-metadata.json` — CVE metadata fixture for bulk test runs
- `test-cases-cve-metadata.json` — CVE metadata fixture for individual test cases
