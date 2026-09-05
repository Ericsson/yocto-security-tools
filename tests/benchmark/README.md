<!-- SPDX-License-Identifier: MIT -->
# CVE Agent Model Benchmark

Runs `cve-agent` across a fixed roster of CVEs and a selection of models,
then (optionally) an AI judge pass on the diffs that came out at least
minor different from the human reference backport — minor through major, and
partial overlaps judged on the shared files only — to get a verdict on
whether the divergence is meaningfully different or just stylistic.
`identical` diffs skip the judge (there is nothing to ask about a zero-line
diff). Produces `agent_results.csv`, `judge_results.csv`, and (via
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

Four committed rosters ship, none regenerated, so every run tests the exact
same CVEs regardless of environment or when it's run. Three hold CVEs that
**need resolution** — a recoverable exit (conflict/ptest/build) that actually
triggers `cve-agent`'s AI — tiered by conflict/file complexity. The fourth
holds CVEs whose cherry-pick applies **cleanly** (no conflict at all), which
is a different kind of case and is scored separately (see
[Clean-apply roster](#clean-apply-roster-6-cves)).

| `--roster` | File | CVEs | Composition |
|---|---|---|---|
| `default` | `benchmark-roster.json` | 6 | 3 easy, 1 medium, 2 hard |
| `balanced` | `benchmark-roster-balanced.json` | 8 | 3 easy, 2 medium, 3 hard |
| `extended` | `benchmark-roster-extended.json` | 20 | 9 easy, 2 medium, 9 hard |
| `clean-apply` | `benchmark-roster-clean-apply.json` | 6 | n/a — no tier, see below |

`default`/`balanced`/`extended` are **nested** — `default` ⊂ `balanced` ⊂
`extended`, with shared entries carrying identical recorded stats — so results
from any of them stay directly comparable. `clean-apply` is **not** nested in
the others: it is a separate, independent measurement, not a "lower
difficulty" version of the same one. Cost rises with size for the resolution
rosters; see [Run cost by roster](#run-cost-by-roster) before starting one.

See [Roster files](#roster-files) below for what is in each and how to change them.

```bash
# Runs the default model set through cve-agent against the default (6-CVE)
# resolution roster, then judges.
./run_benchmark.sh

# The same, against the 8-CVE balanced roster or the 20-CVE extended one:
./run_benchmark.sh --roster balanced
./run_benchmark.sh --roster extended

# Against the separate 6-CVE clean-apply roster (mandatory-analysis phase,
# not conflict resolution -- see "Clean-apply roster" below):
./run_benchmark.sh --roster clean-apply

# Preview the plan (row counts, cost-weight) without touching git/OE state
# or invoking cve-agent/the judge:
./run_benchmark.sh --dry-run
./run_benchmark.sh --roster balanced --dry-run

# Re-verify a roster's cached stats against the current OE-Core state
# (re-probes with cve-corrector, no AI cost). Does NOT add, remove, or
# reorder roster CVEs -- only refreshes their recorded exit_code/
# conflict_markers/files_involved/tier (or, for clean-apply,
# exit_code/diff_lines/series_len) in the selected roster file:
./run_benchmark.sh --retier
./run_benchmark.sh --roster extended --retier
./run_benchmark.sh --roster clean-apply --retier

# A specific model selection:
./run_benchmark.sh --models claude-opus-5,claude-sonnet-4.6

# Run one native OpenAI profile while retaining the default Kiro judge:
./run_openai_benchmark.sh --backend openai-qwen3.8-l40s

# Use a separately configured native OpenAI profile as the judge too:
./run_openai_benchmark.sh \
    --backend openai-qwen3.8-l40s \
    --judge-backend openai-deepseek-v4-flash

# List the roster CVEs as numbered cases (in run order), then run only some
# of them -- handy to avoid an expensive recipe (e.g. skip glib/binutils), to
# re-run a single case, or to work through a larger roster in affordable
# slices instead of committing to a full run:
./run_benchmark.sh --list-cases
./run_benchmark.sh --run-case 3                          # just case 3
./run_benchmark.sh --run-case 1 2 3                      # the first three cases
./run_benchmark.sh --roster balanced --run-case 5 6 7

# Skip the judge phase entirely (no prompt, no cost, nothing runs):
./run_benchmark.sh --skip-judge

# Resume an interrupted run (reuses its agent_results.csv/judge_results.csv):
./run_benchmark.sh --resume test-results/bench_20260814_120000
```

## Flags

| Flag | Effect |
|------|--------|
| `--roster <default\|balanced\|extended\|clean-apply\|path>` | Which committed roster to run (default: `default`, 6 CVEs; `balanced` is 8, `extended` is 20, and the three nest. `clean-apply` is separate, see [Clean-apply roster](#clean-apply-roster-6-cves)). A path selects an arbitrary roster JSON. The chosen roster is logged at startup so a run's provenance is recorded. |
| `--retier` | Re-probes the selected roster's CVEs with cve-corrector (no AI cost) and updates their recorded stats/tier in that roster file in place. Never changes which CVEs are in the roster. Only accepts a recoverable exit for the three resolution rosters (a clean or unrecoverable exit leaves the cached entry unchanged and warns), and only a clean exit for `clean-apply` (any conflict leaves it unchanged and warns) — see [Roster files](#roster-files). |
| `--models <default\|full\|comma-list>` | Model selection for phase 1 (default: `default`) |
| `--backend <selector>` | Agent backend; `run_benchmark.sh` defaults to `kiro`, while `run_openai_benchmark.sh` defaults to `openai` |
| `--model <model>` | Run one model, optionally overriding a named OpenAI profile's configured model; mutually exclusive with `--models` |
| `--session-timeout <seconds>` | Per-agent-session budget. The generic runner uses the cve-agent default when omitted; the OpenAI wrapper defaults to 1,800 seconds and honors `OPENAI_BENCHMARK_SESSION_TIMEOUT` |
| `--judge-backend <selector>` | `kiro` (default), `openai`, or a named `openai-<profile>` |
| `--judge-model <model>` | Judge model; defaults to `claude-opus-4.8` for Kiro and may be omitted for a named OpenAI profile |
| `--list-cases` | List the roster CVEs as numbered cases (in run order: easy→medium→hard, alphabetical within a tier; `clean-apply` has no tiers, so its cases are just alphabetical) and exit, without running anything. |
| `--run-case <N...>` | Run only the given 1-based case number(s) from `--list-cases` (space-separated, e.g. `--run-case 1 2 3`). Scopes the agent run, the cost estimate, and `--retier`; the judge phase follows whatever was run. |
| `--dry-run` | Print the planned run (rows, cost-weight) without invoking cve-agent, without running the judge, and without prompting for confirmation |
| `--skip-judge` | Phase 2 (the judge pass) does not run at all |
| `--resume <dir>` | Reuse an existing `test-results/bench_*` directory and its CSVs, skipping any `(cve_id, model)` pair already present. Resume is rejected if the roster, metadata, resolved agent configuration, or resolved judge configuration differs from the directory's immutable `run-manifest.json`. |

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
- `agent-artifacts/<cve>_<model>.<id>/` — the unique host-selected cve-agent
  data root. Durable status and telemetry are read only from the exact run
  beneath this root; `Artifacts:` lines in model-controlled output are ignored.
- `run-manifest.json` — immutable roster/metadata digests and resolved agent and
  judge identities used to reject incompatible resumes

(`compare_patches_detailed` writes the first two per-CVE; the benchmark renames
them per-model right after reading the bucket/diff_lines.)

### `agent_results.csv`

```
cve_id,tier,model,exit_status,outcome,skip_reason,credits,duration_s,commands,diff_bucket,diff_lines
```

- `exit_status` — `0` for a security-verified cve-agent run, `TIMEOUT`, the raw
  exit code when no durable result exists, or a durable summary such as
  `WORKFLOW_COMPLETED_UNVERIFIED` when a release gate returns nonzero after
  producing a built candidate
- `outcome` — cve-agent's **own** verdict (`cve_agent.ResultStatus`), read from the run log by `bench_lib.parse_agent_outcome`: `conflict_resolved`, `success`, `skipped`, `escalated`, or `failed`. Empty when the log has no verdict line (timeout, kill, environment failure). **Read this rather than `exit_status`** — the exit code collapses four meaningfully different results into two:
  - `skipped` exits **0** but produced no patch at all. See `skip_reason` for why; only some of these are the model's own claim.
  - `escalated` exits **14** but is the *intended* result when the fix cannot be made within the allowed file scope — the model declined to guess and asked for a human.
  - Only `failed` is an outright breakage, and only `conflict_resolved`/`success` are real backports.

  Ranking models on `exit_status` therefore rewards a confident wrong dismissal over a correct refusal to guess. Results directories predating this column still generate a report; their rows count as "no outcome".
- `skip_reason` — for a `skipped` row only, *why* it was skipped (`bench_lib.parse_skip_reason`). `ResultStatus.SKIPPED` covers several unrelated situations and only one is a judgement call, so the report audits only that one:
  - `ai_not_applicable` — the model concluded on its own reasoning that the CVE does not apply. **This is the only kind worth auditing**, and the only one that can silently leave a live vulnerability unpatched.
  - `empty_cherry_pick` — the cherry-pick produced no changes, so the fix looked already present. Frequently not the model's fault: a commit already reachable from HEAD *guarantees* an empty result, which is how CVE-2024-6387 (a live pre-auth RCE) got dismissed before `cve_corrector.git_ops.is_ancestor_of_head` started filtering those out.
  - `build_preexisting` / `ptest_preexisting` — the recipe was already broken before patching (corrector exit 10 / 8). An environment problem, not a result.
  - `already_applied`, `corrector_not_applicable`, `ignored_by_status` — decided by cve-corrector (exit 11 / 12 / 16) before the AI was consulted.

  The corrector's exit code wins over the printed AI wording, because the already-applied path prints the same "Agent concluded ... is not applicable" line; trusting that string alone misreports a mechanical skip as a model judgement.
- `credits` — parsed from cve-agent's kiro-cli output (`cve_agent.metrics.parse_kiro_credits`); empty if unavailable
- `duration_s` — wall-clock seconds measured by the script
- `commands` — tool-call count from cve-agent's durable telemetry when
  available, with Kiro's captured console markers as a compatibility fallback.
  A clean corrector-only apply legitimately records `0` because no model was
  needed; its candidate is still preserved and compared.
- `diff_bucket` — `identical` / `minor` / `moderate` / `major` / `partial` / `file-mismatch`, same line thresholds as `tests/integration/generate_differences_report.py`. `partial` means the generated and reference patch sets overlap but aren't identical filesets (some files shared, some missing/extra); the judge then evaluates only the shared files (`bench_lib.scope_diff_to_common_files`). `identical` and `file-mismatch` stay unjudged — `identical` because a zero-line diff needs no wording judgment, `file-mismatch` because disjoint filesets leave no shared-file diff to hand the judge at all. Every other bucket, including `minor`, gets a verdict.
- `diff_lines` — changed-line count from `compare_patches_detailed`. For a `partial` row this is scoped to the shared files only (counted over `bench_lib.scope_diff_to_common_files`), matching what the judge evaluates; for all other buckets it is the whole-patch divergence.

### `judge_results.csv`

```
cve_id,model,judgment,reason,judge_credits,scope
```

- `judgment` — `meaningful` or `stylistic`, from the configured judge (Kiro
  `claude-opus-4.8` by default, deliberately not part of the benchmarked
  roster); or one of two verdicts recorded without a judge call:
  `structural-only` for a `partial` overlap whose shared files were identical,
  and `comment-only` when every remaining changed line was a comment (see the
  report note)
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

Resolution rosters (`default`/`balanced`/`extended`) schema:

```json
{
  "CVE-2024-XXXXX": {
    "tier": "easy",
    "recipe": "busybox",
    "exit_code": 1,
    "conflict_markers": 3,
    "files_involved": 1
  }
}
```

`tier` is derived from `conflict_markers` and `files_involved` by
`bench_lib.score_tier` — see [How tiering works](#how-tiering-works) below.
`exit_code` is always a recoverable exit (1 conflict, 3 ptest, 4 build; in
practice every entry mined so far is 1). There is no `diff_lines` or
`series_len` here: a conflict has not been resolved yet, so there is no
generated patch to diff against the reference, and the fix's commit count has
no bearing on how hard the *conflict* is.

Three files are committed in this schema, all selected with `--roster`:

- `tests/benchmark/benchmark-roster.json` — the default, 6 CVEs.
- `tests/benchmark/benchmark-roster-balanced.json` — 8 CVEs.
- `tests/benchmark/benchmark-roster-extended.json` — 20 CVEs, the full pool
  of CVEs mined so far that need resolution.

They nest: `default` ⊂ `balanced` ⊂ `extended`. Each is the entire, fixed
candidate pool for a run. Every benchmark run reads exactly the CVEs in the
selected file; there is no regenerable cache or candidate probing involved in
normal use.

Every entry's `tier`/`exit_code`/`conflict_markers`/`files_involved` is real
measured data, not an estimate: captured from a live `cve-corrector` probe
against openembedded-core (scarthgap). Refresh with `--retier`, which
re-probes without any AI cost and writes back to whichever roster `--roster`
selected — but **only accepts a recoverable exit** (1/3/4). If a CVE no longer
reproduces a conflict (the corrector now exits 0) or fails for an unrelated
reason (a metadata/checkout/git error), `--retier` leaves that entry's cached
stats untouched and prints a warning instead of overwriting real data with a
non-signal; drop or replace that CVE by hand once you see the warning (see
[Changing a roster](#changing-a-roster)). Note that `--retier` rewrites the
file with `json.dump(sort_keys=True)`, so the entries come back alphabetized
regardless of how they were ordered before.

`tests/benchmark/test_benchmark_roster.py` validates **all three** resolution
files: schema completeness, tier agreement with `score_tier`, that every exit
code is recoverable, the nesting chain, and that shared entries carry
identical stats in every file that contains them.

#### How tiering works

```python
EASY_MAX_MARKERS = 3
MEDIUM_MAX_MARKERS = 10
HARD_MIN_FILES = 4
```

`conflict_markers` is the count of git's own `CONFLICT (content):` marker
lines from the probe log (`bench_lib.count_conflict_markers`) — one per
conflicting *hunk*, so a single badly-diverged file can rack up several on its
own. `files_involved` is the count of *distinct* files named in those same
lines (`bench_lib.count_conflicted_files`) — the complementary "how much of
the tree is touched" signal. `score_tier` combines them:

1. `files_involved >= HARD_MIN_FILES` → `hard`, regardless of marker count. A
   conflict spread across many files is a structurally harder resolution even
   if each file's individual conflict is small.
2. `conflict_markers > MEDIUM_MAX_MARKERS` → `hard`.
3. `conflict_markers > EASY_MAX_MARKERS` → `medium`.
4. Otherwise → `easy`.

Thresholds were picked from the pool's real distribution at
calibration time (markers ranged 0–45, roughly terciled at 3 and 10) rather
than guessed; see `bench_lib.py`'s module comment above `score_tier` if you
retune them. `0`/`0` (no marker, no file) is a **structural** failure — the
corrector hit a non-content error (e.g. an empty cherry-pick with "nothing to
commit," or a merge-commit strategy failure) rather than a text conflict —
and currently scores `easy` for lack of a better signal; see
`CVE-2025-24857` in the extended roster.

#### Default roster (6 CVEs)

The cheap roster for quick model comparisons: 3 `easy`, 1 `medium`, 2 `hard`.

| Tier | CVE | Recipe | `conflict_markers` | `files_involved` |
|---|---|---|---|---|
| easy | `CVE-2024-32487` | less | 2 | 1 |
| easy | `CVE-2024-6345` | python3-setuptools | 2 | 2 |
| medium | `CVE-2025-50181` | python3-urllib3 | 4 | 2 |
| hard | `CVE-2025-47203` | dropbear | 7 | 5 |
| hard | `CVE-2026-27135` | nghttp2 | 6 | 5 |
| hard | `CVE-2025-1153` | binutils | 45 | 28 |

#### Balanced roster (8 CVEs)

3 `easy`, 2 `medium`, 3 `hard` — the closest even split the real 20-CVE pool
supports (only 2 CVEs in the whole pool measure `medium`; both are included
here). A superset of the default roster and a subset of the extended one.

| Tier | CVE | Recipe | `conflict_markers` | `files_involved` |
|---|---|---|---|---|
| easy | `CVE-2024-32487` | less | 2 | 1 |
| easy | `CVE-2024-6345` | python3-setuptools | 2 | 2 |
| easy | `CVE-2026-26158` | busybox | 3 | 2 |
| medium | `CVE-2025-50181` | python3-urllib3 | 4 | 2 |
| medium | `CVE-2026-27459` | python3-pyopenssl | 6 | 3 |
| hard | `CVE-2025-47203` | dropbear | 7 | 5 |
| hard | `CVE-2026-27135` | nghttp2 | 6 | 5 |
| hard | `CVE-2025-1153` | binutils | 45 | 28 |

#### Extended roster (19 CVEs)

8 `easy`, 2 `medium`, 9 `hard` — every CVE mined so far that reproduces a
recoverable exit against openembedded-core (scarthgap). A superset of the
balanced roster.

| Tier | CVE | Recipe | `conflict_markers` | `files_involved` |
|---|---|---|---|---|
| easy | `CVE-2024-32487` | less | 2 | 1 |
| easy | `CVE-2024-39689` | python3-certifi | 2 | 1 |
| easy | `CVE-2024-52532` | libsoup-2.4 | 3 | 1 |
| easy | `CVE-2024-6345` | python3-setuptools | 2 | 2 |
| easy | `CVE-2024-7537` | ofono | 2 | 1 |
| easy | `CVE-2026-21441` | python3-urllib3 | 3 | 1 |
| easy | `CVE-2026-24049` | python3-wheel | 2 | 2 |
| easy | `CVE-2026-26158` | busybox | 3 | 2 |
| medium | `CVE-2025-50181` | python3-urllib3 | 4 | 2 |
| medium | `CVE-2026-27459` | python3-pyopenssl | 6 | 3 |
| hard | `CVE-2025-47273` | python3-setuptools | 6 | 5 |
| hard | `CVE-2026-27135` | nghttp2 | 6 | 5 |
| hard | `CVE-2025-47203` | dropbear | 7 | 5 |
| hard | `CVE-2025-4674` | go-runtime | 12 | 5 |
| hard | `CVE-2026-39881` | vim-tiny | 12 | 4 |
| hard | `CVE-2026-26007` | python3-cryptography | 16 | 13 |
| hard | `CVE-2024-6387` | openssh | 23 | 14 |
| hard | `CVE-2025-1176` | binutils | 33 | 22 |
| hard | `CVE-2025-1153` | binutils | 45 | 28 |

`python3-setuptools` and `binutils` each appear twice (a 2-per-recipe cap
still holds); every other recipe appears once.

`CVE-2025-64505` (libpng) was removed after `bench_20260831_140123`: the recipe
fails `cve-corrector`'s pre-patch build check (`EXIT_BUILD_PREEXISTING`, exit
10) in a stock scarthgap environment, so all five models "skipped" it without
ever being consulted. That fails identically for every model and measures
nothing — the same reason selection rule 2 excludes mirror gaps. Re-add it if
the recipe builds cleanly for you.

**Refresh before trusting the numbers.** These values describe OE-Core as of
the last `--retier`. Run `./run_benchmark.sh --retier` (no AI cost) to
re-probe them against your current checkout before reading much into the
tiers.

#### Changing a roster

Edit the relevant JSON file directly, or run `--retier` and act on its
warnings: a CVE that no longer conflicts should move to the
[clean-apply roster](#clean-apply-roster-5-cves) instead (or be dropped if you
already have enough clean-apply coverage); a CVE with an unrelated failure
should be replaced. To pick a new candidate with real data instead of
guessing, probe it with `setup_cve_branch` + `run_cve_corrector` from
`test_common.sh` (as `--retier` does), confirm the exit code is recoverable,
then score it with `bench_lib.count_conflict_markers` /
`count_conflicted_files` / `score_tier`. If you add a CVE to a smaller roster,
add it to every larger one too, or the nesting test in
`test_benchmark_roster.py` will fail.

### Clean-apply roster (7 CVEs)

```json
{
  "CVE-2024-XXXXX": {
    "phase": "clean_apply",
    "recipe": "acpica",
    "exit_code": 0,
    "diff_lines": 3,
    "series_len": 1
  }
}
```

`tests/benchmark/benchmark-roster-clean-apply.json` holds CVEs whose
cherry-pick applies **with no conflict at all** (`exit_code == 0`). This is a
deliberately different schema from the three resolution rosters above: it has
`phase: "clean_apply"` instead of `tier`, because `score_tier`'s
conflict/file-complexity measurement has nothing to size when there is no
conflict — and it keeps `diff_lines`/`series_len`, which the resolution
rosters dropped, because they *do* mean something once a clean patch actually
exists to diff against the reference.

**Why a clean apply is worth benchmarking at all.** `cve-agent`'s exit-0 path
does not enter the conflict-resolution loop — `EXIT_SUCCESS` is routed to a
*mandatory analysis phase* instead (`_handle_clean_apply` in
`cve_agent/orchestrator.py`), where the model reviews the already-applied
patch and must approve it, edit it, conclude it is not applicable, or
escalate. That tests a different failure mode than conflict resolution: not
"can the model fix a conflict" but "can the model recognize a correct result
and leave it alone," or catch a cherry-pick that applied cleanly but is
subtly wrong for this recipe version. A model that edits everything it is
shown scores badly here even though the underlying merge needed no help.
Mixing these CVEs into the resolution rosters under `tier: easy`/`medium`
would conflate that distinct behavior with genuine (if small) conflict
resolution, which is why this roster is kept separate.

| CVE | Recipe | `series_len` | `diff_lines` |
|---|---|---|---|
| `CVE-2024-24856` | acpica | 1 | 0 |
| `CVE-2024-5569` | python3-zipp | 1 | 2 |
| `CVE-2025-11687` | gi-docgen | 1 | 0 |
| `CVE-2025-24857` | u-boot-tools | 1 | 0 |
| `CVE-2025-46805` | screen | 1 | 10 |
| `CVE-2025-46836` | net-tools | 2 | 4 |
| `CVE-2025-47183` | gstreamer1.0-plugins-good | 1 | 0 |

`CVE-2025-24857` (u-boot-tools) moved here from the extended roster. It used to
fail with an empty cherry-pick because its only recorded fix commit was
`c253573f3e2` *"Prepare v2017.11"* — a 2017 release bump, and an ancestor of the
recipe's own version. Once the metadata carried the real fix
(`87d85139a96`, from the `Upstream-Status` header of OE-Core's own patch) and
`cve-corrector` learned to skip commits already in history, it applies cleanly
and reproduces the reference backport exactly (`diff_lines: 0`, *"Patches are
equivalent"*).

Run it the same way as the others: `./run_benchmark.sh --roster clean-apply`,
`--retier` to refresh, `--list-cases`/`--run-case` to slice it. `--retier`
only accepts a clean exit here — a CVE that now conflicts leaves its cached
entry unchanged and warns, mirroring the resolution rosters' symmetric
restriction. `tests/benchmark/test_benchmark_roster.py` validates its schema
separately from the resolution rosters (no `tier` field, `phase` always
`"clean_apply"`, `exit_code` always `0`), and confirms it shares no CVE with
the extended resolution roster.

#### Run cost by roster

Every entry in the three resolution rosters reaches `cve-agent`'s AI (a
recoverable exit always enters the resolution loop), so cost tracks CVE count
directly there. The clean-apply roster's mandatory-analysis phase also calls
the AI, but for a single review turn rather than an open-ended
conflict-resolution loop, so it is typically cheaper per CVE.

| | default (6) | balanced (8) | extended (20) | clean-apply (6) |
|---|---|---|---|---|
| AI-consuming entries | 6 | 8 | 20 | 6 |
| Agent invocations, 5 models | 30 | 40 | 100 | 30 |

Use `--run-case` to work through a roster in affordable slices rather than
committing to a full run, and `--models` to narrow the model set:

```bash
./run_benchmark.sh --roster extended --list-cases          # 20 numbered cases
./run_benchmark.sh --roster extended --run-case 1 2 3 4 5 6 7 8 9 10  # the 10 easy ones
./run_benchmark.sh --roster extended --models claude-opus-5,claude-sonnet-4.6 \
    --run-case 13 14
```

## Report

```bash
python3 generate_benchmark_report.py test-results/bench_20260814_120000
```

Produces `benchmark_report.md` (or `-o <path>`) with a per-model summary
(total credits, avg duration, avg commands, run count), a **per-model outcome
distribution** (resolved / skipped / escalated / failed — see the `outcome`
column above for why this and not the exit status), a per-tier bucket
distribution table, a meaningful-vs-stylistic split for the judged subset, and
a **"Not-Applicable Verdicts"** audit listing every CVE a model declared
inapplicable **on its own reasoning**, with how many of the models that ran it
agreed. A CVE dismissed by some models but backported by others is the cheapest
available signal that one side is wrong. Skips with a mechanical cause (a
pre-existing build failure, an empty cherry-pick) are listed separately, since
those never involved the model's opinion.

## Files

- `run_benchmark.sh` — main entry point (`--retier`, phase 1, phase 2)
- `run_openai_benchmark.sh` — single-model native OpenAI entry point with a
  configurable judge and Kiro as the default judge
- `bench_lib.py` — pure-Python helpers (conflict/file-complexity tiering, mirror-gap/conflict-marker/conflicted-file detection, cost weight, tool-call counting, judge call, CSV filtering)
- `generate_benchmark_report.py` — markdown report generator
- `benchmark-roster.json` — the default committed resolution roster, 6 CVEs (see [Roster files](#roster-files) above)
- `benchmark-roster-balanced.json` — the balanced committed resolution roster, 8 CVEs (3/2/3)
- `benchmark-roster-extended.json` — the extended committed resolution roster, 20 CVEs (the full mined pool)
- `benchmark-roster-clean-apply.json` — the separate clean-apply roster, 6 CVEs (see [Clean-apply roster](#clean-apply-roster-6-cves))
- `test_benchmark_roster.py` — integrity tests for all four roster files
- `test_run_openai_benchmark.py` — offline contracts for the native entry point
