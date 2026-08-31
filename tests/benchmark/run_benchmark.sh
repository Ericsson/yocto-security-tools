#!/bin/bash
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
# CVE Agent Model Benchmark: runs cve-agent across a tiered set of CVEs and
# a selection of models, then (optionally) an AI judge pass on the diffs
# that came out moderately/majorly different from the reference patch, or
# that partially overlap it (judged on the shared files only).
#
# Depends on tests/integration/test_common.sh for the OE tree lifecycle
# (reset_oe_tree, setup_cve_branch, run_cve_corrector, compare_patches_detailed)
# — see tests/benchmark/README.md for that coupling and the required env vars.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CVE_METADATA="${REPO_ROOT}/tests/integration/test-cve-metadata-agent.json"

# Four committed rosters (see README "Roster files"), nested so their results
# stay comparable: default (6) subset balanced (8) subset extended (24) --
# all CVEs that need resolution (a recoverable exit: conflict/ptest/build).
# clean-apply (5) is separate and NOT nested in the others: it holds CVEs
# whose cherry-pick applies with no conflict, which score_tier's easy/medium/
# hard has no meaning for. The default is the small, cheap one; the larger
# two are opt-in via --roster because they cost roughly 2.9x and 5.7x as much
# to run.
ROSTER_DEFAULT="${SCRIPT_DIR}/benchmark-roster.json"
ROSTER_BALANCED="${SCRIPT_DIR}/benchmark-roster-balanced.json"
ROSTER_EXTENDED="${SCRIPT_DIR}/benchmark-roster-extended.json"
ROSTER_CLEAN_APPLY="${SCRIPT_DIR}/benchmark-roster-clean-apply.json"
ROSTER_FILE="$ROSTER_DEFAULT"
ROSTER_NAME="default"

# So every inline `python3 -c "from tests.benchmark.bench_lib import ..."`
# call below can just import directly, without each one repeating its own
# `sys.path.insert(0, '${REPO_ROOT}')` line.
export PYTHONPATH="${REPO_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"

RETIER=false
DRY_RUN=false
SKIP_JUDGE=false
MODELS_SELECTOR="default"
MODELS_EXPLICIT=false
AGENT_BACKEND="kiro"
AGENT_MODEL=""
AGENT_MODEL_SET=false
CUSTOM_MODEL_LABEL=""
RESUME_DIR=""
RUN_TIMEOUT="${RUN_TIMEOUT:-3600}"  # per cve-agent invocation, seconds
SESSION_TIMEOUT=""
JUDGE_BACKEND="kiro"
JUDGE_MODEL="claude-opus-4.8"
JUDGE_MODEL_SET=false
LIST_CASES=false
declare -a RUN_CASES=()   # 1-based case numbers from --run-case; empty = all
SELECTED_CVES=""          # newline-separated CVE ids to run; empty = all

# shellcheck source=../integration/test_common.sh
source "${REPO_ROOT}/tests/integration/test_common.sh"

die() { log "FATAL: $*"; exit 1; }

# ── Interrupt handling ───────────────────────────────────────────────────────
# The agent is launched under `setsid` (see run_agent_phase), which detaches it
# into its own session/process group so a per-run `timeout` can reap the whole
# process tree. That same detachment means a Ctrl+C at the terminal never
# reaches the agent — the SIGINT goes only to this script's process group. So
# we trap it here, forward a kill to the agent's process group by hand, and
# stop. AGENT_PGID holds the process-group id of the currently running agent
# (empty when none is running); the agent is run in the background and `wait`ed
# on so this trap can fire promptly instead of being deferred until the
# foreground child exits.
AGENT_PGID=""
INTERRUPTED=false

on_interrupt() {
    # Guard against a second signal re-entering the handler mid-cleanup.
    [[ "$INTERRUPTED" == true ]] && return
    INTERRUPTED=true
    echo    # break the line after a terminal "^C"
    log "Interrupted — stopping the benchmark..."
    if [[ -n "$AGENT_PGID" ]]; then
        log "  Terminating agent process group ${AGENT_PGID}..."
        kill -TERM "-${AGENT_PGID}" 2>/dev/null || true
        # Give the tree a few seconds to exit cleanly, then force-kill.
        local i
        for i in 1 2 3 4 5; do
            kill -0 "-${AGENT_PGID}" 2>/dev/null || break
            sleep 1
        done
        kill -KILL "-${AGENT_PGID}" 2>/dev/null || true
    fi
    # Best-effort: leave the OE tree checked out clean for the next run.
    reset_oe_tree 2>/dev/null || true
    log "Benchmark aborted by user (partial results are in ${RESULTS_DIR:-<unset>})."
    exit 130
}
trap on_interrupt INT TERM


# ── CLI ──────────────────────────────────────────────────────────────────────
usage() {
    cat <<'EOF'
Usage: run_benchmark.sh [options]

The benchmark runs a fixed, committed roster -- never regenerated, so every
run tests the exact same CVEs. Four rosters are available: three hold CVEs
that need resolution (a recoverable exit), nested and tiered by conflict/file
complexity; the fourth holds CVEs whose cherry-pick applies with no conflict
at all, scored separately (see README "Clean-apply roster").

  default      benchmark-roster.json             6 CVEs  (3 easy, 1 medium, 2 hard)
  balanced     benchmark-roster-balanced.json     8 CVEs  (3 easy, 2 medium, 3 hard)
  extended     benchmark-roster-extended.json    20 CVEs  (9 easy, 2 medium, 9 hard)
  clean-apply  benchmark-roster-clean-apply.json  6 CVEs  (no tier -- clean cherry-picks)

They are nested -- default is a subset of balanced, which is a subset of
extended -- so results stay comparable across them. See
tests/benchmark/README.md for what is in each and how to change them.

  --roster <sel>      "default" (default), "balanced", "extended",
                       "clean-apply", or a path to a roster JSON file.
                       Relative to the default roster, balanced is ~2.9x the
                       runs and extended ~5.7x -- see the README section "Run
                       cost by roster" first. "clean-apply" is a separate
                       5-CVE roster of clean cherry-picks (no tier field);
                       see the README section "Clean-apply roster".
  --retier            Re-probe the selected roster's CVEs with cve-corrector
                       only (no AI cost) and refresh their recorded exit_code/
                       diff_lines/conflict_markers/tier in that roster file.
                       Does NOT add, remove, or reorder roster CVEs, and
                       preserves the author-supplied recipe and series_len.
  --models <sel>      "default" (default), "full", or a comma-separated list
                       of Kiro model names
  --backend <name>    Agent backend selector (default: kiro). Named native
                       OpenAI profiles use openai-<profile>.
  --model <name>      Run one model instead of the Kiro model roster. Optional
                       for a named OpenAI profile that supplies its own model.
  --session-timeout N Agent session timeout in seconds. When omitted, use the
                       cve-agent default. The OpenAI wrapper defaults to 1800.
  --judge-backend <b> Judge with kiro (default), openai, or openai-<profile>
  --judge-model <m>   Judge model (default: claude-opus-4.8 for Kiro). May be
                       omitted when a named OpenAI judge profile supplies it.
  --list-cases        List the roster CVEs as numbered cases (in run order)
                       and exit, without running anything.
  --run-case N [N...] Run only the given case number(s) from --list-cases
                       (1-based, space-separated, e.g. --run-case 1 2 3).
                       Scopes the agent run, the cost estimate, and --retier;
                       the judge phase follows whatever was run.
  --dry-run           Print the planned run without invoking cve-agent or
                       the judge, and without prompting for confirmation
  --skip-judge        Do not run the judge phase at all
  --resume <dir>      Reuse an existing tests/benchmark/test-results/bench_*
                       directory and its agent_results.csv/judge_results.csv
  -h, --help          Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --retier) RETIER=true ;;
        --full) die "--full was removed: the benchmark runs a fixed roster (see --roster and --help)" ;;
        --roster)
            shift
            [[ $# -gt 0 ]] || die "--roster requires an argument (default|balanced|extended|clean-apply|<path>)"
            case "$1" in
                default)  ROSTER_FILE="$ROSTER_DEFAULT";  ROSTER_NAME="default" ;;
                balanced) ROSTER_FILE="$ROSTER_BALANCED"; ROSTER_NAME="balanced" ;;
                extended) ROSTER_FILE="$ROSTER_EXTENDED"; ROSTER_NAME="extended" ;;
                clean-apply) ROSTER_FILE="$ROSTER_CLEAN_APPLY"; ROSTER_NAME="clean-apply" ;;
                *)
                    [[ -f "$1" ]] || \
                        die "--roster: not one of default|balanced|extended|clean-apply, and not a file: $1"
                    ROSTER_FILE="$1"; ROSTER_NAME="$(basename "$1")"
                    ;;
            esac
            ;;
        --dry-run) DRY_RUN=true ;;
        --skip-judge) SKIP_JUDGE=true ;;
        --models)
            shift
            [[ $# -gt 0 ]] || die "--models requires an argument"
            MODELS_SELECTOR="$1"
            MODELS_EXPLICIT=true
            ;;
        --backend)
            shift
            [[ $# -gt 0 ]] || die "--backend requires an argument"
            AGENT_BACKEND="$1"
            ;;
        --model)
            shift
            [[ $# -gt 0 ]] || die "--model requires an argument"
            AGENT_MODEL="$1"
            AGENT_MODEL_SET=true
            ;;
        --session-timeout)
            shift
            [[ $# -gt 0 ]] || die "--session-timeout requires an argument"
            SESSION_TIMEOUT="$1"
            ;;
        --judge-backend)
            shift
            [[ $# -gt 0 ]] || die "--judge-backend requires an argument"
            JUDGE_BACKEND="$1"
            ;;
        --judge-model)
            shift
            [[ $# -gt 0 ]] || die "--judge-model requires an argument"
            JUDGE_MODEL="$1"
            JUDGE_MODEL_SET=true
            ;;
        --list-cases) LIST_CASES=true ;;
        --run-case)
            shift
            [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]] || \
                die "--run-case requires one or more case numbers (see --list-cases)"
            while [[ $# -gt 0 && "$1" =~ ^[0-9]+$ ]]; do
                RUN_CASES+=("$1")
                shift
            done
            continue  # already advanced past the consumed numbers; skip trailing shift
            ;;
        --resume)
            shift
            [[ $# -gt 0 ]] || die "--resume requires a directory argument"
            RESUME_DIR="$1"
            [[ -d "$RESUME_DIR" ]] || die "Resume directory not found: $RESUME_DIR"
            ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
    shift
done

if [[ "$AGENT_MODEL_SET" == true && "$MODELS_EXPLICIT" == true ]]; then
    die "--model and --models are mutually exclusive"
fi
if [[ -n "$SESSION_TIMEOUT" && ! "$SESSION_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
    die "--session-timeout must be a positive integer"
fi
if [[ ! "$RUN_TIMEOUT" =~ ^[1-9][0-9]*$ ]]; then
    die "RUN_TIMEOUT must be a positive integer"
fi
if [[ "$AGENT_BACKEND" != "kiro" && "$MODELS_EXPLICIT" == true ]]; then
    die "--models is the Kiro roster; use --model with backend '$AGENT_BACKEND'"
fi
if [[ "$JUDGE_BACKEND" != "kiro" && "$JUDGE_BACKEND" != "openai" \
        && "$JUDGE_BACKEND" != openai-* ]]; then
    die "--judge-backend must be kiro, openai, or openai-<profile>"
fi
if [[ "$JUDGE_BACKEND" != "kiro" && "$JUDGE_MODEL_SET" != true ]]; then
    # A named OpenAI profile (or CVE_AGENT_OPENAI_MODEL for plain openai)
    # supplies the model unless the operator explicitly overrides it.
    JUDGE_MODEL=""
fi

# Non-Kiro backends and an explicit --model are single-model runs. Keep the
# display/artifact key separate from the optional model override: a named
# OpenAI profile can supply its model without receiving a conflicting --model.
if [[ "$AGENT_MODEL_SET" == true || "$AGENT_BACKEND" != "kiro" ]]; then
    if [[ -n "$AGENT_MODEL" ]]; then
        CUSTOM_MODEL_LABEL="${AGENT_MODEL//\//_}"
        CUSTOM_MODEL_LABEL="${CUSTOM_MODEL_LABEL//:/_}"
    elif [[ "$AGENT_BACKEND" == openai-* ]]; then
        CUSTOM_MODEL_LABEL="${AGENT_BACKEND#openai-}"
    else
        CUSTOM_MODEL_LABEL="openai"
    fi
    if [[ ! "$CUSTOM_MODEL_LABEL" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
        die "model label is not safe for result filenames: $CUSTOM_MODEL_LABEL"
    fi
fi

[[ -f "$CVE_METADATA" ]] || die "CVE metadata fixture not found: $CVE_METADATA"
[[ -f "$ROSTER_FILE" ]] || die "Fixed roster not found: $ROSTER_FILE"

# State it up front: the two rosters differ by 5.7x in cost, so a run whose
# log does not say which one it used is not interpretable after the fact.
log "Roster: ${ROSTER_NAME} ($(basename "$ROSTER_FILE"), $(python3 -c "
import json, sys
with open('${ROSTER_FILE}') as f:
    print(len(json.load(f)))
") CVEs)"

# ── Case listing / selection (--list-cases / --run-case) ─────────────────────
# Case numbers are the roster CVEs enumerated in run order (easy->medium->hard,
# alphabetical within a tier) -- see bench_lib.ordered_roster_cases(). Both
# reads are pure roster lookups, no build env needed.
if [[ "$LIST_CASES" == true ]]; then
    python3 - "$ROSTER_FILE" <<'PY'
import json, sys
from tests.benchmark.bench_lib import ordered_roster_cases
with open(sys.argv[1]) as f:
    roster = json.load(f)
cases = ordered_roster_cases(roster)
print(f"{'#':>3}  {'tier':<7} {'recipe':<28} cve")
print("-" * 56)
for c in cases:
    print(f"{c['case']:>3}  {c['tier']:<7} {c['recipe']:<28} {c['cve_id']}")
PY
    exit 0
fi

# Resolve --run-case numbers to the concrete CVE ids to run (empty = all).
if [[ ${#RUN_CASES[@]} -gt 0 ]]; then
    SELECTED_CVES=$(python3 - "$ROSTER_FILE" "${RUN_CASES[@]}" <<'PY'
import json, sys
from tests.benchmark.bench_lib import ordered_roster_cases, select_cases
with open(sys.argv[1]) as f:
    roster = json.load(f)
try:
    sel = select_cases(ordered_roster_cases(roster),
                       [int(x) for x in sys.argv[2:]])
except ValueError as exc:
    sys.stderr.write(f"{exc}\n")
    sys.exit(2)
print("\n".join(c["cve_id"] for c in sel))
PY
    ) || die "Invalid --run-case selection (see --list-cases)."
    log "Selected cases ${RUN_CASES[*]} -> $(echo "$SELECTED_CVES" | tr '\n' ' ')"
fi

# True when a CVE should be processed: always true when nothing was selected
# (whole roster), otherwise only for the CVEs --run-case resolved to.
is_selected_cve() {
    [[ -z "$SELECTED_CVES" ]] && return 0
    grep -qxF "$1" <<< "$SELECTED_CVES"
}

# Copy the patch files the run generated in the meta layer (new or modified vs
# the reset baseline) into the results dir as generated_<cve>_<file>.patch, so
# they survive reset_oe_tree and can be evaluated later. No-op when the run
# produced no patches (e.g. a conflict that never reached devtool finish).
save_generated_patches() {
    local cve_id="$1" model="$2" dest count=0 f
    while IFS= read -r f; do
        [[ "$f" == *.patch ]] || continue
        dest="${RESULTS_DIR}/generated_${cve_id}_${model}_$(basename "$f")"
        cp "${OE_DIR}/${f}" "$dest" 2>/dev/null && count=$((count + 1))
    done < <(cd "$OE_DIR" && git ls-files --others --modified --exclude-standard -- meta 2>/dev/null)
    [[ $count -gt 0 ]] && log "  saved $count generated patch(es) to $RESULTS_DIR"
    return 0
}

# ── Results directory ───────────────────────────────────────────────────────
# Resolved to an absolute path up front: test_common.sh's helpers (setup_cve_branch,
# reset_oe_tree, ...) `cd "$OE_DIR"`, so a relative --resume path would silently
# break every later reference to $RESULTS_DIR/$AGENT_CSV/$JUDGE_CSV.
if [[ -n "$RESUME_DIR" ]]; then
    RESULTS_DIR="$(cd "$RESUME_DIR" && pwd)"
    log "Resuming from $RESULTS_DIR"
else
    RESULTS_DIR="${SCRIPT_DIR}/test-results/bench_$(date +%Y%m%d_%H%M%S)"
fi
mkdir -p "$RESULTS_DIR"
LOG_DIR="$RESULTS_DIR"  # test_common.sh's remove_cve_patch()/compare_patches_detailed() use $LOG_DIR
AGENT_CSV="${RESULTS_DIR}/agent_results.csv"
JUDGE_CSV="${RESULTS_DIR}/judge_results.csv"
[[ -f "$AGENT_CSV" ]] || echo "cve_id,tier,model,exit_status,outcome,skip_reason,credits,duration_s,commands,diff_bucket,diff_lines" > "$AGENT_CSV"
JUDGE_HEADER="cve_id,model,judgment,reason,judge_credits,scope"
if [[ ! -f "$JUDGE_CSV" ]]; then
    echo "$JUDGE_HEADER" > "$JUDGE_CSV"
elif [[ "$(head -n1 "$JUDGE_CSV")" != "$JUDGE_HEADER" && "$(wc -l < "$JUDGE_CSV")" -le 1 ]]; then
    # --resume of a results dir created before the 'scope'/'reason' columns
    # were added: the judge CSV holds only an outdated header (no data rows
    # yet), so upgrade it in place. This avoids appending 6-field rows under a
    # 4- or 5-field header. A file that already has data rows is left untouched
    # to preserve results; those older rows keep their own column set, and
    # csv.DictReader gives the missing keys as None.
    echo "$JUDGE_HEADER" > "$JUDGE_CSV"
fi

ensure_campaign_manifest() {
    local resume=false
    [[ -n "$RESUME_DIR" ]] && resume=true
    python3 - "$RESULTS_DIR" "$resume" "$ROSTER_FILE" "$CVE_METADATA" \
        "$AGENT_BACKEND" "$AGENT_MODEL" "$CUSTOM_MODEL_LABEL" \
        "$MODELS_SELECTOR" "$JUDGE_BACKEND" "$JUDGE_MODEL" \
        "$SESSION_TIMEOUT" "$RUN_TIMEOUT" <<'PY'
import sys
from pathlib import Path

from tests.benchmark.bench_lib import resolve_models
from tests.benchmark.benchmark_manifest import (
    BenchmarkManifestError,
    build_run_manifest,
    ensure_run_manifest,
)

(results_dir, resume, roster, metadata, agent_backend, agent_model,
 custom_label, models_selector, judge_backend, judge_model,
 session_timeout, run_timeout) = sys.argv[1:]
agent_models = (
    [agent_model or None]
    if custom_label else [entry['name'] for entry in resolve_models(models_selector)]
)
try:
    manifest = build_run_manifest(
        Path(roster),
        Path(metadata),
        agent_backend,
        agent_models,
        judge_backend,
        judge_model or None,
        session_timeout=int(session_timeout) if session_timeout else None,
        run_timeout=int(run_timeout),
    )
    ensure_run_manifest(Path(results_dir), manifest, resume=resume == 'true')
except (BenchmarkManifestError, OSError, ValueError) as error:
    print(f'ERROR: {error}', file=sys.stderr)
    raise SystemExit(2)
PY
}


# ── Fixed roster: re-verify (optional) then read ────────────────────────────
# The CVEs in the selected resolution roster (default/balanced/extended) are
# the entire candidate pool -- always the same CVEs, every run. --retier
# re-probes them with cve-corrector only (no AI cost) to refresh their
# recorded stats; it never changes which CVEs are in the roster.
#
# Restricted to CVEs that need resolution: a recoverable exit (1/3/4 --
# conflict/ptest/build) is the only outcome retier_roster() will accept for
# these three files. A clean exit (0) or an unrecoverable exit (metadata
# lookup failure, checkout error, etc.) leaves the cached stats unchanged and
# warns instead of overwriting tier/exit_code -- see retier_clean_apply_roster()
# below for the roster that DOES want a clean exit.
retier_roster() {
    log "=== Re-verifying the fixed roster (no AI, cve-corrector only) ==="
    source_build_env

    local cve_ids
    cve_ids=$(python3 -c "
import json
with open('${ROSTER_FILE}') as f:
    data = json.load(f)
data.pop('_comment', None)
print('\n'.join(data.keys()))
")

    local i=0 count
    count=$(echo "$cve_ids" | while IFS= read -r c; do
        [[ -z "$c" ]] && continue
        is_selected_cve "$c" && echo "$c"
    done | wc -l)
    while IFS= read -r cve_id; do
        [[ -z "$cve_id" ]] && continue
        is_selected_cve "$cve_id" || continue
        i=$((i + 1))
        local recipe
        recipe=$(python3 -c "
import json
with open('${ROSTER_FILE}') as f:
    data = json.load(f)
print(data['${cve_id}']['recipe'])
")

        local log_file="${RESULTS_DIR}/retier_${cve_id}.log"
        log "[$i/$count] $cve_id ($recipe) ..."
        setup_cve_branch "$cve_id" "$log_file" "retier"

        if [[ "$SETUP_CVE_STATUS" != "OK" ]]; then
            log "  WARNING: setup failed ($SETUP_CVE_STATUS) -- leaving cached stats for $cve_id unchanged"
            reset_oe_tree >> "$log_file" 2>&1
            continue
        fi

        run_cve_corrector "$cve_id" "$log_file" "--skip-build --skip-ptest"
        local exit_code
        exit_code=$(echo "$CVE_CORRECTOR_RESULT" | cut -d: -f1)

        local is_recoverable
        is_recoverable=$(python3 -c "
from cve_agent import RECOVERABLE_EXITS
print(${exit_code} in RECOVERABLE_EXITS)
")
        if [[ "$is_recoverable" != "True" ]]; then
            log "  WARNING: exit=$exit_code is not a recoverable exit (need resolution: conflict/ptest/build) -- leaving cached stats for $cve_id unchanged. A clean exit belongs in the clean-apply roster (--roster clean-apply), not here; any other exit means the corrector bailed before reaching a conflict."
            reset_oe_tree >> "$log_file" 2>&1
            continue
        fi

        local conflict_markers files_involved mirror_gap_only
        read -r mirror_gap_only conflict_markers files_involved <<< "$(python3 -c "
from tests.benchmark.bench_lib import (
    count_conflict_markers, count_conflicted_files, is_mirror_gap_only)
with open('${log_file}') as f:
    text = f.read()
print(is_mirror_gap_only(text), count_conflict_markers(text),
      count_conflicted_files(text))
")"

        local tier
        tier=$(python3 -c "
from tests.benchmark.bench_lib import score_tier
print(score_tier(${exit_code}, ${conflict_markers}, ${files_involved}))
")
        log "  exit=$exit_code conflict_markers=$conflict_markers files_involved=$files_involved mirror_gap_only=$mirror_gap_only -> tier=$tier"
        if [[ "$mirror_gap_only" == "True" ]]; then
            log "  WARNING: $cve_id now fails with a mirror gap, not a genuine conflict -- stats updated, but consider swapping it out of the fixed roster (see README)"
        fi

        python3 -c "
import json
path = '${ROSTER_FILE}'
with open(path) as f:
    data = json.load(f)
data['${cve_id}'] = {
    'tier': '${tier}', 'recipe': '${recipe}', 'exit_code': ${exit_code},
    'conflict_markers': ${conflict_markers}, 'files_involved': ${files_involved},
}
with open(path, 'w') as f:
    json.dump(data, f, indent=2, sort_keys=True)
    f.write('\n')
"
        reset_oe_tree >> "$log_file" 2>&1
    done <<< "$cve_ids"
    log "Refreshed stats for $count roster CVE(s) in $ROSTER_FILE"
}

# ── Clean-apply roster: re-verify (optional) ────────────────────────────────
# Companion to retier_roster() for the opposite case: benchmark-roster-
# clean-apply.json holds CVEs whose cherry-pick applies with NO conflict
# (exit_code == 0). It has no tier/score_tier -- schema uses `phase:
# "clean_apply"` instead, since easy/medium/hard measures conflict
# complexity, which a clean apply has none of by definition. Only accepts
# exit_code == 0; any other outcome leaves the cached entry unchanged and
# warns, mirroring retier_roster()'s symmetric restriction.
retier_clean_apply_roster() {
    log "=== Re-verifying the clean-apply roster (no AI, cve-corrector only) ==="
    source_build_env

    local cve_ids
    cve_ids=$(python3 -c "
import json
with open('${ROSTER_FILE}') as f:
    data = json.load(f)
data.pop('_comment', None)
print('\n'.join(data.keys()))
")

    local i=0 count
    count=$(echo "$cve_ids" | while IFS= read -r c; do
        [[ -z "$c" ]] && continue
        is_selected_cve "$c" && echo "$c"
    done | wc -l)
    while IFS= read -r cve_id; do
        [[ -z "$cve_id" ]] && continue
        is_selected_cve "$cve_id" || continue
        i=$((i + 1))
        local recipe
        recipe=$(python3 -c "
import json
with open('${ROSTER_FILE}') as f:
    data = json.load(f)
print(data['${cve_id}']['recipe'])
")

        local log_file="${RESULTS_DIR}/retier_${cve_id}.log"
        log "[$i/$count] $cve_id ($recipe) ..."
        setup_cve_branch "$cve_id" "$log_file" "retier"

        if [[ "$SETUP_CVE_STATUS" != "OK" ]]; then
            log "  WARNING: setup failed ($SETUP_CVE_STATUS) -- leaving cached stats for $cve_id unchanged"
            reset_oe_tree >> "$log_file" 2>&1
            continue
        fi

        run_cve_corrector "$cve_id" "$log_file" "--skip-build --skip-ptest"
        local exit_code diff_lines
        exit_code=$(echo "$CVE_CORRECTOR_RESULT" | cut -d: -f1)
        diff_lines=$(echo "$CVE_CORRECTOR_RESULT" | cut -d: -f2)
        [[ "$diff_lines" =~ ^[0-9]+$ ]] || diff_lines=0

        if [[ "$exit_code" != "0" ]]; then
            log "  WARNING: exit=$exit_code is not a clean apply -- leaving cached stats for $cve_id unchanged. This roster is only for CVEs whose cherry-pick applies with no conflict; a non-zero exit belongs in one of the resolution rosters (default/balanced/extended) instead."
            reset_oe_tree >> "$log_file" 2>&1
            continue
        fi

        local series_len
        series_len=$(python3 -c "
import json
with open('${ROSTER_FILE}') as f:
    data = json.load(f)
print(data['${cve_id}']['series_len'])
")
        log "  exit=$exit_code diff_lines=$diff_lines series_len=$series_len -> phase=clean_apply"

        python3 -c "
import json
path = '${ROSTER_FILE}'
with open(path) as f:
    data = json.load(f)
data['${cve_id}'] = {
    'phase': 'clean_apply', 'recipe': '${recipe}', 'exit_code': ${exit_code},
    'diff_lines': ${diff_lines}, 'series_len': ${series_len},
}
with open(path, 'w') as f:
    json.dump(data, f, indent=2, sort_keys=True)
    f.write('\n')
"
        reset_oe_tree >> "$log_file" 2>&1
    done <<< "$cve_ids"
    log "Refreshed stats for $count clean-apply roster CVE(s) in $ROSTER_FILE"
}

if [[ "$RETIER" == true ]]; then
    if [[ "$ROSTER_NAME" == "clean-apply" ]]; then
        retier_clean_apply_roster
    else
        retier_roster
    fi
fi

if ! ensure_campaign_manifest; then
    die "Benchmark run manifest validation failed"
fi

cves_for_tier() {
    local tier="$1"
    python3 -c "
import json
with open('${ROSTER_FILE}') as f:
    data = json.load(f)
data.pop('_comment', None)
for cve in sorted(cve for cve, info in data.items()
                  if info.get('tier') == '${tier}' or info.get('phase') == '${tier}'):
    print(cve)
"
}

# clean-apply's schema uses `phase: "clean_apply"` instead of `tier` (see
# README "Clean-apply roster") -- cves_for_tier() checks both keys above, and
# this picks which single-value list the outer loop iterates so the rest of
# the phase-1/phase-2 machinery (built around iterating "tiers") needs no
# further special-casing.
if [[ "$ROSTER_NAME" == "clean-apply" ]]; then
    ROSTER_TIERS=("clean_apply")
else
    ROSTER_TIERS=("easy" "medium" "hard")
fi

TOTAL_PLANNED=0
for tier in "${ROSTER_TIERS[@]}"; do
    while IFS= read -r cve_id; do
        [[ -z "$cve_id" ]] && continue
        is_selected_cve "$cve_id" && TOTAL_PLANNED=$((TOTAL_PLANNED + 1))
    done < <(cves_for_tier "$tier")
done

# ── Cost visibility + single confirmation (covers phase 1 AND phase 2) ─────
if [[ "$DRY_RUN" != true ]]; then
    if [[ -n "$CUSTOM_MODEL_LABEL" ]]; then
        weight=$(python3 -c "print(f'{float(${TOTAL_PLANNED}):.2f}')")
        log "Relative cost weight uses a neutral 1.00 multiplier for custom model '$CUSTOM_MODEL_LABEL'."
    else
        weight=$(python3 -c "
from tests.benchmark.bench_lib import relative_cost_weight, resolve_models
models = resolve_models('${MODELS_SELECTOR}')
print(f'{relative_cost_weight(models, ${TOTAL_PLANNED}):.2f}')
")
    fi
    log "Relative cost weight (models x planned CVEs, NOT a credit prediction): $weight"

    if [[ -s "$AGENT_CSV" ]] && [[ $(wc -l < "$AGENT_CSV") -gt 1 ]]; then
        projected=$(python3 -c "
from tests.benchmark.bench_lib import project_remaining_cost
p = project_remaining_cost('${AGENT_CSV}', ${TOTAL_PLANNED})
print('n/a' if p is None else f'{p:.2f}')
")
        log "Projected remaining cost, based on observed average so far (NOT a prediction): $projected"
    fi

    read -r -p "Proceed with the benchmark run? [y/N]: " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { log "Aborted."; exit 0; }
else
    log "[dry-run] Would print relative cost weight and prompt for confirmation here."
fi

# ── Phase 1: agent-run phase ─────────────────────────────────────────────────
row_exists() {
    local csv="$1" cve_id="$2" model="$3"
    awk -F, -v c="$cve_id" -v m="$model" 'NR>1 && $1==c && $3==m {found=1} END{exit !found}' "$csv"
}

run_agent_phase() {
    source_build_env

    # Kiro is required when it drives either phase. An OpenAI agent run with
    # --skip-judge or an OpenAI judge does not need kiro-cli at all.
    local needs_kiro=false
    if [[ "$AGENT_BACKEND" == "kiro" \
            || ("$SKIP_JUDGE" != true && "$JUDGE_BACKEND" == "kiro") ]]; then
        needs_kiro=true
    fi
    if [[ "$DRY_RUN" != true && "$needs_kiro" == true ]] \
            && ! command -v kiro-cli >/dev/null 2>&1; then
        die "kiro-cli not found on PATH — the selected agent or judge requires it. Install/activate kiro-cli (https://kiro.dev/docs/install) before benchmarking."
    fi

    local models_list
    if [[ -n "$CUSTOM_MODEL_LABEL" ]]; then
        models_list="$CUSTOM_MODEL_LABEL"
    else
        models_list=$(python3 -c "
from tests.benchmark.bench_lib import resolve_models
for m in resolve_models('${MODELS_SELECTOR}'):
    print(m['name'])
")
    fi

    for tier in "${ROSTER_TIERS[@]}"; do
        while IFS= read -r cve_id; do
            [[ -z "$cve_id" ]] && continue
            is_selected_cve "$cve_id" || continue
            while IFS= read -r model; do
                [[ -z "$model" ]] && continue

                if row_exists "$AGENT_CSV" "$cve_id" "$model"; then
                    log "SKIP (resumed): $cve_id / $model"
                    continue
                fi

                if [[ "$DRY_RUN" == true ]]; then
                    log "[dry-run] would run: $cve_id (tier=$tier) x $model"
                    continue
                fi

                log "=== $cve_id (tier=$tier) x $model ==="
                local run_log="${RESULTS_DIR}/${cve_id}_${model}.log"
                log "  live log: tail -f $run_log"
                setup_cve_branch "$cve_id" "$run_log" "bench"

                local exit_status="SETUP_FAILED" credits="" duration_s=0 commands=0
                local diff_bucket="-" diff_lines="-"

                if [[ "$SETUP_CVE_STATUS" == "OK" ]]; then
                    local start_s
                    start_s=$(date +%s)
                    local agent_exit=0
                    # --trust still prompts once for the trust-mode warning
                    # (cve_agent/__main__.py's _show_trust_warning); feed it
                    # "y" via a pipe instead of </dev/null, matching
                    # test_cve_corrector.sh's `echo "y" | python3 -m cve_agent`
                    # pattern — </dev/null would hit EOF on that input() call
                    # and crash the process before any AI session starts.
                    #
                    # Launched in the background (not foreground) so the
                    # SIGINT/SIGTERM trap can fire promptly: `wait` is
                    # interruptible by a trapped signal, whereas a foreground
                    # child would defer the trap until it exits. `setsid` puts
                    # the agent in its own process group; $! is that group's
                    # leader, so on_interrupt can `kill -- -$AGENT_PGID` the
                    # whole tree.
                    local requested_model="$model"
                    if [[ -n "$CUSTOM_MODEL_LABEL" ]]; then
                        requested_model="$AGENT_MODEL"
                    fi
                    local artifact_data_root="" artifact_dir=""
                    mkdir -p "${RESULTS_DIR}/agent-artifacts"
                    artifact_data_root=$(mktemp -d \
                        "${RESULTS_DIR}/agent-artifacts/${cve_id}_${model}.XXXXXX") \
                        || die "Cannot create host-owned artifact root"
                    local -a agent_command=(python3 -m cve_agent \
                        --cve-info "$CVE_METADATA" \
                        --cve-id "$cve_id" \
                        --backend "$AGENT_BACKEND" \
                        --trust \
                        --no-knowledge \
                        --meta-layer "${OE_DIR}/meta" \
                        --mirror-dir "$MIRROR_DIR" \
                        --clean)
                    if [[ -n "$requested_model" ]]; then
                        agent_command+=(--model "$requested_model")
                    fi
                    if [[ -n "$SESSION_TIMEOUT" ]]; then
                        agent_command+=(--session-timeout "$SESSION_TIMEOUT")
                    fi
                    echo "y" | CVE_TOOLS_DATA_DIR="$artifact_data_root" \
                        setsid timeout "$RUN_TIMEOUT" "${agent_command[@]}" \
                        >> "$run_log" 2>&1 &
                    AGENT_PGID=$!
                    wait "$AGENT_PGID" || agent_exit=$?
                    AGENT_PGID=""
                    duration_s=$(( $(date +%s) - start_s ))

                    # The root is unique to this host-launched process, and its
                    # location is filtered out of the Kiro child environment.
                    # Select the sole created run directory out-of-band; model
                    # text in the combined stdout/stderr log is never consulted.
                    artifact_dir=$(python3 - "$artifact_data_root" "$cve_id" <<'PY'
import sys
from pathlib import Path

case_root = Path(sys.argv[1]) / 'results' / 'cases' / sys.argv[2]
try:
    runs = [entry for entry in case_root.iterdir()
            if entry.is_dir() and not entry.is_symlink()]
except OSError:
    runs = []
if len(runs) != 1:
    raise SystemExit(1)
print(runs[0].resolve(strict=True))
PY
                    ) || artifact_dir=""

                    # An agent that never ran because the environment can't
                    # trigger it (missing/unusable kiro-cli, un-installable
                    # agent configs) would fail identically for every model and
                    # CVE — that's not a model-quality signal, so stop the whole
                    # benchmark instead of recording a wall of identical rows.
                    if python3 -c "
import sys
from tests.benchmark.bench_lib import is_agent_env_failure
with open('${run_log}', encoding='utf-8', errors='replace') as f:
    sys.exit(0 if is_agent_env_failure(f.read()) else 1)
"; then
                        reset_oe_tree >> "$run_log" 2>&1 || true
                        die "Agent could not be triggered due to an environment problem (see ${run_log}). Fix the environment (e.g. install/activate kiro-cli) and re-run; use --resume ${RESULTS_DIR} to keep completed rows."
                    fi


                    if [[ $agent_exit -eq 0 ]]; then
                        exit_status="0"
                    elif [[ $agent_exit -eq 124 || $agent_exit -eq 137 ]]; then
                        exit_status="TIMEOUT"
                    else
                        exit_status="$agent_exit"
                    fi

                    credits=$(python3 -c "
from cve_agent.metrics import parse_kiro_credits
with open('${run_log}', encoding='utf-8', errors='replace') as f:
    c = parse_kiro_credits(f.read())
print('' if c is None else c)
")
                    commands=$(python3 - "$run_log" "$artifact_dir" \
                        "$cve_id" "$AGENT_BACKEND" "$requested_model" <<'PY'
import sys
from pathlib import Path

from tests.benchmark.bench_lib import (
    BenchmarkArtifactExpectation,
    count_tool_calls,
)
from tests.benchmark.benchmark_manifest import resolve_backend_identity

log_path, artifact_path, cve_id, selector, requested_model = sys.argv[1:]
identity = resolve_backend_identity(selector, requested_model or None)
expected = BenchmarkArtifactExpectation(
    cve_id,
    str(identity['backend']),
    identity['profile'] if isinstance(identity['profile'], str) else None,
    str(identity['model']),
)
with open(log_path, encoding='utf-8', errors='replace') as handle:
    transcript = handle.read()
artifact_dir = Path(artifact_path) if artifact_path else None
print(count_tool_calls(transcript, artifact_dir, expected))
PY
                    )

                    # Preserve generated recipe patches before classifying the
                    # durable result. A strict semantic gate may make cve-agent
                    # exit non-zero after the workflow and build completed.
                    save_generated_patches "$cve_id" "$model"

                    local durable_summary="" candidate_ready=false
                    read -r durable_summary candidate_ready < <(python3 - \
                        "$artifact_dir" "$cve_id" "$AGENT_BACKEND" \
                        "$requested_model" <<'PY'
import sys
from pathlib import Path

from tests.benchmark.bench_lib import (
    BenchmarkArtifactExpectation,
    benchmark_artifact_outcome,
)
from tests.benchmark.benchmark_manifest import resolve_backend_identity

artifact_path, cve_id, selector, requested_model = sys.argv[1:]
identity = resolve_backend_identity(selector, requested_model or None)
expected = BenchmarkArtifactExpectation(
    cve_id,
    str(identity['backend']),
    identity['profile'] if isinstance(identity['profile'], str) else None,
    str(identity['model']),
)
outcome = (
    benchmark_artifact_outcome(Path(artifact_path), expected)
    if artifact_path else None
)
if outcome is None:
    print('- false')
else:
    print(outcome[0], 'true' if outcome[1] else 'false')
PY
                    )
                    if [[ "$durable_summary" == "SECURITY_VERIFIED" ]]; then
                        exit_status="0"
                    elif [[ "$durable_summary" != "-" ]]; then
                        exit_status="$durable_summary"
                    fi

                    # A skipped durable outcome has no candidate. Completed,
                    # built outcomes remain comparable even when the semantic
                    # release gate requires review and returned exit 14.
                    if [[ "$durable_summary" == "SKIPPED" ]]; then
                        diff_bucket="skipped"
                    elif [[ "$candidate_ready" == true \
                            || "$exit_status" == "0" ]]; then
                        local diff_output
                        diff_output=$(compare_patches_detailed "$cve_id" "$RESULTS_DIR" "meta") || true
                        diff_lines=$(echo "$diff_output" | grep "^DIFF_CHANGES:" | cut -d: -f2 || echo "-")
                        diff_bucket=$(python3 -c "
from tests.benchmark.bench_lib import classify_diff_bucket
diff_file = '${RESULTS_DIR}/${cve_id}_differences.txt'
try:
    with open(diff_file) as f:
        text = f.read()
except OSError:
    text = None
print(classify_diff_bucket(text))
")
                        # For a partial overlap, report diff_lines scoped to the
                        # shared files (what the judge sees), not the whole-patch
                        # divergence, which is dominated by the missing/extra files.
                        if [[ "$diff_bucket" == "partial" ]]; then
                            diff_lines=$(python3 -c "
from tests.benchmark.bench_lib import scope_diff_to_common_files, count_diff_changed_lines
diff_patch = '${RESULTS_DIR}/${cve_id}_differences_diff.patch'
try:
    with open(diff_patch, encoding='utf-8', errors='replace') as f:
        text = f.read()
except OSError:
    text = ''
print(count_diff_changed_lines(scope_diff_to_common_files(text)))
")
                        fi
                        # compare_patches_detailed writes the differences report
                        # keyed by CVE only; rename it per-model so each model's
                        # comparison survives the next model's run (which would
                        # otherwise overwrite it) and the judge phase reads the
                        # right model's diff.
                        for _sfx in differences.txt differences_diff.patch; do
                            if [[ -f "${RESULTS_DIR}/${cve_id}_${_sfx}" ]]; then
                                mv -f "${RESULTS_DIR}/${cve_id}_${_sfx}" "${RESULTS_DIR}/${cve_id}_${model}_${_sfx}"
                            fi
                        done
                    fi
                fi

                # cve-agent's own verdict, read from the log rather than
                # inferred from the exit code. The exit status collapses
                # skipped (a "not applicable" verdict -- exit 0, but NOT a
                # backport) with a real success, and escalated (asking for a
                # human -- the correct outcome when the fix is out of scope)
                # with a genuine failure. Recording it keeps those four
                # distinguishable in the report.
                # A 'skipped' outcome has several unrelated causes, only one of
                # which is the model's own claim -- record which, so the report
                # cannot accuse a model of dismissing a CVE it never saw.
                local outcome="" skip_reason=""
                if [[ -f "$run_log" ]]; then
                    read -r outcome skip_reason < <(python3 -c "
from tests.benchmark.bench_lib import parse_agent_outcome, parse_skip_reason
with open('${run_log}', encoding='utf-8', errors='replace') as f:
    text = f.read()
outcome = parse_agent_outcome(text)
reason = parse_skip_reason(text) if outcome == 'skipped' else ''
print(outcome or '-', reason or '-')
")
                    [[ "$outcome" == "-" ]] && outcome=""
                    [[ "$skip_reason" == "-" ]] && skip_reason=""
                fi

                echo "${cve_id},${tier},${model},${exit_status},${outcome},${skip_reason},${credits},${duration_s},${commands},${diff_bucket},${diff_lines}" >> "$AGENT_CSV"
                log "  -> exit=${exit_status} outcome=${outcome:-?}${skip_reason:+ (${skip_reason})} credits=${credits} duration=${duration_s}s commands=${commands} bucket=${diff_bucket} diff_lines=${diff_lines}"

                # Always reset, regardless of outcome, to recover for the next run.
                reset_oe_tree >> "$run_log" 2>&1
            done <<< "$models_list"
        done < <(cves_for_tier "$tier")
    done
}

run_agent_phase

# ── Phase 2: judge phase ─────────────────────────────────────────────────────
if [[ "$SKIP_JUDGE" == true ]]; then
    log "Skipping judge phase (--skip-judge)."
elif [[ "$DRY_RUN" == true ]]; then
    log "[dry-run] Would run the judge phase here."
else
    log "=== Judge phase ==="
    to_judge=$(python3 -c "
import csv
from tests.benchmark.bench_lib import filter_for_judging
with open('${AGENT_CSV}', newline='') as f:
    agent_rows = list(csv.DictReader(f))
with open('${JUDGE_CSV}', newline='') as f:
    judge_rows = list(csv.DictReader(f))
for row in filter_for_judging(agent_rows, judge_rows):
    print(f\"{row['cve_id']},{row['model']},{row['diff_bucket']}\")
")

    if [[ -z "$to_judge" ]]; then
        log "Nothing to judge."
    else
        while IFS=, read -r cve_id model bucket; do
            [[ -z "$cve_id" ]] && continue
            diff_patch="${RESULTS_DIR}/${cve_id}_${model}_differences_diff.patch"
            if [[ ! -f "$diff_patch" ]]; then
                log "  SKIP $cve_id/$model: no diff patch at $diff_patch"
                continue
            fi
            log "  Judging $cve_id / $model (bucket=$bucket) ..."
            # For a 'partial' fileset overlap, judge ONLY the files common to
            # both patch sets (scope_diff_to_common_files strips the one-sided
            # missing/extra blocks). If nothing common actually differs, the
            # scoped diff is empty: the only divergence is which files were
            # touched, which the wording judge can't assess. Record that as a
            # distinct 'structural-only' verdict (no judge call) rather than
            # leaving the row unjudged -- so the report doesn't conflate it with
            # a genuinely pending row, and a resume won't re-scope it.
            #
            # judge_diff also drops comment-only changes and answers
            # 'comment-only' by itself when nothing else is left, so a reworded
            # comment never costs a model call.
            #
            # The row is written by csv.writer, not echo: the judge's reason is
            # free-form prose containing commas and quotes.
            scope="full"
            [[ "$bucket" == "partial" ]] && scope="partial"
            # stdout carries exactly two lines: the CSV row, then a short
            # human-readable summary for the console log.
            if ! payload=$(python3 - "$diff_patch" "$bucket" "$cve_id" \
                    "$model" "$scope" "$JUDGE_BACKEND" "$JUDGE_MODEL" <<'PY'
import csv
import io
import sys

from tests.benchmark.bench_lib import judge_diff, scope_diff_to_common_files

diff_patch, bucket, cve_id, model, scope, backend, judge_model = sys.argv[1:]
with open(diff_patch, encoding='utf-8', errors='replace') as f:
    diff_text = f.read()
if bucket == 'partial':
    diff_text = scope_diff_to_common_files(diff_text)
if not diff_text.strip():
    judgment, reason, credits = 'structural-only', 'Shared files are identical; only the set of touched files differs.', None
else:
    judgment, reason, credits = judge_diff(
        diff_text, model=judge_model, backend=backend)
buf = io.StringIO()
csv.writer(buf, lineterminator='').writerow(
    [cve_id, model, judgment, reason,
     '' if credits is None else credits, scope])
print(buf.getvalue())
print(f'{judgment} (scope={scope}) -- {reason}'.replace(chr(10), ' '))
PY
            ); then
                die "Judge backend '$JUDGE_BACKEND' failed for $cve_id / $model"
            fi
            printf '%s\n' "$(printf '%s' "$payload" | head -n1)" >> "$JUDGE_CSV"
            log "    -> $(printf '%s' "$payload" | tail -n1)"
        done <<< "$to_judge"
    fi
fi

log "Done. Results in $RESULTS_DIR"
