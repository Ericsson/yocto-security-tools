#!/bin/bash
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
# CVE Agent Model Benchmark: runs cve-agent across a tiered set of CVEs and
# a selection of models, then (optionally) an AI judge pass on the diffs
# that came out moderately/majorly different from the reference patch.
#
# Depends on tests/integration/test_common.sh for the OE tree lifecycle
# (reset_oe_tree, setup_cve_branch, run_cve_corrector, compare_patches_detailed)
# — see tests/benchmark/README.md for that coupling and the required env vars.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CVE_METADATA="${REPO_ROOT}/tests/integration/test-cve-metadata-agent.json"
ROSTER_FILE="${SCRIPT_DIR}/benchmark-roster.json"

# So every inline `python3 -c "from tests.benchmark.bench_lib import ..."`
# call below can just import directly, without each one repeating its own
# `sys.path.insert(0, '${REPO_ROOT}')` line.
export PYTHONPATH="${REPO_ROOT}${PYTHONPATH:+:${PYTHONPATH}}"

RETIER=false
DRY_RUN=false
SKIP_JUDGE=false
MODELS_SELECTOR="default"
RESUME_DIR=""
RUN_TIMEOUT="${RUN_TIMEOUT:-3600}"  # per cve-agent invocation, seconds
JUDGE_MODEL="claude-opus-4.8"

# shellcheck source=../integration/test_common.sh
source "${REPO_ROOT}/tests/integration/test_common.sh"

die() { log "FATAL: $*"; exit 1; }

# ── CLI ──────────────────────────────────────────────────────────────────────
usage() {
    cat <<'EOF'
Usage: run_benchmark.sh [options]

The benchmark always runs the fixed 7-CVE roster in benchmark-roster.json
(1 easy, 1 medium, 5 hard) -- committed, not regenerated, so every run tests
the exact same CVEs. See tests/benchmark/README.md to change the roster.

  --retier            Re-probe the 7 roster CVEs with cve-corrector only (no
                       AI cost) and refresh their recorded exit_code/
                       diff_lines/conflict_markers/tier in benchmark-roster.json.
                       Does NOT add, remove, or reorder roster CVEs.
  --models <sel>      "default" (default), "full", or a comma-separated list
                       of model names
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
        --full) die "--full was removed: the benchmark now always runs the fixed 7-CVE roster (see --help)" ;;
        --dry-run) DRY_RUN=true ;;
        --skip-judge) SKIP_JUDGE=true ;;
        --models)
            shift
            [[ $# -gt 0 ]] || die "--models requires an argument"
            MODELS_SELECTOR="$1"
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

[[ -f "$CVE_METADATA" ]] || die "CVE metadata fixture not found: $CVE_METADATA"
[[ -f "$ROSTER_FILE" ]] || die "Fixed roster not found: $ROSTER_FILE"

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
[[ -f "$AGENT_CSV" ]] || echo "cve_id,tier,model,exit_status,credits,duration_s,commands,diff_bucket,diff_lines" > "$AGENT_CSV"
[[ -f "$JUDGE_CSV" ]] || echo "cve_id,model,judgment,judge_credits" > "$JUDGE_CSV"


# ── Fixed roster: re-verify (optional) then read ────────────────────────────
# The 7 CVEs in benchmark-roster.json are the entire candidate pool -- always
# the same CVEs, every run. --retier re-probes them with cve-corrector only
# (no AI cost) to refresh their recorded stats; it never changes which CVEs
# are in the roster.
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
    count=$(echo "$cve_ids" | wc -l)
    while IFS= read -r cve_id; do
        [[ -z "$cve_id" ]] && continue
        i=$((i + 1))
        local recipe series_len
        read -r recipe series_len <<< "$(python3 -c "
import json
with open('${ROSTER_FILE}') as f:
    data = json.load(f)
entry = data['${cve_id}']
print(entry['recipe'], entry['series_len'])
")"

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

        local conflict_markers=0 mirror_gap_only=False
        if [[ "$exit_code" != "0" ]]; then
            read -r mirror_gap_only conflict_markers <<< "$(python3 -c "
from tests.benchmark.bench_lib import count_conflict_markers, is_mirror_gap_only
with open('${log_file}') as f:
    text = f.read()
print(is_mirror_gap_only(text), count_conflict_markers(text))
")"
        fi

        local tier
        tier=$(python3 -c "
from tests.benchmark.bench_lib import score_tier
print(score_tier(${exit_code}, ${diff_lines}, ${series_len}))
")
        log "  exit=$exit_code diff_lines=$diff_lines series_len=$series_len conflict_markers=$conflict_markers mirror_gap_only=$mirror_gap_only -> tier=$tier"
        if [[ "$mirror_gap_only" == "True" ]]; then
            log "  WARNING: $cve_id now fails with a mirror gap, not a genuine conflict/success -- stats updated, but consider swapping it out of the fixed roster (see README)"
        fi

        python3 -c "
import json
path = '${ROSTER_FILE}'
with open(path) as f:
    data = json.load(f)
data['${cve_id}'] = {
    'tier': '${tier}', 'recipe': '${recipe}', 'exit_code': ${exit_code},
    'diff_lines': ${diff_lines}, 'series_len': ${series_len},
    'conflict_markers': ${conflict_markers},
}
with open(path, 'w') as f:
    json.dump(data, f, indent=2, sort_keys=True)
    f.write('\n')
"
        reset_oe_tree >> "$log_file" 2>&1
    done <<< "$cve_ids"
    log "Refreshed stats for $count roster CVE(s) in $ROSTER_FILE"
}

[[ "$RETIER" == true ]] && retier_roster

cves_for_tier() {
    local tier="$1"
    python3 -c "
import json
with open('${ROSTER_FILE}') as f:
    data = json.load(f)
data.pop('_comment', None)
for cve in sorted(cve for cve, info in data.items() if info['tier'] == '${tier}'):
    print(cve)
"
}

TOTAL_PLANNED=0
for tier in easy medium hard; do
    n=$(cves_for_tier "$tier" | wc -l)
    TOTAL_PLANNED=$((TOTAL_PLANNED + n))
done

# ── Cost visibility + single confirmation (covers phase 1 AND phase 2) ─────
if [[ "$DRY_RUN" != true ]]; then
    weight=$(python3 -c "
from tests.benchmark.bench_lib import relative_cost_weight, resolve_models
models = resolve_models('${MODELS_SELECTOR}')
print(f'{relative_cost_weight(models, ${TOTAL_PLANNED}):.2f}')
")
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
    local models_list
    models_list=$(python3 -c "
from tests.benchmark.bench_lib import resolve_models
for m in resolve_models('${MODELS_SELECTOR}'):
    print(m['name'])
")

    for tier in easy medium hard; do
        while IFS= read -r cve_id; do
            [[ -z "$cve_id" ]] && continue
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
                    echo "y" | setsid timeout "$RUN_TIMEOUT" python3 -m cve_agent \
                        --cve-info "$CVE_METADATA" \
                        --cve-id "$cve_id" \
                        --model "$model" \
                        --backend kiro \
                        --trust \
                        --no-knowledge \
                        --meta-layer "${OE_DIR}/meta" \
                        --mirror-dir "$MIRROR_DIR" \
                        --clean \
                        >> "$run_log" 2>&1 || agent_exit=$?
                    duration_s=$(( $(date +%s) - start_s ))

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
                    commands=$(python3 -c "
from tests.benchmark.bench_lib import count_tool_calls
with open('${run_log}', encoding='utf-8', errors='replace') as f:
    print(count_tool_calls(f.read()))
")

                    # cve-agent's SUCCESS and SKIPPED result statuses both exit
                    # 0 (see cve_agent/__init__.py's ResultStatus and
                    # __main__.py's success-status tuple) — SKIPPED means "the
                    # corrector bailed out before touching anything" (e.g. a
                    # pre-existing build failure unrelated to this CVE), so
                    # there is no generated patch to compare against the
                    # reference fix. Detect it from the CLI's own printed
                    # "✓ <cve>: skipped" line and record it distinctly instead
                    # of running compare_patches_detailed against nothing.
                    if [[ "$exit_status" == "0" ]] && grep -q "✓ ${cve_id}: skipped" "$run_log"; then
                        diff_bucket="skipped"
                    elif [[ "$exit_status" == "0" ]]; then
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
                    fi
                fi

                echo "${cve_id},${tier},${model},${exit_status},${credits},${duration_s},${commands},${diff_bucket},${diff_lines}" >> "$AGENT_CSV"
                log "  -> exit=${exit_status} credits=${credits} duration=${duration_s}s commands=${commands} bucket=${diff_bucket} diff_lines=${diff_lines}"

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
    print(f\"{row['cve_id']},{row['model']}\")
")

    if [[ -z "$to_judge" ]]; then
        log "Nothing to judge."
    else
        while IFS=, read -r cve_id model; do
            [[ -z "$cve_id" ]] && continue
            diff_patch="${RESULTS_DIR}/${cve_id}_differences_diff.patch"
            if [[ ! -f "$diff_patch" ]]; then
                log "  SKIP $cve_id/$model: no diff patch at $diff_patch"
                continue
            fi
            log "  Judging $cve_id / $model ..."
            result=$(python3 -c "
from tests.benchmark.bench_lib import judge_diff
with open('${diff_patch}', encoding='utf-8', errors='replace') as f:
    diff_text = f.read()
judgment, credits = judge_diff(diff_text, model='${JUDGE_MODEL}')
print(f'{judgment},{\"\" if credits is None else credits}')
")
            echo "${cve_id},${model},${result}" >> "$JUDGE_CSV"
            log "    -> ${result}"
        done <<< "$to_judge"
    fi
fi

log "Done. Results in $RESULTS_DIR"
