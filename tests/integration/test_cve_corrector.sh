#!/bin/bash
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
# Test harness for cve_corrector: for each CVE, removes its patch from openembedded-core,
# runs cve_corrector to regenerate it, then compares old vs new patch.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# Prefer proprietary metadata from extra/ if available, fall back to open-source test data
if [[ -z "${CVE_METADATA:-}" ]]; then
    if [[ -f "${REPO_ROOT}/extra/test-cve-metadata.json" ]]; then
        CVE_METADATA="${REPO_ROOT}/extra/test-cve-metadata.json"
    else
        CVE_METADATA="${SCRIPT_DIR}/test-cve-metadata.json"
    fi
fi
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="${SCRIPT_DIR}/test-results/bulk_${TIMESTAMP}"
RESUME_DIR=""
TEST_TIMEOUT=3600  # 60 minutes per CVE
MIN_YEAR="${MIN_YEAR:-2024}"  # Skip CVEs older than this year
SKIP_MIRRORS=false
FULL_ONLY=false
COMPONENTS=()  # empty = all

# shellcheck source=test_common.sh
source "${SCRIPT_DIR}/test_common.sh"

# ── Run test for single CVE ──────────────────────────────────────────────────
test_single_cve() {
    local cve_id="$1" recipe="$2" extra_flags="$3" mode="$4"
    local log_file="${LOG_DIR}/${cve_id}_${mode}.log"

    > "$log_file"
    setup_cve_branch "$cve_id" "$log_file" "$mode"

    case "$SETUP_CVE_STATUS" in
        NOTFOUND) CVE_CORRECTOR_RESULT="6:-:-:-"; return ;;
        GIT_ERROR) CVE_CORRECTOR_RESULT="7:-:-:-"; return ;;
    esac

    run_cve_corrector "$cve_id" "$log_file" "$extra_flags"

    # If corrector failed with a recoverable error, retry with cve_agent (skip for skip-build-ptest mode)
    local exit_code
    exit_code=$(echo "$CVE_CORRECTOR_RESULT" | cut -d: -f1)
    if [[ "$exit_code" =~ ^(1|3|4|5)$ && "$mode" != "skip-build-ptest" ]]; then
        log "  Corrector failed (exit $exit_code), retrying with cve_agent..."
        local agent_log="${LOG_DIR}/${cve_id}_${mode}_agent.log"
        setup_cve_branch "$cve_id" "$agent_log" "${mode}_agent"
        cd "$SCRIPT_DIR"
        local agent_exit=0
        local -a flags_arr=()
        [[ -n "$extra_flags" ]] && read -ra flags_arr <<< "$extra_flags"
        # Run agent with timeout — kill entire process group on expiry
        AGENT_LOG="$agent_log" setsid bash -c '
            echo "y" | python3 -m cve_agent \
                --cve-info "$1" \
                --cve-id "$2" \
                --meta-layer "$3" \
                --mirror-dir "$4" \
                --trust \
                --clean \
                "${@:5}" \
                >> "$AGENT_LOG" 2>&1
        ' _ "$CVE_METADATA" "$cve_id" "${OE_DIR}/meta" "$MIRROR_DIR" "${flags_arr[@]}" &
        local agent_pid=$!
        ( sleep "$TEST_TIMEOUT"
          log "  TIMEOUT: cve_agent for $cve_id exceeded ${TEST_TIMEOUT}s ($(( TEST_TIMEOUT / 60 )) min), killing..."
          kill -TERM -- -"$agent_pid" 2>/dev/null
          sleep 5
          kill -KILL -- -"$agent_pid" 2>/dev/null
        ) &
        local watchdog_pid=$!
        wait "$agent_pid" 2>/dev/null || agent_exit=$?
        kill "$watchdog_pid" 2>/dev/null; wait "$watchdog_pid" 2>/dev/null || true
        if [[ "$agent_exit" -eq 0 ]]; then
            # Compare agent-generated patches against originals
            local agent_diff_output
            agent_diff_output=$(compare_patches_detailed "$cve_id" "$LOG_DIR" "meta") || true
            local a_changes a_patches a_files
            a_changes=$(echo "$agent_diff_output" | grep "^DIFF_CHANGES:" | cut -d: -f2 || echo "agent")
            a_patches=$(echo "$agent_diff_output" | grep "^DIFF_PATCHES:" | cut -d: -f2 || echo "-")
            a_files=$(echo "$agent_diff_output" | grep "^DIFF_FILES:" | cut -d: -f2 || echo "-")
            CVE_CORRECTOR_RESULT="0:agent:${a_patches}:${a_files}"
            # Store agent diff changes separately (status stays AGENT_RESOLVED via "agent" marker)
            echo "$agent_diff_output" >> "$agent_log"
        elif [[ "$agent_exit" -gt 128 ]]; then
            log "  TIMEOUT: cve_agent for $cve_id did not complete within ${TEST_TIMEOUT}s ($(( TEST_TIMEOUT / 60 )) min). Continuing."
            echo "AGENT TIMEOUT after ${TEST_TIMEOUT}s" >> "$agent_log"
            CVE_CORRECTOR_RESULT="99:-:-:-"
        else
            log "  Agent also failed (exit $agent_exit)"
            # Preserve original corrector exit code but mark agent attempted
            CVE_CORRECTOR_RESULT="${exit_code}:agent_fail:-:-"
        fi
    fi
}

# ── CVE iteration loop ───────────────────────────────────────────────────────
run_loop() {
    local mode="$1" extra_flags="$2" cve_list="$3" failed_recipes="$4"
    local results_file="${LOG_DIR}/results_${mode}.csv"
    local summary_file="${LOG_DIR}/summary_${mode}.txt"
    local total success=0 fail=0 skip=0 identical=0 resumed=0
    total=$(echo "$cve_list" | wc -l)

    log "=== Run: $mode ==="

    # Import previous results on resume
    local prev_results=""
    if [[ -n "$RESUME_DIR" ]]; then
        local prev_file="${RESUME_DIR}/results_${mode}.csv"
        if [[ -f "$prev_file" ]]; then
            prev_results=$(awk -F, 'NR>1{print $1}' "$prev_file" | sort)
            local prev_count
            prev_count=$(echo "$prev_results" | wc -l)
            log "Resuming: importing $prev_count results from $prev_file"
            # Seed results file with previous data (skip if same dir)
            if [[ "$prev_file" != "$results_file" ]]; then
                cp "$prev_file" "$results_file"
                while IFS= read -r cve; do
                    for f in "${RESUME_DIR}/${cve}_${mode}"*.log "${RESUME_DIR}/${cve}_"*.patch; do
                        [[ -f "$f" ]] && [[ ! -f "${LOG_DIR}/$(basename "$f")" ]] && cp "$f" "$LOG_DIR/"
                    done
                done <<< "$prev_results"
            fi
            # Recompute counters from imported rows
            while IFS=, read -r _ _ status _ _ _; do
                case "$status" in
                    SUCCESS|IDENTICAL|AGENT_RESOLVED|ALREADY_APPLIED) success=$((success + 1))
                        [[ "$status" == "IDENTICAL" || "$status" == "ALREADY_APPLIED" ]] && identical=$((identical + 1)) ;;
                    SKIP*) skip=$((skip + 1)) ;;
                    FAIL*) fail=$((fail + 1)) ;;
                esac
            done < <(tail -n +2 "$prev_file")
        else
            log "No previous results for mode $mode, starting fresh"
            echo "cve_id,recipe,status,exit_code,diff_changes,diff_patches,diff_files,duration_s" > "$results_file"
        fi
    else
        echo "cve_id,recipe,status,exit_code,diff_changes,diff_patches,diff_files,duration_s" > "$results_file"
    fi

    local current=0
    while IFS=: read -r cve_id recipe; do
        current=$((current + 1))
        local log_file="${LOG_DIR}/${cve_id}_${mode}.log"
        echo -n "[$(date +%H:%M:%S)] [$current/$total] $cve_id ($recipe) log: $log_file ... "

        if [[ -n "$failed_recipes" ]] && echo "$failed_recipes" | grep -qx "$recipe"; then
            echo "SKIP (fetch failed)"
            skip=$((skip + 1))
            echo "$cve_id,$recipe,SKIP_FETCH,,-,-,-,0" >> "$results_file"
            continue
        fi

        # Skip CVEs already in previous results
        if [[ -n "$prev_results" ]] && echo "$prev_results" | grep -qx "$cve_id"; then
            echo "SKIP (resumed)"
            resumed=$((resumed + 1))
            continue
        fi

        local start_time duration
        start_time=$(date +%s)

        # Run test (no outer timeout – cve_corrector always runs to completion,
        # only cve_agent has a timeout inside test_single_cve)
        local result_file="${LOG_DIR}/${cve_id}_${mode}_result.tmp"
        ( set +e
          test_single_cve "$cve_id" "$recipe" "$extra_flags" "$mode"
          echo "$CVE_CORRECTOR_RESULT" > "$result_file"
        ) || true
        CVE_CORRECTOR_RESULT=$(cat "$result_file" 2>/dev/null || echo "1:-:-:-")
        rm -f "$result_file"

        # Always reset OE tree after each CVE to recover from any corruption
        # (e.g. devtool finish deleting patches, broken bbappends)
        reset_oe_tree >> "${LOG_DIR}/${cve_id}_${mode}_reset.log" 2>&1 || log "  WARNING: OE tree reset failed"

        local exit_code diff_changes diff_patches diff_files
        exit_code=$(echo "$CVE_CORRECTOR_RESULT" | cut -d: -f1)
        diff_changes=$(echo "$CVE_CORRECTOR_RESULT" | cut -d: -f2)
        diff_patches=$(echo "$CVE_CORRECTOR_RESULT" | cut -d: -f3)
        diff_files=$(echo "$CVE_CORRECTOR_RESULT" | cut -d: -f4)
        duration=$(( $(date +%s) - start_time ))

        local exit_name
        case $exit_code in
            0) exit_name="SUCCESS" ;;
            1) exit_name="CONFLICT" ;;
            2) exit_name="CHECKOUT_ERROR" ;;
            3) exit_name="PTEST_ERROR" ;;
            4) exit_name="BUILD_ERROR" ;;
            5) exit_name="PATCH_ERROR" ;;
            6) exit_name="METADATA_ERROR" ;;
            7) exit_name="GIT_ERROR" ;;
            8) exit_name="PTEST_PREEXISTING" ;;
            9) exit_name="DEVTOOL_ERROR" ;;
            10) exit_name="BUILD_PREEXISTING" ;;
            11) exit_name="ALREADY_APPLIED" ;;
            12) exit_name="NOT_APPLICABLE" ;;
            99) exit_name="TIMEOUT" ;;
            *) exit_name="UNKNOWN_${exit_code}" ;;
        esac

        local status
        case $exit_code in
            0)
                success=$((success + 1))
                if [[ "$diff_changes" == "agent" ]]; then
                    status="AGENT_RESOLVED"
                    echo "✓ AGENT_RESOLVED (${duration}s) [✓$success ✗$fail ⊘$skip]"
                elif [[ "$diff_changes" == "0" ]]; then
                    status="IDENTICAL"; identical=$((identical + 1))
                    echo "✓ IDENTICAL (${duration}s) [✓$success ✗$fail ⊘$skip]"
                else
                    status="SUCCESS"
                    echo "✓ $diff_changes changes (${duration}s) [✓$success ✗$fail ⊘$skip]"
                fi ;;
            4) status="FAIL_BUILD_ERROR"; fail=$((fail + 1))
                echo "✗ BUILD_ERROR (${duration}s) [✓$success ✗$fail ⊘$skip]" ;;
            6) status="SKIP"; skip=$((skip + 1))
                echo "⊘ skipped (${duration}s) [✓$success ✗$fail ⊘$skip]" ;;
            8) status="SKIP_PTEST_PREEXISTING"; skip=$((skip + 1))
                echo "⊘ pre-existing ptest failure (${duration}s) [✓$success ✗$fail ⊘$skip]" ;;
            10) status="SKIP_BUILD_PREEXISTING"; skip=$((skip + 1))
                echo "⊘ pre-existing build failure (${duration}s) [✓$success ✗$fail ⊘$skip]" ;;
            11) status="ALREADY_APPLIED"; success=$((success + 1)); identical=$((identical + 1))
                echo "✓ ALREADY_APPLIED (${duration}s) [✓$success ✗$fail ⊘$skip]" ;;
            12) status="SKIP_NOT_APPLICABLE"; skip=$((skip + 1))
                echo "⊘ not applicable (${duration}s) [✓$success ✗$fail ⊘$skip]" ;;
            *) status="FAIL_${exit_name}"; fail=$((fail + 1))
                echo "✗ $exit_name (${duration}s) [✓$success ✗$fail ⊘$skip]" ;;
        esac

        echo "$cve_id,$recipe,$status,$exit_name,$diff_changes,$diff_patches,$diff_files,$duration" >> "$results_file"
        (( current % 10 == 0 )) && log "  Progress: $current/$total | ✓$success (${identical} identical) ✗$fail ⊘$skip"
    done <<< "$cve_list"

    local pct_success=0 testable=$((success + fail))
    (( testable > 0 )) && pct_success=$(( success * 100 / testable ))

    cat > "$summary_file" <<EOF
=== CVE Corrector Test Summary ($mode) ===
Date:       $(date)
Branch:     test/<CVE-ID>
Metadata:   $CVE_METADATA

Total CVEs:     $total
Resumed:        $resumed
Success:        $success
  Identical:    $identical
  With changes: $((success - identical))
Failed:         $fail
Skipped:        $skip
Testable:       $testable
Success Rate:   ${pct_success}%

Results CSV:    $results_file
Per-CVE logs:   ${LOG_DIR}/CVE-ID_${mode}.log
EOF
    log ""; cat "$summary_file"
    if (( fail > 0 )); then
        log ""; log "=== Failure Breakdown ($mode) ==="
        awk -F, 'NR>1 && $3 ~ /^FAIL/ {codes[$4]++} END {for(c in codes) printf "  %s: %d\n", c, codes[c]}' "$results_file" | sort
    fi
}

# ── Verification ────────────────────────────────────────────────────────────
verify_mirrors() {
    local cve_list="$1"
    [[ "$SKIP_MIRRORS" == true ]] && return
    log "=== Verifying mirrors ==="
    local components_arg=""
    [[ ${#COMPONENTS[@]} -gt 0 ]] && components_arg=$(printf ',%s' "${COMPONENTS[@]}") && components_arg="${components_arg:1}"
    local missing
    missing=$(python3 "$SCRIPT_DIR/test_utils.py" check_mirrors "$CVE_METADATA" "$MIRROR_DIR" "$MIN_YEAR" ${components_arg:+"$components_arg"})
    if [[ -n "$missing" ]]; then
        log "ERROR: Missing mirrors:"
        echo "$missing" | while read -r line; do log "  $line"; done
        die "Run fetch_mirrors.sh to download missing mirrors"
    fi
    log "All mirrors verified ✓"
}

# Sets FAILED_RECIPES global
verify_fetch() {
    local cve_list="$1"
    log "=== Verifying bitbake fetch ==="
    local recipes_to_fetch recipe_array fetch_log
    recipes_to_fetch=$(echo "$cve_list" | cut -d: -f2 | sort -u | while read -r r; do
        case "$r" in qemu-system) echo "qemu" ;; *) echo "$r" ;; esac
    done)
    mapfile -t recipe_array <<< "$recipes_to_fetch"
    log "Fetching ${#recipe_array[@]} recipes..."
    fetch_log="${LOG_DIR}/fetch.log"
    bitbake -k "${recipe_array[@]}" -c fetch 2>&1 | tee "$fetch_log" || true
    FAILED_RECIPES=$(grep -i 'ERROR.*do_fetch' "$fetch_log" | grep -oP '[^/]+(?=_[^_]+\.bb)' | sort -u || true)
    if [[ -n "$FAILED_RECIPES" ]]; then
        log "WARNING: bitbake fetch failed for:"
        echo "$FAILED_RECIPES" | while read -r r; do log "  $r"; done
        log "These recipes will be skipped."
    else
        log "All recipes fetched successfully ✓"
    fi
}

# ── Main test loop ───────────────────────────────────────────────────────────
run_tests() {
    log "=== Testing cve_corrector on each CVE ==="

    setup_oe_git
    cd "$SCRIPT_DIR"

    local cve_list
    cve_list=$(python3 "$SCRIPT_DIR/test_utils.py" list_cves "$CVE_METADATA" "$MIN_YEAR")

    if [[ ${#COMPONENTS[@]} -gt 0 ]]; then
        local filter
        filter=$(printf '|%s' "${COMPONENTS[@]}"); filter="${filter:1}"
        cve_list=$(echo "$cve_list" | grep -E ":($filter)$" || true)
        [[ -n "$cve_list" ]] || die "No CVEs found for component(s): ${COMPONENTS[*]}"
        log "Filtered to components: ${COMPONENTS[*]}"
    fi

    verify_mirrors "$cve_list"
    FAILED_RECIPES=""
    verify_fetch "$cve_list"

    [[ "$FULL_ONLY" != true ]] && run_loop "skip-build-ptest" "--skip-build --skip-ptest" "$cve_list" "$FAILED_RECIPES"
    run_loop "full" "" "$cve_list" "$FAILED_RECIPES"
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-mirrors) SKIP_MIRRORS=true ;;
            --full-only) FULL_ONLY=true ;;
            --resume)
                shift
                [[ $# -gt 0 ]] || die "--resume requires a directory argument"
                RESUME_DIR="$1"
                [[ -d "$RESUME_DIR" ]] || die "Resume directory not found: $RESUME_DIR"
                LOG_DIR="$RESUME_DIR"
                log "Resuming from $RESUME_DIR"
                ;;
            --component)
                shift
                [[ $# -gt 0 && "$1" != --* ]] || die "--component requires at least one component name"
                while [[ $# -gt 0 && "$1" != --* ]]; do
                    COMPONENTS+=("$1"); shift
                done
                continue
                ;;
            *) die "Unknown option: $1" ;;
        esac
        shift
    done

    [[ -d "$OE_DIR/.git" ]] || die "$OE_DIR is not a git repository"
    [[ -f "$CVE_METADATA" ]] || die "CVE metadata not found: $CVE_METADATA"

    mkdir -p "$LOG_DIR"
    source_build_env
    run_tests

    log "Done. Results in $LOG_DIR"
}

main "$@"
