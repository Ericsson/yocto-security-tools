#!/bin/bash
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
# Test harness for cve_corrector: for each CVE, removes its patch from openembedded-core,
# runs cve_corrector to regenerate it, then compares old vs new patch.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
ENRICHED_ROUND=false
REQUIRE_SECURITY_STATUS="${REQUIRE_SECURITY_STATUS:-}"
COMPONENTS=()  # empty = all
RESULT_SCHEMA_TOOL="${SCRIPT_DIR}/result_schema.py"
RESULTS_HEADER="cve_id,recipe,status,exit_code,diff_changes,diff_patches,diff_files,duration_s,schema_version,workflow_status,build_status,security_status,failure_class,failure_code,legacy_status,summary_state"
EVALUATION_RUN_MODE="resume-compatible-legacy"
AGENT_BACKEND="${AGENT_BACKEND:-kiro}"
AGENT_MODEL="${AGENT_MODEL:-}"

# shellcheck source=test_common.sh
source "${SCRIPT_DIR}/test_common.sh"

build_agent_flags() {
    local output_name="$1" extra_flags="$2"
    local -n output="$output_name"
    output=(--backend "$AGENT_BACKEND")
    [[ -n "$AGENT_MODEL" ]] && output+=(--model "$AGENT_MODEL")
    if [[ -n "$extra_flags" ]]; then
        local -a extra_flags_array=()
        read -ra extra_flags_array <<< "$extra_flags"
        output+=("${extra_flags_array[@]}")
    fi
}

# ── Run test for single CVE ──────────────────────────────────────────────────
remove_agent_reference_copies() {
    local cve_id="$1" mode="$2"
    local reference_copy
    for reference_copy in "${LOG_DIR}/${mode}_agent_${cve_id}_"*.patch; do
        [[ -e "$reference_copy" ]] || continue
        rm -f -- "$reference_copy"
    done
}

copy_agent_candidate() {
    local artifacts="$1" cve_id="$2" mode="$3"
    local candidate="${artifacts}/final.patch"
    [[ -f "$candidate" ]] || return 0
    cp -- "$candidate" "${LOG_DIR}/${mode}_agent_${cve_id}_candidate.patch"
}

classify_agent_summary() {
    local summary_state="$1"
    case "$summary_state" in
        SECURITY_VERIFIED) echo "AGENT_RESOLVED success" ;;
        SECURITY_REVIEW_REQUIRED|WORKFLOW_COMPLETED_UNVERIFIED)
            echo "$summary_state review" ;;
        SKIPPED) echo "SKIP_AGENT skip" ;;
        *) echo "FAIL_${summary_state} fail" ;;
    esac
}

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
        # The second setup saves another reference snapshot with an _agent_
        # name. Remove it so agent-prefixed patches are always real candidates.
        remove_agent_reference_copies "$cve_id" "$mode"
        cd "$SCRIPT_DIR"
        local agent_exit=0
        local -a flags_arr=()
        build_agent_flags flags_arr "$extra_flags"
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
        local durable_artifacts
        # -a: the agent log can contain multi-byte UTF-8 (warning icons,
        # em-dashes in escalation messages) that grep's binary-content
        # heuristic misdetects as a binary file, silently suppressing
        # stdout and losing the Artifacts: line entirely -- which drops a
        # valid SECURITY_REVIEW_REQUIRED/escalated durable result down to
        # the coarse agent_exit-code fallback below and misclassifies it
        # as a plain failure.
        durable_artifacts=$(grep -a '^Artifacts: ' "$agent_log" | tail -n 1 | cut -d' ' -f2- || true)
        local copied_artifacts="" agent_result=""
        if [[ -n "$durable_artifacts" && -d "$durable_artifacts" ]]; then
            copied_artifacts="${LOG_DIR}/${cve_id}_${mode}_artifacts"
            mkdir -p "$copied_artifacts"
            cp -a "${durable_artifacts}/." "$copied_artifacts/"
            copy_agent_candidate "$copied_artifacts" "$cve_id" "$mode"
            if [[ -f "${copied_artifacts}/result.json" ]]; then
                agent_result="${copied_artifacts}/result.json"
            fi
        fi
        local durable_result=false
        if [[ -n "$agent_result" ]] && \
                python3 "$RESULT_SCHEMA_TOOL" artifact-fields "$agent_result" > /dev/null 2>&1; then
            durable_result=true
        fi
        if [[ "$durable_result" == true ]]; then
            # A release security gate can return nonzero after the workflow and
            # build completed. Preserve its comparison and let run_loop classify
            # the authoritative durable outcome.
            local agent_diff_output
            agent_diff_output=$(compare_patches_detailed "$cve_id" "$LOG_DIR" "meta") || true
            local a_patches a_files
            a_patches=$(echo "$agent_diff_output" | grep "^DIFF_PATCHES:" | cut -d: -f2 || echo "-")
            a_files=$(echo "$agent_diff_output" | grep "^DIFF_FILES:" | cut -d: -f2 || echo "-")
            CVE_CORRECTOR_RESULT="${exit_code}:agent:${a_patches}:${a_files}:${agent_result}"
            echo "$agent_diff_output" >> "$agent_log"
        elif [[ "$agent_exit" -eq 0 ]]; then
            # Compare agent-generated patches against originals
            local agent_diff_output
            agent_diff_output=$(compare_patches_detailed "$cve_id" "$LOG_DIR" "meta") || true
            local a_patches a_files
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
    local total success=0 review=0 fail=0 skip=0 identical=0 resumed=0
    total=$(echo "$cve_list" | wc -l)

    log "=== Run: $mode ==="

    # Import previous results on resume
    local prev_results=""
    if [[ -n "$RESUME_DIR" ]]; then
        local prev_file="${RESUME_DIR}/results_${mode}.csv"
        if [[ -f "$prev_file" ]]; then
            python3 "$RESULT_SCHEMA_TOOL" migrate "$prev_file" "$mode"
            local -a resume_args=(resumable "$prev_file" "$mode")
            [[ -n "$REQUIRE_SECURITY_STATUS" ]] && resume_args+=(--required "$REQUIRE_SECURITY_STATUS")
            prev_results=$(python3 "$RESULT_SCHEMA_TOOL" "${resume_args[@]}" | sort)
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
                    SECURITY_REVIEW_REQUIRED|WORKFLOW_COMPLETED_UNVERIFIED)
                        review=$((review + 1)) ;;
                    SKIP*) skip=$((skip + 1)) ;;
                    FAIL*) fail=$((fail + 1)) ;;
                esac
            done < <(tail -n +2 "$prev_file")
        else
            log "No previous results for mode $mode, starting fresh"
            echo "$RESULTS_HEADER" > "$results_file"
        fi
    else
        echo "$RESULTS_HEADER" > "$results_file"
    fi

    local current=0
    while IFS=: read -r cve_id recipe; do
        current=$((current + 1))
        local log_file="${LOG_DIR}/${cve_id}_${mode}.log"
        echo -n "[$(date +%H:%M:%S)] [$current/$total] $cve_id ($recipe) log: $log_file ... "

        if [[ -n "$failed_recipes" ]] && echo "$failed_recipes" | grep -qx "$recipe"; then
            echo "SKIP (fetch failed)"
            skip=$((skip + 1))
            local skip_fields
            skip_fields=$(python3 "$RESULT_SCHEMA_TOOL" fields SKIP_FETCH)
            echo "$cve_id,$recipe,SKIP_FETCH,,-,-,-,0,$skip_fields" >> "$results_file"
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

        local exit_code diff_changes diff_patches diff_files durable_result
        exit_code=$(echo "$CVE_CORRECTOR_RESULT" | cut -d: -f1)
        diff_changes=$(echo "$CVE_CORRECTOR_RESULT" | cut -d: -f2)
        diff_patches=$(echo "$CVE_CORRECTOR_RESULT" | cut -d: -f3)
        diff_files=$(echo "$CVE_CORRECTOR_RESULT" | cut -d: -f4)
        durable_result=$(echo "$CVE_CORRECTOR_RESULT" | cut -d: -f5-)
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
            16) exit_name="IGNORED_BY_STATUS" ;;
            17) exit_name="PREP_BASE_MISMATCH" ;;
            99) exit_name="TIMEOUT" ;;
            *) exit_name="UNKNOWN_${exit_code}" ;;
        esac

        local status schema_fields=""
        if [[ -n "$durable_result" && -f "$durable_result" ]]; then
            schema_fields=$(python3 "$RESULT_SCHEMA_TOOL" artifact-fields "$durable_result")
            local summary_state result_bucket
            summary_state=$(echo "$schema_fields" | cut -d, -f8)
            read -r status result_bucket < <(classify_agent_summary "$summary_state")
            exit_name="$summary_state"
            case "$result_bucket" in
                success)
                    success=$((success + 1))
                    echo "✓ $status (${duration}s) [✓$success !$review ✗$fail ⊘$skip]" ;;
                review)
                    review=$((review + 1))
                    echo "! $status (${duration}s) [✓$success !$review ✗$fail ⊘$skip]" ;;
                skip)
                    skip=$((skip + 1))
                    echo "⊘ $status (${duration}s) [✓$success !$review ✗$fail ⊘$skip]" ;;
                fail)
                    fail=$((fail + 1))
                    echo "✗ $summary_state (${duration}s) [✓$success !$review ✗$fail ⊘$skip]" ;;
            esac
        else
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
        fi

        if [[ -z "$schema_fields" ]]; then
            local -a schema_args=(fields "$status")
            if [[ ( "$mode" == "full" || "$mode" == "full-enriched" ) && "$exit_code" -eq 0 ]]; then
                schema_args+=(--build-evidence)
            fi
            [[ "$status" == FAIL* ]] && schema_args+=(--failure-code "$exit_name")
            schema_fields=$(python3 "$RESULT_SCHEMA_TOOL" "${schema_args[@]}")
        fi
        echo "$cve_id,$recipe,$status,$exit_name,$diff_changes,$diff_patches,$diff_files,$duration,$schema_fields" >> "$results_file"
        (( current % 10 == 0 )) && log "  Progress: $current/$total | ✓$success (${identical} identical) !$review ✗$fail ⊘$skip"
    done <<< "$cve_list"

    local pct_success=0 testable=$((success + review + fail))
    (( testable > 0 )) && pct_success=$(( success * 100 / testable ))

    cat > "$summary_file" <<EOF
=== CVE Corrector Test Summary ($mode) ===
Evaluation mode: $EVALUATION_RUN_MODE (not a valid crossover comparison)
Date:       $(date)
Branch:     test/<CVE-ID>
Metadata:   $CVE_METADATA

Total CVEs:     $total
Resumed:        $resumed
Success:        $success
  Identical:    $identical
  With changes: $((success - identical))
Review needed:  $review
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
    # -a: bitbake fetch output can include non-UTF8 bytes from a tool's
    # own stderr; grep's binary-content heuristic would otherwise silently
    # suppress stdout and this check would never see a real fetch failure.
    FAILED_RECIPES=$(grep -ai 'ERROR.*do_fetch' "$fetch_log" | grep -oP '[^/]+(?=_[^_]+\.bb)' | sort -u || true)
    if [[ -n "$FAILED_RECIPES" ]]; then
        log "WARNING: bitbake fetch failed for:"
        echo "$FAILED_RECIPES" | while read -r r; do log "  $r"; done
        log "These recipes will be skipped."
    else
        log "All recipes fetched successfully ✓"
    fi
}

# ── Ground-truth enrichment (round 2) ───────────────────────────────────────
# Produces a corrected copy of $CVE_METADATA using enrich_metadata_from_oe.py,
# the same Upstream-Status-backed ground-truth recovery the benchmark roster
# relies on (see tests/benchmark/README.md "Roster files" and
# tests/integration/enrich_metadata_from_oe.py's module docstring). This finds
# the upstream commit each OE-Core patch itself declares via
# "Upstream-Status: Backport [<url>]" and prepends it ahead of whatever the
# public trackers (Debian/OSV/CVEList/NVD/UCT) guessed, so round 2 measures
# cve_corrector against the hash OE-Core actually backported rather than a
# tracker's best guess.
ENRICH_TOOL="${SCRIPT_DIR}/enrich_metadata_from_oe.py"
ENRICHED_METADATA=""

# Sets ENRICHED_METADATA to a corrected copy of $CVE_METADATA. Logs what the
# enrichment changed to ${LOG_DIR}/enrich_metadata.log.
prepare_enriched_metadata() {
    local enrich_log="${LOG_DIR}/enrich_metadata.log"
    ENRICHED_METADATA="${LOG_DIR}/enriched-cve-metadata.json"

    log "=== Preparing enriched metadata (ground-truth Upstream-Status pass) ==="
    cp "$CVE_METADATA" "$ENRICHED_METADATA"

    if python3 "$ENRICH_TOOL" "$ENRICHED_METADATA" "${OE_DIR}/meta" \
            --correct-existing > "$enrich_log" 2>&1; then
        log "Enrichment complete, see $enrich_log"
        cat "$enrich_log"
    else
        log "WARNING: enrich_metadata_from_oe.py failed, see $enrich_log — round 2 will reuse the original metadata"
        cat "$enrich_log"
        cp "$CVE_METADATA" "$ENRICHED_METADATA"
    fi
}

# ── Backend preflight ────────────────────────────────────────────────────────
# Verifies the agent backend/model actually responds before spending any
# corrector/build time. Catches a misconfigured named OpenAI profile early
# (e.g. a profile file that only exists outside the resolved config
# directory -- --backend openai-<profile> loads ONLY
# <repo>/etc/openai-<profile>.cfg or an absolute $CVE_AGENT_OPENAI_CONFIG_DIR;
# it never searches a relative path, the workspace, or any parent directory).
# Skipped automatically when no CVE in this run will ever reach the agent
# (--full-only is not required for that -- corrector-only cases still skip
# the agent on a clean exit).
verify_agent_backend() {
    log "=== Verifying agent backend ($AGENT_BACKEND${AGENT_MODEL:+, model: $AGENT_MODEL}) ==="
    local verify_log="${LOG_DIR}/verify_backend.log"
    local -a verify_flags=(--backend "$AGENT_BACKEND")
    [[ -n "$AGENT_MODEL" ]] && verify_flags+=(--model "$AGENT_MODEL")
    if python3 -m cve_agent "${verify_flags[@]}" --verify-backend > "$verify_log" 2>&1; then
        log "Backend OK, see $verify_log"
    else
        log "FATAL: backend verification failed, see $verify_log"
        cat "$verify_log"
        if [[ "$AGENT_BACKEND" == openai-* ]]; then
            log "Hint: --backend $AGENT_BACKEND loads openai-<profile>.cfg from"
            log "  <repo>/etc/ or an ABSOLUTE \$CVE_AGENT_OPENAI_CONFIG_DIR only --"
            log "  there is no relative-path or parent-directory fallback. If your"
            log "  profile file lives elsewhere (e.g. ../openai/), export:"
            log "    export CVE_AGENT_OPENAI_CONFIG_DIR=/absolute/path/to/that/dir"
        fi
        die "Fix the agent backend before running tests."
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

    # Round 1: tracker-sourced metadata, as recorded in $CVE_METADATA.
    [[ "$FULL_ONLY" != true ]] && run_loop "skip-build-ptest" "--skip-build --skip-ptest" "$cve_list" "$FAILED_RECIPES"
    run_loop "full" "" "$cve_list" "$FAILED_RECIPES"

    if [[ "$ENRICHED_ROUND" == true ]]; then
        # Round 2: same CVEs, same cve_list, but against metadata corrected
        # with the ground-truth Upstream-Status hashes OE-Core's own patches
        # declare. Distinct mode names (*-enriched) keep results/logs from
        # colliding with round 1's. $CVE_METADATA is swapped for the duration
        # of these two run_loop calls and restored immediately after, since
        # run_cve_corrector/the agent subprocess both read it as a global at
        # call time.
        prepare_enriched_metadata
        local original_metadata="$CVE_METADATA"
        CVE_METADATA="$ENRICHED_METADATA"
        [[ "$FULL_ONLY" != true ]] && run_loop "skip-build-ptest-enriched" "--skip-build --skip-ptest" "$cve_list" "$FAILED_RECIPES"
        run_loop "full-enriched" "" "$cve_list" "$FAILED_RECIPES"
        CVE_METADATA="$original_metadata"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --skip-mirrors) SKIP_MIRRORS=true ;;
            --full-only) FULL_ONLY=true ;;
            --enriched-round) ENRICHED_ROUND=true ;;
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
            --require-security-status)
                shift
                [[ $# -gt 0 ]] || die "--require-security-status requires a value"
                case "$1" in
                    verified|equivalent|plausible_needs_review|divergent|rejected|not_evaluated) ;;
                    *) die "invalid --require-security-status: $1" ;;
                esac
                REQUIRE_SECURITY_STATUS="$1"
                ;;
            *) die "Unknown option: $1" ;;
        esac
        shift
    done

    [[ -d "$OE_DIR/.git" ]] || die "$OE_DIR is not a git repository"
    [[ -f "$CVE_METADATA" ]] || die "CVE metadata not found: $CVE_METADATA"
    if [[ "$ENRICHED_ROUND" == true ]]; then
        [[ -f "$ENRICH_TOOL" ]] || die "enrich_metadata_from_oe.py not found: $ENRICH_TOOL"
    fi

    mkdir -p "$LOG_DIR"
    source_build_env
    verify_agent_backend
    run_tests

    log "Done. Results in $LOG_DIR"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
