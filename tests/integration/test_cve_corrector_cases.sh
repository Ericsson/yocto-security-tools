#!/bin/bash
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
# Test cases for cve_corrector covering scenarios:
#   0. Build environment sanity check (core-image-minimal)
#   1. Multiple patches with removed subsequent (CVE-2024-12086 / rsync)
#   2. Single patch with build+ptest (CVE-2025-5915 / libarchive)
#   3. Multiple patches / series with build+ptest (CVE-2026-25210 / expat)
#   4. Conflict (CVE-2026-2903 / re2c)
#   5. Single patch with build+ptest (CVE-2023-42363 / busybox)
#   6. Agent conflict resolution + ptest, single patch (CVE-2026-26157 / busybox)
#   7. Agent build-fix + backport, single patch (CVE-2024-0684 / coreutils)
#   8. Missing autotools files between git and tarball (CVE-2024-0684 / coreutils)
#   9. Monorepo subprojects/ path stripping (CVE-2024-47539 / gstreamer1.0-plugins-good)
#  10. Single-patch SRC_URI += removal (CVE-2024-39689 / python3-certifi)
#  11. Agent conflict + devtool finish recovery (CVE-2024-39894 / openssh)
#  12. Skip-build-ptest baseline (CVE-2024-44331 / gstreamer1.0-rtsp-server)
#  13. Full build investigation (CVE-2024-44331 / gstreamer1.0-rtsp-server)
#  14. Binutils underscore tag matching (CVE-2024-53589 / binutils)
#  15. Cross-recipe shared patch removal (CVE-2025-32909 / libsoup-2.4)
#  16. Ignored untracked files blocking devtool checkout (CVE-2025-46802 / screen)
#  17. Monorepo build verification (CVE-2024-47539 / gstreamer1.0-plugins-good)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CVE_METADATA="${SCRIPT_DIR}/test-cases-cve-metadata.json"
LOG_DIR="${SCRIPT_DIR}/test-results/cases_$(date +%Y%m%d_%H%M%S)"
RESULTS_FILE="${LOG_DIR}/results.txt"
RUN_TEST=""

# AI backend for the agent test cases (6, 7, 11, 13). Any backend registered
# with cve_agent works: kiro (default), claude, or a plugin from extra/.
# AGENT_MODEL optionally overrides the model passed to the backend.
AGENT_BACKEND="${AGENT_BACKEND:-kiro}"
AGENT_MODEL="${AGENT_MODEL:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --test) shift; RUN_TEST="$1" ;;
        *) echo "Usage: $0 [--test N]"; exit 1 ;;
    esac
    shift
done

mkdir -p "$LOG_DIR"

# shellcheck source=test_common.sh
source "${SCRIPT_DIR}/test_common.sh"

[[ -d "$OE_DIR/.git" ]] || die "$OE_DIR is not a git repository"

source_build_env
setup_oe_git

# Extract sorted list of file://...patch entries from a recipe's directory
get_recipe_patches() {
    local meta_layer="$1"
    local recipe="$2"
    local search_dir="${OE_DIR}/${meta_layer}"
    local recipe_dir
    recipe_dir=$(find "$search_dir" -name "${recipe}_*.bb" -o -name "${recipe}.bb" 2>/dev/null | head -1)
    if [[ -z "$recipe_dir" ]]; then
        return
    fi
    recipe_dir=$(dirname "$recipe_dir")
    grep -rh 'file://.*\.patch' "$recipe_dir" --include='*.bb' --include='*.inc' --include='*.bbappend' 2>/dev/null \
        | grep -oP 'file://[^\s"\\]+\.patch' | sort
}

# Verify no pre-existing patches were removed after cve_corrector ran
verify_no_patches_removed() {
    local before_file="$1"
    local after_file="$2"
    local missing
    missing=$(comm -23 "$before_file" "$after_file" || true)
    if [[ -n "$missing" ]]; then
        echo "FAIL"
        return 0
    fi
    echo "PASS"
    return 0
}

# Validate patch naming: CVE-ID.patch for single, CVE-ID-X.patch for series
validate_patch_names() {
    local cve_id="$1"
    local expect_series="$2"
    local meta_layer="$3"
    local search_dir="${OE_DIR}/${meta_layer}"
    local patches
    patches=$(find "$search_dir" -iname "${cve_id}*.patch" -type f 2>/dev/null | sort)

    if [[ -z "$patches" ]]; then
        echo "FAIL"; return 0
    fi

    local count
    count=$(echo "$patches" | wc -l)

    if [[ "$expect_series" == "false" ]]; then
        if [[ $count -ne 1 ]]; then
            echo "FAIL"; return 0
        fi
        local name
        name=$(basename "$patches")
        if [[ "$name" == "${cve_id}.patch" ]]; then
            echo "PASS"
        else
            echo "FAIL"
        fi
    else
        if [[ $count -lt 2 ]]; then
            echo "FAIL"; return 0
        fi
        local all_ok=true
        local idx=1
        while IFS= read -r p; do
            local name
            name=$(basename "$p")
            if [[ "$name" != "${cve_id}-${idx}.patch" ]]; then
                all_ok=false
            fi
            idx=$((idx + 1))
        done <<< "$patches"
        if $all_ok; then
            echo "PASS"
        else
            echo "FAIL"
        fi
    fi
    return 0
}

run_test() {
    local test_name="$1"
    local cve_id="$2"
    local expected_exit="$3"
    local expect_series="$4"
    local metadata_file="$5"
    local runner="${6:-corrector}"
    local extra_flags="${7:-}"
    TEST_NUM=$((TEST_NUM + 1))

    if [[ -n "$RUN_TEST" && "$RUN_TEST" != "$TEST_NUM" ]]; then
        return
    fi
    local log_file="${LOG_DIR}/${TEST_NUM}_${cve_id}.log"

    local patches_before="${LOG_DIR}/${TEST_NUM}_${cve_id}_patches_before.txt"
    local patches_after="${LOG_DIR}/${TEST_NUM}_${cve_id}_patches_after.txt"

    log "=== TEST $TEST_NUM: $test_name ($cve_id) [runner: $runner] ==="

    local recipe
    recipe=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(d[sys.argv[2]]['name'])" "$metadata_file" "$cve_id")

    setup_cve_branch "$cve_id" "$log_file" "${TEST_NUM}"
    log "  [$TEST_NUM] Branch status: $SETUP_CVE_STATUS"
    if [[ "$SETUP_CVE_STATUS" == "NOTFOUND" ]]; then
        log "  [$TEST_NUM] CVE $cve_id not found in tree (expected for conflict test)"
    fi

    # Capture patches after setup (baseline for cve_corrector)
    get_recipe_patches "meta" "$recipe" > "$patches_before"

    # Clean build workspace to avoid pre-existing build failures from prior tests
    rm -rf "${BUILD_DIR}/workspace" 2>/dev/null || true
    rm -f "${BUILD_DIR}/conf/bblayers.conf.bak" 2>/dev/null || true
    sed -i '\|/workspace|d' "${BUILD_DIR}/conf/bblayers.conf" 2>/dev/null || true
    # Invalidate bitbake parse cache so recipe modifications are picked up
    rm -rf "${BUILD_DIR}"/tmp*/cache 2>/dev/null || true
    # Stop any resident bitbake server to avoid stale in-memory state
    bitbake --kill-server >> "$log_file" 2>&1 || true
    bitbake -c cleansstate "$recipe" >> "$log_file" 2>&1 || true

    cd "$SCRIPT_DIR"

    log "  [$TEST_NUM] Running $runner..."
    local exit_code=0
    if [[ "$runner" == "agent" ]]; then
        local backend_flags=(--backend "${AGENT_BACKEND}")
        if [[ -n "$AGENT_MODEL" ]]; then
            backend_flags+=(--model "${AGENT_MODEL}")
        fi
        echo "y" | python3 -m cve_agent \
            --cve-info "$metadata_file" \
            --cve-id "$cve_id" \
            --mirror-dir "$MIRROR_DIR" \
            --trust \
            --clean \
            "${backend_flags[@]}" \
            $extra_flags \
            >> "$log_file" 2>&1 || exit_code=$?
    else
        python3 -m cve_corrector \
            --cve-info "$metadata_file" \
            --cve-id "$cve_id" \
            --mirror-dir "$MIRROR_DIR" \
            --yes \
            --clean \
            $extra_flags \
            >> "$log_file" 2>&1 || exit_code=$?
    fi

    log "  [$TEST_NUM] Exit code: $exit_code (expected: $expected_exit)"

    local result="FAIL"
    if [[ "$exit_code" == "$expected_exit" ]]; then
        result="PASS"
    fi

    # For successful cases, validate patch naming, no-removal invariant, and diff
    local naming_result="-"
    local preserve_result="-"
    local diff_result="-"
    local patches_result="-"
    local files_result="-"
    if [[ "$exit_code" -eq 0 ]]; then
        cd "$OE_DIR"
        if [[ "$runner" != "agent" ]]; then
            naming_result=$(validate_patch_names "$cve_id" "$expect_series" "meta") || true
            log "  [$TEST_NUM] Naming: $naming_result"
        fi

        get_recipe_patches "meta" "$recipe" > "$patches_after"
        preserve_result=$(verify_no_patches_removed "$patches_before" "$patches_after") || true
        log "  [$TEST_NUM] Preserve: $preserve_result"
        if [[ "$preserve_result" == "FAIL" ]]; then
            result="FAIL"
        fi

        local diff_output
        diff_output=$(compare_patches_detailed "$cve_id" "$LOG_DIR" "meta") || true
        diff_result=$(echo "$diff_output" | grep "^DIFF_CHANGES:" | cut -d: -f2 || echo "-")
        patches_result=$(echo "$diff_output" | grep "^DIFF_PATCHES:" | cut -d: -f2 || echo "-")
        files_result=$(echo "$diff_output" | grep "^DIFF_FILES:" | cut -d: -f2 || echo "-")
        log "  [$TEST_NUM] Diff: $diff_result  Patches: $patches_result  Files: $files_result"
    fi

    # Save agent AI context/changes logs for analysis
    local agent_logs_src="${BUILD_DIR}/workspace/cve_agent"
    if [[ -d "$agent_logs_src" ]]; then
        cp -r "$agent_logs_src" "${LOG_DIR}/${TEST_NUM}_${cve_id}_agent/"
    fi

    printf "%-20s %-40s %-8s %-8s %-8s %-8s %-8s %s\n" "$cve_id" "$test_name" "$result" "$naming_result" "$preserve_result" "$diff_result" "$patches_result" "$files_result" >> "$RESULTS_FILE"
    log "  [$TEST_NUM] Result: $result"
    echo
}

# ── Main ─────────────────────────────────────────────────────────────────────
TEST_NUM=0
log "Starting cve_corrector test cases"
log "OE_DIR:     $OE_DIR"
log "BUILD_DIR:  $BUILD_DIR"
log "BBPATH:     ${BBPATH:-(not set)}"
log "MIRROR_DIR: $MIRROR_DIR"
log "BACKEND:    $AGENT_BACKEND${AGENT_MODEL:+ (model: $AGENT_MODEL)}"
log "Results:    $LOG_DIR"
echo

printf "%-20s %-40s %-8s %-8s %-8s %-8s %-8s %s\n" "CVE_ID" "TEST" "STATUS" "NAMING" "PRESERVE" "DIFF" "PATCHES" "FILES" > "$RESULTS_FILE"
printf "%-20s %-40s %-8s %-8s %-8s %-8s %-8s %s\n" "--------------------" "----------------------------------------" "--------" "--------" "--------" "--------" "--------" "--------" >> "$RESULTS_FILE"

# Test 0: Verify build environment is functional (opt-in: --test 0)
if [[ "$RUN_TEST" == "0" ]]; then
    log "=== TEST 0: Build environment sanity check (core-image-minimal) ==="
    local_log="${LOG_DIR}/0_build_env_check.log"
    if bitbake core-image-minimal >> "$local_log" 2>&1; then
        log "  [0] Build environment OK"
        printf "%-20s %-40s %-8s %-8s %-8s %-8s %-8s %s\n" "-" "Build env check (core-image-minimal)" "PASS" "-" "-" "-" "-" "-" >> "$RESULTS_FILE"
    else
        log "  [0] FATAL: core-image-minimal build failed — environment broken"
        printf "%-20s %-40s %-8s %-8s %-8s %-8s %-8s %s\n" "-" "Build env check (core-image-minimal)" "FAIL" "-" "-" "-" "-" "-" >> "$RESULTS_FILE"
        log "  [0] See: $local_log"
        log "  [0] Fix the build environment before running tests."
        reset_oe_tree
        cat "$RESULTS_FILE"
        exit 1
    fi
fi

# Test 1: Multiple patches with removed subsequent (rsync series)
run_test "Multi-patch + removed subsequent" "CVE-2024-12086" "0" "false" "$CVE_METADATA" "corrector" "--skip-build --skip-ptest"

# Test 2: Single patch (clean cherry-pick)
run_test "Single patch (clean cherry-pick)" "CVE-2025-5915" "0" "false" "$CVE_METADATA"

# Test 3: Multiple patches (series)
run_test "Multiple patches (series)" "CVE-2026-25210" "0" "true" "$CVE_METADATA"

# Test 4: Conflict
run_test "Conflict" "CVE-2026-2903" "1" "false" "$CVE_METADATA"

# Test 5: Single patch with ptest
run_test "Single patch with ptest" "CVE-2023-42363" "0" "false" "$CVE_METADATA"

# Test 6: Agent conflict resolution with ptest (single patch)
run_test "Agent conflict+ptest" "CVE-2026-26157" "0" "false" "$CVE_METADATA" "agent"

# Test 7: Agent build-fix + backport (single patch)
run_test "Agent build-fix" "CVE-2024-0684" "0" "false" "$CVE_METADATA" "agent"

# Test 8: Missing autotools files between git and tarball (single patch)
run_test "Missing autotools files" "CVE-2024-0684" "0" "false" "$CVE_METADATA"

# Test 9: Monorepo subprojects/ path stripping (gstreamer)
run_test "Monorepo subprojects strip" "CVE-2024-47539" "0" "false" "$CVE_METADATA" "corrector" "--skip-build --skip-ptest"

# Test 10: Single-patch SRC_URI += removal + zero-padded tag (python3-certifi)
run_test "Single-patch SRC_URI += removal" "CVE-2024-39689" "1" "false" "$CVE_METADATA" "corrector" "--skip-build --skip-ptest"

# Test 11: Agent conflict resolution with subsequent patch removal (openssh)
run_test "Agent conflict + devtool finish recovery" "CVE-2024-39894" "0" "false" "$CVE_METADATA" "agent" "--skip-ptest"

# Test 12: Skip-build-ptest baseline for gstreamer1.0-rtsp-server
run_test "Skip-build-ptest baseline" "CVE-2024-44331" "0" "false" "$CVE_METADATA" "corrector" "--skip-build --skip-ptest"

# Test 13: Full build for gstreamer1.0-rtsp-server
run_test "Agent resolution" "CVE-2024-44331" "0" "false" "$CVE_METADATA" "agent"

# Test 14: Binutils underscore tag matching
run_test "Binutils underscore tag" "CVE-2024-53589" "0" "false" "$CVE_METADATA" "corrector" "--skip-build --skip-ptest --skip-cve-applicability --meta-layer ${OE_DIR}/meta"

# Test 15: Cross-recipe shared patch removal
run_test "Cross-recipe shared patch removal" "CVE-2025-32909" "1" "false" "$CVE_METADATA" "corrector" "--skip-build --skip-ptest"

# Test 16: Ignored untracked files blocking devtool checkout
run_test "Ignored untracked files cleanup" "CVE-2025-46802" "0" "false" "$CVE_METADATA" "corrector" "--skip-build --skip-ptest"

# Test 17: Monorepo build verification
run_test "Monorepo build" "CVE-2024-47539" "0" "false" "$CVE_METADATA" "corrector" "--skip-ptest"

# ── Summary ──────────────────────────────────────────────────────────────────
reset_oe_tree

echo
log "=== RESULTS ==="
cat "$RESULTS_FILE"
echo
log "Detailed logs: $LOG_DIR"
