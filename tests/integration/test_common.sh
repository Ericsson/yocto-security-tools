#!/bin/bash
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
# Common functions shared between integration test scripts.
# Source this file; do not execute directly.

_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Autodetect from bitbake environment if available
if [[ -n "${BUILDDIR:-}" && -z "${BUILD_DIR:-}" ]]; then
    BUILD_DIR="$BUILDDIR"
fi
if [[ -n "${BUILD_DIR:-}" && -z "${OE_DIR:-}" ]]; then
    # Standard layout: <project>/build/ alongside <project>/openembedded-core/
    for candidate in \
        "$(dirname "$BUILD_DIR")/openembedded-core" \
        "$(dirname "$BUILD_DIR")/poky/meta/.." \
        "$(dirname "$BUILD_DIR")/meta/.."; do
        if [[ -d "$candidate/meta/conf" ]]; then
            OE_DIR="$(cd "$candidate" && pwd)"
            break
        fi
    done
fi

# Fall back to required env vars if autodetection failed
: "${OE_DIR:?Set OE_DIR to your openembedded-core checkout (or source oe-init-build-env first)}"
: "${BUILD_DIR:?Set BUILD_DIR to your Yocto build directory (or source oe-init-build-env first)}"
: "${MIRROR_DIR:=${HOME}/git}"

# Optional
BUILDTOOLS_ENV="${BUILDTOOLS_ENV:-}"

log() { echo "[$(date +%H:%M:%S)] $*"; }
die() { log "FATAL: $*"; exit 1; }

source_build_env() {
    if [[ -z "${BBPATH:-}" ]]; then
        log "Sourcing build environment from $BUILD_DIR..."
        [[ -n "$BUILDTOOLS_ENV" && -f "$BUILDTOOLS_ENV" ]] && source "$BUILDTOOLS_ENV"
        # oe-init-build-env sets OEROOT=$(dirname "$THIS_SCRIPT"), so it lives at
        # the root of the OE checkout itself — true for both poky (poky/) and a
        # standalone openembedded-core checkout (whinlatter/wrynose have no poky
        # branch). The ../ forms are kept as fallbacks for superproject layouts.
        local oe_init="${OE_DIR}/oe-init-build-env"
        [[ -f "$oe_init" ]] || oe_init="${OE_DIR}/../oe-init-build-env"
        [[ -f "$oe_init" ]] || oe_init="${OE_DIR}/../../oe-init-build-env"
        [[ -f "$oe_init" ]] || die "Cannot find oe-init-build-env relative to OE_DIR"
        set +u
        # shellcheck disable=SC1090
        source "$oe_init" "$BUILD_DIR" > /dev/null
        set -u
    fi
    [[ -n "${BBPATH:-}" ]] || die "BBPATH not set after sourcing build environment"

    # Activate project venv so python3 resolves to our installed packages
    # (oe-init-build-env prepends buildtools SDK python to PATH)
    local venv_activate="${BUILD_DIR}/venv/bin/activate"
    if [[ -f "$venv_activate" ]]; then
        set +u
        # shellcheck disable=SC1090
        source "$venv_activate"
        set -u
    fi
}

reset_oe_tree() {
    log "Resetting openembedded-core to clean state..."
    cd "$OE_DIR"
    git am --abort 2>/dev/null || true
    git cherry-pick --abort 2>/dev/null || true
    git reset --hard origin/scarthgap 2>&1
    git clean -fd 2>&1 | tail -1
    git checkout origin/scarthgap 2>&1 || git checkout scarthgap 2>&1
    log "Reset complete."
}

setup_oe_git() {
    cd "$OE_DIR"
    local orig_branch
    orig_branch=$(git symbolic-ref --short HEAD 2>/dev/null || git rev-parse --short HEAD)
    trap "cd '$OE_DIR' && git checkout '$orig_branch' 2>/dev/null || true" EXIT
    git fetch origin
    git for-each-ref --format='%(refname:short)' 'refs/heads/test/**' | xargs -r git branch -D 2>/dev/null || true
}

# Setup per-CVE branch and commit patch removal.
# Sets global SETUP_CVE_STATUS to OK/NOTFOUND/GIT_ERROR.
setup_cve_branch() {
    local cve_id="$1" log_file="$2" mode="${3:-default}"
    local branch_name="test/${mode}/${cve_id}"
    reset_oe_tree >> "$log_file" 2>&1
    cd "$OE_DIR"
    git checkout -B "$branch_name"

    local remove_output
    remove_output=$(remove_cve_patch "$cve_id" "$mode")
    echo "$remove_output" >> "$log_file"

    if echo "$remove_output" | grep -q "NOTFOUND"; then
        SETUP_CVE_STATUS="NOTFOUND"
        return
    fi
    git add -A
    if git commit -m "test: remove $cve_id for testing" >> "$log_file" 2>&1; then
        SETUP_CVE_STATUS="OK"
    else
        SETUP_CVE_STATUS="GIT_ERROR"
    fi
}

# Run cve_corrector and compare patches. Args: cve_id log_file extra_flags
# Sets CVE_CORRECTOR_RESULT to exit_code:diff_changes
run_cve_corrector() {
    local cve_id="$1" log_file="$2" extra_flags="$3"
    local exit_code=0
    cd "$_COMMON_DIR"
    # shellcheck disable=SC2086
    python3 -m cve_corrector \
        --cve-info "$CVE_METADATA" \
        --cve-id "$cve_id" \
        $extra_flags \
        --mirror-dir "$MIRROR_DIR" \
        --meta-layer "${OE_DIR}/meta" \
        --yes \
        --clean \
        --verbose \
        >> "$log_file" 2>&1 || exit_code=$?

    local diff_changes="-"
    local diff_patches="-"
    local diff_files="-"
    if [[ $exit_code -eq 0 ]]; then
        local diff_output
        diff_output=$(compare_patches_detailed "$cve_id" "$LOG_DIR" "meta") || true
        diff_changes=$(echo "$diff_output" | grep "^DIFF_CHANGES:" | cut -d: -f2 || echo "-")
        diff_patches=$(echo "$diff_output" | grep "^DIFF_PATCHES:" | cut -d: -f2 || echo "-")
        diff_files=$(echo "$diff_output" | grep "^DIFF_FILES:" | cut -d: -f2 || echo "-")
        echo "$diff_output" >> "$log_file"
    fi
    CVE_CORRECTOR_RESULT="$exit_code:$diff_changes:$diff_patches:$diff_files"
}

remove_cve_patch() {
    python3 "${_COMMON_DIR}/test_utils.py" remove_cve "$OE_DIR" "$1" "$LOG_DIR" "${2:-}"
}

compare_patches() {
    python3 "${_COMMON_DIR}/test_utils.py" compare "$1" "$2"
}

# Compare original vs generated patches, write differences file.
# Args: cve_id log_dir meta_layer
# Prints DIFF_CHANGES:<n>
compare_patches_detailed() {
    local cve_id="$1" log_dir="$2" meta_layer="${3:-meta}"
    local diff_file="${log_dir}/${cve_id}_differences.txt"

    # Original patches saved by remove_cve_patch as {mode}_{cve_id}_{filename}
    # Exclude agent-generated copies ({mode}_agent_{cve_id}_{filename})
    local -a old_patches=()
    while IFS= read -r -d '' f; do
        old_patches+=("$f")
    done < <(find "$log_dir" -maxdepth 1 -name "*${cve_id}_*.patch" ! -name "*_diff.patch" ! -name "*_agent_*" -print0 2>/dev/null)

    # Generated patches in the OE tree
    local -a new_patches=()
    local cve_lower="${cve_id,,}"
    cve_lower="${cve_lower#cve-}"
    while IFS= read -r -d '' f; do
        new_patches+=("$f")
    done < <(find "${OE_DIR}/${meta_layer}" -iname "*${cve_lower}*.patch" -type f -print0 2>/dev/null)

    if [[ ${#old_patches[@]} -eq 0 || ${#new_patches[@]} -eq 0 ]]; then
        echo "DIFF_CHANGES:-"
        return
    fi

    python3 "${_COMMON_DIR}/test_utils.py" compare_detailed "$diff_file" "${old_patches[@]}" -- "${new_patches[@]}"
}
