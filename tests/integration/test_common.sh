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

# meta-openembedded layers (meta-oe, meta-networking, meta-python,
# meta-filesystems) are a separate checkout, sibling to OE_DIR, each its
# own layer root (unlike openembedded-core, which nests every layer under
# meta/). remove_cve_patch must search these too, or any CVE whose patch
# lives there is unconditionally reported NOTFOUND. Override with
# META_OE_LAYERS (space-separated absolute paths) if your checkout differs.
# META_OE_DIR is the single git repo root all those layers share -- reset
# and commit operations run against it once, not per-layer.
if [[ -z "${META_OE_LAYERS+x}" ]]; then
    _meta_oe_root="$(dirname "$OE_DIR")/meta-openembedded"
    META_OE_LAYERS=""
    for _layer in meta-oe meta-networking meta-python meta-filesystems; do
        if [[ -d "${_meta_oe_root}/${_layer}" ]]; then
            META_OE_LAYERS="${META_OE_LAYERS} ${_meta_oe_root}/${_layer}"
        fi
    done
    META_OE_LAYERS="${META_OE_LAYERS# }"
fi
if [[ -z "${META_OE_DIR:-}" ]]; then
    _candidate="$(dirname "$OE_DIR")/meta-openembedded"
    [[ -d "${_candidate}/.git" ]] && META_OE_DIR="$_candidate"
fi
: "${META_OE_DIR:=}"

# Pinned to a fixed scarthgap commit rather than the moving origin/scarthgap
# branch tip, so integration test runs are reproducible over time. Override
# with a newer commit/tag when intentionally moving the pin forward.
: "${OE_SCARTHGAP_REF:=310eec2cb646d7d1a3ca99bad7e37495bb418a0d}"
: "${META_OE_SCARTHGAP_REF:=bec755063a8b5da65df626f5749496aadaa4f4bb}"

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
    log "Resetting openembedded-core to clean state (pinned to $OE_SCARTHGAP_REF)..."
    cd "$OE_DIR"
    git am --abort 2>/dev/null || true
    git cherry-pick --abort 2>/dev/null || true
    git reset --hard "$OE_SCARTHGAP_REF" 2>&1
    git clean -fd 2>&1 | tail -1
    git checkout "$OE_SCARTHGAP_REF" 2>&1
    log "Reset complete."

    if [[ -n "$META_OE_DIR" ]]; then
        log "Resetting meta-openembedded to clean state (pinned to $META_OE_SCARTHGAP_REF)..."
        cd "$META_OE_DIR"
        git am --abort 2>/dev/null || true
        git cherry-pick --abort 2>/dev/null || true
        git reset --hard "$META_OE_SCARTHGAP_REF" 2>&1
        git clean -fd 2>&1 | tail -1
        git checkout "$META_OE_SCARTHGAP_REF" 2>&1
        log "meta-openembedded reset complete."
    fi
}

setup_oe_git() {
    cd "$OE_DIR"
    local orig_branch
    orig_branch=$(git symbolic-ref --short HEAD 2>/dev/null || git rev-parse --short HEAD)
    trap "cd '$OE_DIR' && git checkout '$orig_branch' 2>/dev/null || true" EXIT
    git fetch origin
    git for-each-ref --format='%(refname:short)' 'refs/heads/test/**' | xargs -r git branch -D 2>/dev/null || true

    if [[ -n "$META_OE_DIR" ]]; then
        cd "$META_OE_DIR"
        git for-each-ref --format='%(refname:short)' 'refs/heads/test/**' | xargs -r git branch -D 2>/dev/null || true
    fi
}

# Setup per-CVE branch and commit patch removal. Mirrors the same
# branch/commit cycle in META_OE_DIR when set, since remove_cve_patch may
# modify files there instead of (or in addition to) OE_DIR -- without this,
# a meta-openembedded-only patch removal has nothing to commit in OE_DIR
# (GIT_ERROR) and the meta-openembedded working tree is left dirty,
# leaking uncommitted changes into every subsequent test iteration.
# Sets global SETUP_CVE_STATUS to OK/NOTFOUND/GIT_ERROR.
setup_cve_branch() {
    local cve_id="$1" log_file="$2" mode="${3:-default}"
    local branch_name="test/${mode}/${cve_id}"
    reset_oe_tree >> "$log_file" 2>&1
    cd "$OE_DIR"
    git checkout -B "$branch_name"
    if [[ -n "$META_OE_DIR" ]]; then
        cd "$META_OE_DIR"
        git checkout -B "$branch_name"
    fi

    local remove_output
    remove_output=$(remove_cve_patch "$cve_id" "$mode")
    echo "$remove_output" >> "$log_file"

    if echo "$remove_output" | grep -q "NOTFOUND"; then
        SETUP_CVE_STATUS="NOTFOUND"
        return
    fi

    cd "$OE_DIR"
    git add -A
    local oe_dir_has_changes=1
    git diff --cached --quiet || oe_dir_has_changes=0

    local meta_oe_committed=1
    if [[ -n "$META_OE_DIR" ]]; then
        cd "$META_OE_DIR"
        git add -A
        if ! git diff --cached --quiet; then
            if git commit -m "test: remove $cve_id for testing" >> "$log_file" 2>&1; then
                meta_oe_committed=0
            fi
        else
            meta_oe_committed=0  # nothing to commit here is fine if OE_DIR has it
        fi
    fi

    cd "$OE_DIR"
    local oe_dir_committed=1
    if [[ "$oe_dir_has_changes" == 0 ]]; then
        if git commit -m "test: remove $cve_id for testing" >> "$log_file" 2>&1; then
            oe_dir_committed=0
        fi
    else
        oe_dir_committed=0  # nothing to commit here is fine if META_OE_DIR has it
    fi

    if [[ "$oe_dir_committed" == 0 && "$meta_oe_committed" == 0 ]]; then
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
    python3 "${_COMMON_DIR}/test_utils.py" remove_cve "$OE_DIR" "$1" "$LOG_DIR" "${2:-}" "${META_OE_LAYERS:-}"
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
    # Exclude agent-generated copies ({mode}_agent_{cve_id}_{filename}) and the
    # benchmark's per-model generated archives (generated_{cve_id}_{model}_...),
    # which live in the same results dir and would otherwise be mistaken for a
    # reference patch on a later model's comparison.
    local -a old_patches=()
    while IFS= read -r -d '' f; do
        old_patches+=("$f")
    done < <(find "$log_dir" -maxdepth 1 -name "*${cve_id}_*.patch" ! -name "*_diff.patch" ! -name "*_agent_*" ! -name "generated_*" -print0 2>/dev/null)

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
