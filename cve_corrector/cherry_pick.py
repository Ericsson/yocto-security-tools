# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Cherry-pick and series application logic for CVE corrector."""
from pathlib import Path
from typing import Optional

from .git_ops import (
    cherry_pick_command,
    git_clean_workspace,
    has_conflict_state,
    is_ancestor_of_head,
    is_bad_object,
    reset_submodules,
    try_cherry_pick,
)
from .meta_layer import write_cve_status
from .state import AlreadyAppliedError, GitError, PatchError, WorkflowState, save_progress
from .transfer import TransferError, transfer_commits
from .utils import logger, run_cmd, run_cmd_capture


def reset_devtool_to_base(workspace_path: Path) -> bool:
    """Reset the devtool branch back to its recipe-patched base commit.

    Used when re-transferring CVE commits on a build/ptest-error resume:
    the AI agent may have amended the CVE-branch commit to fix the error,
    so the devtool branch needs a clean re-application of the (updated)
    patch rather than another commit stacked on top of the stale one from
    the previous attempt. Without this, ``git cherry`` in
    :func:`collect_cve_commits` compares against a devtool branch that
    already contains the stale patch-id and incorrectly concludes the CVE
    commit is already applied, aborting the whole resume with
    :class:`AlreadyAppliedError`.

    The reset target is ``devtool-patched`` — the source with **all** of the
    recipe's ``SRC_URI`` patches applied but without the CVE fix
    cve_corrector transfers on top. It is *not* ``devtool-base`` (the pristine
    upstream tarball import): resetting to ``devtool-base`` strips every
    recipe patch, and since :func:`cherry_pick_to_devtool` only re-applies the
    CVE commits, those recipe patches would never come back. That silently
    drops files the build and ptest steps depend on — e.g. libxml2's
    ``install-tests.patch``, which adds the ``install-test-data`` make target
    that ``do_install_ptest_base`` invokes, so ptest fails with
    "No rule to make target 'install-test-data'". ``devtool-patched`` keeps
    those patches and drops only the previously-transferred CVE commits.

    ``devtool-patched`` is created by ``devtool modify`` whenever the recipe
    has ``SRC_URI`` patches. When a recipe has none, devtool omits it and
    ``devtool-base`` already *is* the fully-patched tree, so fall back to it.
    ``main``/``master`` are never used here (unlike ``workspace.py``'s
    non-CVE-branch search): they point at upstream's own history, which may
    already contain the CVE fix or unrelated later commits — exactly the
    stale/wrong content this reset must avoid.

    Args:
        workspace_path: Path to workspace.

    Returns:
        True if a base ref was found and devtool was reset, False otherwise.
    """
    base_ref = None
    for ref in ('devtool-patched', 'devtool-base'):
        if run_cmd_capture(['git', 'rev-parse', '--verify', ref],
                           cwd=workspace_path).returncode == 0:
            base_ref = ref
            break
    if base_ref is None:
        logger.error("Failed to find devtool-patched or devtool-base to reset "
                     "devtool before re-transfer")
        return False

    git_clean_workspace(workspace_path, remove_ignored=True)
    run_cmd(['git', 'checkout', '.'], cwd=workspace_path)
    if run_cmd(['git', 'checkout', '-f', 'devtool'], cwd=workspace_path) != 0:
        return False
    return run_cmd(['git', 'reset', '--hard', base_ref], cwd=workspace_path) == 0


def handle_empty_cherry_pick(state: WorkflowState) -> None:
    """Write CVE_STATUS when cherry-pick produces no changes."""
    if not state.meta_layer:
        return
    subject = run_cmd_capture(
        ['git', 'log', '-1', '--format=%s', state.commit_hash],
        cwd=state.workspace_path
    ).stdout.strip()
    reason = (f"Upstream fix ({state.commit_hash[:12]}: {subject}) produces "
              f"no changes — code already matches the fixed version")
    write_cve_status(state.meta_layer, state.recipe, state.cve_id,
                     reason, skip_confirm=state.skip_confirm,
                     sign_off=state.sign_off)


def collect_cve_commits(state: WorkflowState) -> list[str]:
    """List the CVE commits to transfer to the devtool branch, oldest first.

    The ``original-version`` tag is created on the CVE branch after the devtool
    prep commits have been cherry-picked, so ``original-version..<cve_id>``
    holds exactly the CVE commits. Commits whose change is already present on
    the devtool branch (matched by patch-id, e.g. a squash-merged PR that is
    also part of the recipe's patch set) are filtered out via ``git cherry``.

    Args:
        state: Workflow state pointing at the devtool workspace.

    Returns:
        Commit hashes in application order (oldest first).
    """
    cherry = run_cmd_capture(
        ['git', 'cherry', 'devtool', state.cve_id, 'original-version'],
        cwd=state.workspace_path)
    if cherry.returncode == 0 and cherry.stdout.strip():
        commits = [line.split(maxsplit=1)[1].strip()
                   for line in cherry.stdout.splitlines()
                   if line.startswith('+ ')]
        skipped = len([ln for ln in cherry.stdout.splitlines() if ln.startswith('- ')])
        if skipped:
            logger.info("Skipping %s commit(s) already present on devtool", skipped)
        return commits

    # git cherry unavailable (e.g. missing refs) — fall back to the raw range.
    rev_list = run_cmd_capture(
        ['git', 'rev-list', '--reverse', f'original-version..{state.cve_id}'],
        cwd=state.workspace_path)
    if rev_list.returncode != 0:
        return []
    return rev_list.stdout.split()


def cherry_pick_to_devtool(state: WorkflowState) -> None:
    """Transfer CVE commits through a bounded, verified host-side plan."""
    logger.info("Transferring CVE commits to devtool branch")
    cve_commits = collect_cve_commits(state)
    if not cve_commits:
        logger.info("No CVE commits to transfer — fix already in tree")
        handle_empty_cherry_pick(state)
        raise AlreadyAppliedError("no CVE commits to transfer to devtool")
    logger.info("Planning %s CVE commit(s) for devtool", len(cve_commits))

    git_clean_workspace(state.workspace_path, remove_ignored=True)
    run_cmd(['git', 'checkout', '.'], cwd=state.workspace_path)
    if run_cmd(['git', 'checkout', '-f', 'devtool'], cwd=state.workspace_path) != 0:
        save_progress(state, 'cherry_pick_to_devtool')
        raise GitError("Failed to checkout devtool branch")
    # Submodule working trees (e.g. coreutils' gnulib) are not touched by the
    # clean/checkout above and can still report dirty on the devtool branch,
    # tripping transfer_commits' strict clean-tree check below.
    reset_submodules(state.workspace_path)
    try:
        manifest = transfer_commits(
            state.workspace_path,
            cve_commits,
            state.recipe,
            state.cve_id,
            source_prefix=state.transfer_source_prefix,
            explicit_mapping=state.transfer_path_map,
        )
    except TransferError as error:
        save_progress(state, 'cherry_pick_to_devtool')
        raise PatchError(str(error)) from error
    logger.info(
        "Transfer verified: %s mapped entries, %s final paths",
        len(manifest.entries), len(manifest.final_changed_paths))
    if not manifest.final_changed_paths:
        logger.info("Selected fix is already present in the devtool target")
        handle_empty_cherry_pick(state)
        raise AlreadyAppliedError("transferred fix already present in target")


def apply_series(workspace_path: Path,
                 series: list[dict],
                 require_all: bool = False) -> tuple[bool, Optional[str], Optional[dict]]:
    """Apply a commit series using batch cherry-pick.

    A series is an ordered set of commits that must all be applied — either
    a pull request's commits or a dependent chain given via repeated
    ``--fix-url``.

    Args:
        workspace_path: Path to the git repository.
        series: Series dicts with ``commits`` (and optional ``pull_url``).
        require_all: Retained for CLI compatibility. Every declared series is
            an ordered fix unit and reports conflict state even at commit one.

    Returns:
        Tuple of (success, last_commit_hash, best_partial_series)
    """
    logger.info("Found %s commit series", len(series))
    best_series = None
    # A series must always surface conflict state, even when its first commit
    # conflicts. Falling back to one commit silently creates a partial fix.
    max_applied = -1

    for idx, pr_series in enumerate(series, 1):
        pull_url = pr_series.get('pull_url', '')
        commits = pr_series.get('commits', [])
        valid = [c for c in commits if not is_bad_object(workspace_path, c)]
        skipped = len(commits) - len(valid)
        if skipped:
            logger.warning("  Skipping %s bad object(s) in series", skipped)
        if not valid:
            logger.warning("[%s/%s] No valid commits in series from %s", idx, len(series),
                           pull_url or 'command line')
            continue
        origin = f"PR {pull_url}" if pull_url else f"dependent chain of {len(valid)} commit(s)"
        logger.info("[%s/%s] Trying %s", idx, len(series), origin)

        result = run_cmd(['git', 'cherry-pick'] + valid, cwd=workspace_path)

        if result == 0:
            logger.info("✓ Successfully applied all %s commits from %s", len(valid), origin)
            return True, valid[-1], None

        cherry_pick_head = workspace_path / '.git' / 'CHERRY_PICK_HEAD'
        cherry_pick_in_progress = cherry_pick_head.exists()
        if cherry_pick_in_progress:
            failed_hash = cherry_pick_head.read_text().strip()[:40]
            try:
                failed_idx = valid.index(failed_hash)
                applied_commits = valid[:failed_idx]
                remaining_commits = valid[failed_idx + 1:]
                if len(applied_commits) > max_applied:
                    max_applied = len(applied_commits)
                    best_series = {
                        'pull_url': pull_url, 'commits': valid,
                        'applied_commits': applied_commits,
                        'failed_at': failed_hash,
                        'remaining_commits': remaining_commits
                    }
            except ValueError:
                # CHERRY_PICK_HEAD not in our list — count applied via git log
                log_result = run_cmd_capture(
                    ['git', 'log', '--oneline', 'original-version..HEAD'],
                    cwd=workspace_path)
                if log_result.returncode == 0:
                    applied_count = len(log_result.stdout.strip().splitlines())
                    if applied_count > max_applied:
                        max_applied = applied_count
                        best_series = {
                            'pull_url': pull_url, 'commits': valid,
                            'applied_commits': valid[:applied_count],
                            'failed_at': failed_hash,
                            'remaining_commits': valid[applied_count:]
                        }
            run_cmd(['git', 'cherry-pick', '--abort'], cwd=workspace_path)

        run_cmd(['git', 'reset', '--hard', 'original-version'], cwd=workspace_path)

    return False, None, best_series


def dependent_chain_commits(series: Optional[list[dict]]) -> set[str]:
    """Commits that only make sense applied together with the rest of a series.

    A series with two or more commits is a dependent chain: ``apply_series``
    applies it in full and in order, because each commit relies on the ones
    before it. Such a commit must never be offered as a standalone candidate —
    applying one alone yields a partial fix that builds and tests clean while
    leaving the vulnerability open, or actively undoes part of itself.
    setuptools' CVE-2025-47273 is the first shape (a refactor without its
    guard); binutils' CVE-2025-1153 is the second (its third commit reverts
    part of its first).

    A single-commit series is not a chain: that commit alone *is* the whole
    fix, so it stays available as a fallback.

    Args:
        series: Series dicts with ``commits``, or None.

    Returns:
        Every commit belonging to a series of two or more commits. Empty when
        there is no such series.
    """
    chained: set[str] = set()
    for pr_series in series or []:
        commits = pr_series.get('commits') or []
        if len(commits) > 1:
            chained.update(c for c in commits if c)
    return chained


def standalone_candidates(hashes: Optional[list[str]],
                          series: Optional[list[dict]]) -> list[str]:
    """``hashes`` filtered down to commits safe to apply on their own.

    Metadata routinely lists a chain's commits in both ``series`` and
    ``hashes``. ``hashes`` are *alternatives*, tried one at a time, so leaving
    a chain member there re-offers the partial fix the series exists to
    prevent — even though the series itself is recorded correctly.

    Hashes that belong to no chain are genuine independent candidates and are
    preserved, in order.

    Args:
        hashes: Candidate commit hashes, or None.
        series: Series dicts used to identify chain members, or None.

    Returns:
        The subset of ``hashes`` that is not part of any dependent chain.
    """
    chained = dependent_chain_commits(series)
    if not chained:
        return list(hashes or [])
    # Hashes and series commits can be recorded at different lengths (a short
    # tracker sha vs a full one from a patch header), so match on prefix.
    def _is_chained(h: str) -> bool:
        return any(h.startswith(c) or c.startswith(h) for c in chained if c)
    kept = [h for h in (hashes or []) if h and not _is_chained(h)]
    dropped = len(hashes or []) - len(kept)
    if dropped:
        logger.info(
            "Ignoring %d dependent-chain commit(s) as standalone candidates; "
            "they are only valid applied as a full series", dropped)
    return kept


def apply_single_commits(workspace_path: Path, hashes: list[str],
                         subproject: Optional[str] = None,
                         mainline_parent: Optional[int] = None,
                         ) -> tuple[bool, Optional[str]]:
    """Apply individual fix commits until one succeeds."""
    logger.info("Attempting %s commit(s)", len(hashes))
    result = run_cmd_capture(['git', 'log', '--oneline', '-10'], cwd=workspace_path)
    for commit_hash in hashes:
        if commit_hash[:8] in result.stdout:
            logger.info("Commit %s already applied, skipping...", commit_hash[:8])
            return True, commit_hash

    # Prefer substantive source changes over changelog and version-only
    # commits, which frequently apply cleanly without carrying a CVE fix.
    substantive: list[str] = []
    metadata_only: list[str] = []
    for commit_hash in hashes:
        if is_bad_object(workspace_path, commit_hash):
            logger.warning("Skipping %s (bad object)", commit_hash[:8])
            continue
        if is_ancestor_of_head(workspace_path, commit_hash):
            logger.warning(
                "Skipping %s: already an ancestor of HEAD (shipped in this "
                "version, so it cannot be the fix)", commit_hash[:8])
            continue
        if _is_metadata_only_commit(workspace_path, commit_hash):
            logger.warning(
                "Deprioritising %s: touches only metadata/changelog files, so "
                "it cannot carry a code fix", commit_hash[:8])
            metadata_only.append(commit_hash)
        else:
            substantive.append(commit_hash)

    candidates = substantive + metadata_only
    for idx, commit_hash in enumerate(candidates, 1):
        logger.info("[%s/%s] Trying %s...", idx, len(candidates), commit_hash[:8])
        if try_cherry_pick(
                workspace_path, commit_hash, subproject=subproject,
                mainline_parent=mainline_parent):
            logger.info("✓ Success")
            return True, commit_hash
        logger.debug("✗ Failed")
        run_cmd(['git', 'cherry-pick', '--abort'], cwd=workspace_path)

    return False, None


_METADATA_ONLY_FILES = frozenset({
    'VERSION', 'CHANGES', 'NEWS', 'ChangeLog', 'RELEASE',
    'configure', 'configure.ac', 'meson.build',
    'Makefile', 'Makefile.am', 'Makefile.in',
})


def _is_metadata_only_commit(workspace_path: Path, commit_hash: str) -> bool:
    """Check if a commit only touches metadata/version files (not source code)."""
    result = run_cmd_capture(
        ['git', 'diff-tree', '--no-commit-id', '--name-only', '-r', commit_hash],
        cwd=workspace_path)
    files = set(result.stdout.splitlines())
    return bool(files) and all(
        Path(f).name in _METADATA_ONLY_FILES for f in files
    )


def find_least_conflict_commit(workspace_path: Path,
                               hashes: list[str],
                               mainline_parent: Optional[int] = None,
                               ) -> tuple[Optional[str], float]:
    """Find commit that produces the fewest merge conflicts.

    Prefers the first hash in the list (usually the actual fix) and
    skips metadata-only commits (version bumps) unless no better option.

    A commit whose cherry-pick is rejected *before it starts* (no conflict
    state created — e.g. a merge SHA that git refuses, a dirty tree) is not a
    candidate at all: scoring it as "0 conflicts" would make it look like the
    best possible pick and send the caller off to resolve a conflict that was
    never created.

    Args:
        workspace_path: Path to the git repository.
        hashes: Candidate commit hashes.

    Returns:
        Tuple of (best commit hash or None, its conflict count or ``inf``).
    """
    logger.info("All cherry-picks failed, finding commit with least conflicts")
    candidates = []

    for idx, commit_hash in enumerate(hashes):
        if is_bad_object(workspace_path, commit_hash):
            continue
        if is_ancestor_of_head(workspace_path, commit_hash):
            logger.warning(
                "Skipping %s: already an ancestor of HEAD (shipped in this "
                "version, so it cannot be the fix)", commit_hash[:8])
            continue
        parents = run_cmd_capture(
            ['git', 'rev-list', '--parents', '-n', '1', commit_hash],
            cwd=workspace_path)
        parent_count = max(0, len(parents.stdout.split()) - 1)
        if ((parent_count > 1 and mainline_parent is None)
                or (parent_count <= 1 and mainline_parent is not None)
                or (mainline_parent is not None
                    and not 1 <= mainline_parent <= parent_count)):
            logger.error("Skipping commit %s: merge mainline is ambiguous or invalid",
                         commit_hash[:12])
            continue
        command = (cherry_pick_command(workspace_path, commit_hash)
                   if mainline_parent is None else
                   cherry_pick_command(
                       workspace_path, commit_hash, mainline_parent))
        pick = run_cmd_capture(command, cwd=workspace_path)
        result = run_cmd_capture(
            ['git', 'diff', '--name-only', '--diff-filter=U'], cwd=workspace_path)
        conflict_count = len(result.stdout.splitlines())
        if pick.returncode != 0 and not has_conflict_state(workspace_path):
            logger.warning(
                "Skipping %s: cherry-pick could not start (no conflict state): %s",
                commit_hash[:8], pick.stderr.strip().splitlines()[:1])
            run_cmd(['git', 'cherry-pick', '--abort'], cwd=workspace_path)
            continue
        is_metadata = _is_metadata_only_commit(workspace_path, commit_hash)
        candidates.append((commit_hash, conflict_count, is_metadata, idx))
        run_cmd(['git', 'cherry-pick', '--abort'], cwd=workspace_path)

    if not candidates:
        return None, float('inf')

    # Sort: non-metadata first, then by conflict count, then by original order
    candidates.sort(key=lambda c: (c[2], c[1], c[3]))
    best = candidates[0]
    return best[0], best[1]
