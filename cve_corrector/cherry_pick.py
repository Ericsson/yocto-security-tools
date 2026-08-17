# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Cherry-pick and series application logic for CVE corrector."""
import tempfile
from pathlib import Path
from typing import Optional

from .git_ops import (
    cherry_pick_command,
    git_clean_workspace,
    has_conflict_state,
    is_ancestor_of_head,
    is_bad_object,
    try_cherry_pick,
)
from .meta_layer import write_cve_status
from .state import AlreadyAppliedError, GitError, PatchError, WorkflowState, save_progress
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


def _git_apply_patch(workspace_path: Path, patch: Path, cve_id: str,
                     strip_level: int) -> bool:
    """Apply a single patch with git-apply, committing it on success."""
    variants = [
        ['git', 'apply', f'-p{strip_level}', str(patch)],
        ['git', 'apply', f'-p{strip_level}', '-C0', str(patch)],
        ['git', 'apply', f'-p{strip_level}', '--3way', str(patch)],
    ]
    # When git am has already failed, this is the last thing standing between
    # a resolved conflict and an unrecoverable PatchError -- so log why each
    # variant refused the patch. Silently returning False here made an
    # over-broad AI resolution (one that no longer matches the tree it must
    # replay onto) indistinguishable from a genuinely malformed patch.
    errors = []
    for apply_args in variants:
        result = run_cmd_capture(apply_args, cwd=workspace_path)
        if result.returncode != 0:
            errors.append(f"{' '.join(apply_args[1:-1])}: "
                          f"{result.stderr.strip() or 'no stderr'}")
            continue
        run_cmd(['git', 'add', '-A'], cwd=workspace_path)
        run_cmd_capture(
            ['git', 'commit', '-m', f'Apply {cve_id} patch ({patch.name})'],
            cwd=workspace_path)
        logger.info("Applied %s via %s", patch.name, ' '.join(apply_args[1:-1]))
        return True
    logger.warning("git apply could not apply %s; tried %s variant(s): %s",
                   patch.name, len(variants), ' | '.join(errors))
    return False


def cherry_pick_to_devtool(state: WorkflowState) -> None:
    """Cherry-pick CVE commits onto devtool branch via format-patch + git am."""
    logger.info("Cherry-picking commits to devtool branch")
    subdir = get_repo_subdir(state.workspace_path)

    with tempfile.TemporaryDirectory() as patch_dir:
        cve_commits = collect_cve_commits(state)
        if not cve_commits:
            logger.info("No CVE commits to transfer — fix already in tree")
            handle_empty_cherry_pick(state)
            raise AlreadyAppliedError("no CVE commits to transfer to devtool")
        logger.info("Transferring %s CVE commit(s) to devtool", len(cve_commits))
        for number, commit in enumerate(cve_commits, 1):
            fmt_result = run_cmd_capture(
                ['git', 'format-patch', '-o', patch_dir,
                 '--start-number', str(number), '-1', commit],
                cwd=state.workspace_path)
            if fmt_result.returncode != 0:
                raise PatchError(
                    f"format-patch failed for {commit[:12]}: {fmt_result.stderr}")
        patches = sorted(Path(patch_dir).glob('*.patch'))
        if not patches:
            logger.info("format-patch produced no patches — fix already in tree")
            handle_empty_cherry_pick(state)
            raise AlreadyAppliedError("format-patch produced no patches")
        logger.info("Generated %s patch(es) for devtool", len(patches))
        for p in patches:
            logger.info("  Patch: %s (first 3 diff lines: %s)", p.name,
                        [ln for ln in p.read_text().splitlines() if ln.startswith('diff ')][:3])

        strip_level = detect_strip_level(patches)
        if strip_level == 1 and subdir:
            strip_level = 2
        logger.info("Monorepo subdir: %s, strip level: %s", subdir, strip_level)

        git_clean_workspace(state.workspace_path, remove_ignored=True)
        run_cmd(['git', 'checkout', '.'], cwd=state.workspace_path)
        if run_cmd(['git', 'checkout', '-f', 'devtool'],
                   cwd=state.workspace_path) != 0:
            save_progress(state, 'cherry_pick_to_devtool')
            raise GitError("Failed to checkout devtool branch")

        # Try detected strip level first, then alternate levels
        strip_levels = [strip_level] + [
            p for p in (1, 2, 3) if p != strip_level
        ]
        am_result = None
        # Every attempt's stderr, in order tried, as (label, stderr) pairs.
        # Without this, `am_result` holds only the LAST attempt's error -- and
        # since the loop ends on `-p3 --3way`, a patch that genuinely failed at
        # the detected strip level for an unrelated reason gets reported as
        # "lacks filename information when removing 3 leading pathname
        # components", which describes only the final, least-relevant attempt.
        am_failures: list[tuple[str, str]] = []
        for p_level in strip_levels:
            am_cmd = ['git', 'am', f'-p{p_level}']
            am_result = run_cmd_capture(
                am_cmd + [str(p) for p in patches],
                cwd=state.workspace_path)
            if am_result.returncode == 0:
                if p_level != strip_level:
                    logger.info("Strip level %s worked (detected %s)",
                                p_level, strip_level)
                break
            logger.debug("git am -p%s failed: %s", p_level, am_result.stderr[:200])
            am_failures.append((f'-p{p_level}', am_result.stderr))
            run_cmd(['git', 'am', '--abort'], cwd=state.workspace_path)
            # Try with --3way at this level
            am_result = run_cmd_capture(
                am_cmd + ['--3way'] + [str(p) for p in patches],
                cwd=state.workspace_path)
            if am_result.returncode == 0:
                if p_level != strip_level:
                    logger.info("Strip level %s (3way) worked (detected %s)",
                                p_level, strip_level)
                break
            logger.debug("git am -p%s --3way failed: %s",
                         p_level, am_result.stderr[:200])
            am_failures.append((f'-p{p_level} --3way', am_result.stderr))
            run_cmd(['git', 'am', '--abort'], cwd=state.workspace_path)

        if am_result and am_result.returncode != 0:
            # Fallback: try cherry-picking CVE commits directly onto devtool
            logger.warning("git am failed at all strip levels, trying direct cherry-pick")
            all_picked = True
            for commit in cve_commits:
                ret = run_cmd_capture(['git', 'cherry-pick', commit],
                                      cwd=state.workspace_path)
                if ret.returncode != 0:
                    run_cmd(['git', 'cherry-pick', '--abort'],
                            cwd=state.workspace_path)
                    all_picked = False
                    break
            if all_picked:
                logger.info("Applied CVE commits via direct cherry-pick on devtool")
                return

            # Last resort: git apply, all patches in order (a partially applied
            # series is worse than no patch at all, so roll back on failure).
            logger.warning("Cherry-pick fallback failed, trying git apply")
            pre_apply = run_cmd_capture(['git', 'rev-parse', 'HEAD'],
                                        cwd=state.workspace_path).stdout.strip()
            if all(_git_apply_patch(state.workspace_path, p, state.cve_id, strip_level)
                   for p in patches):
                logger.info("Applied %s patch(es) via git apply on devtool", len(patches))
                return
            if pre_apply:
                run_cmd(['git', 'reset', '--hard', pre_apply], cwd=state.workspace_path)

            # Report the attempt at the DETECTED strip level, not the last one
            # tried: the alternate levels are speculative retries, and their
            # "lacks filename information" complaints are an artifact of
            # stripping too many path components rather than the real problem.
            if am_failures:
                primary_label, primary_err = am_failures[0]
            else:
                primary_label, primary_err = f'-p{strip_level}', am_result.stderr
            tried = ', '.join(label for label, _ in am_failures)
            logger.error("git am failed at all strip levels (tried: %s); "
                         "error at detected level %s: %s",
                         tried, primary_label, primary_err)
            save_progress(state, 'cherry_pick_to_devtool')
            raise PatchError(
                f"git am {primary_label} failed: {primary_err.strip()} "
                f"(also tried: {tried}; then direct cherry-pick and git apply)")



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
        require_all: When True the commits form a caller-declared dependent
            chain, so conflict state is reported even if nothing applied.

    Returns:
        Tuple of (success, last_commit_hash, best_partial_series)
    """
    logger.info("Found %s commit series", len(series))
    best_series = None
    # A required chain must always surface conflict state, even when the very
    # first commit conflicts and zero commits were applied — otherwise the
    # caller falls back to applying a single commit, silently leaving the CVE
    # only partially fixed. Candidate series keep the original ">0 applied"
    # bar so their existing fallback behaviour is unchanged.
    max_applied = -1 if require_all else 0

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

    # Order candidates before trying any of them. This loop returns the *first*
    # commit that cherry-picks cleanly, so a trivial-but-irrelevant commit
    # sitting ahead of the real fix wins outright — and the more irrelevant it
    # is, the more likely it applies without conflict.
    #
    # CVE-2024-6387's metadata is the cautionary case: four hashes drawn from
    # three different repositories (openssh-portable twice, plus the
    # openela-main and hpn-ssh forks). After the bad-object and ancestor
    # filters, two survive: the genuine 9.8 fix 81c1099d2, which touches
    # sshd.c and conflicts heavily against 9.6p1, and 651879740 — a 2006
    # ChangeLog-only commit on the V_4_4 branch, which applies trivially.
    # Without this ordering the corrector reports success having backported a
    # twenty-year-old documentation change as the fix for a pre-auth RCE.
    substantive: list[str] = []
    metadata_only: list[str] = []
    for commit_hash in hashes:
        if is_bad_object(workspace_path, commit_hash):
            logger.warning("Skipping %s (bad object)", commit_hash[:8])
            continue
        # A commit already in this branch's history shipped in this version, so
        # it cannot be the fix. Replaying it pits stale code against whatever
        # superseded it, which surfaces as a large, plausible-looking conflict.
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
    # A commit touching *only* the top-level Makefile is a release/version
    # bump, not a fix: upstreams like u-boot cut releases by editing the
    # VERSION/PATCHLEVEL variables there. CVE-2025-24857's sole metadata hash
    # (c253573f3e2, "Prepare v2017.11") is exactly this shape -- a 2017 release
    # commit changing one Makefile line, eight years older than the CVE. A
    # genuine fix that happens to touch a Makefile also touches source, so it
    # never trips this all()-based check.
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
        # Same reasoning as apply_single_commits: an ancestor of HEAD is not a
        # candidate. Without this it is often the *winner* here, because
        # replaying superseded code conflicts in a way that can score lower
        # than the real fix's genuine adaptation work.
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
