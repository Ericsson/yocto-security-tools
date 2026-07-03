# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Main workflow functions for CVE corrector."""
import contextlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .bitbake_ops import get_state_dir
from .blame import check_vulnerability_origin
from .cherry_pick import (
    apply_series,
    apply_single_commits,
    cherry_pick_to_devtool,
    find_least_conflict_commit,
)
from .git_ops import (
    copy_missing_files_from_devtool,
    detect_monorepo_subproject,
    find_exact_tag,
    git_clean_workspace,
    is_bad_object,
    try_cherry_pick,
)
from .meta_layer import create_layer_commit, write_cve_status
from .patch_ops import update_patches_with_metadata
from .ptest import check_ptest_in_recipe, compare_ptest_results, run_ptest
from .recipe_ops import (
    remove_bbappend_leaks,
    restore_bbappend_extras,
    save_bbappend_extras,
    snapshot_src_uri,
)
from .state import (
    AlreadyAppliedError,
    BuildError,
    BuildPreexistingError,
    ConflictError,
    GitError,
    MetadataError,
    NotApplicableError,
    PtestError,
    PtestPreexistingError,
    WorkflowState,
    save_progress,
    save_workflow_state,
)
from .ui import print_conflict_instructions, print_edit_instructions, print_manual_instructions
from .utils import logger, run_cmd, run_cmd_capture
from .workspace import prepare_cve_branch, setup_devtool_workspace, setup_upstream_remote


def _kill_bitbake_server() -> None:
    """Kill any running bitbake server and all child processes."""
    import os
    import signal
    import time
    builddir = os.environ.get('BUILDDIR', os.environ.get('BBPATH', ''))
    if not builddir:
        run_cmd(['bitbake', '--kill-server'], timeout=30)
        return
    lockfile = Path(builddir) / 'bitbake.lock'
    if not lockfile.exists():
        run_cmd(['bitbake', '--kill-server'], timeout=30)
        return
    try:
        pid = int(lockfile.read_text().strip())
        # Kill entire process group to catch workers and child processes
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGTERM)
        time.sleep(3)
        # Force-kill stragglers
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
            os.kill(pid, signal.SIGKILL)
    except (ValueError, ProcessLookupError, PermissionError, OSError):
        pass
    # Remove all stale IPC files so a fresh server starts cleanly
    build = Path(builddir)
    for pattern in ('bitbake.sock', 'bitbake.lock', 'hashserve.sock'):
        (build / pattern).unlink(missing_ok=True)
    time.sleep(2)


def _ensure_devtool_branch(workspace_path: Path) -> None:
    """Ensure the workspace source tree is on the devtool branch.

    After agent conflict resolution, the tree may be left on the CVE branch.
    devtool finish requires the devtool branch to generate patches correctly.
    """
    result = run_cmd_capture(['git', 'branch', '--show-current'], cwd=workspace_path)
    current = result.stdout.strip() if result.returncode == 0 else ''
    if current != 'devtool':
        logger.warning("⚠ Agent switched to %s branch — forcing back to devtool",
                       current or '(detached)')
        if run_cmd(['git', 'checkout', '-f', 'devtool'], cwd=workspace_path) != 0:
            raise GitError("Failed to checkout devtool branch for finish step")


def _ensure_layer_branch(meta_layer: Path) -> None:
    """Ensure the target meta-layer is on a branch (not detached HEAD).

    devtool finish commits into the meta-layer, which requires a branch.
    A detached HEAD causes a cryptic git failure at the end of the workflow.
    """
    result = run_cmd_capture(['git', 'branch', '--show-current'], cwd=meta_layer)
    branch = result.stdout.strip() if result.returncode == 0 else ''
    if not branch:
        raise GitError(
            f"Meta-layer {meta_layer} has detached HEAD. "
            f"Check out a branch (e.g. 'git checkout <branch>') before running."
        )


def _run_build_step(state: WorkflowState) -> None:
    """Build recipe after patch, saving progress on failure."""
    if state.skip_build:
        logger.info("Skipping build")
        return
    logger.info("Building %s", state.recipe)
    git_clean_workspace(state.workspace_path, remove_ignored=True)
    copy_missing_files_from_devtool(state.workspace_path)
    run_cmd(['bitbake', '-c', 'clean', state.recipe])
    if run_cmd(['devtool', 'build', state.recipe]) != 0:
        save_progress(state, 'build_after_patch')
        raise BuildError(f"Build failed for {state.recipe}")


def _run_ptest_step(state: WorkflowState) -> Optional[str]:
    """Run ptest after patch, returning ptest output or None."""
    if state.skip_ptest:
        logger.info("Skipping ptest")
        return None
    logger.info("Running ptest for %s (after patch)", state.recipe)
    try:
        ptest_after = run_ptest(state.recipe)
    except BuildPreexistingError:
        save_progress(state, 'build_after_patch')
        raise BuildError(f"Test image build failed for {state.recipe}") from None
    if ptest_after:
        logger.info("✓ Ptest completed: %s", ptest_after)
        if state.ptest_before:
            logger.info("Before: %s", state.ptest_before)
            logger.info("After: %s", ptest_after)
            if not compare_ptest_results(state.ptest_before, ptest_after):
                logger.error("Ptest failures increased after patch. Fix the patch to correct the failing test cases.")
                logger.error("cd %s", state.workspace_path)
                save_progress(state, 'ptest_after_patch')
                raise PtestError("Ptest failures increased after patch")
    elif state.ptest_before:
        logger.error("Post-patch ptest failed to run. Fix the patch.")
        logger.error("cd %s", state.workspace_path)
        save_progress(state, 'ptest_after_patch')
        raise PtestError("Post-patch ptest failed to run")
    state.ptest_after = ptest_after
    return ptest_after


def _make_should_run(state: WorkflowState):
    """Return a function that checks whether a step should run based on resume state."""
    steps = ['cherry_pick_to_devtool', 'build_after_patch', 'ptest_after_patch', 'finish']

    if state.current_step and state.current_step not in steps:
        logger.warning("Unknown resume step '%s', running all steps", state.current_step)

    def should_run(step):
        if not state.current_step or state.current_step not in steps:
            return True
        return steps.index(step) >= steps.index(state.current_step)
    return should_run


def finish_cve_workflow(state: WorkflowState) -> None:
    """Complete CVE workflow: build, test, generate patch, and commit.

    Args:
        state: WorkflowState with all necessary context

    Raises:
        SystemExit: On build, ptest, or git operation failure
    """
    should_run = _make_should_run(state)

    if should_run('cherry_pick_to_devtool'):
        cherry_pick_to_devtool(state)

    if should_run('build_after_patch'):
        _run_build_step(state)

    ptest_after = None
    if should_run('ptest_after_patch'):
        ptest_after = _run_ptest_step(state)

    ptest_output = (f"Before: {state.ptest_before}\nAfter: {ptest_after}"
                    if state.ptest_before and ptest_after else None)

    state_file = get_state_dir() / f"{state.workspace_path.name}.json"

    logger.info("Cleaning workspace")
    run_cmd(['git', 'clean', '-fdx', '-e', 'oe-local-files'],
            cwd=state.workspace_path)
    # Restore modified tracked files (e.g. autotools-regenerated Makefile.in)
    # so devtool finish doesn't choke exporting them to a partial temp dir.
    run_cmd(['git', 'checkout', '.'], cwd=state.workspace_path)

    if should_run('finish'):
        # Pre-flight: meta-layer must be on a branch for devtool finish to commit.
        if state.meta_layer:
            _ensure_layer_branch(state.meta_layer)
        # Ensure we're on the devtool branch — devtool finish uses it to
        # generate patches.  The agent may have left us on the CVE branch.
        _ensure_devtool_branch(state.workspace_path)
        saved_extras = save_bbappend_extras(state.meta_layer, state.recipe)
        pre_finish_entries = snapshot_src_uri(state.meta_layer, state.recipe)
        if state.bbappend:
            logger.info("Creating bbappend for %s in %s", state.recipe, state.meta_layer)
            if run_cmd(['devtool', 'update-recipe', '-a', str(state.meta_layer),
                        '-w', state.recipe]) != 0:
                save_progress(state, 'finish')
                raise GitError("Git operation failed")
            # Rename wildcard bbappend (recipe_%.bbappend) to versioned name
            if state.version and state.meta_layer:
                for wc in state.meta_layer.rglob(f'{state.recipe}_%.bbappend'):
                    versioned = wc.with_name(
                        f'{state.recipe}_{state.version}.bbappend')
                    wc.rename(versioned)
                    logger.info("Renamed %s -> %s", wc.name, versioned.name)
            if run_cmd(['devtool', 'reset', state.recipe]) != 0:
                logger.warning("devtool reset failed, continuing anyway")
        else:
            logger.info("Running devtool finish %s %s", state.recipe, state.meta_layer)
            # Kill stale bitbake server (e.g. from ptest image build) so
            # devtool finish gets a fresh server that picks up workspace changes.
            _kill_bitbake_server()
            ret = run_cmd(['devtool', 'finish', '-f', '-n',
                           state.recipe, str(state.meta_layer)],
                          timeout=600)
            if ret == -1:
                logger.warning("devtool finish timed out — killing bitbake "
                               "server and retrying")
                _kill_bitbake_server()
                ret = run_cmd(['devtool', 'finish', '-f', '-n',
                               state.recipe, str(state.meta_layer)],
                              timeout=600)
            if ret != 0:
                save_progress(state, 'finish')
                raise GitError("Git operation failed")
        restore_bbappend_extras(state.meta_layer, state.recipe, saved_extras)
        remove_bbappend_leaks(state.meta_layer, state.recipe, pre_finish_entries)

    update_patches_with_metadata(state)

    used_commits = (state.series_state or {}).get('commits') or [state.commit_hash]
    committed = create_layer_commit(state.meta_layer, state.recipe, state.cve_id,
                                    ptest_output, state.skip_confirm,
                                    hash_details=state.hash_details,
                                    series_state=state.series_state,
                                    used_commits=used_commits)

    if not committed and state.meta_layer:
        # Check if there were actually no changes (vs user cancelled)
        result = run_cmd_capture(
            ['git', 'status', '--porcelain'], cwd=state.meta_layer)
        if not result.stdout.strip():
            # No changes at all — write CVE_STATUS instead
            subject = run_cmd_capture(
                ['git', 'log', '-1', '--format=%s', state.commit_hash],
                cwd=state.workspace_path if state.workspace_path.exists() else state.meta_layer
            ).stdout.strip()
            reason = (f"Upstream fix ({state.commit_hash[:12]}: {subject}) produces "
                      f"no net changes after conflict resolution — "
                      f"code already matches the fixed version")
            write_cve_status(state.meta_layer, state.recipe, state.cve_id,
                             reason, skip_confirm=state.skip_confirm)
            if state_file.exists():
                state_file.unlink()
            logger.info("CVE_STATUS written for %s — no patch needed", state.cve_id)
            raise AlreadyAppliedError("CVE already applied")
        else:
            # User cancelled — just exit cleanly
            if state_file.exists():
                state_file.unlink()
            logger.info("Commit cancelled by user. Changes remain in meta-layer working tree.")
            return

    if state_file.exists():
        state_file.unlink()

    logger.info("✓ Successfully corrected %s", state.cve_id)


def continue_from_conflict() -> WorkflowState:
    """Continue CVE correction after manual conflict resolution."""
    state_dir = get_state_dir()
    state_files = list(state_dir.glob('*.json'))
    if not state_files:
        logger.error("No saved state found. Run without --continue first.")
        raise MetadataError("Metadata error")

    if len(state_files) > 1:
        names = ', '.join(sf.name for sf in state_files)
        logger.error(
            "Multiple state files found (%s). Specify which CVE to resume with "
            "--cve-id or remove the unwanted state files from %s.",
            names, state_dir)
        raise MetadataError("Ambiguous resume state — multiple CVEs in progress")

    with open(state_files[0], encoding='utf-8') as f:
        data = json.load(f)

    state = WorkflowState.from_dict(data)
    logger.info("Resuming %s for %s...", state.cve_id, state.recipe)
    if state.current_step:
        logger.info("Resuming from step: %s", state.current_step)
    if state.series_state:
        applied = len(state.series_state.get('applied_commits', []))
        remaining = len(state.series_state.get('remaining_commits', []))
        logger.info("Series state: %d commits applied, %d remaining", applied, remaining)
    logger.info("Working in: %s", state.workspace_path)

    logger.info("Cleaning old build data")
    git_clean_workspace(state.workspace_path)

    if state.current_step != 'ptest_after_patch':
        # Check for actual unmerged (conflicted) files, not just any dirty file.
        # Modified files (e.g. autotools-generated configure) are normal.
        result = run_cmd_capture(['git', 'status', '--porcelain'], cwd=state.workspace_path)
        has_conflicts = any(
            line and len(line) >= 2 and ('U' in line[:2] or line[:2] == 'DD' or line[:2] == 'AA')
            for line in result.stdout.splitlines()
        )
        if has_conflicts:
            logger.error("Conflicts still present. Please resolve first.")
            raise ConflictError("Conflict detected")

    if state.series_state and state.series_state.get('remaining_commits'):
        logger.info("Continuing series application")
        remaining_commits: list = state.series_state['remaining_commits']
        # Check if git cherry-pick --continue already applied them
        log_result = run_cmd_capture(
            ['git', 'log', '--oneline', 'original-version..HEAD'],
            cwd=state.workspace_path)
        applied_log = log_result.stdout if log_result.returncode == 0 else ''
        remaining_commits = [c for c in remaining_commits if c[:8] not in applied_log]
        if not remaining_commits:
            logger.info("All remaining commits already applied (via cherry-pick --continue)")
        for idx, commit_hash in enumerate(remaining_commits, 1):
            if is_bad_object(state.workspace_path, commit_hash):
                logger.warning("[%d/%d] Skipping %s (bad object)",
                               idx, len(remaining_commits), commit_hash[:8])
                continue
            logger.info("[%d/%d] Cherry-picking %s...",
                        idx, len(remaining_commits), commit_hash[:8])
            if not try_cherry_pick(state.workspace_path, commit_hash,
                                   subproject=state.subproject):
                logger.error("Failed at commit %s", commit_hash[:8])
                state.series_state['remaining_commits'] = remaining_commits[idx:]
                save_workflow_state(state)
                print_conflict_instructions(state.workspace_path, state.recipe)
                raise ConflictError("Conflict detected")
        logger.info("✓ All remaining commits applied successfully")

    # After conflict resolution, transfer commits to devtool branch.
    # Only reset to cherry_pick_to_devtool if we haven't passed that step yet.
    post_conflict_steps = {'cherry_pick_to_devtool', 'build_after_patch',
                           'ptest_after_patch', 'finish'}
    if state.current_step not in post_conflict_steps:
        state.current_step = 'cherry_pick_to_devtool'
    return state


@dataclass
class WorkflowConfig:
    """Configuration parameters for CVE workflow initialization."""
    mirror_path: Optional[Path]
    mirror_dir: Optional[Path]
    meta_layer: Optional[Path]
    skip_build: bool
    clean: bool
    skip_ptest: bool
    edit_mode: bool
    manual_mode: bool = False
    bbappend: bool = False
    skip_cve_applicability: bool = False
    skip_confirm: bool = False


def _handle_failed_series(workspace_path, best_series, make_state, recipe):
    """Handle partial series application by setting up conflict state."""
    run_cmd(['git', 'cherry-pick'] + best_series['commits'], cwd=workspace_path)
    state = make_state(best_series['failed_at'], best_series)
    save_workflow_state(state)
    print_conflict_instructions(workspace_path, recipe, best_series)
    logger.error("Conflict at commit %s", best_series['failed_at'][:8])
    raise ConflictError("Conflict detected")


def _handle_no_clean_apply(workspace_path, hashes, series, make_state, recipe):
    """Handle case where no commit applied cleanly."""
    if series:
        logger.error("All PR series failed")
    if hashes:
        best_hash, conflicts = find_least_conflict_commit(workspace_path, hashes)
        if best_hash and conflicts < float('inf'):
            logger.info("Applying commit %s with %s conflict(s)...",
                        best_hash[:8], conflicts)
            run_cmd(['git', 'cherry-pick', best_hash], cwd=workspace_path)
            save_workflow_state(make_state(best_hash))
            print_conflict_instructions(workspace_path, recipe)
            raise ConflictError("Conflict detected")
    logger.error("Failed to apply any fix")
    raise ConflictError("Conflict detected")


def initialize_cve_workflow(
        cve_data: dict, cve_id: str, config: WorkflowConfig
) -> WorkflowState:
    """Initialize CVE correction workflow and apply fix commits.

    Sets up the devtool workspace, configures upstream remote, prepares the
    CVE branch, runs pre-patch verification (ptest and/or build), then
    applies the CVE fix commits via series or single cherry-picks.

    The pre-patch build verification is skipped when ptest is enabled for
    the recipe, since ptest already builds the recipe as part of its run.

    Args:
        cve_data: Dict of CVE metadata from JSON file
        cve_id: CVE identifier to process
        config: WorkflowConfig with all configuration options

    Returns:
        WorkflowState ready for finish_cve_workflow

    Raises:
        SystemExit: On conflict (EXIT_CONFLICT), pre-existing build failure
            (EXIT_BUILD_PREEXISTING), pre-existing ptest failure
            (EXIT_PTEST_PREEXISTING), or other errors
    """
    if cve_id not in cve_data:
        logger.error("CVE %s not found in metadata", cve_id)
        raise MetadataError("Metadata error")

    cve_info = cve_data[cve_id]
    recipe = cve_info.get('name')
    hashes = cve_info.get('hashes', [])
    hash_details = cve_info.get('hash_details', [])
    series = cve_info.get('series', [])

    if not recipe or (not hashes and not series):
        logger.error("CVE %s missing recipe name or fix commits/series", cve_id)
        raise MetadataError("Metadata error")

    logger.info("Processing %s for recipe: %s", cve_id, recipe)

    # Pre-flight: fail fast if the meta-layer is on a detached HEAD, before the
    # expensive devtool modify / ptest / build steps. devtool finish needs a
    # branch to commit the CVE patch onto; catching it here avoids wasting a
    # full build+ptest cycle only to fail at the finish step (see
    # _ensure_layer_branch, also re-checked before finish as a safety net).
    if config.meta_layer:
        _ensure_layer_branch(config.meta_layer)

    workspace_path, version = setup_devtool_workspace(
        recipe, config.clean, config.skip_ptest)
    mirror_name = setup_upstream_remote(
        workspace_path, config.mirror_path, config.mirror_dir,
        recipe, hash_details, series,
        references=cve_info.get('references', []))

    # Detect monorepo layout (e.g. GStreamer monorepo with subprojects/)
    subproject = None
    if mirror_name and version:
        result = run_cmd_capture(['git', 'tag'], cwd=workspace_path)
        tags = result.stdout.strip().split('\n') if result.stdout.strip() else []
        search_version = re.sub(r"^\d+_", "", version.replace("p", "_P"))
        tag = find_exact_tag(tags, search_version)
        if tag:
            subproject = detect_monorepo_subproject(
                workspace_path, tag, mirror_name, recipe=recipe)

    checkout_ok, skipped = prepare_cve_branch(workspace_path, version, cve_id, subproject=subproject)
    if skipped:
        logger.warning("Skipped %d devtool commit(s) during branch preparation", len(skipped))

    # Check if CVE is already fixed by an existing patch in the recipe
    # Exclude upstream history to avoid false positives when the full
    # upstream repo is fetched (only devtool-applied patches matter).
    log_cmd = ['git', 'log', '--grep', f'CVE: {cve_id}', '--format=%h %s',
               'original-version']
    remotes = run_cmd_capture(['git', 'remote'], cwd=workspace_path)
    remote_names = remotes.stdout.split()
    upstream_remotes = [r for r in remote_names if r.startswith('upstream')]
    if upstream_remotes:
        log_cmd.append('--not')
        log_cmd += [f'--remotes={r}' for r in upstream_remotes]
    existing = run_cmd_capture(log_cmd, cwd=workspace_path)
    if existing.stdout.strip():
        logger.info("CVE %s: already patched in recipe — %s",
                    cve_id, existing.stdout.strip().splitlines()[0])
        raise AlreadyAppliedError("CVE already applied")

    # Check if the vulnerable code exists in this recipe version
    if not config.skip_cve_applicability and version:
        not_applicable = check_vulnerability_origin(
            workspace_path, hashes, version, series)
        if not_applicable:
            logger.info("CVE %s: %s", cve_id, not_applicable)
            if config.meta_layer:
                if not config.skip_confirm:
                    print("\n⚠ Applicability check determined CVE is NOT applicable:")
                    print(f"  {not_applicable}")
                    response = input("Write CVE_STATUS to mark as not-applicable? [Y/n]: ").strip().lower()
                    if response and response != 'y':
                        logger.info("Skipping CVE_STATUS write, continuing with patch.")
                        # User disagrees — don't raise, continue with normal workflow
                    else:
                        write_cve_status(config.meta_layer, recipe, cve_id,
                                         not_applicable, skip_confirm=True)
                        raise NotApplicableError("CVE not applicable")
                else:
                    write_cve_status(config.meta_layer, recipe, cve_id,
                                     not_applicable, skip_confirm=True)
                    raise NotApplicableError("CVE not applicable")
            else:
                raise NotApplicableError("CVE not applicable")

    ptest_before = None

    if not config.skip_ptest and check_ptest_in_recipe(recipe):
        logger.info("Running ptest for %s (before patch)", recipe)
        ptest_before = run_ptest(recipe)
        if not ptest_before:
            logger.error("Failed to run pre-patch tests")
            raise PtestPreexistingError("Pre-patch ptest failed")
        if 'FAILED:' in ptest_before and re.search(r'FAILED:\s*[1-9]', ptest_before):
            logger.warning("Pre-patch ptest has existing failures — recording baseline")
            logger.warning("Results: %s", ptest_before)
        logger.info("Before: %s", ptest_before)

    if not config.skip_build and not ptest_before:
        logger.info("Pre-patch build verification for %s", recipe)
        if run_cmd(['devtool', 'build', recipe]) != 0:
            logger.error("Pre-patch build failed")
            raise BuildPreexistingError("Pre-patch build failed")
        logger.info("Pre-patch build OK, cleaning")
        run_cmd(['bitbake', '-c', 'clean', recipe])

    def make_state(commit_hash, series_state=None):
        return WorkflowState(
            workspace_path=workspace_path, cve_id=cve_id, recipe=recipe,
            commit_hash=commit_hash,
            hash_details=hash_details,
            meta_layer=config.meta_layer,
            skip_build=config.skip_build, skip_ptest=config.skip_ptest,
            ptest_before=ptest_before, series_state=series_state,
            subproject=subproject, bbappend=config.bbappend,
            version=version)

    if config.manual_mode:
        state = make_state(hashes[0] if hashes else '')
        save_workflow_state(state)
        print_manual_instructions(workspace_path, recipe, hashes, series)
        raise SystemExit(0)

    success, successful_hash, best_series = False, None, None
    applied_series = None

    if series:
        success, successful_hash, best_series = apply_series(
            workspace_path, series)
        if success:
            # Preserve commit list for patch metadata (Upstream-Status per patch)
            for pr_series in series:
                commits = pr_series.get('commits', [])
                if successful_hash in commits:
                    applied_series = pr_series
                    break
        if not success and best_series:
            _handle_failed_series(
                workspace_path, best_series, make_state, recipe)

    if not success and hashes:
        success, successful_hash = apply_single_commits(
            workspace_path, hashes, subproject=subproject)

    if not success:
        _handle_no_clean_apply(
            workspace_path, hashes, series, make_state, recipe)

    if config.edit_mode:
        save_workflow_state(make_state(successful_hash))
        print_edit_instructions(workspace_path, recipe, successful_hash or "")
        raise SystemExit(0)

    return make_state(successful_hash, applied_series)
