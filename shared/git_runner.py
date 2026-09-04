# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Consolidated git/subprocess runner used by cve_corrector and cve_agent.

Provides two levels of abstraction:
- run_capture(): low-level, returns CompletedProcess (for corrector)
- run_git_stdout(): high-level git-only, returns stdout str (for agent)
"""
import logging
import subprocess
from pathlib import Path
from typing import Optional

from shared import TEXT_ENCODING, TEXT_ERRORS, build_git_env

logger = logging.getLogger(__name__)

# Batch size for chunking file lists into `git checkout`/`git reset`
# invocations. Keeps argv comfortably under typical platform ARG_MAX limits
# even for long absolute-ish repo-relative paths, while still collapsing
# hundreds of per-file subprocess spawns into a handful of calls.
_CHECKOUT_BATCH_SIZE = 200


def _chunked(items: list[str], size: int) -> list[list[str]]:
    """Split ``items`` into consecutive chunks of at most ``size`` entries."""
    return [items[i:i + size] for i in range(0, len(items), size)]


def is_git_cmd(cmd: list[str]) -> bool:
    """Check if a command is a git command that needs the restricted env."""
    return bool(cmd) and str(cmd[0]) == 'git'


def run_capture(cmd: list[str],
                cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    """Execute command and capture output.

    Automatically injects the restricted git environment for git commands.

    Args:
        cmd: Command and arguments to execute.
        cwd: Working directory for the command.

    Returns:
        CompletedProcess with stdout/stderr as strings (undecodable bytes
        replaced, see shared.TEXT_ERRORS).
    """
    env = build_git_env() if is_git_cmd(cmd) else None
    return subprocess.run(cmd, cwd=cwd, capture_output=True,
                          encoding=TEXT_ENCODING, errors=TEXT_ERRORS,
                          check=False, env=env)


def run_git_stdout(args: list[str], cwd: Path) -> str:
    """Run git command and return stdout, or empty string on failure.

    Args:
        args: Git arguments (without 'git' prefix).
        cwd: Working directory.

    Returns:
        Stripped stdout on success, empty string on failure or missing cwd.
    """
    if not cwd.exists():
        return ""
    result = subprocess.run(
        ['git'] + args, cwd=cwd, env=build_git_env(),
        capture_output=True, encoding=TEXT_ENCODING, errors=TEXT_ERRORS,
        check=False
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def is_merge_commit(cwd: Path, commit: str) -> bool:
    """Check whether *commit* is a merge (has more than one parent).

    Args:
        cwd: Repository working directory.
        commit: Commit-ish to inspect.

    Returns:
        True if the commit resolves and has 2+ parents, False otherwise
        (including when the object is missing).
    """
    # "<commit> <parent1> [<parent2> ...]" — 3+ fields means a merge.
    out = run_git_stdout(['rev-list', '--parents', '-n', '1', commit], cwd)
    return len(out.split()) > 2


def merge_diff_flags(cwd: Path, commit: str) -> list[str]:
    """Return the ``git show``/``diff-tree`` flags needed to see *commit*'s diff.

    ``git show`` deliberately prints **no diff** for a merge commit: the default
    combined-diff format suppresses hunks that came verbatim from a parent, so a
    clean GitHub "Merge pull request" commit shows an empty diff and an empty
    ``--name-only`` file list. Many upstream CVE fixes are referenced by exactly
    such merge SHAs, and treating their file list as empty silently drops the
    whole fix from any scope computed from it.

    ``-m --first-parent`` asks git for the diff against the first parent (the
    branch being merged into), which is the change the merge actually
    introduced. Both flags are harmless on non-merge commits, but they are only
    added when needed so ordinary commits keep their exact previous output.

    Args:
        cwd: Repository working directory.
        commit: Commit-ish that will be passed to ``git show``/``diff-tree``.

    Returns:
        ``['-m', '--first-parent']`` for a merge commit, else an empty list.
    """
    return ['-m', '--first-parent'] if is_merge_commit(cwd, commit) else []


def force_checkout_branch(cwd: Path, branch: str) -> bool:
    """Check out a branch, escalating cleanup until the switch succeeds.

    A devtool workspace tree is routinely left dirty: builds regenerate
    tracked autotools output (``configure``, ``Makefile.in``, ``aclocal.m4``,
    ``config/*``) and submodule content, and an aborted AI session can leave
    unmerged index entries behind.  A plain ``git checkout`` then fails with
    "Your local changes would be overwritten by checkout", stranding the tree
    on the wrong branch.

    Escalation order — each step only runs if the previous checkout failed,
    so no more state is discarded than necessary:

    1. plain ``checkout``
    2. ``checkout -f`` (discard tracked modifications and unmerged entries)
    3. ``reset --hard`` + submodule ``reset --hard`` then ``checkout -f``
    4. ``clean -fd`` (keeping ``oe-local-files``) then ``checkout -f``

    On success after any forced step, submodule working trees are re-synced to
    the target branch's gitlinks so the tree is coherent for the next
    cherry-pick.  A plain (non-forced) checkout leaves submodules untouched.

    Args:
        cwd: Repository working directory.
        branch: Branch name to check out.

    Returns:
        True if the repo ends up on ``branch``, False otherwise.
    """
    def _checkout(*flags: str) -> bool:
        if run_capture(['git', 'checkout', *flags, branch],
                       cwd=cwd).returncode != 0:
            return False
        # A forced switch leaves submodule working trees at the previous
        # branch's commits, which shows up as a dirty tree and blocks the
        # next cherry-pick.
        if flags and (cwd / '.gitmodules').exists():
            run_capture(['git', 'submodule', 'update', '--init',
                         '--recursive', '--force'], cwd=cwd)
        return True

    if _checkout():
        return True
    if _checkout('-f'):
        return True

    run_capture(['git', 'reset', '--hard', 'HEAD'], cwd=cwd)
    run_capture(['git', 'submodule', 'foreach', '--recursive',
                 'git', 'reset', '--hard'], cwd=cwd)
    if _checkout('-f'):
        return True

    # Last resort: untracked files (e.g. copied from the devtool branch) are
    # shadowing tracked paths on the target branch.  They are regenerated by
    # copy_missing_files_from_devtool() before the next build.
    run_capture(['git', 'clean', '-fd', '-e', 'oe-local-files'], cwd=cwd)
    run_capture(['git', 'submodule', 'foreach', '--recursive',
                 'git', 'clean', '-fd'], cwd=cwd)
    return _checkout('-f')


def run_git_display(args: list[str], cwd: Path) -> None:
    """Run git command with output printed directly (no pager).

    Args:
        args: Git arguments (without 'git' prefix).
        cwd: Working directory.
    """
    subprocess.run(
        ['git', '--no-pager'] + args, cwd=cwd, env=build_git_env(),
        check=False
    )


def _get_submodule_paths(workspace_path: Path) -> set[str]:
    """Return registered submodule paths from .gitmodules, if any."""
    gitmodules = workspace_path / '.gitmodules'
    if not gitmodules.exists():
        return set()
    paths: set[str] = set()
    for line in gitmodules.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith('path'):
            # e.g. "path = modules/oniguruma"
            _, _, value = stripped.partition('=')
            if value.strip():
                paths.add(value.strip())
    return paths


def copy_missing_files_from_devtool(workspace_path: Path) -> None:
    """Copy files present in devtool but missing from the CVE branch.

    Release tarballs contain generated autotools files (configure, Makefile.in,
    m4/*.m4, etc.) and secondary-tarball payloads (e.g. libxml2's ``xmlconf/``
    W3C conformance suite fetched via a second ``SRC_URI`` entry) that are
    committed on the devtool branch but do not exist on the upstream-history
    CVE branch. Switching to the CVE branch therefore strips them, and the
    build (do_configure/do_compile) then fails on the missing files. This
    copies them across from the devtool branch without tracking them, so the
    build succeeds on the CVE branch too. It is a no-op when nothing is
    missing (e.g. when already on the devtool branch).

    Files under registered submodule paths are skipped — those are tracked
    by git submodule and must not be overwritten with regular file copies.

    Files under paths that HEAD tracks as symlinks are also skipped — release
    tarballs dereference symlinks into real directories, and copying those
    files would clobber the symlink and break subsequent cherry-picks.
    """
    devtool_files = run_capture(
        ['git', 'ls-tree', '-r', '--name-only', 'devtool'], cwd=workspace_path)
    if devtool_files.returncode != 0:
        return
    cve_files = run_capture(
        ['git', 'ls-tree', '-r', '--name-only', 'HEAD'], cwd=workspace_path)
    if cve_files.returncode != 0:
        return

    cve_set = set(cve_files.stdout.strip().splitlines())
    submodule_paths = _get_submodule_paths(workspace_path)

    # Collect paths that HEAD tracks as symlinks (git mode 120000). Release
    # tarballs dereference symlinks into real directories, so the devtool
    # branch lists the symlink target's contents (e.g.
    # tutorial/swift/swift-dep/Sources/*.swift) as regular files. Copying
    # those out of devtool would clobber the symlink with a real directory,
    # leaving a staged deletion + untracked dir that blocks every subsequent
    # cherry-pick. Skip anything living under a HEAD symlink: the symlink
    # already resolves to an in-tree path, so nothing is actually missing.
    symlink_prefixes: tuple[str, ...] = ()
    cve_tree = run_capture(
        ['git', 'ls-tree', '-r', 'HEAD'], cwd=workspace_path)
    if cve_tree.returncode == 0:
        symlinks = []
        for line in cve_tree.stdout.strip().splitlines():
            # Format: "<mode> <type> <hash>\t<path>"
            meta, _, path = line.partition('\t')
            if path and meta.split(' ', 1)[0] == '120000':
                symlinks.append(path + '/')
        symlink_prefixes = tuple(symlinks)

    missing = [f for f in devtool_files.stdout.strip().splitlines()
               if f not in cve_set
               and not any(f == sm or f.startswith(sm + '/')
                           for sm in submodule_paths)
               and not (symlink_prefixes and f.startswith(symlink_prefixes))]
    if not missing:
        return

    logger.info("Copying %s missing file(s) from devtool branch", len(missing))
    # A single `git checkout devtool -- <paths...>` instead of one subprocess
    # per file: each subprocess spawn dominates the cost for trees with many
    # missing files (generated autotools output, secondary-tarball payloads
    # such as libxml2's xmlconf/ suite can be hundreds of files), so batching
    # cuts this from O(files) process spawns to one. Chunked to stay under
    # typical platform argv-length limits (ARG_MAX) for very large file sets.
    checkout_failed: list[str] = []
    for chunk in _chunked(missing, _CHECKOUT_BATCH_SIZE):
        result = run_capture(
            ['git', 'checkout', 'devtool', '--', *chunk], cwd=workspace_path)
        if result.returncode != 0:
            checkout_failed.extend(chunk)
    succeeded = [f for f in missing if f not in checkout_failed]
    if checkout_failed:
        logger.warning(
            "Failed to copy %s of %s missing file(s) from devtool branch",
            len(checkout_failed), len(missing))
    if not succeeded:
        return
    # Unstage so they remain as untracked working-tree files
    for chunk in _chunked(succeeded, _CHECKOUT_BATCH_SIZE):
        run_capture(['git', 'reset', 'HEAD', *chunk], cwd=workspace_path)
