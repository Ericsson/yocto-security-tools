# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Devtool workspace setup and CVE branch preparation."""
from pathlib import Path
from typing import Optional

from .bitbake_ops import (
    cleanup_workspace,
    find_mirror_repo,
    get_build_path,
    get_recipe_src_uri_git,
    get_upstream_check_uri,
)
from .git_ops import checkout_version, copy_missing_files_from_devtool, deduce_repo_from_patches
from .ptest import enable_ptest
from .state import DevtoolError, GitError, MetadataError
from .utils import logger, run_cmd, run_cmd_capture

# Branch names to check when determining the devtool workspace base ref
_DEVTOOL_BASE_BRANCHES = ('main', 'master', 'devtool-base')


def setup_devtool_workspace(
        recipe: str, clean: bool, skip_ptest: bool
) -> tuple[Path, Optional[str]]:
    """Setup devtool workspace for recipe modification.

    Args:
        recipe: Name of the recipe to modify
        clean: If True, clean existing workspace before starting
        skip_ptest: If True, skip ptest enablement

    Returns:
        Tuple of (workspace_path, version) where version may be None
    """
    build_path = get_build_path()

    if clean:
        logger.info("Cleaning up workspace")
        cleanup_workspace(str(build_path))

    if not skip_ptest:
        logger.info("Enabling ptest")
        enable_ptest()

    logger.info("Running devtool modify %s", recipe)
    ret = run_cmd(['devtool', 'modify', recipe])
    if ret != 0:
        result = run_cmd_capture(['devtool', 'status'])
        if recipe not in result.stdout:
            logger.error("devtool modify failed")
            raise DevtoolError("devtool modify failed")
        logger.info("Recipe %s already in workspace, continuing...", recipe)

    logger.debug("Getting version from bitbake")
    result = run_cmd_capture(['bitbake-getvar', 'PV', '-r', recipe])
    version = None
    for line in result.stdout.splitlines():
        if line.startswith('PV='):
            version = line.split('=', 1)[1].strip('"')
            logger.info("Recipe version: %s", version)
            break
    if not version:
        logger.warning("Could not get version from bitbake")

    workspace_path = build_path / 'workspace' / 'sources' / recipe
    if not workspace_path.exists():
        logger.error("Workspace not found: %s", workspace_path)
        raise MetadataError("Metadata error")

    logger.debug("Working in: %s", workspace_path)
    return workspace_path, version


def setup_upstream_remote(workspace_path: Path, mirror_path: Optional[Path],
                          mirror_dir: Optional[Path], recipe: str,
                          hash_details: list[dict],
                          series: Optional[list[dict]] = None,
                          references: Optional[list[dict]] = None) -> Optional[str]:
    """Configure upstream git remote and fetch references.

    Priority for upstream URL:
      1. Local mirror (if --mirror-dir provided and mirror found)
      2. Recipe SRC_URI git repo (authoritative source)
      3. UPSTREAM_CHECK_URI (used by AUH)
      4. Deduce from hash_details/series/references URLs

    Warns if the deduced URL differs from the recipe's known upstream,
    as this could indicate a supply-chain mismatch.

    Returns:
        Mirror directory name when a local mirror is used, or upstream repo
        basename when fetched from a remote URL. None if setup failed.
    """
    mirror_name = None
    if not mirror_path and mirror_dir:
        mirror_path = find_mirror_repo(mirror_dir, recipe, hash_details)
        if mirror_path:
            logger.info("Found mirror for %s: %s", recipe, mirror_path)
    if mirror_path:
        mirror_name = mirror_path.stem

    # Determine the recipe's authoritative upstream URL for comparison
    recipe_upstream: Optional[str] = None

    if mirror_path:
        upstream_url: Optional[str] = str(mirror_path.absolute())
    else:
        # Try SRC_URI git repo first (authoritative)
        src_uri_git = get_recipe_src_uri_git(recipe)
        if src_uri_git:
            logger.info("Using SRC_URI git repo: %s", src_uri_git)
            upstream_url = src_uri_git
            recipe_upstream = src_uri_git
        else:
            # Try UPSTREAM_CHECK_URI (used by AUH)
            check_uri = get_upstream_check_uri(recipe)
            if check_uri:
                logger.info("Using UPSTREAM_CHECK_URI: %s", check_uri)
                upstream_url = check_uri
                recipe_upstream = check_uri
            else:
                # Fall back to deduction from hash_details/references
                logger.info("No git SRC_URI or UPSTREAM_CHECK_URI, deducing from hash details")
                urls = [d['url'] for d in hash_details if d.get('url')]
                if not urls and series:
                    urls = [s['pull_url'] for s in series if s.get('pull_url')]
                    if urls:
                        logger.info("Deducing upstream repo from series pull_url")
                upstream_url = deduce_repo_from_patches(urls)
                if not upstream_url and references:
                    logger.info("Falling back to references for upstream deduction")
                    ref_urls = [r['url'] for r in references if r.get('url')]
                    upstream_url = deduce_repo_from_patches(ref_urls)
                if upstream_url:
                    logger.info("Deduced upstream: %s", upstream_url)
                else:
                    logger.warning("Could not deduce upstream repo")
                    return None

        # Warn if the patch-deduced upstream differs from the recipe's known
        # upstream. This must run even when SRC_URI/UPSTREAM_CHECK_URI was used
        # as the fetch source, to surface cases where the fix commit lives in a
        # different repo than the recipe fetches (e.g. bzip2 vs bzip2-tests).
        if recipe_upstream:
            patch_urls = [d['url'] for d in hash_details if d.get('url')]
            if not patch_urls and references:
                patch_urls = [r['url'] for r in references if r.get('url')]
            deduced = deduce_repo_from_patches(patch_urls)
            if deduced and _urls_differ(deduced, recipe_upstream):
                logger.warning(
                    "⚠ Deduced upstream (%s) differs from recipe SRC_URI (%s) "
                    "— verify patch origin", deduced, recipe_upstream)

    logger.info("Adding upstream remote: %s", upstream_url)
    assert upstream_url is not None
    result = run_cmd_capture(['git', 'remote'], cwd=workspace_path)
    if 'upstream' not in result.stdout:
        run_cmd(['git', 'remote', 'add', 'upstream', upstream_url], cwd=workspace_path)
    else:
        logger.debug("Upstream remote already exists, skipping...")

    logger.info("Fetching upstream references")
    if run_cmd(['git', 'fetch', 'upstream', '--tags', '--progress'], cwd=workspace_path) != 0:
        logger.warning("Failed to fetch upstream — continuing without upstream history")
        run_cmd(['git', 'remote', 'remove', 'upstream'], cwd=workspace_path)
        return None

    # Return mirror_name if available, else derive from upstream URL
    if mirror_name:
        return mirror_name
    return upstream_url.rstrip('/').rsplit('/', 1)[-1].removesuffix('.git')


def _urls_differ(url_a: str, url_b: str) -> bool:
    """Compare two git URLs ignoring protocol and .git suffix differences."""
    def normalize(url: str) -> str:
        return (url.rstrip('/').removesuffix('.git')
                .replace('https://', '').replace('http://', '')
                .replace('git://', ''))
    return normalize(url_a) != normalize(url_b)


def prepare_cve_branch(workspace_path: Path, version: Optional[str],
                       cve_id: str, subproject: Optional[str] = None) -> tuple[bool, list[str]]:
    """Checkout recipe version and prepare branch for CVE fix.

    Returns:
        Tuple of (version_checkout_ok, skipped_commits).
    """
    checkout_ok = True
    if version:
        logger.info("Checking out version %s", version)
        result = run_cmd_capture(['git', 'branch', '--list', cve_id], cwd=workspace_path)
        if result.stdout.strip():
            logger.debug("Branch %s already exists, checking out...", cve_id)
            run_cmd(['git', 'checkout', cve_id], cwd=workspace_path)
        elif not checkout_version(workspace_path, version, cve_id,
                                  subproject=subproject):
            logger.warning("Version checkout failed, will try format-patch fallback...")
            run_cmd(['git', 'checkout', '-b', cve_id], cwd=workspace_path)
            checkout_ok = False

    logger.info("Cherry-picking devtool commits")
    base_branch = None
    for candidate in _DEVTOOL_BASE_BRANCHES:
        result = run_cmd_capture(['git', 'rev-parse', '--verify', candidate],
                                 cwd=workspace_path)
        if result.returncode == 0:
            base_branch = candidate
            break
    if not base_branch:
        logger.error("Failed to find base branch (main/master/devtool-base)")
        raise GitError("Git operation failed")
    commit_list = run_cmd_capture(
        ['git', 'rev-list', '--reverse', f'{base_branch}..devtool'],
        cwd=workspace_path)
    if commit_list.returncode != 0:
        logger.error("Failed to list devtool commits")
        raise GitError("Git operation failed")
    skipped = []
    for commit in commit_list.stdout.strip().splitlines():
        if run_cmd(['git', 'cherry-pick', commit], cwd=workspace_path) != 0:
            subj = run_cmd_capture(['git', 'log', '-1', '--format=%s', commit],
                                   cwd=workspace_path)
            skipped.append(f"{commit[:12]} {subj.stdout.strip()}")
            logger.warning("Skipping devtool commit: %s", subj.stdout.strip())
            run_cmd_capture(['git', 'cherry-pick', '--abort'], cwd=workspace_path)
    if skipped:
        logger.info("Skipped %s devtool commit(s) that failed to apply:", len(skipped))
        for entry in skipped:
            logger.info("  - %s", entry)

    copy_missing_files_from_devtool(workspace_path)

    logger.debug("Creating tag original-version at current position")
    run_cmd_capture(['git', 'tag', '-f', 'original-version'], cwd=workspace_path)
    return checkout_ok, skipped
