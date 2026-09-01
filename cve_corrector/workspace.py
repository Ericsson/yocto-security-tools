# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Devtool workspace setup and CVE branch preparation."""
import re
from pathlib import Path
from typing import Optional

from shared.git_runner import force_checkout_branch

from .bitbake_ops import (
    cleanup_workspace,
    find_mirror_repo,
    get_build_path,
    get_recipe_src_uri_git,
    get_upstream_check_uri,
)
from .git_ops import (
    checkout_version,
    copy_missing_files_from_devtool,
    deduce_repo_from_patches,
    remove_git_only_build_triggers,
)
from .ptest import enable_ptest
from .state import DevtoolError, GitError, MetadataError
from .utils import logger, run_cmd, run_cmd_capture

# Branch names to check when determining the devtool workspace base ref
_DEVTOOL_BASE_BRANCHES = ('main', 'master', 'devtool-base')


def _commit_exists(repository: Path, commit_hash: str) -> bool:
    """Return whether *commit_hash* resolves to a commit in *repository*."""
    return run_cmd_capture(
        ['git', 'cat-file', '-e', f'{commit_hash}^{{commit}}'],
        cwd=repository,
    ).returncode == 0


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
                          references: Optional[list[dict]] = None,
                          premirror: Optional[str] = None) -> Optional[str]:
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
    # A patch-deduced repo that differs from the fetch source (e.g. the fix
    # commit lives in bzip2 while the recipe SRC_URI is bzip2-tests). When set,
    # it is fetched as a secondary remote so the fix commits/tags are reachable.
    fix_repo_urls: list[str] = []
    missing_hashes: list[str] = []

    if mirror_path:
        upstream_url: Optional[str] = str(mirror_path.absolute())
        missing_details = [
            detail for detail in hash_details
            if isinstance(detail.get('hash'), str)
            and not _commit_exists(mirror_path, detail['hash'])
        ]
        missing_hashes = [detail['hash'] for detail in missing_details]
        missing_by_repo: dict[str, list[str]] = {}
        for detail in missing_details:
            url = detail.get('url')
            repo = (
                deduce_repo_from_patches([url])
                if isinstance(url, str) and url else None
            )
            if repo:
                missing_by_repo.setdefault(repo, []).append(detail['hash'])
        for repo, hashes in missing_by_repo.items():
            fix_repo_urls.append(repo)
            logger.warning(
                "Local mirror lacks %d declared fix commit(s); fetching "
                "their canonical source %s",
                len(hashes), repo,
            )
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
                fix_repo_urls.append(deduced)

    logger.info("Adding upstream remote: %s", upstream_url)
    assert upstream_url is not None
    result = run_cmd_capture(['git', 'remote'], cwd=workspace_path)

    # Determine the fetch URL — try premirror first when configured and
    # the upstream URL is a remote (not a local mirror path).
    fetch_url = upstream_url
    using_premirror = False
    if premirror and not mirror_path:
        from .bitbake_ops import rewrite_url_for_premirror
        premirror_url = rewrite_url_for_premirror(upstream_url, premirror)
        logger.info("Trying premirror: %s", premirror_url)
        fetch_url = premirror_url
        using_premirror = True

    if 'upstream' not in result.stdout:
        run_cmd(['git', 'remote', 'add', 'upstream', fetch_url], cwd=workspace_path)
    else:
        logger.debug("Upstream remote already exists, skipping...")

    logger.info("Fetching upstream references")
    if not _fetch_remote(workspace_path, 'upstream', fetch_url):
        if using_premirror:
            logger.warning("Premirror fetch failed, falling back to %s", upstream_url)
            run_cmd(['git', 'remote', 'set-url', 'upstream', upstream_url],
                    cwd=workspace_path)
            if not _fetch_remote(workspace_path, 'upstream', upstream_url):
                logger.error("Failed to fetch upstream from %s — version checkout "
                             "and blame analysis will be unavailable", upstream_url)
                run_cmd(['git', 'remote', 'remove', 'upstream'], cwd=workspace_path)
                return None
        else:
            logger.error("Failed to fetch upstream from %s — version checkout and "
                         "blame analysis will be unavailable", upstream_url)
            run_cmd(['git', 'remote', 'remove', 'upstream'], cwd=workspace_path)
            return None

    # When the fix commits live in a different repo than the recipe fetches,
    # add that repo as a secondary remote and fetch it so the fix commits and
    # their release tags are reachable for diff/blame/cherry-pick. This does
    # not change the primary 'upstream' used as the build/version source.
    if fix_repo_urls:
        result = run_cmd_capture(['git', 'remote'], cwd=workspace_path)
        remote_names = set(result.stdout.split())
        for index, fix_repo_url in enumerate(dict.fromkeys(fix_repo_urls), 1):
            remote_name = 'upstream-fix' if index == 1 else f'upstream-fix-{index}'
            logger.info("Adding fix-source remote: %s", fix_repo_url)
            if remote_name not in remote_names:
                run_cmd(['git', 'remote', 'add', remote_name, fix_repo_url],
                        cwd=workspace_path)
                remote_names.add(remote_name)
            else:
                run_cmd(['git', 'remote', 'set-url', remote_name, fix_repo_url],
                        cwd=workspace_path)
            logger.info("Fetching fix-source references")
            if not _fetch_remote(workspace_path, remote_name, fix_repo_url):
                logger.warning(
                    "Failed to fetch fix-source repo %s — fix commits may be "
                    "unavailable", fix_repo_url)
                run_cmd(['git', 'remote', 'remove', remote_name], cwd=workspace_path)
                remote_names.discard(remote_name)

    unresolved_hashes = [
        commit_hash for commit_hash in missing_hashes
        if not _commit_exists(workspace_path, commit_hash)
    ]
    if unresolved_hashes:
        abbreviated = ', '.join(commit_hash[:12] for commit_hash in unresolved_hashes)
        raise GitError(
            f"Missing fix commit(s) after canonical fetch: {abbreviated}")

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


def _alternate_protocol_url(url: str) -> Optional[str]:
    """Return the same repo URL over an alternate transport protocol.

    Swaps between ``https://`` and ``git://`` for the same host/path. Used
    as a fallback when one transport is unusable in the build environment —
    e.g. a relocated OE SDK whose git sets ``http.sslCAInfo`` to a
    non-existent CA bundle, which breaks all ``https`` git access while
    ``git://`` still works.

    Returns None for local paths or unrecognised schemes.
    """
    if url.startswith('https://'):
        return 'git://' + url[len('https://'):]
    if url.startswith('git://'):
        return 'https://' + url[len('git://'):]
    return None


def _fetch_remote(workspace_path: Path, remote_name: str, url: str) -> bool:
    """Fetch a remote's refs and tags, retrying over an alternate protocol.

    On the first failure, retries once with ``https``<->``git`` swapped
    (updating the remote URL) before giving up. This tolerates build
    environments where one transport is broken (see _alternate_protocol_url).

    Returns True on success, False if both attempts fail.
    """
    if run_cmd(['git', 'fetch', remote_name, '--tags', '--progress'],
               cwd=workspace_path) == 0:
        return True
    alt = _alternate_protocol_url(url)
    if not alt:
        # Surface the reason: without upstream history every fix commit
        # later reads as "bad object" and the run ends in a generic
        # conflict, which hides that the real failure was here.
        res = run_cmd_capture(['git', 'fetch', remote_name, '--tags'],
                              cwd=workspace_path)
        logger.error("Fetch of %s failed and no alternate protocol to retry:\n%s",
                     url, (res.stderr or res.stdout or '').strip()[-2000:])
        return False
    logger.warning("Fetch of %s failed — retrying via %s", url, alt)
    run_cmd(['git', 'remote', 'set-url', remote_name, alt], cwd=workspace_path)
    if run_cmd(['git', 'fetch', remote_name, '--tags', '--progress'],
               cwd=workspace_path) == 0:
        return True
    logger.error("Fetch of %s also failed (tried both %s and %s)", remote_name, url, alt)
    return False


def resolve_relative_submodule_url(base_url: str, relative_url: str) -> Optional[str]:
    """Resolve a relative ``.gitmodules`` URL against a base repository URL.

    Projects hosted on GitLab/GitHub commonly reference their submodules
    relative to the superproject, e.g. glib's ``.gitmodules`` says
    ``url = ../../GNOME/gvdb.git``. Git resolves that against the URL of the
    superproject's remote, which normally is
    ``https://gitlab.gnome.org/GNOME/glib.git`` and therefore yields
    ``https://gitlab.gnome.org/GNOME/gvdb.git``.

    In a cve-corrector workspace the ``upstream`` remote often points at a
    *local bare mirror* instead (``/home/user/git/glib``), so git resolves the
    same relative URL to a nonexistent local path
    (``/home/user/GNOME/gvdb.git``) and submodule init fails. This helper
    re-resolves against the project's real upstream URL so the submodule can
    still be fetched.

    Mirrors git's own algorithm: each ``..`` drops the last path component of
    the base (the ``.git`` suffix is *not* stripped first), ``.`` is skipped,
    and remaining components are appended.

    Args:
        base_url: Superproject URL (``https://``, ``git://``, ``ssh://``,
            scp-like ``git@host:path``, or a local path).
        relative_url: URL from ``.gitmodules``, starting with ``./`` or ``../``.

    Returns:
        The absolute URL, or None if *relative_url* is not relative, no base
        was given, or the relative path escapes past the base's root.
    """
    if not base_url or not relative_url.startswith(('./', '../')):
        return None

    base = base_url.rstrip('/')
    scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+.\-]*://[^/]+)(/.*)?$', base)
    if scheme_match:
        root, path = scheme_match.group(1), scheme_match.group(2) or ''
        separator = '/'
    else:
        scp_match = re.match(r'^([^/@]+@[^/:]+:)(.*)$', base)
        if scp_match:
            root, path = scp_match.group(1), scp_match.group(2)
            separator = ''
        else:
            # Local path (absolute or relative).
            root = '/' if base.startswith('/') else ''
            path = base
            separator = ''

    parts = [p for p in path.split('/') if p]
    for component in relative_url.split('/'):
        if component in ('', '.'):
            continue
        if component == '..':
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(component)
    if not parts:
        return None
    return f"{root}{separator}{'/'.join(parts)}"


def _is_remote_url(url: str) -> bool:
    """Check whether a git URL is fetched over a network transport."""
    return bool(re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://', url)) or bool(
        re.match(r'^[^/@]+@[^/:]+:', url))


def _submodule_base_url(workspace_path: Path,
                        hash_details: Optional[list[dict]]) -> Optional[str]:
    """Determine the URL that relative submodule URLs should resolve against.

    Prefers the workspace's ``upstream`` remote when it is a real remote URL.
    When it is a local mirror path (``--mirror-dir``), relative submodule URLs
    would resolve to nonexistent sibling directories, so fall back to the
    project's canonical URL deduced from the CVE's fix-commit URLs.

    Args:
        workspace_path: Path to the devtool workspace.
        hash_details: CVE metadata fix-commit entries, used for deduction.

    Returns:
        A base URL, or None when none could be determined.
    """
    remote_url = run_cmd_capture(
        ['git', 'remote', 'get-url', 'upstream'], cwd=workspace_path).stdout.strip()
    if remote_url and _is_remote_url(remote_url):
        return remote_url
    urls = [d['url'] for d in (hash_details or []) if d.get('url')]
    return deduce_repo_from_patches(urls)


def _gitmodules_entries(workspace_path: Path) -> list[tuple[str, str]]:
    """List ``(name, url)`` pairs declared in the workspace's .gitmodules.

    Args:
        workspace_path: Path to the devtool workspace.

    Returns:
        One entry per configured submodule; empty when .gitmodules is absent
        or unparseable.
    """
    result = run_cmd_capture(
        ['git', 'config', '-f', '.gitmodules', '--get-regexp', r'^submodule\..*\.url$'],
        cwd=workspace_path)
    entries = []
    for line in result.stdout.splitlines():
        key, _, url = line.partition(' ')
        name = key.removeprefix('submodule.').removesuffix('.url')
        if name and url:
            entries.append((name, url.strip()))
    return entries


def _init_submodules(workspace_path: Path,
                     hash_details: Optional[list[dict]] = None,
                     mirror_dir: Optional[Path] = None) -> None:
    """Initialize git submodules if the repo defines any.

    When a recipe is built from a tarball, devtool extracts the archive into
    a git repo without initializing submodules.  After checking out the
    upstream tag (which has a .gitmodules file), submodule directories remain
    empty.  Later, copy_missing_files_from_devtool() copies those files as
    untracked content, leaving the working tree dirty and causing cherry-pick
    to fail.  Builds fail too when the build system bootstraps the submodule
    itself (glib's ``meson.build`` runs ``git submodule update --init`` and
    aborts with "git submodule failed to init").

    Running ``git submodule update --init --recursive`` populates submodule
    directories as tracked content, preventing the dirty-tree problem.

    Before that, submodule URLs are rewritten where the workspace's defaults
    cannot work:

    * A **relative** URL (``../../GNOME/gvdb.git``) resolves against the
      ``upstream`` remote, which is a local bare mirror whenever
      ``--mirror-dir``/``--mirror-path`` is used — yielding a nonexistent
      sibling path. It is re-resolved against the project's real upstream URL
      (see :func:`resolve_relative_submodule_url`).
    * When ``mirror_dir`` holds a mirror of the submodule itself, that local
      mirror is used instead of the network URL, matching how the
      superproject is fetched. Local transports need
      ``protocol.file.allow=always``, which git blocks by default for
      submodules (CVE-2022-39253).

    Args:
        workspace_path: Path to the devtool workspace.
        hash_details: CVE fix-commit metadata, used to deduce the project's
            canonical URL when ``upstream`` points at a local mirror.
        mirror_dir: Directory of local bare mirrors, if one was configured.
    """
    gitmodules = workspace_path / '.gitmodules'
    if not gitmodules.exists():
        return
    logger.info("Initializing submodules")

    # 'submodule init' copies .gitmodules URLs into the local config; the
    # overrides below then replace only the ones that cannot work as-is.
    # 'submodule init' never overwrites an existing submodule.<name>.url.
    run_cmd(['git', 'submodule', 'init'], cwd=workspace_path)

    base_url: Optional[str] = None
    uses_local_transport = False
    for name, url in _gitmodules_entries(workspace_path):
        override: Optional[str] = None
        sub_name = url.rstrip('/').rsplit('/', 1)[-1].removesuffix('.git')
        if mirror_dir:
            sub_mirror = find_mirror_repo(mirror_dir, sub_name)
            if sub_mirror:
                override = str(sub_mirror.absolute())
                logger.info("Submodule %s: using local mirror %s", name, override)
        if override is None and url.startswith(('./', '../')):
            if base_url is None:
                base_url = _submodule_base_url(workspace_path, hash_details) or ''
            override = resolve_relative_submodule_url(base_url, url)
            if override:
                logger.info("Submodule %s: resolved %s -> %s", name, url, override)
            else:
                logger.warning(
                    "Submodule %s: cannot resolve relative URL %s (no upstream "
                    "URL to resolve against) — init will likely fail", name, url)
        if override:
            run_cmd(['git', 'config', f'submodule.{name}.url', override],
                    cwd=workspace_path)
            if not _is_remote_url(override):
                uses_local_transport = True

    # Local paths are a blocked transport for submodules unless allowed
    # explicitly (CVE-2022-39253), and the mirrors here are trusted local
    # clones the caller pointed us at.
    allow_file = ['-c', 'protocol.file.allow=always'] if uses_local_transport else []
    ret = run_cmd(
        ['git', *allow_file, 'submodule', 'update', '--init', '--recursive'],
        cwd=workspace_path,
    )
    if ret != 0:
        logger.warning("Submodule initialization failed — continuing without submodules")


def prepare_cve_branch(workspace_path: Path, version: Optional[str],
                       cve_id: str, subproject: Optional[str] = None,
                       hash_details: Optional[list[dict]] = None,
                       mirror_dir: Optional[Path] = None) -> tuple[bool, list[str]]:
    """Checkout recipe version and prepare branch for CVE fix.

    Args:
        workspace_path: Path to the devtool workspace.
        version: Recipe version to check out, if known.
        cve_id: CVE identifier, also used as the branch name.
        subproject: Monorepo subproject directory, if detected.
        hash_details: CVE fix-commit metadata, forwarded to submodule setup to
            resolve relative submodule URLs when ``upstream`` is a local
            mirror.
        mirror_dir: Local mirror directory, forwarded to submodule setup so
            mirrored submodules are used instead of network URLs.

    Returns:
        Tuple of (version_checkout_ok, skipped_commits).
    """
    checkout_ok = True
    if version:
        logger.info("Checking out version %s", version)
        result = run_cmd_capture(['git', 'branch', '--list', cve_id], cwd=workspace_path)
        if result.stdout.strip():
            logger.debug("Branch %s already exists, checking out...", cve_id)
            if not force_checkout_branch(workspace_path, cve_id):
                logger.error("Failed to check out existing branch %s", cve_id)
                raise GitError("Git operation failed")
        elif not checkout_version(workspace_path, version, cve_id,
                                  subproject=subproject):
            logger.warning("Version checkout failed, will try format-patch fallback...")
            run_cmd(['git', 'checkout', '-b', cve_id], cwd=workspace_path)
            checkout_ok = False

    # Initialize submodules before cherry-picking devtool commits or copying
    # missing files.  Without this, repos with submodules (e.g. jq with
    # modules/) leave submodule directories empty, and copy_missing_files
    # fills them with untracked files that block later cherry-picks.
    _init_submodules(workspace_path, hash_details=hash_details,
                     mirror_dir=mirror_dir)

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
    remove_git_only_build_triggers(workspace_path)

    logger.debug("Creating tag original-version at current position")
    run_cmd_capture(['git', 'tag', '-f', 'original-version'], cwd=workspace_path)
    return checkout_ok, skipped
