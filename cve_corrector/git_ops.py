# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Git operations for CVE corrector."""
import re
import subprocess
from pathlib import Path
from typing import Optional

from .utils import logger, run_cmd, run_cmd_capture


def get_git_user_info() -> tuple[str, str]:
    """Get git user name and email."""
    result = run_cmd_capture(['git', 'config', 'user.name'])
    author = result.stdout.strip() if result.returncode == 0 else 'Unknown'
    result = run_cmd_capture(['git', 'config', 'user.email'])
    email = result.stdout.strip() if result.returncode == 0 else 'unknown@example.com'
    return author, email


def find_exact_tag(tags: list[str], version: str) -> Optional[str]:
    """Find exact tag matching version."""
    norm = version.replace('.', '_')
    escaped = re.escape(version)
    escaped_norm = re.escape(norm)
    pattern = re.compile(
        rf'{escaped}$|{escaped_norm}$|.*{escaped_norm}$|.*{escaped}$'
    )
    for tag in tags:
        if pattern.match(tag):
            return tag
    # Retry with leading-zero-stripped comparison (e.g. 2024.2.2 vs 2024.02.02)
    def strip_zeros(s):
        return '.'.join(p.lstrip('0') or '0' for p in s.split('.'))

    v_stripped = strip_zeros(version)
    for tag in tags:
        if strip_zeros(tag) == v_stripped:
            return tag
    return None


def detect_monorepo_subproject(repo_path: Path, tag: str,
                               mirror_name: str,
                               recipe: Optional[str] = None) -> Optional[str]:
    """Detect if tag is a monorepo and return the subproject path.

    Checks if ``subprojects/<name>/meson.build`` (or similar build file)
    exists at the given tag.  When *recipe* is provided, derives candidate
    subproject names from the recipe first so that e.g.
    ``gstreamer1.0-rtsp-server`` resolves to ``subprojects/gst-rtsp-server``
    rather than the mirror name ``gst-plugins-bad``.

    Returns the relative subproject prefix
    (e.g. ``subprojects/gst-plugins-good``) or *None*.
    """
    candidates = []
    if recipe:
        # gstreamer1.0-rtsp-server -> gst-rtsp-server
        stripped = re.sub(r'^gstreamer\d+\.\d+-', 'gst-', recipe)
        if stripped != recipe:
            candidates.append(stripped)
    candidates.append(mirror_name)

    build_files = ('meson.build', 'CMakeLists.txt', 'configure.ac')
    for name in dict.fromkeys(candidates):
        prefix = f"subprojects/{name}"
        for build_file in build_files:
            result = run_cmd_capture(
                ['git', 'cat-file', '-e', f'{tag}:{prefix}/{build_file}'],
                cwd=repo_path)
            if result.returncode == 0:
                logger.info("Monorepo detected: subproject at %s", prefix)
                return prefix
    return None


def checkout_version(repo_path: Path, version: str, branch_name: str,
                     subproject: Optional[str] = None) -> bool:
    """Checkout specific version from upstream.

    When *subproject* is set (e.g. ``subprojects/gst-plugins-good``), the
    tag's subtree at that path is extracted as the root of a new commit so
    the workspace keeps a standalone source layout.
    """
    search_version = re.sub(r"^\d+_", "", version.replace("p", "_P"))
    result = run_cmd_capture(['git', 'tag'], cwd=repo_path)
    tags = result.stdout.strip().split('\n') if result.stdout.strip() else []

    target_tag = find_exact_tag(tags, search_version)
    logger.info("Searching %s -> Matched: %s", search_version, target_tag)

    if not target_tag:
        return False

    if subproject:
        # Extract subproject subtree into a standalone commit
        subtree = run_cmd_capture(
            ['git', 'rev-parse', f'{target_tag}:{subproject}'],
            cwd=repo_path)
        if subtree.returncode != 0:
            logger.warning("Subproject %s not found at %s", subproject, target_tag)
            return False
        tag_commit = run_cmd_capture(
            ['git', 'rev-parse', f'{target_tag}^{{commit}}'],
            cwd=repo_path)
        new_commit = run_cmd_capture(
            ['git', 'commit-tree', subtree.stdout.strip(),
             '-m', f'Extract {subproject} from {target_tag}',
             '-p', tag_commit.stdout.strip()],
            cwd=repo_path)
        if new_commit.returncode != 0:
            logger.warning("Failed to create subproject commit")
            return False
        if run_cmd(['git', 'checkout', '-b', branch_name,
                    new_commit.stdout.strip()], cwd=repo_path) != 0:
            return False
        logger.info("Checked out %s:%s on branch %s", target_tag, subproject, branch_name)
    else:
        if run_cmd(['git', 'checkout', '-b', branch_name, target_tag],
                   cwd=repo_path) != 0:
            return False
        logger.info("Checked out %s on branch %s", target_tag, branch_name)
    return True


def is_bad_object(workspace_path: Path, commit_hash: str) -> bool:
    """Check if a commit hash is a bad/missing object in the repo."""
    result = run_cmd_capture(
        ['git', 'cat-file', '-e', commit_hash], cwd=workspace_path)
    if result.returncode != 0:
        # Try fetching from upstream in case it's not yet available locally
        run_cmd_capture(
            ['git', 'fetch', 'upstream', commit_hash], cwd=workspace_path)
        result = run_cmd_capture(
            ['git', 'cat-file', '-e', commit_hash], cwd=workspace_path)
    return result.returncode != 0


def try_cherry_pick(workspace_path: Path, commit_hash: str,
                    subproject: Optional[str] = None) -> bool:
    """Try to cherry-pick a commit, return True on success.

    When *subproject* is set, strips the subproject prefix from the patch
    so monorepo commits apply to a standalone source layout.
    """
    if subproject:
        return _cherry_pick_monorepo(workspace_path, commit_hash, subproject)

    ret = run_cmd(['git', 'cherry-pick', commit_hash], cwd=workspace_path)
    if ret == 0:
        return True
    run_cmd_capture(['git', 'cherry-pick', '--abort'], cwd=workspace_path)

    # Only try -m 1 if this is a merge commit (has more than one parent)
    parents = run_cmd_capture(
        ['git', 'cat-file', '-p', commit_hash], cwd=workspace_path)
    parent_count = sum(1 for line in parents.stdout.splitlines()
                       if line.startswith('parent '))
    if parent_count > 1:
        result = run_cmd_capture(
            ['git', 'cherry-pick', '-m', '1', commit_hash], cwd=workspace_path)
        if result.returncode == 0:
            return True
        run_cmd_capture(['git', 'cherry-pick', '--abort'], cwd=workspace_path)

    return False


def _cherry_pick_monorepo(workspace_path: Path, commit_hash: str,
                          subproject: str) -> bool:
    """Cherry-pick a monorepo commit by stripping the subproject prefix."""
    prefix = f"{subproject}/"
    fmt = run_cmd_capture(
        ['git', 'format-patch', '-1', commit_hash, '--stdout', '--',
         f'{subproject}/'],
        cwd=workspace_path)
    if fmt.returncode != 0 or not fmt.stdout.strip():
        return False
    # Strip subproject prefix from diff paths
    patch = fmt.stdout.replace(f'a/{prefix}', 'a/').replace(f'b/{prefix}', 'b/')
    am = subprocess.run(
        ['git', 'am', '--whitespace=fix'], cwd=workspace_path,
        input=patch, text=True, check=False,
        capture_output=True)
    if am.returncode == 0:
        logger.info("Applied monorepo commit %s (stripped %s/)", commit_hash[:8], subproject)
        return True
    run_cmd_capture(['git', 'am', '--abort'], cwd=workspace_path)
    # Try with 3-way merge
    am = subprocess.run(
        ['git', 'am', '--3way', '--whitespace=fix'], cwd=workspace_path,
        input=patch, text=True, check=False,
        capture_output=True)
    if am.returncode == 0:
        logger.info("Applied monorepo commit %s via 3-way merge", commit_hash[:8])
        return True
    run_cmd_capture(['git', 'am', '--abort'], cwd=workspace_path)
    return False


def deduce_repo_from_patches(patches: list[str]) -> Optional[str]:
    """Deduce git repository URL from patch URLs."""
    for url in patches:
        new_url = (url.replace("gitweb.cgi?p=", "")
                   .split("-/commit")[0].split("-/merge_requests")[0]
                   .split("-/issues")[0]
                   .split("/pull/")[0].split("/commit")[0])
        if '?p=' in url and ';a=commit' in url:
            # Generic gitweb URL: https://<host>/?p=<repo>;a=commit;h=<hash>
            from urllib.parse import urlparse
            parsed = urlparse(url.split(';')[0].split('?')[0])
            repo_name = url.split('?p=')[1].split(';', maxsplit=1)[0]
            host = parsed.hostname or ''
            if host == 'sourceware.org' or host.endswith('.sourceware.org'):
                new_url = f'https://sourceware.org/git/{repo_name}'
            elif 'sourceware.org' in host:
                continue
            else:
                new_url = f'{parsed.scheme}://{parsed.netloc}/{repo_name}'
        else:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname or ''
            if host == 'git.savannah.gnu.org' or host.endswith('.savannah.gnu.org'):
                if '/cgit/' in parsed.path:
                    repo_name = parsed.path.split('/cgit/')[1].split('/')[0]
                elif '/git/' in parsed.path:
                    repo_name = parsed.path.split('/git/')[1].split('/')[0]
                else:
                    continue
                new_url = f'https://git.savannah.gnu.org/git/{repo_name}'
            elif 'savannah.gnu.org' in host or 'git.savannah' in host:
                continue
        skip_patterns = ("bugzilla", "viewtopic", "inbox.", "mail.python.org",
                         "openwall.com", "cve.org", "nvd.nist.gov",
                         "/archives/", "/advisories/", "/lists/",
                         "seclists.org")
        if any(p in new_url for p in skip_patterns):
            continue
        # Must look like a git-hosting URL (contains a known forge or ends in .git)
        git_indicators = ("github.com", "gitlab.com", "gitlab.", "git.savannah",
                          "sourceware.org/git", "git.kernel.org", "git.openssl.org",
                          "git.gnome.org", "git.freedesktop.org", "codeberg.org",
                          "bitbucket.org", ".git")
        if any(g in new_url for g in git_indicators):
            return new_url.rstrip('/')
    return None


def copy_missing_files_from_devtool(workspace_path: Path) -> None:
    """Copy files present in devtool but missing from the CVE branch.

    Release tarballs contain generated autotools files (configure, Makefile.in,
    m4/*.m4, etc.) that don't exist in the upstream git repo. This copies them
    from the devtool branch without tracking them, so builds succeed.
    """
    devtool_files = run_cmd_capture(
        ['git', 'ls-tree', '-r', '--name-only', 'devtool'], cwd=workspace_path)
    if devtool_files.returncode != 0:
        return
    cve_files = run_cmd_capture(
        ['git', 'ls-tree', '-r', '--name-only', 'HEAD'], cwd=workspace_path)
    if cve_files.returncode != 0:
        return

    cve_set = set(cve_files.stdout.strip().splitlines())
    missing = [f for f in devtool_files.stdout.strip().splitlines()
               if f not in cve_set]
    if not missing:
        return

    logger.info("Copying %s missing file(s) from devtool branch", len(missing))
    for filepath in missing:
        run_cmd_capture(['git', 'checkout', 'devtool', '--', filepath],
                        cwd=workspace_path)
    # Unstage so they remain as untracked working-tree files
    run_cmd_capture(['git', 'reset', 'HEAD'] + missing, cwd=workspace_path)


def git_clean_workspace(workspace_path: Path, remove_ignored: bool = False) -> None:
    """Clean untracked files from workspace, preserving oe-local-files."""
    flags = '-fdx' if remove_ignored else '-fd'
    run_cmd_capture(['git', 'clean', flags, '-e', 'oe-local-files'], cwd=workspace_path)


def get_repo_subdir(workspace_path: Path) -> Optional[str]:
    """Return the source subdirectory name if repo is a monorepo, else None.

    Checks the git tree (not the working directory) to avoid being misled
    by untracked files copied from other branches.
    """
    result = run_cmd_capture(
        ['git', 'ls-tree', '--name-only', 'HEAD'], cwd=workspace_path)
    if result.returncode != 0:
        return None
    top_entries = result.stdout.strip().splitlines()
    # If the root has any build system marker, it's not a monorepo
    build_files = {'CMakeLists.txt', 'configure.ac', 'configure', 'meson.build',
                   'setup.py', 'setup.cfg', 'pyproject.toml', 'Makefile.am',
                   'Makefile', 'Cargo.toml', 'go.mod'}
    if build_files & set(top_entries):
        return None
    for entry in sorted(top_entries):
        if entry.startswith('oe-') or entry.startswith('.'):
            continue
        sub_result = run_cmd_capture(
            ['git', 'ls-tree', '--name-only', f'HEAD:{entry}'], cwd=workspace_path)
        if sub_result.returncode != 0:
            continue
        sub_entries = set(sub_result.stdout.strip().splitlines())
        if build_files & sub_entries:
            return entry
    return None


def detect_strip_level(patches: list[Path]) -> int:
    """Detect the correct git-am -p level from patch diff headers.

    Handles monorepo layouts (e.g. GStreamer) where upstream commits use
    paths like ``subprojects/gst-plugins-good/gst/file.c`` but the
    devtool workspace has ``gst/file.c`` at the root.
    """
    import re
    pattern = re.compile(r'^diff --git a/(.+?) b/')
    for patch in patches:
        for line in patch.read_text().splitlines():
            m = pattern.match(line)
            if not m:
                continue
            parts = Path(m.group(1)).parts
            if len(parts) > 2 and parts[0] == 'subprojects':
                return 3  # strip a/subprojects/<name>/
            return 1
    return 1
