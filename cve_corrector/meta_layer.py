# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Meta-layer git operations for CVE corrector.

Handles committing patches and CVE_STATUS entries to the meta-layer,
staging files, restoring devtool-modified content, and exporting patches.
"""
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional

from .bitbake_ops import get_build_path, get_layerseries_corename
from .git_ops import get_git_user_info
from .recipe_ops import _append_src_uri_entries
from .utils import logger, run_cmd, run_cmd_capture


def _export_commit_patch(meta_layer: Path) -> None:
    """Export the latest commit as a patch file under BBPATH/patches/.

    The patch subject is prefixed with the release corename (from
    ``LAYERSERIES_CORENAMES``), e.g. ``[scarthgap][PATCH]``, following the
    Yocto Project convention for submitting fixes to a stable branch (see
    "Submitting Changes to Stable Release Branches" in the Yocto Project
    contributor guide). This lets mailing-list reviewers immediately see
    which release the patch targets. If the corename can't be determined,
    the patch is exported without a subject prefix.
    """
    patches_dir = get_build_path() / 'patches'
    patches_dir.mkdir(parents=True, exist_ok=True)
    cmd = ['git', 'format-patch', '-1', 'HEAD', '-o', str(patches_dir)]
    corename = get_layerseries_corename()
    if corename:
        cmd += ['--subject-prefix', f'{corename}][PATCH']
    result = run_cmd_capture(cmd, cwd=meta_layer)
    if result.returncode == 0 and result.stdout.strip():
        logger.info("Exported patch: %s", result.stdout.strip())
    else:
        logger.warning("Failed to export patch via git format-patch")


# Preferred order for attributing a fix reference to a single source.
# Sources earlier in this list win when a commit is reported by several feeds.
# This is the set of public, non-proprietary sources shipped with
# yocto-security-tools (see cve_metadata_extractor). Proprietary plugin sources
# such as "bdba" are deliberately excluded so they never leak into public
# commit messages. It is defined here (rather than imported from the extractor)
# to preserve the acyclic dependency invariant: the corrector must not depend
# on the extractor.
_SOURCE_PRIORITY = ('nvd', 'cvelistv5', 'debian', 'ubuntu', 'osv')

# Templated tracker/advisory URLs for each public source, keyed by CVE id.
# These point at the source's page for the CVE and are derived purely from the
# CVE id (no per-CVE data needed). Proprietary sources have no template here, so
# they can never be turned into a public reference URL.
_SOURCE_URL_TEMPLATES = {
    'nvd': 'https://nvd.nist.gov/vuln/detail/{cve}',
    'cvelistv5': 'https://www.cve.org/CVERecord?id={cve}',
    'debian': 'https://security-tracker.debian.org/tracker/{cve}',
    'ubuntu': 'https://ubuntu.com/security/{cve}',
    'osv': 'https://osv.dev/list?q={cve}',
}


def _preferred_source(sources: list[str]) -> str:
    """Pick the single most-preferred public source from a list.

    Only the public sources in ``_SOURCE_PRIORITY`` are eligible; proprietary
    plugin sources (e.g. "bdba") are ignored so they are never disclosed in
    commit messages.

    Args:
        sources: Source names associated with a fix reference.

    Returns:
        The highest-priority public source; an empty string if none of the
        sources are public (e.g. a proprietary-only reference).
    """
    for preferred in _SOURCE_PRIORITY:
        if preferred in sources:
            return preferred
    return ''


def _reference_urls(cve_id: str, hash_details: Optional[list]) -> list[str]:
    """Build templated tracker URLs for the public sources of a CVE.

    NVD is always included as the canonical record. Any additional public
    source (see ``_SOURCE_URL_TEMPLATES``) that contributed a fix reference is
    added, ordered by ``_SOURCE_PRIORITY``. Proprietary sources are excluded.

    Args:
        cve_id: The CVE identifier used to fill in each URL template.
        hash_details: Fix metadata entries whose ``source`` field is inspected.

    Returns:
        Templated reference URLs, one per contributing public source.
    """
    present = {'nvd'}
    for d in hash_details or []:
        for src in (d.get('source') or '').split(','):
            src = src.strip()
            if src in _SOURCE_URL_TEMPLATES:
                present.add(src)
    return [_SOURCE_URL_TEMPLATES[s].format(cve=cve_id)
            for s in _SOURCE_PRIORITY if s in present]


def create_layer_commit(meta_layer: Optional[Path], recipe: str, cve_id: str,
                        ptest_output: Optional[str] = None, skip_confirm: bool = False,
                        hash_details: Optional[list] = None,
                        series_state: Optional[dict] = None,
                        used_commits: Optional[list] = None) -> bool:
    """Create git commit in meta-layer with updated recipe and patch.

    Returns:
        True if a commit was created, False otherwise.
    """
    if not meta_layer or not meta_layer.exists():
        logger.warning("Meta-layer path invalid: %s", meta_layer)
        return False

    author, email = get_git_user_info()
    commit_msg = f"{recipe}: fix {cve_id}\n\nBackport patch to fix {cve_id}.\n\n"

    # Templated per-source tracker references (NVD plus any contributing public
    # source), derived from the CVE id. Proprietary sources are never listed.
    commit_msg += "References:\n"
    for ref_url in _reference_urls(cve_id, hash_details):
        commit_msg += f"  {ref_url}\n"
    commit_msg += "\n"

    # Add upstream fix references — prefer PR link, fall back to commit URLs.
    # Each reference is annotated with a single source, chosen by the preferred
    # order below, so reviewers can trace provenance without noise.
    pull_url = (series_state or {}).get('pull_url', '')
    if pull_url:
        commit_msg += f"Upstream fix:\n  {pull_url}\n\n"
    elif hash_details:
        if used_commits:
            used_set = set(used_commits)
            details = [d for d in hash_details
                       if d.get('url') and d.get('hash') in used_set]
        else:
            details = [d for d in hash_details if d.get('url')]
        # Map each URL to the ordered, de-duplicated list of sources it came
        # from. The 'source' field may be a comma-joined string (e.g.
        # "debian, ubuntu") when the same commit was reported by multiple feeds.
        url_sources: dict[str, list[str]] = {}
        for d in details:
            srcs = url_sources.setdefault(d['url'], [])
            for src in (d.get('source') or '').split(','):
                src = src.strip()
                if src and src not in srcs:
                    srcs.append(src)
        if url_sources:
            commit_msg += "Upstream fix:\n"
            for url, srcs in url_sources.items():
                source = _preferred_source(srcs)
                if source:
                    commit_msg += f"  {url} [{source}]\n"
                else:
                    commit_msg += f"  {url}\n"
            commit_msg += "\n"

    if ptest_output:
        logger.info("Ptest Results:")
        logger.info(ptest_output)
        commit_msg += f"Tested with ptest:\n{ptest_output}\n\n"

    commit_msg += f"Signed-off-by: {author} <{email}>\n"

    logger.info("Commit Message:")
    logger.info(commit_msg)

    if not skip_confirm:
        response = input("\nCreate commit with this message? [Y/n]: ").strip().lower()
        if response and response != 'y':
            logger.info("Commit cancelled.")
            return False

    # Restore any files that devtool finish deleted from the working tree
    deleted_wt = run_cmd_capture(
        ['git', 'diff', '--relative', '--name-only', '--diff-filter=D'],
        cwd=meta_layer).stdout.strip().splitlines()
    if deleted_wt:
        logger.warning("Restoring %s file(s) deleted by devtool finish", len(deleted_wt))
        for f in deleted_wt:
            logger.debug("  restoring: %s", f)
            run_cmd(['git', 'checkout', 'HEAD', '--', f], cwd=meta_layer)

    # Stage only new and modified files in the recipe directory
    changed = run_cmd_capture(
        ['git', 'diff', '--relative', '--name-only'],
        cwd=meta_layer).stdout.strip().splitlines()
    untracked = run_cmd_capture(
        ['git', 'ls-files', '--others', '--exclude-standard'],
        cwd=meta_layer).stdout.strip().splitlines()

    # Restore existing .patch files that devtool merely regenerated
    for f in changed:
        if not f.endswith('.patch'):
            continue
        diff = run_cmd_capture(
            ['git', 'diff', '-I', r'^From ', '-I', r'^index ', '--', f],
            cwd=meta_layer).stdout.strip()
        if not diff:
            logger.debug("Restoring unchanged patch: %s", f)
            run_cmd(['git', 'checkout', 'HEAD', '--', f], cwd=meta_layer)

    # Restore .bb/.inc files that devtool rewrote with duplicate SRC_URI,
    # then append only the new file:// entries
    new_patches = set(
        Path(f).name for f in untracked
        if f.endswith('.patch') and f'/{recipe}/' in f
    )
    if new_patches:
        for f in changed:
            if (f.endswith('.bb') or f.endswith('.inc')) and f'/{recipe}' in f:
                run_cmd(['git', 'checkout', 'HEAD', '--', f], cwd=meta_layer)

        target = None
        for pattern in (f'**/{recipe}*.inc', f'**/{recipe}*.bb',
                        f'**/{recipe}*.bbappend'):
            for candidate in sorted(meta_layer.glob(pattern)):
                try:
                    if 'file://' in candidate.read_text(encoding='utf-8'):
                        target = candidate
                        break
                except OSError:
                    continue
            if target:
                break
        if target:
            _append_src_uri_entries(target, sorted(new_patches))
            logger.info("Added %s new SRC_URI entry/entries to %s",
                        len(new_patches), target.name)

    # Re-read changed files after restoring
    changed = run_cmd_capture(
        ['git', 'diff', '--relative', '--name-only'],
        cwd=meta_layer).stdout.strip().splitlines()

    recipe_prefix = 'recipes-'
    to_stage = [f for f in changed + untracked
                if recipe_prefix in f and f'/{recipe}/' in f]
    if to_stage:
        run_cmd(['git', 'add', '--'] + to_stage, cwd=meta_layer)
    else:
        logger.warning("No recipe files to stage")

    logger.info("Creating commit")
    with NamedTemporaryFile('w', delete=False, encoding='utf-8') as f:
        f.write(commit_msg)
        msg_file = f.name

    try:
        rc = run_cmd(['git', 'commit', '-F', msg_file], cwd=meta_layer)
        if rc != 0:
            logger.warning("git commit failed (nothing to commit?)")
            return False
        logger.info("Created commit")
    finally:
        Path(msg_file).unlink()

    _export_commit_patch(meta_layer)
    return True


def _map_cve_status_reason(reason: str) -> str:
    """Map a human-readable reason to the correct CVE_STATUS keyword.

    Uses Yocto CVE_CHECK_STATUSMAP values:
    - fixed-version: fix already present via version or backport
    - not-applicable-platform: platform-specific, doesn't affect this target
    - not-applicable-config: requires config/feature not enabled
    - cpe-incorrect: CVE doesn't actually apply to this component
    """
    lower = reason.lower()
    if any(kw in lower for kw in ('already', 'matches the fixed', 'no net changes',
                                   'backport', 'patched')):
        return 'fixed-version'
    if any(kw in lower for kw in ('platform', 'architecture', 'target')):
        return 'not-applicable-platform'
    if any(kw in lower for kw in ('config', 'feature', 'disabled', 'not enabled')):
        return 'not-applicable-config'
    if any(kw in lower for kw in ('cpe', 'wrong component', 'different package',
                                   'not present', 'does not apply')):
        return 'cpe-incorrect'
    # Default for generic not-applicable conclusions
    return 'not-applicable-config'


def write_cve_status(meta_layer: Optional[Path], recipe: str, cve_id: str,
                     reason: str, skip_confirm: bool = False) -> bool:
    """Append a CVE_STATUS line to the recipe's .bb or .bbappend in the meta-layer.

    Returns:
        True if the CVE_STATUS was written and committed, False otherwise.
    """
    from .recipe_ops import _find_recipe_file

    if not meta_layer or not meta_layer.exists():
        logger.warning("Meta-layer path invalid: %s", meta_layer)
        return False

    status_line = f'CVE_STATUS[{cve_id}] = "{_map_cve_status_reason(reason)}: {reason}"'

    recipe_file = _find_recipe_file(meta_layer, recipe)
    if not recipe_file:
        logger.warning("No .bb or .bbappend found for %s in %s", recipe, meta_layer)
        return False

    content = recipe_file.read_text(encoding='utf-8')
    if cve_id in content:
        logger.info("CVE_STATUS for %s already in %s", cve_id, recipe_file)
        return True

    if not content.endswith('\n'):
        content += '\n'
    content += status_line + '\n'
    recipe_file.write_text(content, encoding='utf-8')
    logger.info("Wrote CVE_STATUS for %s to %s", cve_id, recipe_file)

    author, email = get_git_user_info()
    commit_msg = (
        f"{recipe}: mark {cve_id} as not applicable\n\n"
        f"{reason}\n\n"
        f"Signed-off-by: {author} <{email}>\n"
    )

    if not skip_confirm:
        print(f"\nCVE_STATUS line:\n  {status_line}")
        print(f"File: {recipe_file}")
        response = input("Create commit? [Y/n]: ").strip().lower()
        if response and response != 'y':
            logger.info("Commit cancelled.")
            return False

    run_cmd(['git', 'add', str(recipe_file)], cwd=meta_layer)

    with NamedTemporaryFile('w', delete=False, encoding='utf-8') as f:
        f.write(commit_msg)
        msg_file = f.name
    try:
        rc = run_cmd(['git', 'commit', '-F', msg_file], cwd=meta_layer)
        if rc != 0:
            logger.warning("git commit failed")
            return False
        logger.info("Created CVE_STATUS commit for %s", cve_id)
    finally:
        Path(msg_file).unlink()

    _export_commit_patch(meta_layer)
    return True
