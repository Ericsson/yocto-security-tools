# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Patch formatting and metadata operations for CVE corrector.

Handles CVE tag insertion, Upstream-Status headers, patch renaming,
and SRC_URI updates after devtool finish.
"""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING

from shared import TEXT_ENCODING, TEXT_ERRORS

from .git_ops import get_git_user_info
from .recipe_ops import _split_src_uri_line, sort_cve_lines_in_recipe, update_recipe_patch
from .utils import logger, run_cmd_capture

if TYPE_CHECKING:
    from .state import WorkflowState


def modify_patch(patch_file: Path, cve_id: str, original_url: str,
                 include_cve_tag: bool = True) -> None:
    """Add CVE and/or Upstream-Status metadata to a patch.

    Args:
        patch_file: Path to the patch file to annotate.
        cve_id: CVE identifier for the ``CVE:`` tag.
        original_url: Upstream commit URL for ``Upstream-Status: Backport``.
        include_cve_tag: When True (default) the patch is the actual CVE fix
            and gets a ``CVE: <cve_id>`` tag. When False the patch is a
            prerequisite the fix depends on — it does not itself fix the CVE,
            so it gets ``Upstream-Status: Backport`` **only**. The ``CVE:``
            tag drives ``sbom-cve-check``; tagging a prerequisite with it
            would falsely report that patch as the fix.
    """
    text = patch_file.read_text(encoding="utf-8")

    # Idempotence: skip if the patch already carries the metadata it needs.
    # The fix patch needs both tags; a prerequisite needs only Upstream-Status.
    has_upstream = "Upstream-Status:" in text
    has_cve = f"CVE: {cve_id}" in text
    if has_upstream and (has_cve or not include_cve_tag):
        return

    author, email = get_git_user_info()

    cve_line = f"CVE: {cve_id}\n" if include_cve_tag else ""
    block = (
        "\n"
        f"{cve_line}"
        f"Upstream-Status: Backport [{original_url}]\n\n"
        f"Signed-off-by: {author} <{email}>\n"
    )

    lines = text.splitlines(keepends=True)

    insert_index = None
    for i, line in enumerate(lines):
        stripped = line.rstrip('\n\r')
        if stripped == '---':
            insert_index = i
            break

    if insert_index is None:
        raise ValueError("No line containing '---' found in patch")

    with NamedTemporaryFile("w", delete=False, encoding="utf-8") as tmp:
        tmp.writelines(lines[:insert_index])
        tmp.write(block)
        tmp.writelines(lines[insert_index:])
        tmp_path = tmp.name

    try:
        shutil.move(tmp_path, str(patch_file))
    except Exception:
        os.unlink(tmp_path)
        raise


def _extract_patch_subject(patch_text: str) -> str:
    """Extract the unwrapped ``Subject:`` line from a format-patch file.

    Handles RFC-822 folded subjects (continuation lines start with
    whitespace) and strips the leading ``[PATCH ...]`` prefix so the result
    can be compared against a plain ``git log --format=%s`` subject.
    """
    lines = patch_text.splitlines()
    parts: list[str] = []
    capturing = False
    for line in lines:
        if not capturing:
            if line.startswith("Subject:"):
                parts.append(line[len("Subject:"):].strip())
                capturing = True
            continue
        # Folded continuation lines are indented and non-empty.
        if line[:1] in (" ", "\t") and line.strip():
            parts.append(line.strip())
        else:
            break
    subject = " ".join(parts)
    subject = re.sub(r"^\[PATCH[^\]]*\]\s*", "", subject)
    return subject.strip()


def _normalize_subject(subject: str) -> str:
    """Collapse whitespace and lowercase a subject for robust comparison."""
    return " ".join(subject.split()).lower()


def _git_commit_subject(workspace_path: Path, commit_hash: str) -> str | None:
    """Return the subject line of ``commit_hash``, or None if unavailable."""
    if not commit_hash:
        return None
    result = run_cmd_capture(
        ["git", "log", "-1", "--format=%s", commit_hash], cwd=workspace_path)
    if result.returncode != 0:
        return None
    subject = result.stdout.strip()
    return subject or None


def _cherry_picked_sha(patch_text: str) -> str | None:
    """Extract the upstream SHA from a ``(cherry picked from commit ...)`` line."""
    match = re.search(r"cherry picked from commit ([0-9a-f]{7,40})", patch_text)
    return match.group(1) if match else None


def _compute_cve_tag_flags(state: WorkflowState, patches: list[str]) -> list[bool]:
    """Decide which generated patches should carry the ``CVE:`` tag.

    Only the patch corresponding to the fix commit gets the ``CVE:`` tag;
    prerequisite commits the agent added get ``Upstream-Status: Backport``
    only. This distinction is applied **only** when the agent introduced
    extra commits (no known series, but more than one patch). A known
    series (``series_state`` set — from a pull request or from repeated
    ``--fix-url``) and single-patch fixes keep the existing all-``CVE:``
    behavior untouched.

    Safety: if the fix commit's subject can't be matched to any generated
    patch, fall back to tagging every patch — the fix must never silently
    lose its ``CVE:`` tag.
    """
    flags = [True] * len(patches)
    series_commits = (state.series_state or {}).get("commits", [])
    if series_commits or len(patches) <= 1 or state.meta_layer is None:
        return flags
    meta_layer = state.meta_layer

    fix_subject = _git_commit_subject(state.workspace_path, state.commit_hash)
    if not fix_subject:
        return flags

    norm_fix = _normalize_subject(fix_subject)
    matched = []
    for patch_rel in patches:
        text = (meta_layer / patch_rel).read_text(
            encoding=TEXT_ENCODING, errors=TEXT_ERRORS)
        matched.append(_normalize_subject(_extract_patch_subject(text)) == norm_fix)

    if not any(matched):
        logger.warning(
            "Could not match fix commit subject to any generated patch; "
            "tagging all patches with CVE so the fix keeps its CVE: tag")
        return flags
    return matched


def update_patches_with_metadata(state: WorkflowState) -> None:
    """Update patches with CVE metadata after devtool finish."""
    logger.info("Updating patches with CVE metadata")
    result = run_cmd_capture(
        ['git', 'ls-files', '--others', '--exclude-standard'], cwd=state.meta_layer)
    if result.returncode != 0:
        return

    # Scope to the recipe's directory to avoid patches from other recipes
    from .recipe_ops import _find_recipe_file
    recipe_file = _find_recipe_file(state.meta_layer, state.recipe)
    recipe_dir = str(recipe_file.parent.relative_to(state.meta_layer)) + '/' if recipe_file and state.meta_layer else None

    original_patches = sorted(
        p for p in result.stdout.splitlines()
        if p.endswith('.patch') and (recipe_dir is None or p.startswith(recipe_dir))
    )
    if not original_patches:
        logger.warning("No patches found in last commit")
        return

    logger.info("Found %s patch(es) to update", len(original_patches))

    url_by_hash = {d['hash']: d['url'] for d in state.hash_details
                   if d.get('hash') and d.get('url')}

    # Deduce repo base URL for constructing commit URLs
    repo_base_url = ''
    for d in state.hash_details:
        url = d.get('url', '')
        if '/commit/' in url:
            repo_base_url = url.split('/commit/')[0]
            break

    series_commits = (state.series_state or {}).get('commits', [])
    if series_commits and len(series_commits) == len(original_patches):
        commit_urls = []
        for c in series_commits:
            if c in url_by_hash:
                commit_urls.append(url_by_hash[c])
            elif repo_base_url:
                commit_urls.append(f"{repo_base_url}/commit/{c}")
            else:
                commit_urls.append(f"commit/{c}")
    else:
        fallback = url_by_hash.get(state.commit_hash, '')
        if not fallback and repo_base_url:
            fallback = f"{repo_base_url}/commit/{state.commit_hash}"
        elif not fallback:
            fallback = f"commit/{state.commit_hash}"
        commit_urls = [fallback] * len(original_patches)

    cve_tag_flags = _compute_cve_tag_flags(state, original_patches)

    for idx, original_patch_path in enumerate(original_patches, 1):
        original_patch = state.meta_layer / original_patch_path
        if not original_patch.exists():
            continue

        include_cve = cve_tag_flags[idx - 1]
        original_url = commit_urls[idx - 1]
        if not include_cve:
            # Prefer the prerequisite's own upstream commit for its
            # Upstream-Status link, if the agent recorded it via
            # `git cherry-pick -x`.
            prereq_sha = _cherry_picked_sha(
                original_patch.read_text(
                    encoding=TEXT_ENCODING, errors=TEXT_ERRORS))
            if prereq_sha and repo_base_url:
                original_url = f"{repo_base_url}/commit/{prereq_sha}"
        kind = "" if include_cve else " (prerequisite, no CVE tag)"
        logger.info("Upstream-Status: Backport [%s]%s", original_url, kind)
        modify_patch(original_patch, state.cve_id, original_url,
                     include_cve_tag=include_cve)

        new_name = (f"{state.cve_id}.patch" if len(original_patches) == 1
                    else f"{state.cve_id}-{idx}.patch")
        new_patch = original_patch.parent / new_name

        update_recipe_patch(state.recipe, new_name, original_patch.name, state.meta_layer)
        original_patch.rename(new_patch)
        logger.info("Renamed %s -> %s", original_patch.name, new_name)

    if len(original_patches) > 1 and state.meta_layer:
        _split_src_uri_line(state.cve_id, state.meta_layer)
        sort_cve_lines_in_recipe(state.cve_id, state.meta_layer)
