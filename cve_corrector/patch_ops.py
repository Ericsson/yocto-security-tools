# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Patch formatting and metadata operations for CVE corrector.

Handles CVE tag insertion, Upstream-Status headers, patch renaming,
and SRC_URI updates after devtool finish.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING

from .git_ops import get_git_user_info
from .recipe_ops import _split_src_uri_line, sort_cve_lines_in_recipe, update_recipe_patch
from .utils import logger, run_cmd_capture

if TYPE_CHECKING:
    from .state import WorkflowState


def modify_patch(patch_file: Path, cve_id: str, original_url: str) -> None:
    """Add CVE tag and Upstream-Status to patch."""
    text = patch_file.read_text(encoding="utf-8")

    if f"CVE: {cve_id}" in text and "Upstream-Status:" in text:
        return

    author, email = get_git_user_info()

    block = (
        "\n"
        f"CVE: {cve_id}\n"
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
    recipe_dir = str(recipe_file.parent.relative_to(state.meta_layer)) + '/' if recipe_file else None

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

    for idx, original_patch_path in enumerate(original_patches, 1):
        original_patch = state.meta_layer / original_patch_path
        if not original_patch.exists():
            continue

        original_url = commit_urls[idx - 1]
        logger.info("Upstream-Status: Backport [%s]", original_url)
        modify_patch(original_patch, state.cve_id, original_url)

        new_name = (f"{state.cve_id}.patch" if len(original_patches) == 1
                    else f"{state.cve_id}-{idx}.patch")
        new_patch = original_patch.parent / new_name

        update_recipe_patch(state.recipe, new_name, original_patch.name, state.meta_layer)
        original_patch.rename(new_patch)
        logger.info("Renamed %s -> %s", original_patch.name, new_name)

    if len(original_patches) > 1 and state.meta_layer:
        _split_src_uri_line(state.cve_id, state.meta_layer)
        sort_cve_lines_in_recipe(state.cve_id, state.meta_layer)
