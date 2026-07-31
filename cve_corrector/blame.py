# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Vulnerability origin detection via git blame.

Determines when the code modified by a CVE fix was introduced, maps the
introducing commit to the nearest release tag, and compares against the
recipe version to decide whether the CVE is applicable.
"""
import re
from pathlib import Path
from typing import Optional

from .utils import logger, run_cmd_capture

# Matches unified diff hunk headers: @@ -old_start,old_count +new_start,new_count @@
_HUNK_RE = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+\d+')
# Matches diff --git a/path b/path
_DIFF_FILE_RE = re.compile(r'^diff --git a/(.+) b/')
# Matches the commit hash line in porcelain blame output
_BLAME_HASH_RE = re.compile(r'^([0-9a-f]{40}) ')


def parse_diff_line_ranges(workspace_path: Path,
                           commit_hash: str,
                           context_lines: int = 3,
                           ) -> dict[str, list[tuple[int, int]]]:
    """Parse an upstream fix commit's diff to find modified/deleted line ranges.

    Extracts the "old" side hunk ranges — these are the lines in the
    pre-fix source that the commit modifies or deletes.  For pure
    additions (count=0), captures a small window of context lines around
    the insertion point so that ``blame_line_ranges`` can still identify
    when the surrounding code was introduced.

    Args:
        workspace_path: Path to the git repository.
        commit_hash: The upstream fix commit hash.
        context_lines: Number of context lines to blame around pure additions.

    Returns:
        Dict mapping file paths to lists of (start_line, end_line) tuples
        representing the old-side line ranges. Empty dict if diff fails.
    """
    result = run_cmd_capture(
        ['git', 'diff', f'{commit_hash}~1', commit_hash, '--unified=0'],
        cwd=workspace_path)
    if result.returncode != 0:
        logger.error("git diff failed for %s: %s", commit_hash[:8], result.stderr)
        return {}

    file_ranges: dict[str, list[tuple[int, int]]] = {}
    current_file = None

    for line in result.stdout.splitlines():
        file_match = _DIFF_FILE_RE.match(line)
        if file_match:
            current_file = file_match.group(1)
            continue

        hunk_match = _HUNK_RE.match(line)
        if hunk_match and current_file:
            start = int(hunk_match.group(1))
            count = int(hunk_match.group(2)) if hunk_match.group(2) else 1
            if count == 0:
                # Pure addition — blame context around insertion point
                ctx_start = max(1, start - context_lines)
                ctx_end = start + context_lines
                file_ranges.setdefault(current_file, []).append(
                    (ctx_start, ctx_end))
                continue
            file_ranges.setdefault(current_file, []).append(
                (start, start + count - 1))

    return file_ranges


def blame_line_ranges(workspace_path: Path,
                      file_ranges: dict[str, list[tuple[int, int]]],
                      revision: Optional[str] = None,
                      file_revisions: Optional[dict[str, str]] = None) -> set[str]:
    """Run git blame on line ranges to find introducing commits.

    Args:
        workspace_path: Path to the git repository.
        file_ranges: Dict mapping file paths to (start, end) line ranges,
            as returned by parse_diff_line_ranges.
        revision: Git revision to blame at for all files (legacy, overridden
            by file_revisions when provided).
        file_revisions: Per-file revision map (filepath -> revision).  When
            provided, each file is blamed at its own parent revision rather
            than a single shared one.

    Returns:
        Set of commit hashes that introduced the blamed lines.
    """
    commits: set[str] = set()

    for filepath, ranges in file_ranges.items():
        rev = (file_revisions or {}).get(filepath, revision)
        for start, end in ranges:
            cmd = ['git', 'blame', '-p', f'-L{start},{end}']
            if rev:
                cmd.append(rev)
            cmd += ['--', filepath]
            result = run_cmd_capture(cmd, cwd=workspace_path)
            if result.returncode != 0:
                logger.warning(
                    f"git blame failed for {filepath}:{start}-{end}: "
                    f"{result.stderr.strip()}")
                continue
            for blame_line in result.stdout.splitlines():
                m = _BLAME_HASH_RE.match(blame_line)
                if m:
                    sha = m.group(1)
                    # Skip the zero commit (uncommitted / boundary)
                    if not sha.startswith('0000000'):
                        commits.add(sha)

    return commits


# Strip ~N or ^N suffixes from git describe --contains output
_DESCRIBE_SUFFIX_RE = re.compile(r'[~^]\d+$')


def _tag_to_version_str(tag: str) -> str:
    """Extract a version string from a tag name.

    Strips common prefixes like 'v', 'release-', 'libfoo-' to get the
    numeric version portion.  Handles OpenSSH-style tags like V_9_6_P1
    (-> 9.6p1) and V_1_2_PRE3 (-> 1.2pre3).
    """
    # Handle OpenSSH-style tags: V_9_6_P1 -> 9.6p1, V_1_2_PRE15 -> 1.2pre15
    m = re.match(r'^V_(\d[\d_]*)_(P|PRE)(\d+)$', tag, re.IGNORECASE)
    if m:
        release = m.group(1).replace('_', '.')
        suffix = m.group(2).lower()
        suffix_num = m.group(3)
        return f"{release}{suffix}{suffix_num}"

    # Remove known prefixes
    cleaned = re.sub(r'^(release[-_]|v)', '', tag)
    # If still has a name prefix (e.g. libfoo-3.7.9), strip up to last dash
    # before a digit
    m = re.match(r'^[a-zA-Z][\w]*-(\d.*)$', cleaned)
    if m:
        cleaned = m.group(1)
    # Normalize underscores to dots for version parsing
    return cleaned.replace('_', '.')


def find_introducing_version(workspace_path: Path,
                             commits: set[str]) -> Optional[str]:
    """Map introducing commits to the earliest release tag version.

    For each commit, tries ``git describe --contains`` first, then falls
    back to ``git tag --contains``.

    Args:
        workspace_path: Path to the git repository.
        commits: Set of introducing commit hashes.

    Returns:
        The earliest version string across all commits, or None if no
        commit could be mapped to a tag.
    """
    # Lazy import to avoid circular dependency at module level
    from .version import Version  # noqa: E402

    versions: list[tuple[str, Version]] = []

    for sha in commits:
        tag = _resolve_tag_for_commit(workspace_path, sha)
        if not tag:
            continue
        ver_str = _tag_to_version_str(tag)
        try:
            versions.append((ver_str, Version(ver_str)))
        except ValueError:
            logger.debug("Could not parse version from tag %r", tag)

    if not versions:
        return None

    # Return the earliest (smallest) version
    versions.sort(key=lambda v: v[1])
    earliest = versions[0][0]
    logger.info("Earliest introducing version: %s", earliest)
    return earliest


def _resolve_tag_for_commit(workspace_path: Path,
                            commit: str) -> Optional[str]:
    """Find the earliest tag containing a commit.

    Tries ``git describe --contains`` first (fast), falls back to
    ``git tag --contains`` (slower but works when describe fails).
    """
    # Lazy import
    from .version import Version  # noqa: E402

    result = run_cmd_capture(
        ['git', 'describe', '--contains', commit], cwd=workspace_path)
    if result.returncode == 0:
        tag = _DESCRIBE_SUFFIX_RE.sub('', result.stdout.strip())
        if tag:
            return tag

    # Fallback: git tag --contains
    result = run_cmd_capture(
        ['git', 'tag', '--contains', commit], cwd=workspace_path)
    if result.returncode != 0 or not result.stdout.strip():
        logger.debug("No tag found containing %s", commit[:8])
        return None

    tags = result.stdout.strip().splitlines()
    # Pick the earliest version tag
    best = None
    for tag in tags:
        ver_str = _tag_to_version_str(tag)
        try:
            v = Version(ver_str)
            if best is None or v < best[1]:
                best = (tag, v)
        except ValueError:
            continue
    return best[0] if best else tags[0]


def is_cve_applicable(introducing_version: str,
                      recipe_version: str) -> Optional[bool]:
    """Compare introducing version against recipe version.

    Args:
        introducing_version: Version where vulnerable code first appeared.
        recipe_version: Current recipe version in the Yocto build.

    Returns:
        True if CVE applies (introducing_version <= recipe_version),
        False if not applicable (introducing_version > recipe_version),
        None if versions cannot be compared.
    """
    from .version import Version  # noqa: E402

    try:
        intro = Version(introducing_version)
        recipe = Version(recipe_version)
    except ValueError:
        logger.warning(
            "Cannot compare versions: %r vs %r",
            introducing_version, recipe_version)
        return None

    if intro > recipe:
        logger.info(
            "CVE not applicable: vulnerable code introduced in %s, recipe is %s",
            introducing_version, recipe_version)
        return False
    logger.info(
        "CVE applicable: vulnerable code introduced in %s, recipe is %s",
        introducing_version, recipe_version)
    return True


def check_vulnerability_origin(workspace_path: Path,
                               commit_hashes: list[str],
                               recipe_version: str,
                               series: Optional[list] = None,
                               ) -> Optional[str]:
    """Check whether the CVE applies to the current recipe version.

    Parses the upstream fix commit diffs, blames the modified lines to
    find when they were introduced, maps to the nearest release tag, and
    compares against the recipe version.

    Args:
        workspace_path: Path to the git repository (on the CVE branch,
            checked out at the recipe version).
        commit_hashes: List of upstream fix commit hashes.
        recipe_version: Current recipe version string.
        series: Optional list of series dicts with 'commits' keys — an
            ordered set of commits that must all be applied, from a pull
            request or from repeated ``--fix-url``.

    Returns:
        A reason string suitable for CVE_STATUS if the CVE is not
        applicable, or None if it is applicable (or indeterminate).
    """
    if not recipe_version:
        logger.debug("No recipe version — skipping origin check")
        return None

    # Collect all commits to analyse (hashes + series commits)
    all_commits = list(commit_hashes)
    for s in (series or []):
        all_commits.extend(s.get('commits', []))
    if not all_commits:
        return None

    # Union diff ranges from all fix commits, tracking parent revision per file
    # so we blame each file at the parent of the commit that actually touches it.
    file_parent: dict[str, str] = {}  # filepath -> parent revision to blame at
    all_ranges: dict[str, list[tuple[int, int]]] = {}
    for sha in all_commits:
        ranges = parse_diff_line_ranges(workspace_path, sha)
        if ranges:
            parent = f'{sha}~1'
            for filepath, file_ranges in ranges.items():
                all_ranges.setdefault(filepath, []).extend(file_ranges)
                # First commit to touch a file wins (earliest parent)
                file_parent.setdefault(filepath, parent)

    if not all_ranges:
        logger.info("No blameable line ranges from fix commits — skipping origin check")
        return None

    # Blame each file at the parent of the commit that first touches it
    introducing_commits = blame_line_ranges(workspace_path, all_ranges,
                                            file_revisions=file_parent)
    if not introducing_commits:
        logger.info("git blame found no introducing commits — skipping origin check")
        return None

    # Map to earliest version
    intro_version = find_introducing_version(workspace_path, introducing_commits)
    if not intro_version:
        logger.info("Could not map introducing commits to a version tag")
        return None

    # Compare
    applicable = is_cve_applicable(intro_version, recipe_version)
    if applicable is False:
        return (f"Vulnerable code introduced in {intro_version}, "
                f"recipe version is {recipe_version} — not affected")

    return None
