# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Knowledge base for CVE conflict resolution patterns.

Stores and retrieves resolution patterns across CVE runs to provide
context for future similar conflicts. Patterns are suggestions only —
never auto-applied.
"""
from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from . import DEFAULT_KNOWLEDGE_PATH
from .git import get_changed_files, run_git_stdout

if TYPE_CHECKING:
    from . import AgentConfig

MAX_SIMILAR_RESULTS = 3


@dataclass
class ResolutionPattern:
    """A recorded conflict resolution pattern."""
    conflict_type: str
    recipe: str
    file_pattern: str
    resolution_summary: str
    cve_id: str
    timestamp: str
    upstream_sha: str = ""
    affected_files: list[str] = field(default_factory=list)
    per_file_changes: dict[str, str] = field(default_factory=dict)
    diff_stat: str = ""
    commit_message: str = ""


class KnowledgeBase:
    """Persistent store of conflict resolution patterns.

    Stores patterns in a JSON file with file-locking for safe concurrent
    access. Patterns are indexed by recipe and file for similarity matching.

    Args:
        path: Path to the knowledge JSON file. Defaults to global location.
    """

    def __init__(self, path: Path | None = None) -> None:
        """Initialize the knowledge base.

        Args:
            path: Path to the JSON storage file. Uses default if None.
        """
        self.path = path or DEFAULT_KNOWLEDGE_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def add_pattern(self, pattern: ResolutionPattern) -> None:
        """Append a resolution pattern to the knowledge base.

        Uses a single exclusive lock for the entire read-modify-write cycle
        to prevent concurrent writers from losing each other's additions.
        """
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_suffix('.lock')
        with open(lock_path, 'w', encoding='utf-8') as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                patterns = self._load_unlocked()
                patterns.append(asdict(pattern))
                self._save_unlocked(patterns)
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)

    def find_similar(self, recipe: str,
                     conflicted_files: list[str]) -> list[ResolutionPattern]:
        """Find resolution patterns similar to the current conflict.

        Matches by recipe name first, then by file pattern overlap.
        Returns up to MAX_SIMILAR_RESULTS patterns sorted by relevance.

        Args:
            recipe: Recipe name to match against.
            conflicted_files: List of conflicted file paths.

        Returns:
            List of matching ResolutionPattern instances, most relevant first.
        """
        patterns = self._load()
        scored = []
        for entry in patterns:
            score = _compute_similarity(entry, recipe, conflicted_files)
            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda item: item[0], reverse=True)
        return [
            _dict_to_pattern(entry)
            for _, entry in scored[:MAX_SIMILAR_RESULTS]
        ]

    def list_patterns(self) -> list[ResolutionPattern]:
        """Return all stored patterns.

        Returns:
            List of all ResolutionPattern instances.
        """
        return [_dict_to_pattern(entry) for entry in self._load()]

    def _load(self) -> list[dict]:
        """Load patterns from disk with shared lock (for read-only access).

        Returns:
            List of pattern dicts from the JSON file.
        """
        if not self.path.exists():
            return []
        with open(self.path, encoding='utf-8') as file:
            fcntl.flock(file, fcntl.LOCK_SH)
            try:
                return json.load(file)
            except json.JSONDecodeError:
                return []
            finally:
                fcntl.flock(file, fcntl.LOCK_UN)

    def _load_unlocked(self) -> list[dict]:
        """Load patterns without locking (caller must hold lock)."""
        if not self.path.exists():
            return []
        try:
            return json.loads(self.path.read_text(encoding='utf-8'))
        except (json.JSONDecodeError, OSError):
            return []

    def _save_unlocked(self, patterns: list[dict]) -> None:
        """Save patterns atomically (caller must hold lock)."""
        import tempfile
        tmp_fd, tmp_path = tempfile.mkstemp(
            dir=self.path.parent, prefix='.knowledge_tmp_', suffix='.json')
        try:
            with os.fdopen(tmp_fd, 'w', encoding='utf-8') as tmp_file:
                json.dump(patterns, tmp_file, indent=2)
            os.rename(tmp_path, self.path)
        except Exception:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)
            raise


def create_pattern(conflict_type: str, recipe: str, file_pattern: str,
                   resolution_summary: str, cve_id: str,
                   upstream_sha: str = "",
                   affected_files: list[str] | None = None,
                   per_file_changes: dict[str, str] | None = None,
                   diff_stat: str = "",
                   commit_message: str = "") -> ResolutionPattern:
    """Create a new resolution pattern with current timestamp.

    Args:
        conflict_type: Type of conflict (e.g., "api_signature", "struct_rename").
        recipe: Recipe name.
        file_pattern: Glob or filename pattern for affected files.
        resolution_summary: One-line description of how it was resolved.
        cve_id: CVE identifier.
        upstream_sha: Full upstream commit SHA.
        affected_files: List of files modified in the resolution.
        per_file_changes: Dict mapping filepath to description of changes.
        diff_stat: Output of git diff --stat for the resolution.
        commit_message: Final commit message of the resolved patch.

    Returns:
        A new ResolutionPattern instance.
    """
    return ResolutionPattern(
        conflict_type=conflict_type,
        recipe=recipe,
        file_pattern=file_pattern,
        resolution_summary=resolution_summary,
        cve_id=cve_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        upstream_sha=upstream_sha,
        affected_files=affected_files or [],
        per_file_changes=per_file_changes or {},
        diff_stat=diff_stat,
        commit_message=commit_message,
    )


def _compute_similarity(entry: dict, recipe: str,
                        conflicted_files: list[str]) -> int:
    """Compute a similarity score between a pattern and current conflict.

    Args:
        entry: Pattern dict from the knowledge base.
        recipe: Current recipe name.
        conflicted_files: Current conflicted file paths.

    Returns:
        Integer score (higher = more similar). 0 means no match.
    """
    score = 0
    if entry.get('recipe') == recipe:
        score += 10

    file_pattern = entry.get('file_pattern', '')
    if file_pattern:
        for filepath in conflicted_files:
            if file_pattern in filepath or filepath in file_pattern:
                score += 5
                break

    # Score overlap between stored affected_files and current conflicted files
    stored_files = set(entry.get('affected_files', []))
    if stored_files and conflicted_files:
        overlap = stored_files & set(conflicted_files)
        score += len(overlap) * 3

    if entry.get('conflict_type') and score > 0:
        score += 2

    return score


def _dict_to_pattern(entry: dict) -> ResolutionPattern:
    """Convert a dict to a ResolutionPattern, tolerating missing or extra keys."""
    kwargs = {}
    for f in dataclasses.fields(ResolutionPattern):
        if f.name in entry:
            kwargs[f.name] = entry[f.name]
        elif f.default is not dataclasses.MISSING:
            kwargs[f.name] = f.default
        elif f.default_factory is not dataclasses.MISSING:  # type: ignore[misc]
            kwargs[f.name] = f.default_factory()
    return ResolutionPattern(**kwargs)


# NOTE: Must be called BEFORE run_corrector(continue_mode=True) which may delete the workspace
def gather_pattern_details(workspace_path: Path,
                           upstream_sha: str) -> dict:
    """Gather rich context for a knowledge base pattern."""
    applied = get_changed_files(
        ['diff', '--name-only', 'original-version..HEAD'], workspace_path
    )
    upstream = get_changed_files(
        ['diff-tree', '--no-commit-id', '--name-only', '-r', upstream_sha],
        workspace_path
    )

    per_file: dict[str, str] = {}
    for filepath in sorted(applied & upstream):
        stat = run_git_stdout(
            ['diff', '--stat', f'{upstream_sha}..HEAD', '--', filepath],
            workspace_path
        ).strip()
        if stat:
            delta = stat.split('|')[-1].strip() if '|' in stat else 'modified'
            per_file[filepath] = f"adapted from upstream ({delta})"
        else:
            per_file[filepath] = "identical to upstream"
    for filepath in sorted(upstream - applied):
        per_file[filepath] = "omitted from backport"

    return {
        'affected_files': sorted(applied),
        'per_file_changes': per_file,
        'diff_stat': run_git_stdout(
            ['diff', '--stat', 'original-version..HEAD'], workspace_path
        ).strip(),
        'commit_message': run_git_stdout(
            ['log', '-1', '--format=%B', 'HEAD'], workspace_path
        ).strip(),
    }


def save_knowledge_pattern(config: AgentConfig,
                           knowledge_base: KnowledgeBase,
                           summary: str,
                           upstream_sha: str,
                           recipe: str = "",
                           details: dict | None = None) -> None:
    """Save a resolution pattern to the knowledge base after success."""
    recipe = recipe or config.cve_id
    details = details or {}

    if config.trust_mode:
        knowledge_base.add_pattern(create_pattern(
            "auto", recipe, "*", summary, config.cve_id,
            upstream_sha=upstream_sha, **details))
        return

    suggested = f"{recipe}: {config.cve_id} backport adaptation"
    response = input(
        f"\nSave resolution pattern? [{suggested}] (enter to accept, "
        f"custom text, or 'n' to skip): "
    ).strip()
    if response.lower() == 'n':
        return

    description = response or suggested
    knowledge_base.add_pattern(create_pattern(
        "manual", recipe, "*", description, config.cve_id,
        upstream_sha=upstream_sha, **details))
    print("Pattern saved.")
