# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Versioned local corrector-to-agent repository handoff contract."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

from shared import TEXT_ENCODING, TEXT_ERRORS, build_git_env

HANDOFF_SCHEMA_VERSION = 1
MAX_HANDOFF_PATHS = 100_000
MAX_HANDOFF_SAMPLE_PATHS = 32
MAX_HANDOFF_BYTES = 1024 * 1024
_OBJECT_RE = re.compile(r"^[0-9a-f]{40,64}$")
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")


class HandoffError(RuntimeError):
    """The trusted handoff cannot be produced or validated."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(f"{code}: {message}")


@dataclass(frozen=True)
class RepositoryHandoff:
    schema_version: int
    cve: str
    workspace_root: str
    baseline_head: str
    current_head: str
    baseline_tree: str
    current_tree: str
    reference_commits: tuple[str, ...]
    selected_commit: str
    mainline_parent: int | None
    selected_parent: str | None
    git_operation: str
    operation_state: str
    conflicted_paths: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    known_generated_paths: tuple[str, ...]
    tracked_out_of_scope_paths: tuple[str, ...]
    index_fingerprint: str
    worktree_fingerprint: str
    critical_sha256: str

    def critical_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "cve": self.cve,
            "workspace_root": self.workspace_root,
            "baseline_head": self.baseline_head,
            "current_head": self.current_head,
            "baseline_tree": self.baseline_tree,
            "current_tree": self.current_tree,
            "reference_commits": list(self.reference_commits),
            "selected_commit": self.selected_commit,
            "mainline_parent": self.mainline_parent,
            "selected_parent": self.selected_parent,
            "git_operation": self.git_operation,
            "operation_state": self.operation_state,
            "conflicted_paths": list(self.conflicted_paths),
            "allowed_paths": list(self.allowed_paths),
            "known_generated_paths": list(self.known_generated_paths),
            "tracked_out_of_scope_paths": list(self.tracked_out_of_scope_paths),
            "index_fingerprint": self.index_fingerprint,
            "worktree_fingerprint": self.worktree_fingerprint,
        }

    def to_dict(self) -> dict[str, object]:
        return {**self.critical_dict(), "critical_sha256": self.critical_sha256}

    def with_digest(self) -> RepositoryHandoff:
        return replace(self, critical_sha256=_digest(self.critical_dict()))

    def validate(self) -> None:
        if self.schema_version != HANDOFF_SCHEMA_VERSION:
            raise HandoffError("HANDOFF_SCHEMA_UNSUPPORTED", "unsupported schema version")
        if not _CVE_RE.fullmatch(self.cve):
            raise HandoffError("HANDOFF_SCHEMA_INVALID", "invalid CVE identifier")
        if not Path(self.workspace_root).is_absolute():
            raise HandoffError("HANDOFF_SCHEMA_INVALID", "workspace must be absolute")
        if self.git_operation != "cherry-pick":
            raise HandoffError("HANDOFF_SCHEMA_INVALID", "unsupported Git operation")
        if self.operation_state not in {"clean", "cherry_pick", "conflicted"}:
            raise HandoffError("HANDOFF_SCHEMA_INVALID", "invalid operation state")
        if ((self.mainline_parent is None) != (self.selected_parent is None)
                or self.mainline_parent is not None and self.mainline_parent < 1):
            raise HandoffError("HANDOFF_INVALID_MAINLINE", "inconsistent mainline")
        for value in (
            self.baseline_head, self.current_head, self.baseline_tree,
            self.current_tree, self.selected_commit, self.index_fingerprint,
            self.worktree_fingerprint,
        ):
            if not _OBJECT_RE.fullmatch(value):
                raise HandoffError("HANDOFF_INVALID_OBJECT", "invalid object identity")
        if self.selected_parent is not None and not _OBJECT_RE.fullmatch(self.selected_parent):
            raise HandoffError("HANDOFF_INVALID_MAINLINE", "invalid selected parent")
        if not self.reference_commits or any(
                not _OBJECT_RE.fullmatch(value) for value in self.reference_commits):
            raise HandoffError("HANDOFF_INVALID_OBJECT", "invalid reference identity")
        if not self.allowed_paths:
            raise HandoffError("HANDOFF_EMPTY_ALLOWED_SCOPE", "allowed path set is empty")
        for values in (
            self.reference_commits, self.conflicted_paths, self.allowed_paths,
            self.known_generated_paths, self.tracked_out_of_scope_paths,
        ):
            if len(values) > MAX_HANDOFF_PATHS:
                raise HandoffError("HANDOFF_PATH_LIMIT", "handoff path limit exceeded")
            if tuple(sorted(set(values))) != values:
                raise HandoffError("HANDOFF_SCHEMA_INVALID", "paths must be sorted and unique")
        for path in set().union(
            self.conflicted_paths, self.allowed_paths, self.known_generated_paths,
            self.tracked_out_of_scope_paths,
        ):
            _validate_path(path)
        if self.critical_sha256 != _digest(self.critical_dict()):
            raise HandoffError("HANDOFF_DIGEST_MISMATCH", "critical fields changed")

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> RepositoryHandoff:
        expected = {
            "schema_version", "cve", "workspace_root", "baseline_head",
            "current_head", "baseline_tree", "current_tree", "reference_commits",
            "selected_commit", "mainline_parent", "selected_parent", "git_operation",
            "operation_state", "conflicted_paths", "allowed_paths",
            "known_generated_paths", "tracked_out_of_scope_paths",
            "index_fingerprint", "worktree_fingerprint", "critical_sha256",
        }
        if set(value) != expected:
            raise HandoffError("HANDOFF_SCHEMA_INVALID", "unknown or missing fields")
        try:
            manifest = cls(
                schema_version=_integer(value["schema_version"]),
                cve=_string(value["cve"]),
                workspace_root=_string(value["workspace_root"]),
                baseline_head=_string(value["baseline_head"]),
                current_head=_string(value["current_head"]),
                baseline_tree=_string(value["baseline_tree"]),
                current_tree=_string(value["current_tree"]),
                reference_commits=_strings(value["reference_commits"]),
                selected_commit=_string(value["selected_commit"]),
                mainline_parent=(None if value["mainline_parent"] is None
                                 else _integer(value["mainline_parent"])),
                selected_parent=(None if value["selected_parent"] is None
                                 else _string(value["selected_parent"])),
                git_operation=_string(value["git_operation"]),
                operation_state=_string(value["operation_state"]),
                conflicted_paths=_strings(value["conflicted_paths"]),
                allowed_paths=_strings(value["allowed_paths"]),
                known_generated_paths=_strings(value["known_generated_paths"]),
                tracked_out_of_scope_paths=_strings(value["tracked_out_of_scope_paths"]),
                index_fingerprint=_string(value["index_fingerprint"]),
                worktree_fingerprint=_string(value["worktree_fingerprint"]),
                critical_sha256=_string(value["critical_sha256"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise HandoffError("HANDOFF_SCHEMA_INVALID", "malformed field") from error
        manifest.validate()
        return manifest


@dataclass(frozen=True)
class CapturedHandoffState:
    head: str
    tree: str
    index_fingerprint: str
    worktree_fingerprint: str
    tracked_paths: tuple[str, ...]
    conflicted_paths: tuple[str, ...]
    operation_state: str


def read_handoff(path: Path) -> RepositoryHandoff:
    try:
        if path.stat().st_size > MAX_HANDOFF_BYTES:
            raise HandoffError("HANDOFF_READ_LIMIT", "manifest exceeds size limit")
        data = json.loads(path.read_bytes().decode("utf-8", errors="strict"))
    except HandoffError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HandoffError("HANDOFF_READ_FAILED", "manifest is unavailable") from error
    if not isinstance(data, dict):
        raise HandoffError("HANDOFF_SCHEMA_INVALID", "manifest must be an object")
    return RepositoryHandoff.from_dict(data)


def write_handoff(path: Path, manifest: RepositoryHandoff) -> None:
    manifest.validate()
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=".handoff-", suffix=".json")
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(manifest.to_dict(), output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def capture_handoff_state(workspace: Path) -> CapturedHandoffState:
    canonical = workspace.resolve(strict=True)
    head = _git(canonical, "rev-parse", "--verify", "HEAD^{commit}").strip()
    tree = _git(canonical, "rev-parse", "--verify", "HEAD^{tree}").strip()
    index = _git(canonical, "ls-files", "--stage", "-z")
    status = _git(
        canonical, "status", "--porcelain=v2", "-z", "--untracked-files=all")
    tracked, conflicted = _tracked_status_paths(status)
    git_dir = Path(_git(canonical, "rev-parse", "--absolute-git-dir").strip())
    operation = "conflicted" if conflicted else "clean"
    if (git_dir / "CHERRY_PICK_HEAD").exists():
        operation = "conflicted" if conflicted else "cherry_pick"
    return CapturedHandoffState(
        head=head,
        tree=tree,
        index_fingerprint=hashlib.sha256(index.encode("utf-8")).hexdigest(),
        worktree_fingerprint=hashlib.sha256(status.encode("utf-8")).hexdigest(),
        tracked_paths=tracked,
        conflicted_paths=conflicted,
        operation_state=operation,
    )


_SOURCE_ROOT_PREFIXES = ("src/", "lib/", "source/")


def _reference_path_variants(path: str) -> tuple[tuple[str, str], ...]:
    """Return deterministic source-root translations for an upstream path."""
    variants: list[tuple[str, str]] = []
    parts = path.split("/")
    if len(parts) > 2 and parts[0] == "subprojects":
        prefix = "/".join(parts[:2]) + "/"
        variants.append((prefix, "/".join(parts[2:])))
    for prefix in _SOURCE_ROOT_PREFIXES:
        if path.startswith(prefix):
            variants.append((prefix, path[len(prefix):]))
    return tuple(variants)


def _workspace_reference_paths(
    workspace: Path, paths: list[str],
) -> tuple[str, ...]:
    """Map upstream-root paths onto an extracted tracked source root."""
    tracked = {
        path for path in _git(workspace, "ls-files", "-z").split("\0") if path
    }
    evidenced_prefixes: set[str] = set()
    for path in paths:
        if path in tracked:
            continue
        for prefix, candidate in _reference_path_variants(path):
            if candidate in tracked:
                evidenced_prefixes.add(prefix)
                break

    mapped: set[str] = set()
    for path in paths:
        if path in tracked:
            mapped.add(path)
            continue
        variants = _reference_path_variants(path)
        tracked_variant = next(
            (candidate for _, candidate in variants if candidate in tracked),
            None,
        )
        if tracked_variant is not None:
            mapped.add(tracked_variant)
            continue
        evidenced_variant = next(
            (candidate for prefix, candidate in variants
             if prefix in evidenced_prefixes),
            None,
        )
        mapped.add(evidenced_variant or path)
    return tuple(sorted(mapped))


def reference_change_paths(
    workspace: Path, selected_commit: str, mainline_parent: int | None,
) -> tuple[tuple[str, ...], str | None]:
    resolved_commit = _git(
        workspace, "rev-parse", "--verify", f"{selected_commit}^{{commit}}",
    ).strip()
    parents_line = _git(
        workspace, "rev-list", "--parents", "-n", "1", resolved_commit).strip()
    fields = parents_line.split()
    if not fields or fields[0] != resolved_commit:
        raise HandoffError("HANDOFF_SELECTED_COMMIT_INVALID", "selected commit unavailable")
    parents = fields[1:]
    selected_parent: str | None = None
    if len(parents) > 1:
        if mainline_parent is None:
            raise HandoffError("HANDOFF_MERGE_MAINLINE_REQUIRED", "merge mainline is ambiguous")
        if mainline_parent < 1 or mainline_parent > len(parents):
            raise HandoffError("HANDOFF_INVALID_MAINLINE", "mainline is not a direct parent")
        selected_parent = parents[mainline_parent - 1]
    elif mainline_parent is not None:
        raise HandoffError("HANDOFF_INVALID_MAINLINE", "non-merge commit has no mainline")
    base = selected_parent or (parents[0] if parents else _EMPTY_TREE)
    output = _git(
        workspace, "diff", "--name-status", "-z", "-M", "-C", base,
        resolved_commit)
    tokens = [token for token in output.split("\0") if token]
    paths: list[str] = []
    index = 0
    while index < len(tokens):
        status_code = tokens[index]
        index += 1
        count = 2 if status_code.startswith(("R", "C")) else 1
        if index + count > len(tokens):
            raise HandoffError("HANDOFF_REFERENCE_DIFF_INVALID", "malformed name status")
        paths.extend(tokens[index:index + count])
        index += count
    normalized = _workspace_reference_paths(workspace, paths)
    if not normalized:
        raise HandoffError("HANDOFF_EMPTY_ALLOWED_SCOPE", "reference change is empty")
    return normalized, selected_parent


def validate_handoff_state(manifest: RepositoryHandoff, workspace: Path) -> None:
    manifest.validate()
    if str(workspace.resolve(strict=True)) != manifest.workspace_root:
        raise HandoffError("HANDOFF_WORKSPACE_MISMATCH", "workspace root changed")
    captured = capture_handoff_state(workspace)
    comparisons = {
        "current_head": (manifest.current_head, captured.head),
        "current_tree": (manifest.current_tree, captured.tree),
        "index_fingerprint": (manifest.index_fingerprint, captured.index_fingerprint),
        "worktree_fingerprint": (manifest.worktree_fingerprint,
                                 captured.worktree_fingerprint),
        "operation_state": (manifest.operation_state, captured.operation_state),
    }
    if any(expected != actual for expected, actual in comparisons.values()):
        raise HandoffError("HANDOFF_STATE_DRIFT", "repository state changed")
    if tuple(sorted(captured.conflicted_paths)) != tuple(sorted(manifest.conflicted_paths)):
        raise HandoffError("HANDOFF_CONFLICT_DRIFT", "conflict set changed")


def git_object(workspace: Path, revision: str) -> str:
    """Resolve a fixed revision expression to an object identity."""
    return _git(workspace, "rev-parse", "--verify", revision).strip()


def restore_tracked_paths(workspace: Path, paths: tuple[str, ...]) -> None:
    """Restore an explicit, previously authorized tracked path set."""
    for path in paths:
        _validate_path(path)
    if not paths:
        return
    result = subprocess.run(
        ["git", "--no-pager", "restore", "--source=HEAD", "--staged",
         "--worktree", "--", *paths], cwd=workspace, env=build_git_env(),
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, encoding=TEXT_ENCODING, errors=TEXT_ERRORS,
        check=False,
    )
    if result.returncode != 0:
        raise HandoffError(
            "HANDOFF_GENERATED_RESTORE_FAILED",
            "explicit generated paths could not be restored",
        )


_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"


def _git(workspace: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "--no-pager", *arguments], cwd=workspace,
        env=build_git_env(), stdin=subprocess.DEVNULL,
        capture_output=True,
        encoding=TEXT_ENCODING, errors=TEXT_ERRORS, check=False,
    )
    if result.returncode != 0:
        raise HandoffError("HANDOFF_GIT_FAILED", "fixed repository inspection failed")
    if len(result.stdout.encode("utf-8")) > 8 * 1024 * 1024:
        raise HandoffError("HANDOFF_CAPTURE_LIMIT", "repository capture exceeded limit")
    return result.stdout


def _tracked_status_paths(output: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    tracked: set[str] = set()
    conflicts: set[str] = set()
    tokens = output.split("\0")
    index = 0
    while index < len(tokens):
        record = tokens[index]
        index += 1
        if not record or record[0] in {"?", "!", "#"}:
            continue
        kind = record[0]
        fields = record.split(" ", 10 if kind == "u" else (9 if kind == "2" else 8))
        expected = 11 if kind == "u" else (10 if kind == "2" else 9)
        if kind not in {"1", "2", "u"} or len(fields) != expected:
            raise HandoffError("HANDOFF_STATUS_INVALID", "malformed Git status")
        path = fields[-1]
        tracked.add(path)
        if kind == "u":
            conflicts.add(path)
        if kind == "2":
            if index >= len(tokens):
                raise HandoffError("HANDOFF_STATUS_INVALID", "rename source missing")
            tracked.add(tokens[index])
            index += 1
    return tuple(sorted(tracked)), tuple(sorted(conflicts))


def _digest(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_path(path: str) -> None:
    if (not path or path.startswith("/") or "\0" in path or "\\" in path
            or any(part in {"", ".", "..", ".git"}
                   for part in PurePosixPath(path).parts)):
        raise HandoffError("HANDOFF_INVALID_PATH", "unsafe repository path")


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError
    return value


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError
    return value


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TypeError
    return tuple(value)
