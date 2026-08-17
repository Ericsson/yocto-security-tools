# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Typed, bounded repository preflight before any model request."""
from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .openai_deadline import RuntimeTimeoutError, SessionDeadline
from .openai_git_tools import (
    MAX_GIT_PREFLIGHT_OUTPUT_BYTES,
    GitCommandExecutor,
    GitCommandResult,
    GitToolLimits,
)
from .openai_tools import FileToolPathPolicy, ToolPolicyError, ToolValidationError

MAX_PREFLIGHT_PATHS = 100_000
MAX_DIAGNOSTIC_PATHS = 32


class PreflightPhase(str, Enum):
    REPOSITORY = "repository"
    ALLOWED_SCOPE = "allowed_scope"
    OPERATION_STATE = "operation_state"
    BASELINE_CAPTURE = "baseline_capture"
    CONSISTENCY = "consistency"
    COMPLETE = "complete"


class PreflightErrorCode(str, Enum):
    REPOSITORY_UNAVAILABLE = "INIT_REPOSITORY_UNAVAILABLE"
    GIT_STATUS_FAILED = "INIT_GIT_STATUS_FAILED"
    UNSUPPORTED_GIT_OPERATION_STATE = "INIT_UNSUPPORTED_GIT_OPERATION_STATE"
    INVALID_ALLOWED_SCOPE = "INIT_INVALID_ALLOWED_SCOPE"
    EMPTY_ALLOWED_SCOPE = "INIT_EMPTY_ALLOWED_SCOPE"
    DIRTY_OUT_OF_SCOPE = "INIT_DIRTY_OUT_OF_SCOPE"
    BASELINE_CAPTURE_FAILED = "INIT_BASELINE_CAPTURE_FAILED"
    BASELINE_CAPTURE_LIMIT = "INIT_BASELINE_CAPTURE_LIMIT"
    PATH_POLICY_FAILED = "INIT_PATH_POLICY_FAILED"
    TRANSCRIPT_FAILED = "INIT_TRANSCRIPT_FAILED"
    WORKSPACE_CHANGED_DURING_CAPTURE = "INIT_WORKSPACE_CHANGED_DURING_CAPTURE"


@dataclass(frozen=True)
class PreflightResult:
    """Complete host evidence or one stable fail-closed diagnostic."""

    ok: bool
    phase: PreflightPhase
    error_code: PreflightErrorCode | None
    workspace: str | None
    head: str | None
    tree: str | None
    branch: str | None
    detached: bool
    operations: Mapping[str, bool]
    status_counts: Mapping[str, int]
    sample_paths: tuple[str, ...]
    sample_truncated: bool
    allowed_path_count: int
    allowed_scope_sha256: str | None
    out_of_scope_count: int
    generated_path_count: int
    state_fingerprint: str | None
    resource_bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "ok": self.ok,
            "phase": self.phase.value,
            "error_code": self.error_code.value if self.error_code else None,
            "workspace": self.workspace,
            "head": self.head,
            "tree": self.tree,
            "branch": self.branch,
            "detached": self.detached,
            "operations": dict(self.operations),
            "status_counts": dict(self.status_counts),
            "sample_paths": list(self.sample_paths),
            "sample_truncated": self.sample_truncated,
            "allowed_path_count": self.allowed_path_count,
            "allowed_scope_sha256": self.allowed_scope_sha256,
            "out_of_scope_count": self.out_of_scope_count,
            "generated_path_count": self.generated_path_count,
            "state_fingerprint": self.state_fingerprint,
            "resource_bytes": self.resource_bytes,
        }


class PreflightFailure(RuntimeError):
    """Fail-closed result with a stable code and no unbounded Git output."""

    def __init__(self, result: PreflightResult) -> None:
        self.result = result
        code = result.error_code.value if result.error_code else "INIT_UNKNOWN"
        super().__init__(f"native repository preflight failed: {code}")


@dataclass(frozen=True)
class _Capture:
    head: str
    tree: str
    branch: str | None
    status: Mapping[str, tuple[str, ...]]
    status_raw: str
    index_raw: str
    operations: Mapping[str, bool]
    resource_bytes: int

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256()
        for value in (self.head, self.tree, self.index_raw, self.status_raw):
            digest.update(value.encode("utf-8", errors="replace"))
            digest.update(b"\0")
        return digest.hexdigest()


class RepositoryPreflight:
    """Capture complete bounded policy state and bounded diagnostics."""

    def __init__(
        self,
        workspace: Path,
        allowed_files: Iterable[str],
        deadline: SessionDeadline,
        *,
        generated_files: Iterable[str] = (),
        reject_out_of_scope: bool = False,
        executor_factory: Callable[
            [Path, SessionDeadline, GitToolLimits], GitCommandExecutor
        ] = GitCommandExecutor,
        between_captures: Callable[[], None] | None = None,
    ) -> None:
        self.workspace_input = workspace
        self.allowed_input = tuple(allowed_files)
        self.generated_input = tuple(generated_files)
        self.reject_out_of_scope = reject_out_of_scope
        self.deadline = deadline
        self.executor_factory = executor_factory
        self.between_captures = between_captures

    def run(self) -> PreflightResult:
        try:
            workspace = self.workspace_input.resolve(strict=True)
            info = workspace.stat()
            if not stat.S_ISDIR(info.st_mode):
                raise OSError
        except (OSError, RuntimeError):
            return self._failure(
                PreflightPhase.REPOSITORY,
                PreflightErrorCode.REPOSITORY_UNAVAILABLE,
            )
        if not self.allowed_input:
            return self._failure(
                PreflightPhase.ALLOWED_SCOPE,
                PreflightErrorCode.EMPTY_ALLOWED_SCOPE,
                workspace=workspace,
            )
        try:
            policy = FileToolPathPolicy(workspace, self.allowed_input)
            allowed = tuple(sorted(policy.allowed_files))
            generated = tuple(sorted(
                FileToolPathPolicy(workspace, self.generated_input).allowed_files
                if self.generated_input else ()))
        except (ToolPolicyError, ToolValidationError):
            return self._failure(
                PreflightPhase.ALLOWED_SCOPE,
                PreflightErrorCode.INVALID_ALLOWED_SCOPE,
                workspace=workspace,
            )
        except ValueError:
            return self._failure(
                PreflightPhase.ALLOWED_SCOPE,
                PreflightErrorCode.PATH_POLICY_FAILED,
                workspace=workspace,
            )
        allowed_digest = _path_digest(allowed)
        try:
            executor = self.executor_factory(workspace, self.deadline, GitToolLimits())
            git_dir_result = executor.run(
                "git_directory", ["rev-parse", "--absolute-git-dir"])
            _require_complete(git_dir_result, "repository")
            git_dir = Path(git_dir_result.stdout.rstrip("\n")).resolve(strict=True)
            if not git_dir.is_dir():
                raise OSError
            executor.git_directory = git_dir
            first = self._capture(executor, git_dir)
            if self.between_captures is not None:
                self.between_captures()
            second = self._capture(executor, git_dir)
        except _CaptureLimit:
            return self._failure(
                PreflightPhase.BASELINE_CAPTURE,
                PreflightErrorCode.BASELINE_CAPTURE_LIMIT,
                workspace=workspace,
                allowed=allowed,
                allowed_digest=allowed_digest,
            )
        except _StatusFailure:
            return self._failure(
                PreflightPhase.BASELINE_CAPTURE,
                PreflightErrorCode.GIT_STATUS_FAILED,
                workspace=workspace,
                allowed=allowed,
                allowed_digest=allowed_digest,
            )
        except (OSError, RuntimeError, RuntimeTimeoutError):
            return self._failure(
                PreflightPhase.BASELINE_CAPTURE,
                PreflightErrorCode.BASELINE_CAPTURE_FAILED,
                workspace=workspace,
                allowed=allowed,
                allowed_digest=allowed_digest,
            )
        if any(first.operations.get(name, False) for name in ("merge", "rebase", "revert")):
            return self._failure(
                PreflightPhase.OPERATION_STATE,
                PreflightErrorCode.UNSUPPORTED_GIT_OPERATION_STATE,
                workspace=workspace,
                allowed=allowed,
                allowed_digest=allowed_digest,
                capture=first,
            )
        if first.fingerprint != second.fingerprint:
            return self._failure(
                PreflightPhase.CONSISTENCY,
                PreflightErrorCode.WORKSPACE_CHANGED_DURING_CAPTURE,
                workspace=workspace,
                allowed=allowed,
                allowed_digest=allowed_digest,
                capture=second,
            )
        tracked = set().union(*(
            set(first.status[name])
            for name in ("staged", "modified", "deleted", "unmerged")
        ))
        out_of_scope = sorted(tracked - set(allowed) - set(generated))
        if self.reject_out_of_scope and out_of_scope:
            return self._failure(
                PreflightPhase.BASELINE_CAPTURE,
                PreflightErrorCode.DIRTY_OUT_OF_SCOPE,
                workspace=workspace,
                allowed=allowed,
                allowed_digest=allowed_digest,
                capture=first,
                out_of_scope=out_of_scope,
                generated_count=len(generated),
            )
        counts = {name: len(paths) for name, paths in first.status.items()}
        all_paths = sorted(set().union(*(set(paths) for paths in first.status.values())))
        return PreflightResult(
            ok=True,
            phase=PreflightPhase.COMPLETE,
            error_code=None,
            workspace=str(workspace),
            head=first.head,
            tree=first.tree,
            branch=first.branch,
            detached=first.branch is None,
            operations=first.operations,
            status_counts=counts,
            sample_paths=tuple(all_paths[:MAX_DIAGNOSTIC_PATHS]),
            sample_truncated=len(all_paths) > MAX_DIAGNOSTIC_PATHS,
            allowed_path_count=len(allowed),
            allowed_scope_sha256=allowed_digest,
            out_of_scope_count=len(out_of_scope),
            generated_path_count=len(generated),
            state_fingerprint=first.fingerprint,
            resource_bytes=first.resource_bytes,
        )

    def _capture(self, executor: GitCommandExecutor, git_dir: Path) -> _Capture:
        head_result = executor.run(
            "preflight_head",
            ["rev-parse", "--verify", "--quiet", "--end-of-options", "HEAD^{commit}"],
            output_limit=1024,
        )
        tree_result = executor.run(
            "preflight_tree",
            ["rev-parse", "--verify", "--quiet", "--end-of-options", "HEAD^{tree}"],
            output_limit=1024,
        )
        status_result = executor.run(
            "preflight_status",
            ["status", "--porcelain=v2", "-z", "--branch", "--untracked-files=all"],
            output_limit=MAX_GIT_PREFLIGHT_OUTPUT_BYTES,
        )
        index_result = executor.run(
            "preflight_index",
            ["ls-files", "--stage", "-z"],
            output_limit=MAX_GIT_PREFLIGHT_OUTPUT_BYTES,
        )
        for result in (head_result, tree_result, status_result, index_result):
            _require_complete(result, "status" if result is status_result else "capture")
        status, branch = _parse_porcelain_v2(status_result.stdout)
        path_count = sum(len(paths) for paths in status.values())
        if path_count > MAX_PREFLIGHT_PATHS:
            raise _CaptureLimit
        operations = _operation_state(git_dir)
        return _Capture(
            head=head_result.stdout.strip(),
            tree=tree_result.stdout.strip(),
            branch=branch,
            status=status,
            status_raw=status_result.stdout,
            index_raw=index_result.stdout,
            operations=operations,
            resource_bytes=(len(status_result.stdout.encode("utf-8"))
                            + len(index_result.stdout.encode("utf-8"))),
        )

    def _failure(
        self,
        phase: PreflightPhase,
        code: PreflightErrorCode,
        *,
        workspace: Path | None = None,
        allowed: tuple[str, ...] = (),
        allowed_digest: str | None = None,
        capture: _Capture | None = None,
        out_of_scope: list[str] | None = None,
        generated_count: int = 0,
    ) -> PreflightResult:
        paths = out_of_scope or []
        counts = (
            {name: len(values) for name, values in capture.status.items()}
            if capture else {})
        return PreflightResult(
            ok=False,
            phase=phase,
            error_code=code,
            workspace=str(workspace) if workspace else None,
            head=capture.head if capture else None,
            tree=capture.tree if capture else None,
            branch=capture.branch if capture else None,
            detached=capture is not None and capture.branch is None,
            operations=capture.operations if capture else {},
            status_counts=counts,
            sample_paths=tuple(paths[:MAX_DIAGNOSTIC_PATHS]),
            sample_truncated=len(paths) > MAX_DIAGNOSTIC_PATHS,
            allowed_path_count=len(allowed),
            allowed_scope_sha256=allowed_digest,
            out_of_scope_count=len(paths),
            generated_path_count=generated_count,
            state_fingerprint=capture.fingerprint if capture else None,
            resource_bytes=capture.resource_bytes if capture else 0,
        )


class _CaptureLimit(Exception):
    pass


class _StatusFailure(Exception):
    pass


def _require_complete(result: GitCommandResult, kind: str) -> None:
    if result.stdout_truncated or result.stderr_truncated:
        raise _CaptureLimit
    if result.timed_out:
        raise RuntimeTimeoutError("repository preflight exceeded its deadline")
    if result.returncode != 0:
        if kind == "status":
            raise _StatusFailure
        raise RuntimeError("bounded repository capture failed")


def _parse_porcelain_v2(output: str) -> tuple[dict[str, tuple[str, ...]], str | None]:
    values: dict[str, list[str]] = {
        "staged": [], "modified": [], "deleted": [],
        "unmerged": [], "untracked": [],
    }
    branch: str | None = None
    tokens = output.split("\0")
    index = 0
    while index < len(tokens):
        record = tokens[index]
        index += 1
        if not record:
            continue
        if record.startswith("# branch.head "):
            value = record.removeprefix("# branch.head ")
            branch = None if value == "(detached)" else value
            continue
        kind = record[0]
        if kind == "?":
            values["untracked"].append(record[2:])
            continue
        if kind == "u":
            fields = record.split(" ", 10)
            if len(fields) != 11:
                raise _StatusFailure
            values["unmerged"].append(fields[10])
            continue
        if kind not in {"1", "2"}:
            if kind == "#" or kind == "!":
                continue
            raise _StatusFailure
        fields = record.split(" ", 8 if kind == "1" else 9)
        expected = 9 if kind == "1" else 10
        if len(fields) != expected:
            raise _StatusFailure
        xy = fields[1]
        path = fields[-1]
        if kind == "2":
            if index >= len(tokens):
                raise _StatusFailure
            index += 1
        if xy[0] != ".":
            values["staged"].append(path)
        if xy[1] not in {".", "D"}:
            values["modified"].append(path)
        if "D" in xy:
            values["deleted"].append(path)
        if "U" in xy or xy in {"AA", "DD"}:
            values["unmerged"].append(path)
    return {name: tuple(paths) for name, paths in values.items()}, branch


def _operation_state(git_dir: Path) -> dict[str, bool]:
    def present(name: str) -> bool:
        try:
            info = os.stat(git_dir / name, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError:
            return True
        return stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)

    return {
        "cherry_pick": present("CHERRY_PICK_HEAD"),
        "merge": present("MERGE_HEAD"),
        "rebase": present("rebase-merge") or present("rebase-apply"),
        "revert": present("REVERT_HEAD"),
        "sequencer": present("sequencer"),
    }


def _path_digest(paths: Iterable[str]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()
