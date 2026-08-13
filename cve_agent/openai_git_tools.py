# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Typed, bounded Git tools for the native OpenAI-compatible backend.

The model can select only the named operations declared in this module.  Git
argv, executable names, configuration, environment values, hooks, pathspec
syntax, and shell text are all constructed by trusted host code.
"""
import contextlib
import os
import selectors
import signal
import stat
import subprocess
import time
import uuid
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, Optional

from shared import TEXT_ENCODING, TEXT_ERRORS, build_git_env

from .openai_backend import validate_openai_model
from .openai_deadline import RuntimeTimeoutError, SessionDeadline
from .openai_tools import (
    MAX_MODEL_RESULT_BYTES,
    TOOL_CONTRACTS,
    FieldContract,
    FileToolLimits,
    FileToolRuntime,
    ToolContract,
    ToolOperationalError,
    ToolPolicyError,
    ToolValidationError,
    _ExecutionResult,
)

GIT_EXECUTABLE = "git"
MAX_GIT_REVISION_BYTES = 256
MAX_GIT_PATHS = 32
MAX_GIT_LOG_ENTRIES = 50
MAX_GIT_STATUS_PATHS = 256
MAX_GIT_OUTPUT_BYTES = 256 * 1024
MAX_GIT_DIFF_BYTES = 48 * 1024
MAX_GIT_DIAGNOSTIC_BYTES = 2048
MAX_RESOLUTION_NOTE_BYTES = 2048
MAX_COMMIT_MESSAGE_BYTES = 16 * 1024
MAX_GIT_COMMAND_SECONDS = 30
MAX_GIT_MESSAGE_BYTES = 256 * 1024
MAX_GIT_SEQUENCE_BYTES = 64 * 1024

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)

_NATIVE_SECRET_ENVIRONMENT = frozenset({
    "ALL_PROXY",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "SSH_AGENT_PID",
    "SSH_AUTH_SOCK",
    "all_proxy",
    "https_proxy",
    "http_proxy",
    "no_proxy",
})


def native_subprocess_environment(
    excluded_roots: Sequence[Path] = (),
) -> dict[str, str]:
    """Return the minimal native Git/build environment without network secrets."""
    environment = build_git_env()
    for name in tuple(environment):
        if name in _NATIVE_SECRET_ENVIRONMENT or name.startswith("LC_"):
            environment.pop(name, None)
    environment.update({"LANG": "C", "LC_ALL": "C"})
    canonical_roots = tuple(root.resolve(strict=False) for root in excluded_roots)
    safe_path = []
    for entry in environment.get("PATH", "").split(os.pathsep):
        candidate = Path(entry)
        if not entry or not candidate.is_absolute():
            continue
        canonical = candidate.resolve(strict=False)
        if any(canonical == root or root in canonical.parents for root in canonical_roots):
            continue
        safe_path.append(entry)
    if not safe_path:
        raise ToolOperationalError("native subprocess PATH has no safe absolute entries")
    environment["PATH"] = os.pathsep.join(safe_path)
    return environment

_READ_ONLY_OPERATIONS = frozenset({
    "initial_head",
    "git_directory",
    "status",
    "diff",
    "show_metadata",
    "show_diff",
    "log",
    "unmerged",
    "submodule_status",
    "resolve_revision",
    "commit_parents",
    "changed_paths",
    "tracked_path",
    "staged_paths",
    "baseline_ancestor",
})

_OPERATION_VERBS: Mapping[str, str] = {
    "initial_head": "rev-parse",
    "git_directory": "rev-parse",
    "status": "status",
    "diff": "diff",
    "show_metadata": "show",
    "show_diff": "show",
    "log": "log",
    "unmerged": "ls-files",
    "submodule_status": "ls-files",
    "resolve_revision": "rev-parse",
    "commit_parents": "show",
    "changed_paths": "diff-tree",
    "tracked_path": "ls-files",
    "staged_paths": "diff",
    "baseline_ancestor": "merge-base",
    "commit": "commit",
    "amend": "commit",
    "stage": "add",
    "unstage": "restore",
    "remove": "rm",
    "restore_conflict": "checkout",
    "cherry_pick_start": "cherry-pick",
    "cherry_pick_continue": "cherry-pick",
    "cherry_pick_abort": "cherry-pick",
    "cherry_pick_skip": "cherry-pick",
}

_FORBIDDEN_ARGV = frozenset({
    "-c",
    "--config-env",
    "--exec-path",
    "--force",
    "--hard",
    "--no-verify",
    "--paginate",
    "--receive-pack",
    "--upload-pack",
})


class GitScopeError(ToolPolicyError):
    """A Git mutation would reach paths outside the session scope."""

    def __init__(self, message: str, rejected_paths: Iterable[str]) -> None:
        super().__init__(message)
        self.payload = {
            "rejected_paths": list(rejected_paths)[:MAX_GIT_PATHS],
        }


class GitStateError(ToolPolicyError):
    """A Git mutation started from an unsafe repository state."""

    def __init__(self, message: str, details: Mapping[str, object]) -> None:
        super().__init__(message)
        self.payload = dict(details)


@dataclass(frozen=True)
class GitToolLimits:
    """Immutable per-session Git limits capped by schema-visible maxima."""

    max_revision_bytes: int = MAX_GIT_REVISION_BYTES
    max_paths: int = MAX_GIT_PATHS
    max_log_entries: int = MAX_GIT_LOG_ENTRIES
    max_status_paths: int = MAX_GIT_STATUS_PATHS
    max_output_bytes: int = MAX_GIT_OUTPUT_BYTES
    max_diff_bytes: int = MAX_GIT_DIFF_BYTES
    max_diagnostic_bytes: int = MAX_GIT_DIAGNOSTIC_BYTES
    max_resolution_note_bytes: int = MAX_RESOLUTION_NOTE_BYTES
    max_command_seconds: int = MAX_GIT_COMMAND_SECONDS

    def __post_init__(self) -> None:
        ceilings = {
            "max_revision_bytes": MAX_GIT_REVISION_BYTES,
            "max_paths": MAX_GIT_PATHS,
            "max_log_entries": MAX_GIT_LOG_ENTRIES,
            "max_status_paths": MAX_GIT_STATUS_PATHS,
            "max_output_bytes": MAX_GIT_OUTPUT_BYTES,
            "max_diff_bytes": MAX_GIT_DIFF_BYTES,
            "max_diagnostic_bytes": MAX_GIT_DIAGNOSTIC_BYTES,
            "max_resolution_note_bytes": MAX_RESOLUTION_NOTE_BYTES,
            "max_command_seconds": MAX_GIT_COMMAND_SECONDS,
        }
        for name, ceiling in ceilings.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
            if value < 1 or value > ceiling:
                raise ValueError(f"{name} must be between 1 and {ceiling}")
        if self.max_diff_bytes > MAX_MODEL_RESULT_BYTES:
            raise ValueError("max_diff_bytes exceeds the model result ceiling")


@dataclass(frozen=True)
class GitCommandResult:
    """Bounded result from one fixed Git subprocess."""

    returncode: int
    stdout: str
    stderr: str
    stdout_truncated: bool
    stderr_truncated: bool
    timed_out: bool = False


@dataclass(frozen=True)
class ChangedPath:
    """One path named by a commit's raw tree diff."""

    path: str
    status: str
    old_mode: str
    new_mode: str


@dataclass(frozen=True)
class RepositorySnapshot:
    """Repository identity captured when a native tool session starts."""

    head: str
    operations: Mapping[str, bool]


class GitCommandExecutor:
    """Run only host-built argv for the closed set of named Git operations."""

    def __init__(self, workspace: Path, deadline: SessionDeadline,
                 limits: GitToolLimits) -> None:
        self.workspace = workspace
        self.deadline = deadline
        self.limits = limits
        self.git_directory: Optional[Path] = None

    def run(self, operation: str, argv: Sequence[str],
            output_limit: Optional[int] = None) -> GitCommandResult:
        """Execute one trusted operation with bounded pipes and deadline."""
        expected_verb = _OPERATION_VERBS.get(operation)
        if expected_verb is None or not argv or argv[0] != expected_verb:
            raise RuntimeError("unregistered Git operation")
        if any(argument in _FORBIDDEN_ARGV for argument in argv):
            raise RuntimeError("forbidden trusted Git argument")

        self.deadline.require("Git operation")
        limit = self.limits.max_output_bytes if output_limit is None else output_limit
        limit = min(limit, self.limits.max_output_bytes)
        command = [GIT_EXECUTABLE, "--no-pager", *argv]
        environment = self._environment(operation)

        try:
            process = subprocess.Popen(
                command,
                cwd=self.workspace,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
            )
        except OSError as exc:
            raise ToolOperationalError("unable to start fixed Git executable") from exc
        timeout = min(
            self.deadline.remaining(), float(self.limits.max_command_seconds))
        return self._collect(process, timeout, limit)

    def _environment(self, operation: str) -> dict[str, str]:
        environment = native_subprocess_environment((self.workspace,))
        environment.update({
            "GIT_ASKPASS": "true",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_EDITOR": "true",
            "GIT_LITERAL_PATHSPECS": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_PAGER": "cat",
            "GIT_SEQUENCE_EDITOR": "true",
            "GIT_TERMINAL_PROMPT": "0",
            "SSH_ASKPASS": "true",
        })
        if self.git_directory is not None:
            overrides = (
                ("commit.gpgSign", "false"),
                ("core.fsmonitor", "false"),
                ("core.hooksPath", str(self.git_directory / "hooks")),
            )
            environment["GIT_CONFIG_COUNT"] = str(len(overrides))
            for index, (key, value) in enumerate(overrides):
                environment[f"GIT_CONFIG_KEY_{index}"] = key
                environment[f"GIT_CONFIG_VALUE_{index}"] = value
        environment.pop("GIT_EXTERNAL_DIFF", None)
        environment.pop("GIT_DIFF_OPTS", None)
        # A benchmark or other trusted launcher may provide only the operator's
        # committer identity.  A new typed follow-up commit also needs an
        # author, so use that explicit identity rather than consulting the
        # disabled global configuration.  Do not do this for cherry-picks or
        # amends: those operations must preserve the existing upstream author.
        if operation == "commit":
            if "GIT_AUTHOR_NAME" not in environment:
                name = environment.get("GIT_COMMITTER_NAME")
                if name:
                    environment["GIT_AUTHOR_NAME"] = name
            if "GIT_AUTHOR_EMAIL" not in environment:
                email = environment.get("GIT_COMMITTER_EMAIL")
                if email:
                    environment["GIT_AUTHOR_EMAIL"] = email
        if operation in _READ_ONLY_OPERATIONS:
            environment["GIT_OPTIONAL_LOCKS"] = "0"
        else:
            environment.pop("GIT_OPTIONAL_LOCKS", None)
        return environment

    @staticmethod
    def _kill(process: subprocess.Popen) -> None:
        with contextlib.suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
            return
        with contextlib.suppress(OSError):
            process.kill()

    def _collect(self, process: subprocess.Popen, timeout: float,
                 limit: int) -> GitCommandResult:
        if process.stdout is None or process.stderr is None:
            self._kill(process)
            process.wait()
            raise ToolOperationalError("Git output capture was unavailable")
        selector = selectors.DefaultSelector()
        try:
            stdout_fd = process.stdout.fileno()
            stderr_fd = process.stderr.fileno()
        except (OSError, ValueError) as exc:
            selector.close()
            self._kill(process)
            process.wait()
            raise ToolOperationalError("Git output capture was unavailable") from exc
        streams = {
            stdout_fd: ("stdout", bytearray()),
            stderr_fd: ("stderr", bytearray()),
        }
        truncated = {"stdout": False, "stderr": False}
        command_deadline = time.monotonic() + timeout
        timed_out = False
        drain_deadline: Optional[float] = None
        try:
            for descriptor in streams:
                os.set_blocking(descriptor, False)
                selector.register(descriptor, selectors.EVENT_READ)
            while selector.get_map():
                now = time.monotonic()
                if not timed_out and now >= command_deadline:
                    timed_out = True
                    self._kill(process)
                    drain_deadline = now + 1.0
                if drain_deadline is not None and now >= drain_deadline:
                    break
                wait = 0.1
                if not timed_out:
                    wait = max(0.0, min(wait, command_deadline - now))
                events = selector.select(wait)
                for key, _ in events:
                    descriptor = key.fd
                    label, buffer = streams[descriptor]
                    try:
                        chunk = os.read(descriptor, 8192)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(descriptor)
                        continue
                    available = max(0, limit - len(buffer))
                    if available:
                        buffer.extend(chunk[:available])
                    if len(chunk) > available:
                        truncated[label] = True
        finally:
            if process.poll() is None:
                self._kill(process)
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self._kill(process)
                process.wait()
            selector.close()
            for stream in (process.stdout, process.stderr):
                with contextlib.suppress(OSError):
                    stream.close()

        returncode = process.returncode if process.returncode is not None else -signal.SIGKILL
        stdout = bytes(streams[stdout_fd][1]).decode(TEXT_ENCODING, TEXT_ERRORS)
        stderr = bytes(streams[stderr_fd][1]).decode(TEXT_ENCODING, TEXT_ERRORS)
        return GitCommandResult(
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            stdout_truncated=truncated["stdout"],
            stderr_truncated=truncated["stderr"],
            timed_out=timed_out,
        )


GIT_TOOL_CONTRACTS: dict[str, ToolContract] = {
    "git_status": ToolContract(
        "git_status",
        "Return parsed branch, index, worktree, conflict, and operation state.",
        {},
        "_git_status",
    ),
    "git_diff": ToolContract(
        "git_diff",
        "Return a bounded diff for a closed mode and optional literal paths.",
        {
            "mode": FieldContract(
                "string", "Diff source.", required=True,
                enum=("working", "staged", "revision")),
            "revision": FieldContract(
                "string", "One commit or one two-commit range."),
            "paths": FieldContract(
                "array", "Explicit literal workspace paths.",
                max_items=MAX_GIT_PATHS, item_type="string"),
        },
        "_git_diff",
    ),
    "git_show": ToolContract(
        "git_show",
        "Show validated commit metadata, message, and a bounded diff.",
        {
            "revision": FieldContract(
                "string", "Revision resolving to one commit.", required=True,
                min_length=1),
            "paths": FieldContract(
                "array", "Optional explicit literal workspace paths.",
                max_items=MAX_GIT_PATHS, item_type="string"),
        },
        "_git_show",
    ),
    "git_log": ToolContract(
        "git_log",
        "Return a bounded number of parsed commit summaries.",
        {
            "count": FieldContract(
                "integer", "Maximum entries.", minimum=1,
                maximum=MAX_GIT_LOG_ENTRIES),
            "path": FieldContract(
                "string", "Optional one literal workspace path."),
        },
        "_git_log",
    ),
    "git_unmerged_files": ToolContract(
        "git_unmerged_files",
        "Return parsed unmerged index stages.",
        {},
        "_git_unmerged_files",
    ),
    "git_submodule_status": ToolContract(
        "git_submodule_status",
        "Inspect recorded gitlinks without initialization, fetch, or update.",
        {
            "paths": FieldContract(
                "array", "Optional explicit literal workspace paths.",
                max_items=MAX_GIT_PATHS, item_type="string"),
        },
        "_git_submodule_status",
    ),
    "git_stage": ToolContract(
        "git_stage",
        "Stage exact authorized file paths.",
        {
            "paths": FieldContract(
                "array", "Exact session-authorized files.", required=True,
                min_items=1, max_items=MAX_GIT_PATHS, item_type="string"),
        },
        "_git_stage",
    ),
    "git_unstage": ToolContract(
        "git_unstage",
        "Unstage exact authorized paths without resetting the worktree.",
        {
            "paths": FieldContract(
                "array", "Exact session-authorized files.", required=True,
                min_items=1, max_items=MAX_GIT_PATHS, item_type="string"),
        },
        "_git_unstage",
    ),
    "git_remove": ToolContract(
        "git_remove",
        "Remove and stage deletion of exact authorized regular files.",
        {
            "paths": FieldContract(
                "array", "Exact session-authorized files.", required=True,
                min_items=1, max_items=MAX_GIT_PATHS, item_type="string"),
        },
        "_git_remove",
    ),
    "git_restore_conflict": ToolContract(
        "git_restore_conflict",
        "Restore one authorized conflicted path from ours or theirs.",
        {
            "path": FieldContract(
                "string", "Exact session-authorized conflicted file.",
                required=True),
            "side": FieldContract(
                "string", "Conflict side to restore.", required=True,
                enum=("ours", "theirs")),
        },
        "_git_restore_conflict",
    ),
    "git_commit": ToolContract(
        "git_commit",
        "Stage exact authorized paths and create one bounded follow-up commit.",
        {
            "paths": FieldContract(
                "array", "Exact session-authorized files.", required=True,
                min_items=1, max_items=MAX_GIT_PATHS, item_type="string"),
            "message": FieldContract(
                "string", "Bounded commit subject and optional body.", required=True,
                min_length=1, max_length=MAX_COMMIT_MESSAGE_BYTES),
        },
        "_git_commit",
    ),
    "git_amend": ToolContract(
        "git_amend",
        "Stage exact authorized repair paths and amend HEAD with a fixed message mode.",
        {
            "paths": FieldContract(
                "array", "Exact session-authorized repair files.", required=True,
                min_items=1, max_items=MAX_GIT_PATHS, item_type="string"),
            "message_mode": FieldContract(
                "string", "Keep the current message or replace it with bounded text.",
                required=True, enum=("no_edit", "replace")),
            "message": FieldContract(
                "string", "Required only when message_mode is replace.",
                max_length=MAX_COMMIT_MESSAGE_BYTES),
        },
        "_git_amend",
    ),
    "git_cherry_pick_start": ToolContract(
        "git_cherry_pick_start",
        "Preflight and start exactly one fully in-scope non-merge commit.",
        {
            "revision": FieldContract(
                "string", "Revision resolving to one commit.", required=True,
                min_length=1),
        },
        "_git_cherry_pick_start",
    ),
    "git_cherry_pick_continue": ToolContract(
        "git_cherry_pick_continue",
        "Continue an active cherry-pick with trusted provenance.",
        {
            "resolution_note": FieldContract(
                "string", "Optional concise backport-resolution note."),
        },
        "_git_cherry_pick_continue",
    ),
    "git_cherry_pick_abort": ToolContract(
        "git_cherry_pick_abort",
        "Abort only an active cherry-pick.",
        {},
        "_git_cherry_pick_abort",
    ),
    "git_cherry_pick_skip": ToolContract(
        "git_cherry_pick_skip",
        "Skip only an active single-commit cherry-pick.",
        {},
        "_git_cherry_pick_skip",
    ),
}

NATIVE_TOOL_CONTRACTS: dict[str, ToolContract] = {
    **TOOL_CONTRACTS,
    **GIT_TOOL_CONTRACTS,
}


def native_openai_tool_schemas() -> list[dict[str, object]]:
    """Return the closed file-and-Git function schema set."""
    return [contract.schema() for contract in NATIVE_TOOL_CONTRACTS.values()]


def build_cherry_pick_message(original: str, resolution_note: Optional[str],
                              model: str) -> str:
    """Preserve Git's message while replacing host-owned provenance lines."""
    note = _normalize_resolution_note(resolution_note)
    retained = []
    for line in original.rstrip().splitlines():
        normalized = line.lstrip().casefold()
        if normalized.startswith("backport-resolution:"):
            continue
        if normalized.startswith("assisted-by: openai:"):
            continue
        retained.append(line)
    body = "\n".join(retained).rstrip()
    additions = []
    if note is not None:
        additions.append(f"Backport-resolution: {note}")
    additions.append(f"Assisted-by: openai:{model}")
    return "\n\n".join(part for part in (body, *additions) if part) + "\n"


def build_typed_commit_message(message: str, model: str) -> str:
    """Return bounded model text with exactly one trusted provenance trailer."""
    if any(character != "\n" and (ord(character) < 32 or ord(character) == 127)
           for character in message):
        raise ToolValidationError("commit message contains a control character")
    if len(message.encode("utf-8")) > MAX_COMMIT_MESSAGE_BYTES:
        raise ToolValidationError("commit message exceeds its byte limit")
    retained = [
        line for line in message.rstrip().splitlines()
        if not line.lstrip().casefold().startswith("assisted-by: openai:")
    ]
    body = "\n".join(retained).rstrip()
    if not body.strip():
        raise ToolValidationError("commit message must not be empty")
    result = f"{body}\n\nAssisted-by: openai:{model}\n"
    if len(result.encode("utf-8")) > MAX_COMMIT_MESSAGE_BYTES:
        raise ToolValidationError("commit message exceeds its byte limit")
    return result


def _normalize_resolution_note(note: Optional[str]) -> Optional[str]:
    if note is None:
        return None
    if "\x00" in note:
        raise ToolValidationError("resolution note must not contain NUL")
    encoded = note.encode("utf-8")
    if len(encoded) > MAX_RESOLUTION_NOTE_BYTES:
        raise ToolValidationError("resolution note exceeds its size limit")
    normalized = " ".join(note.split())
    if not normalized:
        raise ToolValidationError("resolution note must not be empty")
    return normalized


class GitToolRuntime(FileToolRuntime):
    """One dispatcher for bounded filesystem and typed Git operations."""

    tool_contracts = NATIVE_TOOL_CONTRACTS

    def __init__(
        self,
        workspace_root: Path,
        allowed_files: Iterable[str],
        model: str,
        timeout_seconds: int,
        agent_root: Optional[Path] = None,
        limits: Optional[FileToolLimits] = None,
        git_limits: Optional[GitToolLimits] = None,
        before_operation: Optional[Callable[[str, Path], None]] = None,
        before_replace: Optional[Callable[[Path], None]] = None,
        deadline: Optional[SessionDeadline] = None,
    ) -> None:
        super().__init__(
            workspace_root,
            allowed_files,
            agent_root=agent_root,
            limits=limits,
            before_operation=before_operation,
            before_replace=before_replace,
        )
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
            raise ValueError("timeout_seconds must be an integer")
        if timeout_seconds < 1:
            raise ValueError("timeout_seconds must be positive")
        self.git_limits = git_limits or GitToolLimits()
        self.workspace = workspace_root.resolve(strict=True)
        self._model = validate_openai_model(model)
        self.deadline = deadline or SessionDeadline.from_timeout(timeout_seconds)
        self._executor = GitCommandExecutor(
            self.workspace, self.deadline, self.git_limits)
        self._git_directory = self._discover_git_directory()
        self._executor.git_directory = self._git_directory
        head = self._resolve_initial_head()
        self.repository_snapshot = RepositorySnapshot(
            head=head,
            operations=self._operation_state(),
        )

    def _discover_git_directory(self) -> Path:
        result = self._executor.run(
            "git_directory", ["rev-parse", "--absolute-git-dir"])
        self._require_complete(result, "Git directory discovery")
        path = Path(result.stdout.rstrip("\n"))
        try:
            canonical = path.resolve(strict=True)
        except OSError as exc:
            raise ValueError("workspace Git directory is unavailable") from exc
        if not canonical.is_dir():
            raise ValueError("workspace Git directory is not a directory")
        info = canonical.stat()
        self._git_directory_identity = (info.st_dev, info.st_ino)
        return canonical

    def _resolve_initial_head(self) -> str:
        result = self._executor.run(
            "initial_head",
            ["rev-parse", "--verify", "--quiet", "--end-of-options", "HEAD^{commit}"],
        )
        self._require_complete(result, "session-start HEAD resolution")
        return result.stdout.strip()

    @classmethod
    def _audit_fields(cls, arguments: object) -> dict[str, object]:
        fields = super()._audit_fields(arguments)
        if not isinstance(arguments, dict):
            return fields
        revision = arguments.get("revision")
        if isinstance(revision, str):
            fields["revision"] = cls._escape_audit_value(revision)
        paths = arguments.get("paths")
        if isinstance(paths, list):
            safe_paths = tuple(
                cls._escape_audit_value(path)
                for path in paths[:MAX_GIT_PATHS]
                if isinstance(path, str)
            )
            if safe_paths:
                fields["paths"] = safe_paths
        return fields

    def _git_status(self, arguments: dict[str, object]) -> _ExecutionResult:
        result = self._executor.run(
            "status",
            ["status", "--porcelain=v2", "-z", "--branch", "--untracked-files=all"],
        )
        self._require_complete(result, "Git status")
        payload = self._parse_status(result.stdout)
        payload["operations"] = self._operation_state()
        return _ExecutionResult(payload)

    def _git_diff(self, arguments: dict[str, object]) -> _ExecutionResult:
        mode = self._required_string(arguments, "mode")
        paths = self._read_paths(arguments.get("paths", []), "git_diff")
        revision_value = arguments.get("revision")
        argv = ["diff", "--no-ext-diff", "--no-textconv", "--no-renames"]
        canonical_revision: Optional[str] = None
        if mode == "working":
            if revision_value is not None:
                raise ToolValidationError("working diff does not accept revision")
        elif mode == "staged":
            if revision_value is not None:
                raise ToolValidationError("staged diff does not accept revision")
            argv.append("--cached")
        else:
            if not isinstance(revision_value, str):
                raise ToolValidationError("revision diff requires revision")
            canonical_revision = self._resolve_diff_revision(revision_value)
            argv.append(canonical_revision)
        if paths:
            argv.extend(["--", *paths])
        result = self._executor.run(
            "diff", argv, output_limit=self.git_limits.max_diff_bytes)
        self._require_returncode(result, "Git diff")
        return _ExecutionResult({
            "mode": mode,
            "revision": canonical_revision,
            "diff": result.stdout,
            "truncated": result.stdout_truncated,
            "stderr_truncated": result.stderr_truncated,
        })

    def _git_show(self, arguments: dict[str, object]) -> _ExecutionResult:
        revision = self._required_string(arguments, "revision")
        commit = self._resolve_commit(revision)
        paths = self._read_paths(arguments.get("paths", []), "git_show")
        metadata = self._executor.run(
            "show_metadata",
            ["show", "-s", "--no-ext-diff", "--no-textconv",
             "--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%B", commit],
        )
        self._require_complete(metadata, "Git show metadata")
        fields = metadata.stdout.split("\x00", 5)
        if len(fields) != 6:
            raise ToolOperationalError("Git show returned malformed metadata")
        argv = [
            "show", "--format=", "--no-ext-diff", "--no-textconv",
            "--no-renames", commit,
        ]
        if paths:
            argv.extend(["--", *paths])
        diff = self._executor.run(
            "show_diff", argv, output_limit=self.git_limits.max_diff_bytes)
        self._require_returncode(diff, "Git show diff")
        return _ExecutionResult({
            "commit": fields[0],
            "parents": fields[1].split() if fields[1] else [],
            "author_name": fields[2],
            "author_email": fields[3],
            "authored_at": fields[4],
            "message": fields[5].rstrip("\n"),
            "diff": diff.stdout,
            "truncated": diff.stdout_truncated,
        })

    def _git_log(self, arguments: dict[str, object]) -> _ExecutionResult:
        count = arguments.get("count", 20)
        if not isinstance(count, int) or isinstance(count, bool):
            raise ToolValidationError("field 'count' must be an integer")
        path_value = arguments.get("path")
        paths: list[str] = []
        if path_value is not None:
            if not isinstance(path_value, str):
                raise ToolValidationError("field 'path' must be a string")
            paths = self._read_paths([path_value], "git_log")
        argv = [
            "log", f"--max-count={count}",
            "--format=%H%x00%P%x00%an%x00%ae%x00%aI%x00%s",
            "-z",
        ]
        if paths:
            argv.extend(["--", *paths])
        result = self._executor.run("log", argv)
        self._require_complete(result, "Git log")
        tokens = result.stdout.split("\x00")
        while tokens and tokens[-1] == "":
            tokens.pop()
        if len(tokens) % 6:
            raise ToolOperationalError("Git log returned malformed entries")
        entries = []
        for index in range(0, len(tokens), 6):
            entries.append({
                "commit": tokens[index],
                "parents": tokens[index + 1].split() if tokens[index + 1] else [],
                "author_name": tokens[index + 2],
                "author_email": tokens[index + 3],
                "authored_at": tokens[index + 4],
                "subject": tokens[index + 5],
            })
        return _ExecutionResult({"entries": entries})

    def _git_unmerged_files(self, arguments: dict[str, object]) -> _ExecutionResult:
        result = self._executor.run("unmerged", ["ls-files", "-u", "-z"])
        self._require_complete(result, "Git unmerged-file inspection")
        return _ExecutionResult({"files": self._parse_unmerged(result.stdout)})

    def _git_submodule_status(self, arguments: dict[str, object]) -> _ExecutionResult:
        paths = self._read_paths(arguments.get("paths", []), "git_submodule_status")
        argv = ["ls-files", "--stage", "-z"]
        if paths:
            argv.extend(["--", *paths])
        result = self._executor.run("submodule_status", argv)
        self._require_complete(result, "Git gitlink inspection")
        gitlinks = []
        for record in result.stdout.split("\x00"):
            if not record:
                continue
            header, separator, path = record.partition("\t")
            parts = header.split()
            if not separator or len(parts) != 3:
                raise ToolOperationalError("Git gitlink inspection returned malformed data")
            if parts[0] == "160000":
                gitlinks.append({
                    "path": path,
                    "recorded_commit": parts[1],
                    "stage": int(parts[2]),
                })
        return _ExecutionResult({"submodules": gitlinks})

    def _git_stage(self, arguments: dict[str, object]) -> _ExecutionResult:
        paths = self._mutation_paths(arguments, "git_stage", allow_missing=True)
        result = self._executor.run("stage", ["add", "--", *paths])
        self._require_returncode(result, "Git stage")
        return _ExecutionResult({"staged": paths}, mutated=True)

    def _git_unstage(self, arguments: dict[str, object]) -> _ExecutionResult:
        paths = self._mutation_paths(arguments, "git_unstage", allow_missing=True)
        result = self._executor.run(
            "unstage", ["restore", "--staged", "--", *paths])
        self._require_returncode(result, "Git unstage")
        return _ExecutionResult({"unstaged": paths}, mutated=True)

    def _git_remove(self, arguments: dict[str, object]) -> _ExecutionResult:
        paths = self._mutation_paths(arguments, "git_remove", allow_missing=True)
        result = self._executor.run("remove", ["rm", "--", *paths])
        self._require_returncode(result, "Git remove")
        return _ExecutionResult({"removed": paths}, mutated=True)

    def _git_restore_conflict(self, arguments: dict[str, object]) -> _ExecutionResult:
        path = self._required_string(arguments, "path")
        side = self._required_string(arguments, "side")
        paths = self._authorize_mutation_paths(
            [path], "git_restore_conflict", allow_missing=True)
        unmerged = {item["path"] for item in self._unmerged_entries()}
        if paths[0] not in unmerged:
            raise ToolPolicyError("path is not currently conflicted")
        # Reauthorize after state inspection and immediately before Git runs.
        paths = self._authorize_mutation_paths(
            paths, "git_restore_conflict", allow_missing=True)
        result = self._executor.run(
            "restore_conflict", ["checkout", f"--{side}", "--", paths[0]])
        self._require_returncode(result, "Git conflict restoration")
        return _ExecutionResult({"path": paths[0], "side": side}, mutated=True)

    def _git_commit(self, arguments: dict[str, object]) -> _ExecutionResult:
        message = build_typed_commit_message(
            self._required_string(arguments, "message"), self._model)
        paths, staged = self._stage_commit_paths(arguments, "git_commit")
        with self._temporary_commit_message(message) as message_path:
            return self._record_commit(
                "commit",
                ["commit", "--only", "--file", str(message_path),
                 "--cleanup=verbatim", "--", *paths],
                paths,
                staged,
                exact_commit_paths=True,
            )

    def _git_amend(self, arguments: dict[str, object]) -> _ExecutionResult:
        mode = self._required_string(arguments, "message_mode")
        message_value = arguments.get("message")
        if mode == "no_edit":
            if message_value is not None:
                raise ToolValidationError(
                    "message is accepted only when message_mode is replace")
            argv = ["commit", "--amend", "--only", "--no-edit", "--"]
            message: Optional[str] = None
        else:
            if not isinstance(message_value, str):
                raise ToolValidationError(
                    "message is required when message_mode is replace")
            message = build_typed_commit_message(message_value, self._model)
            argv = []

        amend_head = self._preflight_amend_scope()
        paths, staged = self._stage_commit_paths(arguments, "git_amend")
        if self._preflight_amend_scope() != amend_head:
            raise GitStateError("HEAD changed while preparing the amend", {})
        if message is None:
            return self._record_commit(
                "amend", [*argv, *paths], paths, staged, exact_commit_paths=False,
                expected_head=amend_head)
        with self._temporary_commit_message(message) as message_path:
            return self._record_commit(
                "amend",
                ["commit", "--amend", "--only", "--file", str(message_path),
                 "--cleanup=verbatim", "--", *paths],
                paths,
                staged,
                exact_commit_paths=False,
                expected_head=amend_head,
            )

    def _git_cherry_pick_start(self, arguments: dict[str, object]) -> _ExecutionResult:
        if any(self._operation_state().values()):
            raise ToolPolicyError("another Git operation is already in progress")
        self._require_clean_cherry_pick_start()
        revision = self._required_string(arguments, "revision")
        commit = self._resolve_commit(revision)
        parents = self._commit_parents(commit)
        if len(parents) > 1:
            raise ToolPolicyError("merge-commit cherry-picks are not supported")
        changed = self._changed_paths(commit)
        if not changed:
            raise ToolPolicyError("empty commits are not supported by cherry-pick start")
        gitlinks = sorted({
            item.path for item in changed
            if item.old_mode == "160000" or item.new_mode == "160000"
        })
        if gitlinks:
            raise GitScopeError("gitlink changes are not supported", gitlinks)
        symlinks = sorted({
            item.path for item in changed
            if item.old_mode == "120000" or item.new_mode == "120000"
        })
        if symlinks:
            raise GitScopeError("symlink changes are not supported", symlinks)
        rejected = self._preflight_changed_paths(changed)
        if rejected:
            raise GitScopeError(
                "cherry-pick would modify paths outside allowed_files", rejected)

        if self._before_operation is not None:
            self._before_operation("git_cherry_pick_start", self.workspace)
        # The immutable commit id, repository state, and all changed paths are
        # rechecked directly before the first mutating command.
        self._require_clean_cherry_pick_start()
        rejected = self._preflight_changed_paths(changed)
        if rejected:
            raise GitScopeError(
                "cherry-pick scope changed before execution", rejected)
        result = self._executor.run(
            "cherry_pick_start", ["cherry-pick", "-x", commit])
        state = self._operation_state()
        if result.returncode == 0:
            return _ExecutionResult({
                "commit": commit,
                "changed_paths": sorted({item.path for item in changed}),
                "conflicted": False,
            }, mutated=True)
        if state["cherry_pick"]:
            return _ExecutionResult({
                "commit": commit,
                "changed_paths": sorted({item.path for item in changed}),
                "conflicted": True,
                "diagnostic": self._diagnostic(result),
            }, mutated=True)
        self._raise_git_failure("Git cherry-pick start", result)

    def _git_cherry_pick_continue(
            self, arguments: dict[str, object]) -> _ExecutionResult:
        self._require_cherry_pick()
        if self._unmerged_entries():
            raise ToolPolicyError("unmerged paths remain")
        staged = self._validate_staged_scope()

        note_value = arguments.get("resolution_note")
        if note_value is not None and not isinstance(note_value, str):
            raise ToolValidationError("field 'resolution_note' must be a string")
        message_path = self._merge_message_path()
        try:
            original_bytes = self._read_git_internal(
                ("MERGE_MSG",), MAX_GIT_MESSAGE_BYTES)
            if original_bytes is None:
                raise ToolOperationalError("Git's cherry-pick message is missing")
            original = original_bytes.decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise ToolOperationalError("unable to read Git's cherry-pick message") from exc
        message = build_cherry_pick_message(original, note_value, self._model)
        self._replace_internal_message(message_path, message)

        try:
            if self._before_operation is not None:
                self._before_operation("git_cherry_pick_continue", self.workspace)
            # This is the final command before Git's commit.  The installed
            # scope hook remains the defense against a hostile external race
            # after this check.
            staged = self._validate_staged_scope()
            before_head = self._current_head()
            result = self._executor.run(
                "cherry_pick_continue", ["cherry-pick", "--continue"])
        except Exception:
            with contextlib.suppress(OSError):
                self._replace_internal_message_bytes(message_path, original_bytes)
            raise
        after_head = self._current_head()
        if result.returncode == 0 or after_head != before_head:
            return _ExecutionResult({
                "commit": after_head,
                "continued": True,
                "staged_paths": staged,
            }, mutated=True)
        if self._operation_state()["cherry_pick"]:
            with contextlib.suppress(OSError):
                self._replace_internal_message_bytes(message_path, original_bytes)
        self._raise_git_failure("Git cherry-pick continue", result)

    def _validate_staged_scope(self) -> list[str]:
        staged = self._staged_paths()
        if not staged:
            raise ToolPolicyError("cherry-pick has no staged changes")
        rejected = self._unauthorized_repository_paths(staged)
        if rejected:
            raise GitScopeError("staged paths are outside allowed_files", rejected)
        expected = {
            item.path for item in self._changed_paths(
                self._resolve_commit("CHERRY_PICK_HEAD"))
        }
        unexpected = sorted(set(staged) - expected)
        if unexpected:
            raise GitScopeError(
                "staged paths were not changed by the active cherry-pick",
                unexpected,
            )
        self._validate_staged_modes(staged)
        return staged

    def _git_cherry_pick_abort(self, arguments: dict[str, object]) -> _ExecutionResult:
        self._require_cherry_pick()
        self._validate_active_cherry_pick_scope()
        if self._before_operation is not None:
            self._before_operation("git_cherry_pick_abort", self.workspace)
        self._validate_active_cherry_pick_scope()
        result = self._executor.run(
            "cherry_pick_abort", ["cherry-pick", "--abort"])
        self._require_returncode(result, "Git cherry-pick abort")
        return _ExecutionResult({
            "aborted": True,
            "head": self._current_head(),
        }, mutated=True)

    def _git_cherry_pick_skip(self, arguments: dict[str, object]) -> _ExecutionResult:
        self._require_cherry_pick()
        if self._has_pending_sequencer_commits():
            raise ToolPolicyError("skip is not allowed for a multi-commit sequence")
        self._validate_active_cherry_pick_scope()
        if self._before_operation is not None:
            self._before_operation("git_cherry_pick_skip", self.workspace)
        self._validate_active_cherry_pick_scope()
        result = self._executor.run(
            "cherry_pick_skip", ["cherry-pick", "--skip"])
        self._require_returncode(result, "Git cherry-pick skip")
        return _ExecutionResult({
            "skipped": True,
            "head": self._current_head(),
        }, mutated=True)

    def _stage_commit_paths(
        self,
        arguments: dict[str, object],
        tool: str,
    ) -> tuple[list[str], list[str]]:
        self._require_idle_commit_state()
        paths = self._mutation_paths(arguments, tool, allow_missing=True)
        self._validate_commit_index(paths, require_changes=False)
        result = self._executor.run("stage", ["add", "--", *paths])
        self._require_returncode(result, "Git commit staging")
        staged = self._validate_commit_index(paths, require_changes=True)
        return paths, staged

    def _require_idle_commit_state(self) -> None:
        operations = self._operation_state()
        active = sorted(name for name, present in operations.items() if present)
        if active:
            raise GitStateError(
                "commit operations require no active Git operation",
                {"operations": active},
            )
        unmerged = self._unmerged_entries()
        if unmerged:
            raise GitStateError(
                "commit operations require a fully resolved index",
                {"paths": [item["path"] for item in unmerged[:MAX_GIT_PATHS]]},
            )

    def _validate_commit_index(
        self,
        paths: Sequence[str],
        *,
        require_changes: bool,
    ) -> list[str]:
        self._require_idle_commit_state()
        staged = self._staged_paths()
        rejected = self._unauthorized_repository_paths(staged)
        if rejected:
            raise GitScopeError("staged paths are outside allowed_files", rejected)
        unexpected = sorted(set(staged) - set(paths))
        if unexpected:
            raise GitScopeError(
                "staged paths were not named by the commit operation",
                unexpected,
            )
        if require_changes and not staged:
            raise GitStateError("commit operation has no staged changes", {})
        self._validate_staged_modes(staged)
        return staged

    def _validate_staged_modes(self, staged: Sequence[str]) -> None:
        if not staged:
            return
        result = self._executor.run(
            "tracked_path", ["ls-files", "--stage", "-z", "--", *staged])
        self._require_complete(result, "Git staged-mode inspection")
        unsupported = []
        for record in result.stdout.split("\x00"):
            if not record:
                continue
            header, separator, path = record.partition("\t")
            parts = header.split()
            if not separator or len(parts) != 3:
                raise ToolOperationalError("Git returned malformed staged-mode data")
            if parts[0] in {"120000", "160000"}:
                unsupported.append(path)
        if unsupported:
            raise GitScopeError(
                "staged symlink or gitlink paths are not supported",
                sorted(set(unsupported)),
            )

    def _record_commit(
        self,
        operation: str,
        argv: Sequence[str],
        paths: Sequence[str],
        staged: Sequence[str],
        *,
        exact_commit_paths: bool,
        expected_head: Optional[str] = None,
    ) -> _ExecutionResult:
        before_head = self._current_head()
        if expected_head is not None and before_head != expected_head:
            raise GitStateError("HEAD changed before the commit operation", {})
        result = self._executor.run(operation, argv)
        after_head = self._current_head()
        if after_head == before_head:
            self._raise_git_failure(f"Git {operation}", result)

        changed = self._changed_paths(after_head)
        changed_paths = sorted({item.path for item in changed})
        unsupported = sorted({
            item.path for item in changed
            if item.old_mode in {"120000", "160000"}
            or item.new_mode in {"120000", "160000"}
        })
        rejected = sorted(
            set(unsupported) | set(self._preflight_changed_paths(changed)))
        if rejected:
            raise GitScopeError(
                "resulting commit reaches unsupported or unauthorized paths",
                rejected,
            )
        if exact_commit_paths:
            expected = set(staged)
            unexpected = sorted(set(changed_paths) - expected)
            missing = sorted(expected - set(changed_paths))
            if unexpected or missing:
                raise GitStateError(
                    "resulting commit does not match the validated staged paths",
                    {"unexpected_paths": unexpected, "missing_paths": missing},
                )
        return _ExecutionResult(
            {
                "commit": after_head,
                "amended": operation == "amend",
                "staged_paths": list(staged),
                "changed_paths": changed_paths,
            },
            mutated=True,
            advances_generation=False,
        )

    def _preflight_amend_scope(self) -> str:
        head = self._current_head()
        if len(self._commit_parents(head)) > 1:
            raise ToolPolicyError("amending merge commits is not supported")
        changed = self._changed_paths(head)
        unsupported = sorted({
            item.path for item in changed
            if item.old_mode in {"120000", "160000"}
            or item.new_mode in {"120000", "160000"}
        })
        rejected = sorted(
            set(unsupported) | set(self._preflight_changed_paths(changed)))
        if rejected:
            raise GitScopeError(
                "current commit reaches unsupported or unauthorized paths",
                rejected,
            )
        return head

    @contextlib.contextmanager
    def _temporary_commit_message(self, message: str) -> Iterator[Path]:
        content = message.encode("utf-8")
        if len(content) > MAX_COMMIT_MESSAGE_BYTES:
            raise ToolValidationError("commit message exceeds its byte limit")
        root_fd = self._open_git_directory()
        name = f".cve-agent-commit-{uuid.uuid4().hex}"
        created = False
        try:
            try:
                fd = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _CLOEXEC | _NOFOLLOW,
                    0o600,
                    dir_fd=root_fd,
                )
                created = True
                try:
                    self._write_all(fd, content)
                    os.fsync(fd)
                    info = os.fstat(fd)
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise ToolPolicyError(
                            "temporary Git message is not a single-link regular file")
                finally:
                    os.close(fd)
            except (ToolOperationalError, ToolPolicyError):
                raise
            except OSError as exc:
                raise ToolOperationalError(
                    "unable to create a trusted Git commit message") from exc
            yield self._git_directory / name
        finally:
            if created:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(name, dir_fd=root_fd)
            os.close(root_fd)

    def _parse_status(self, output: str) -> dict[str, object]:
        branch: dict[str, object] = {}
        staged: list[str] = []
        unstaged: list[str] = []
        untracked: list[str] = []
        deleted: list[str] = []
        conflicted: list[str] = []
        tokens = output.split("\x00")
        index = 0
        while index < len(tokens):
            record = tokens[index]
            index += 1
            if not record:
                continue
            if record.startswith("# "):
                key, _, value = record[2:].partition(" ")
                if key == "branch.oid":
                    branch["oid"] = None if value == "(initial)" else value
                elif key == "branch.head":
                    branch["head"] = None if value == "(detached)" else value
                elif key == "branch.upstream":
                    branch["upstream"] = value
                elif key == "branch.ab":
                    parts = value.split()
                    if len(parts) == 2:
                        branch["ahead"] = int(parts[0][1:])
                        branch["behind"] = int(parts[1][1:])
                continue
            kind = record[0]
            if kind == "?":
                path = record[2:]
                untracked.append(path)
            elif kind == "u":
                parts = record.split(" ", 10)
                if len(parts) != 11:
                    raise ToolOperationalError("Git status returned malformed conflict data")
                path = parts[10]
                conflicted.append(path)
            elif kind in {"1", "2"}:
                parts = record.split(" ", 8 if kind == "1" else 9)
                expected = 9 if kind == "1" else 10
                if len(parts) != expected:
                    raise ToolOperationalError("Git status returned malformed path data")
                xy = parts[1]
                path = parts[-1]
                if kind == "2":
                    if index >= len(tokens):
                        raise ToolOperationalError("Git status rename source is missing")
                    index += 1
                if xy[0] != ".":
                    staged.append(path)
                if xy[1] != ".":
                    unstaged.append(path)
                if "D" in xy:
                    deleted.append(path)
                if "U" in xy or xy in {"AA", "DD"}:
                    conflicted.append(path)
            else:
                raise ToolOperationalError("Git status returned an unknown record")
            total = sum(map(len, (staged, unstaged, untracked, deleted, conflicted)))
            if total > self.git_limits.max_status_paths:
                raise ToolOperationalError("Git status exceeds the configured path limit")
        return {
            "branch": branch,
            "staged": sorted(set(staged)),
            "unstaged": sorted(set(unstaged)),
            "untracked": sorted(set(untracked)),
            "deleted": sorted(set(deleted)),
            "conflicted": sorted(set(conflicted)),
        }

    def _operation_state(self) -> dict[str, bool]:
        return {
            "cherry_pick": (self._git_directory / "CHERRY_PICK_HEAD").is_file(),
            "merge": (self._git_directory / "MERGE_HEAD").is_file(),
            "rebase": (
                (self._git_directory / "rebase-merge").is_dir()
                or (self._git_directory / "rebase-apply").is_dir()
            ),
            "revert": (self._git_directory / "REVERT_HEAD").is_file(),
        }

    def _resolve_commit(self, revision: str) -> str:
        self._validate_revision_token(revision)
        result = self._executor.run(
            "resolve_revision",
            ["rev-parse", "--verify", "--quiet", "--end-of-options",
             f"{revision}^{{commit}}"],
        )
        if result.returncode != 0 or result.stdout_truncated:
            raise ToolPolicyError("revision does not resolve to a commit")
        commit = result.stdout.strip()
        if not commit or any(character not in "0123456789abcdefABCDEF" for character in commit):
            raise ToolOperationalError("Git returned an invalid commit identifier")
        return commit.lower()

    def _resolve_diff_revision(self, revision: str) -> str:
        for separator in ("...", ".."):
            if separator in revision:
                if revision.count(separator) != 1:
                    raise ToolValidationError("revision range is ambiguous")
                left, right = revision.split(separator)
                if not left or not right:
                    raise ToolValidationError("revision range requires two commits")
                return f"{self._resolve_commit(left)}{separator}{self._resolve_commit(right)}"
        return self._resolve_commit(revision)

    def _validate_revision_token(self, revision: str) -> None:
        if not revision:
            raise ToolValidationError("revision must not be empty")
        if len(revision.encode("utf-8")) > self.git_limits.max_revision_bytes:
            raise ToolValidationError("revision exceeds its size limit")
        if revision.startswith("-"):
            raise ToolPolicyError("revision must not start with an option marker")
        if ("\x00" in revision or "\n" in revision or "\r" in revision
                or any(character.isspace() for character in revision)
                or not revision.isprintable()):
            raise ToolPolicyError("revision must be one printable token")
        if revision in {"@{-1}", "@{-2}"} or revision.startswith(":"):
            raise ToolPolicyError("ambiguous revision syntax is not allowed")

    def _read_paths(self, value: object, tool: str) -> list[str]:
        if not isinstance(value, list):
            raise ToolValidationError("field 'paths' must be an array")
        if len(value) > self.git_limits.max_paths:
            raise ToolValidationError("path list exceeds its item limit")
        normalized: list[str] = []
        for raw in value:
            if not isinstance(raw, str):
                raise ToolValidationError("path items must be strings")
            authorized = self._reauthorize(tool, raw, write=False)
            path = authorized.repository_path
            if path is None:
                raise ToolPolicyError("Git paths must be workspace-relative")
            self._reject_pathspec_syntax(path)
            normalized.append(path)
        if len(normalized) != len(set(normalized)):
            raise ToolPolicyError("duplicate paths are not allowed")
        return normalized

    def _mutation_paths(self, arguments: dict[str, object], tool: str,
                        allow_missing: bool) -> list[str]:
        value = arguments.get("paths")
        if not isinstance(value, list):
            raise ToolValidationError("field 'paths' must be an array")
        self._authorize_mutation_paths(value, tool, allow_missing)
        # Repeat the full descriptor-backed check directly before execution.
        return self._authorize_mutation_paths(value, tool, allow_missing)

    def _authorize_mutation_paths(self, value: Sequence[object], tool: str,
                                  allow_missing: bool) -> list[str]:
        if not value:
            raise ToolValidationError("path list must not be empty")
        if len(value) > self.git_limits.max_paths:
            raise ToolValidationError("path list exceeds its item limit")
        paths: list[str] = []
        for raw in value:
            if not isinstance(raw, str):
                raise ToolValidationError("path items must be strings")
            authorized = self._reauthorize(tool, raw, write=True)
            path = authorized.repository_path
            if path is None:
                raise ToolPolicyError("Git mutation path must be repository-relative")
            self._reject_pathspec_syntax(path)
            try:
                file_fd, _ = self.policy.open_regular(authorized)
            except ToolOperationalError as exc:
                if not allow_missing or not self._is_tracked_regular(path):
                    raise ToolPolicyError(
                        "mutation path does not name an exact file") from exc
            else:
                os.close(file_fd)
            paths.append(path)
        if len(paths) != len(set(paths)):
            raise ToolPolicyError("duplicate paths are not allowed")
        return paths

    @staticmethod
    def _reject_pathspec_syntax(path: str) -> None:
        if ("\ufffd" in path or path.startswith(":")
                or any(character in path for character in "*?[]")):
            raise ToolPolicyError("pathspec magic and wildcard syntax are not allowed")

    def _is_tracked_regular(self, path: str) -> bool:
        result = self._executor.run(
            "tracked_path",
            ["ls-files", "--stage", "-z", "--error-unmatch", "--", path])
        if result.returncode != 0 or result.stdout_truncated:
            return False
        records = [record for record in result.stdout.split("\x00") if record]
        if not records:
            return False
        for record in records:
            header, separator, found_path = record.partition("\t")
            parts = header.split()
            if (not separator or len(parts) != 3 or found_path != path
                    or not parts[0].startswith("100")):
                return False
        return True

    def _require_clean_cherry_pick_start(self) -> None:
        result = self._executor.run(
            "status",
            ["status", "--porcelain=v2", "-z", "--branch", "--untracked-files=all"],
        )
        self._require_complete(result, "cherry-pick start status")
        status = self._parse_status(result.stdout)
        dirty = {
            key: status[key]
            for key in ("staged", "unstaged", "deleted", "conflicted")
            if status[key]
        }
        if dirty:
            raise GitStateError(
                "cherry-pick start requires a clean tracked working state",
                dirty,
            )

    def _validate_active_cherry_pick_scope(self) -> None:
        commit = self._resolve_commit("CHERRY_PICK_HEAD")
        changed = self._changed_paths(commit)
        unsupported = sorted({
            item.path for item in changed
            if item.old_mode in {"120000", "160000"}
            or item.new_mode in {"120000", "160000"}
        })
        rejected = sorted(set(unsupported) | set(self._preflight_changed_paths(changed)))
        if rejected:
            raise GitScopeError(
                "active cherry-pick reaches unsupported or unauthorized paths",
                rejected,
            )
        expected = {item.path for item in changed}
        result = self._executor.run(
            "status",
            ["status", "--porcelain=v2", "-z", "--branch", "--untracked-files=all"],
        )
        self._require_complete(result, "active cherry-pick status")
        status = self._parse_status(result.stdout)
        dirty: set[str] = set()
        for key in ("staged", "unstaged", "deleted", "conflicted"):
            paths = status[key]
            if not isinstance(paths, list) or not all(
                    isinstance(path, str) for path in paths):
                raise ToolOperationalError("Git status returned malformed paths")
            dirty.update(paths)
        unexpected = sorted(dirty - expected)
        if unexpected:
            raise GitScopeError(
                "active cherry-pick state includes unrelated tracked paths",
                unexpected,
            )

    def _commit_parents(self, commit: str) -> list[str]:
        result = self._executor.run(
            "commit_parents", ["show", "-s", "--format=%P", commit])
        self._require_complete(result, "Git parent inspection")
        return result.stdout.split()

    def _changed_paths(self, commit: str) -> list[ChangedPath]:
        result = self._executor.run(
            "changed_paths",
            ["diff-tree", "--root", "--no-commit-id", "--raw", "-z", "-r",
             "-M", "-C", "--find-copies-harder", commit],
        )
        self._require_complete(result, "Git changed-path preflight")
        tokens = result.stdout.split("\x00")
        changed: list[ChangedPath] = []
        index = 0
        while index < len(tokens):
            header = tokens[index]
            index += 1
            if not header:
                continue
            parts = header.split()
            if len(parts) != 5 or not parts[0].startswith(":"):
                raise ToolPolicyError("commit contains malformed changed-path metadata")
            old_mode = parts[0][1:]
            new_mode = parts[1]
            status = parts[4]
            path_count = 2 if status[:1] in {"R", "C"} else 1
            if index + path_count > len(tokens):
                raise ToolPolicyError("commit changed-path metadata is incomplete")
            for _ in range(path_count):
                path = tokens[index]
                index += 1
                changed.append(ChangedPath(path, status, old_mode, new_mode))
            if len(changed) > self.git_limits.max_paths:
                raise ToolPolicyError("commit exceeds the changed-path limit")
        return changed

    def _preflight_changed_paths(self, changed: Sequence[ChangedPath]) -> list[str]:
        rejected = []
        for item in changed:
            try:
                self._reject_pathspec_syntax(item.path)
                authorized = self.policy.authorize_write(item.path)
                parent_fd, name = self.policy.open_write_parent(authorized)
                try:
                    try:
                        info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                            raise ToolPolicyError(
                                "changed path is not a regular file")
                finally:
                    os.close(parent_fd)
            except (OSError, ToolOperationalError, ToolPolicyError,
                    ToolValidationError):
                rejected.append(item.path)
        return sorted(set(rejected))

    def _unmerged_entries(self) -> list[dict[str, object]]:
        result = self._executor.run("unmerged", ["ls-files", "-u", "-z"])
        self._require_complete(result, "Git unmerged-file inspection")
        return self._parse_unmerged(result.stdout)

    def _parse_unmerged(self, output: str) -> list[dict[str, object]]:
        grouped: dict[str, list[dict[str, object]]] = {}
        for record in output.split("\x00"):
            if not record:
                continue
            header, separator, path = record.partition("\t")
            parts = header.split()
            if not separator or len(parts) != 3:
                raise ToolOperationalError("Git returned malformed unmerged data")
            grouped.setdefault(path, []).append({
                "mode": parts[0],
                "object": parts[1],
                "stage": int(parts[2]),
            })
            if len(grouped) > self.git_limits.max_status_paths:
                raise ToolOperationalError("unmerged paths exceed the configured limit")
        return [
            {"path": path, "stages": sorted(stages, key=lambda item: str(item["stage"]))}
            for path, stages in sorted(grouped.items())
        ]

    def _staged_paths(self) -> list[str]:
        result = self._executor.run(
            "staged_paths", ["diff", "--cached", "--name-only", "-z", "--diff-filter=ACDMRTUXB"])
        self._require_complete(result, "Git staged-path inspection")
        return [path for path in result.stdout.split("\x00") if path]

    def _unauthorized_repository_paths(self, paths: Sequence[str]) -> list[str]:
        rejected = []
        for path in paths:
            try:
                self.policy.authorize_write(path)
            except (ToolPolicyError, ToolValidationError):
                rejected.append(path)
        return sorted(set(rejected))

    def _require_cherry_pick(self) -> None:
        if not self._operation_state()["cherry_pick"]:
            raise ToolPolicyError("no cherry-pick is in progress")

    def _merge_message_path(self) -> Path:
        path = self._git_directory / "MERGE_MSG"
        try:
            canonical_parent = path.parent.resolve(strict=True)
        except OSError as exc:
            raise ToolOperationalError("Git message directory is unavailable") from exc
        if canonical_parent != self._git_directory:
            raise ToolPolicyError("Git message path escaped its metadata directory")
        return path

    def _replace_internal_message(self, path: Path, message: str) -> None:
        self._replace_internal_message_bytes(path, message.encode("utf-8"))

    def _replace_internal_message_bytes(self, path: Path, content: bytes) -> None:
        if path != self._git_directory / "MERGE_MSG":
            raise ToolPolicyError("Git message path is not trusted")
        if len(content) > MAX_GIT_MESSAGE_BYTES + MAX_RESOLUTION_NOTE_BYTES + 128:
            raise ToolOperationalError("Git message exceeds its size limit")
        root_fd = self._open_git_directory()
        temporary = f".cve-agent-message-{uuid.uuid4().hex}"
        created = False
        try:
            self._validate_git_internal_regular(root_fd, "MERGE_MSG")
            fd = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _CLOEXEC | _NOFOLLOW,
                0o600,
                dir_fd=root_fd,
            )
            created = True
            try:
                view = memoryview(content)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("short Git message write")
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            self._validate_git_internal_regular(root_fd, "MERGE_MSG")
            os.replace(
                temporary, "MERGE_MSG", src_dir_fd=root_fd, dst_dir_fd=root_fd)
            created = False
            os.fsync(root_fd)
        except (ToolOperationalError, ToolPolicyError):
            raise
        except OSError as exc:
            raise ToolOperationalError("unable to replace Git's message safely") from exc
        finally:
            if created:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary, dir_fd=root_fd)
            os.close(root_fd)

    def _has_pending_sequencer_commits(self) -> bool:
        data = self._read_git_internal(
            ("sequencer", "todo"), MAX_GIT_SEQUENCE_BYTES, allow_missing=True)
        if data is None:
            return False
        try:
            lines = data.decode("utf-8").splitlines()
        except UnicodeError as exc:
            raise ToolOperationalError("unable to inspect cherry-pick sequence") from exc
        return any(line.strip() and not line.lstrip().startswith("#") for line in lines)

    def _open_git_directory(self) -> int:
        try:
            descriptor = os.open(
                self._git_directory,
                os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW,
            )
        except OSError as exc:
            raise ToolPolicyError("Git metadata directory is unavailable") from exc
        try:
            info = os.fstat(descriptor)
        except OSError as exc:
            os.close(descriptor)
            raise ToolPolicyError("Git metadata directory is unavailable") from exc
        if (info.st_dev, info.st_ino) != self._git_directory_identity:
            os.close(descriptor)
            raise ToolPolicyError("Git metadata directory changed during the session")
        return descriptor

    @staticmethod
    def _validate_git_internal_regular(parent_fd: int, name: str) -> os.stat_result:
        try:
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise ToolOperationalError("Git metadata file is unavailable") from exc
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_nlink != 1):
            raise ToolPolicyError("Git metadata file must be a single-link regular file")
        return info

    def _read_git_internal(
        self,
        parts: Sequence[str],
        limit: int,
        *,
        allow_missing: bool = False,
    ) -> Optional[bytes]:
        current_fd = self._open_git_directory()
        try:
            for part in parts[:-1]:
                try:
                    next_fd = os.open(
                        part,
                        os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW,
                        dir_fd=current_fd,
                    )
                except FileNotFoundError:
                    if allow_missing:
                        return None
                    raise ToolOperationalError("Git metadata path is unavailable") from None
                except OSError as exc:
                    raise ToolPolicyError("Git metadata path is unsafe") from exc
                os.close(current_fd)
                current_fd = next_fd
            try:
                info = self._validate_git_internal_regular(current_fd, parts[-1])
            except FileNotFoundError:
                if allow_missing:
                    return None
                raise ToolOperationalError("Git metadata file is unavailable") from None
            if info.st_size > limit:
                raise ToolOperationalError("Git metadata file exceeds its size limit")
            try:
                fd = os.open(
                    parts[-1],
                    os.O_RDONLY | _CLOEXEC | _NOFOLLOW | _NONBLOCK,
                    dir_fd=current_fd,
                )
            except OSError as exc:
                raise ToolOperationalError("unable to open Git metadata file") from exc
            try:
                opened = os.fstat(fd)
                if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                        or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)):
                    raise ToolPolicyError("Git metadata file changed during inspection")
                chunks = bytearray()
                while len(chunks) <= limit:
                    chunk = os.read(fd, min(64 * 1024, limit + 1 - len(chunks)))
                    if not chunk:
                        break
                    chunks.extend(chunk)
                if len(chunks) > limit:
                    raise ToolOperationalError("Git metadata file exceeds its size limit")
                return bytes(chunks)
            finally:
                os.close(fd)
        finally:
            os.close(current_fd)

    def _current_head(self) -> str:
        result = self._executor.run(
            "initial_head",
            ["rev-parse", "--verify", "--quiet", "--end-of-options", "HEAD^{commit}"],
        )
        self._require_complete(result, "current HEAD resolution")
        return result.stdout.strip()

    def _require_complete(self, result: GitCommandResult, label: str) -> None:
        if result.stdout_truncated or result.stderr_truncated:
            raise ToolOperationalError(f"{label} exceeded its output limit")
        self._require_returncode(result, label)

    def _require_returncode(self, result: GitCommandResult, label: str) -> None:
        if result.timed_out:
            raise RuntimeTimeoutError(
                f"{label} exceeded its allowed session time")
        if result.returncode != 0:
            self._raise_git_failure(label, result)

    def _raise_git_failure(self, label: str,
                           result: GitCommandResult) -> NoReturn:
        diagnostic = self._diagnostic(result)
        message = f"{label} failed"
        if diagnostic:
            message += f": {diagnostic}"
        raise ToolOperationalError(message)

    def _diagnostic(self, result: GitCommandResult) -> str:
        text = result.stderr or result.stdout
        safe = " ".join(text.split())
        encoded = safe.encode("utf-8")
        if len(encoded) <= self.git_limits.max_diagnostic_bytes:
            return safe
        shortened = encoded[:self.git_limits.max_diagnostic_bytes]
        return shortened.decode("utf-8", "ignore") + "..."
