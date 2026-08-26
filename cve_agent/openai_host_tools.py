# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Build, approval, and terminal host tools for the native backend."""
import contextlib
import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import IO, Optional, Protocol

from shared import TEXT_ENCODING, TEXT_ERRORS

from .backend import SessionResult
from .corrector import validate_recipe_name
from .openai_deadline import RuntimeTimeoutError, SessionDeadline
from .openai_git_tools import (
    MAX_GIT_PATHS,
    NATIVE_TOOL_CONTRACTS,
    GitToolRuntime,
    native_subprocess_environment,
)
from .openai_redaction import redact_openai_text
from .openai_tools import (
    FieldContract,
    FileToolLimits,
    ToolApprovalError,
    ToolContract,
    ToolOperationalError,
    ToolPolicyError,
    ToolValidationError,
    _ExecutionResult,
)
from .result import outcome_for_finish

DEVTOOL_EXECUTABLE = "devtool"
BUILD_LOG_NAME = "openai-build.log"
CONCLUSION_NAME = "conclusion.json"
MAX_BUILD_TAIL_BYTES = 16 * 1024
MAX_BUILD_LOG_BYTES = 16 * 1024 * 1024
MAX_APPROVAL_SUMMARY_CHARS = 512
MAX_TERMINAL_TEXT_BYTES = 2048
BUILD_TERMINATION_GRACE_SECONDS = 1.0

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


class ApprovalDecision(Enum):
    """Closed operator responses to one side-effect request."""

    APPROVE_ONCE = "approve_once"
    APPROVE_CLASS = "approve_class"
    DENY = "deny"
    TIMEOUT = "timeout"


@dataclass(frozen=True)
class ApprovalRequest:
    """Trusted concise description shown to an operator."""

    category: str
    operation: str
    summary: str


class ApprovalProvider(Protocol):
    """Injectable source of interactive approval decisions."""

    def request(self, request: ApprovalRequest,
                timeout: float) -> ApprovalDecision:
        """Return one closed decision before the supplied timeout."""


class ConsoleApprovalProvider:
    """POSIX terminal approval that fails closed on EOF or non-TTY input."""

    def __init__(self, input_stream: IO[str] = sys.stdin,
                 output_stream: IO[str] = sys.stderr) -> None:
        self.input_stream = input_stream
        self.output_stream = output_stream

    def request(self, request: ApprovalRequest,
                timeout: float) -> ApprovalDecision:
        """Prompt once, waiting no longer than the remaining session time."""
        try:
            if not self.input_stream.isatty():
                return ApprovalDecision.DENY
            descriptor = self.input_stream.fileno()
        except (AttributeError, OSError, ValueError):
            return ApprovalDecision.DENY

        self.output_stream.write(
            f"Native side effect [{request.category}] {request.operation}: "
            f"{request.summary}\n"
            "Approve? [y] once / [a] this class / [n] deny: ")
        self.output_stream.flush()
        selector = selectors.DefaultSelector()
        try:
            selector.register(descriptor, selectors.EVENT_READ)
            if not selector.select(timeout):
                return ApprovalDecision.TIMEOUT
            line = self.input_stream.readline()
        except (OSError, ValueError):
            return ApprovalDecision.DENY
        finally:
            selector.close()
        if not line:
            return ApprovalDecision.DENY
        answer = line.strip().lower()
        if answer in {"y", "yes"}:
            return ApprovalDecision.APPROVE_ONCE
        if answer in {"a", "all", "class"}:
            return ApprovalDecision.APPROVE_CLASS
        return ApprovalDecision.DENY


class ApprovalGate:
    """Apply interactive approval and remember approved operation classes."""

    def __init__(self, interactive: bool, deadline: SessionDeadline,
                 provider: Optional[ApprovalProvider] = None,
                 event_sink: Optional[
                     Callable[[str, Mapping[str, object]], None]
                 ] = None) -> None:
        self.interactive = interactive
        self.deadline = deadline
        self.provider = provider or ConsoleApprovalProvider()
        self.event_sink = event_sink
        self._approved_categories: set[str] = set()

    def require(self, category: str, operation: str, summary: str) -> None:
        """Approve one trusted side effect or raise a structured refusal."""
        if not self.interactive or category in self._approved_categories:
            return
        remaining = self.deadline.require("interactive approval")
        request = ApprovalRequest(
            category=category,
            operation=operation,
            summary=_bounded_summary(summary),
        )
        self._emit("approval_request", {
            "category": category,
            "operation": operation,
            "summary": request.summary,
        })
        decision = self.provider.request(request, remaining)
        self._emit("approval_result", {
            "category": category,
            "operation": operation,
            "decision": decision.value,
        })
        if decision is ApprovalDecision.APPROVE_CLASS:
            self._approved_categories.add(category)
            return
        if decision is ApprovalDecision.APPROVE_ONCE:
            return
        if decision is ApprovalDecision.TIMEOUT:
            raise RuntimeTimeoutError(
                f"approval timed out for {operation}")
        raise ToolApprovalError(f"operator denied {operation}")

    def _emit(self, kind: str, data: Mapping[str, object]) -> None:
        if self.event_sink is not None:
            self.event_sink(kind, data)


@dataclass(frozen=True)
class BuildCommandResult:
    """Bounded host result with only a small tail retained in memory."""

    returncode: int
    duration: float
    timed_out: bool
    tail: str
    truncated: bool
    total_output_bytes: int
    log_path: Path
    log_truncated: bool = False

    @property
    def successful(self) -> bool:
        """Return true only for a normal zero exit."""
        return not self.timed_out and self.returncode == 0


class BuildRunner(Protocol):
    """Injectable controlled-build implementation."""

    def run(self, recipe: str) -> BuildCommandResult:
        """Run the fixed build command for one trusted recipe."""


class TrustedAgentDirectory:
    """Descriptor-anchored access to host-owned agent artifacts."""

    def __init__(self, path: Path,
                 before_conclusion_replace: Optional[Callable[[Path], None]] = None) -> None:
        try:
            canonical = path.resolve(strict=True)
            info = canonical.stat()
        except (OSError, RuntimeError) as exc:
            raise ValueError("agent root must be an existing directory") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("agent root must be a directory")
        self.path = canonical
        self._device = info.st_dev
        self._inode = info.st_ino
        self._before_conclusion_replace = before_conclusion_replace

    def open_root(self) -> int:
        """Open and verify the original agent directory without symlinks."""
        try:
            descriptor = os.open(
                self.path, os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW)
        except OSError as exc:
            raise ToolPolicyError("trusted agent directory is unavailable") from exc
        try:
            info = os.fstat(descriptor)
        except OSError as exc:
            os.close(descriptor)
            raise ToolPolicyError("trusted agent directory is unavailable") from exc
        if (info.st_dev, info.st_ino) != (self._device, self._inode):
            os.close(descriptor)
            raise ToolPolicyError("trusted agent directory changed during the session")
        return descriptor

    def open_log(self) -> tuple[IO[bytes], Path]:
        """Atomically replace the fixed build log with a host-owned inode."""
        root_fd = self.open_root()
        temporary = f".cve-build-{uuid.uuid4().hex}"
        log_fd: Optional[int] = None
        try:
            self._reject_symlink_or_nonregular(root_fd, BUILD_LOG_NAME)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _CLOEXEC | _NOFOLLOW
            try:
                log_fd = os.open(temporary, flags, 0o600, dir_fd=root_fd)
            except OSError as exc:
                raise ToolOperationalError("unable to open trusted build log") from exc
            os.fchmod(log_fd, 0o600)
            os.replace(
                temporary, BUILD_LOG_NAME,
                src_dir_fd=root_fd, dst_dir_fd=root_fd)
            os.fsync(root_fd)
            log = os.fdopen(log_fd, "wb", buffering=0)
            log_fd = None
            return log, self.path / BUILD_LOG_NAME
        except (ToolOperationalError, ToolPolicyError):
            raise
        except OSError as exc:
            raise ToolOperationalError("unable to create trusted build log") from exc
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=root_fd)
            if log_fd is not None:
                with contextlib.suppress(OSError):
                    os.close(log_fd)
            os.close(root_fd)

    def write_conclusion(self, payload: Mapping[str, object]) -> Path:
        """Atomically write one trusted orchestrator-compatible conclusion."""
        encoded = (
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")
        root_fd = self.open_root()
        temporary = f".cve-conclusion-{uuid.uuid4().hex}"
        try:
            self._reject_symlink_or_nonregular(root_fd, CONCLUSION_NAME)
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _CLOEXEC | _NOFOLLOW
            temporary_fd = os.open(temporary, flags, 0o600, dir_fd=root_fd)
            try:
                os.fchmod(temporary_fd, 0o600)
                view = memoryview(encoded)
                while view:
                    written = os.write(temporary_fd, view)
                    if written <= 0:
                        raise OSError("short conclusion write")
                    view = view[written:]
                os.fsync(temporary_fd)
            finally:
                os.close(temporary_fd)
            if self._before_conclusion_replace is not None:
                self._before_conclusion_replace(self.path / CONCLUSION_NAME)
            self._reject_symlink_or_nonregular(root_fd, CONCLUSION_NAME)
            os.replace(
                temporary, CONCLUSION_NAME,
                src_dir_fd=root_fd, dst_dir_fd=root_fd)
            os.fsync(root_fd)
        except (ToolOperationalError, ToolPolicyError):
            raise
        except OSError as exc:
            raise ToolOperationalError("atomic conclusion write failed") from exc
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=root_fd)
            os.close(root_fd)
        return self.path / CONCLUSION_NAME

    def clear_conclusion(self) -> bool:
        """Remove a stale regular conclusion without following symlinks."""
        root_fd = self.open_root()
        try:
            try:
                info = os.stat(
                    CONCLUSION_NAME, dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
            if stat.S_ISLNK(info.st_mode):
                raise ToolPolicyError("conclusion path must not be a symlink")
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ToolPolicyError("conclusion path must be a regular file")
            os.unlink(CONCLUSION_NAME, dir_fd=root_fd)
            os.fsync(root_fd)
            return True
        except ToolPolicyError:
            raise
        except OSError as exc:
            raise ToolOperationalError("unable to clear stale conclusion") from exc
        finally:
            os.close(root_fd)

    @staticmethod
    def _reject_symlink_or_nonregular(root_fd: int, name: str) -> None:
        try:
            info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode):
            raise ToolPolicyError("trusted artifact path must not be a symlink")
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ToolPolicyError("trusted artifact path must be a regular file")


class ControlledBuildRunner:
    """Stream one fixed devtool build to a protected bounded local log."""

    def __init__(self, workspace: Path, artifacts: TrustedAgentDirectory,
                 deadline: SessionDeadline,
                 termination_grace: float = BUILD_TERMINATION_GRACE_SECONDS) -> None:
        self.workspace = workspace
        self.artifacts = artifacts
        self.deadline = deadline
        if termination_grace < 0 or termination_grace > BUILD_TERMINATION_GRACE_SECONDS:
            raise ValueError("termination grace is outside its safe bound")
        self.termination_grace = termination_grace

    def run(self, recipe: str) -> BuildCommandResult:
        """Run ``devtool build <recipe>`` under the shared deadline."""
        self.deadline.require("recipe build")
        command = [DEVTOOL_EXECUTABLE, "build", recipe]
        environment = native_subprocess_environment(
            (self.workspace, self.artifacts.path))
        environment["PAGER"] = "cat"
        log, log_path = self.artifacts.open_log()
        started = self.deadline.clock()
        try:
            try:
                process = subprocess.Popen(
                    command,
                    cwd=self.workspace,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    start_new_session=True,
                )
            except OSError as exc:
                raise ToolOperationalError(
                    "unable to start fixed devtool executable") from exc
            return self._collect(
                process, log, log_path, started, self.deadline.remaining())
        finally:
            log.close()

    def _collect(self, process: subprocess.Popen, log: IO[bytes], log_path: Path,
                 started: float, initial_remaining: float) -> BuildCommandResult:
        if process.stdout is None:
            self._kill_group(process, signal.SIGKILL)
            self._reap(process)
            raise ToolOperationalError("devtool output capture was unavailable")
        selector = selectors.DefaultSelector()
        tail = bytearray()
        total = 0
        logged = 0
        timed_out = False
        term_sent_at: Optional[float] = None
        kill_sent = False
        command_end = time.monotonic() + initial_remaining
        try:
            descriptor = process.stdout.fileno()
            os.set_blocking(descriptor, False)
            selector.register(descriptor, selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                now = time.monotonic()
                if not timed_out and now >= command_end:
                    timed_out = True
                    term_sent_at = now
                    self._kill_group(process, signal.SIGTERM)
                if (timed_out and not kill_sent and term_sent_at is not None
                        and now - term_sent_at >= self.termination_grace):
                    self._kill_group(process, signal.SIGKILL)
                    kill_sent = True

                events = selector.select(0.05)
                for key, _ in events:
                    try:
                        chunk = os.read(key.fd, 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fd)
                        continue
                    remaining_log = MAX_BUILD_LOG_BYTES - logged
                    if remaining_log > 0:
                        to_write = chunk[:remaining_log]
                        self._write_all(log, to_write)
                        logged += len(to_write)
                    total += len(chunk)
                    tail.extend(chunk)
                    if len(tail) > MAX_BUILD_TAIL_BYTES:
                        del tail[:-MAX_BUILD_TAIL_BYTES]
                if process.poll() is not None and not events and selector.get_map():
                    continue
        except (OSError, ValueError) as exc:
            raise ToolOperationalError("devtool output capture failed") from exc
        finally:
            if process.poll() is None:
                self._kill_group(process, signal.SIGKILL)
            self._reap(process)
            selector.close()
            with contextlib.suppress(OSError):
                process.stdout.close()
            log.flush()
            os.fsync(log.fileno())
        duration = max(0.0, self.deadline.clock() - started)
        returncode = process.returncode if process.returncode is not None else -signal.SIGKILL
        return BuildCommandResult(
            returncode=returncode,
            duration=duration,
            timed_out=timed_out,
            tail=bytes(tail).decode(TEXT_ENCODING, TEXT_ERRORS),
            truncated=total > MAX_BUILD_TAIL_BYTES,
            total_output_bytes=total,
            log_path=log_path,
            log_truncated=total > logged,
        )

    @staticmethod
    def _write_all(log: IO[bytes], data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = log.write(view)
            if written is None or written <= 0:
                raise OSError("short build log write")
            view = view[written:]

    @staticmethod
    def _kill_group(process: subprocess.Popen, sig: signal.Signals) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, sig)

    @staticmethod
    def _reap(process: subprocess.Popen) -> None:
        if process.poll() is not None:
            process.wait()
            return
        try:
            process.wait(timeout=BUILD_TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            ControlledBuildRunner._kill_group(process, signal.SIGKILL)
            process.wait()


HOST_TOOL_CONTRACTS: dict[str, ToolContract] = {
    "build_recipe": ToolContract(
        "build_recipe",
        "Build the trusted session recipe with fixed host-controlled devtool argv.",
        {},
        "_build_recipe",
    ),
    "finish": ToolContract(
        "finish",
        "Request a host-verified terminal session outcome.",
        {
            "status": FieldContract(
                "string", "Claimed outcome.", required=True,
                enum=("done", "not_applicable", "needs_human")),
            "reason": FieldContract(
                "string", "Bounded plain-text reason.", required=True,
                min_length=1, max_length=MAX_TERMINAL_TEXT_BYTES),
            "summary": FieldContract(
                "string", "Optional bounded completion summary.",
                max_length=MAX_TERMINAL_TEXT_BYTES),
        },
        "_finish",
    ),
}

COMPLETE_TOOL_CONTRACTS: dict[str, ToolContract] = {
    **NATIVE_TOOL_CONTRACTS,
    **HOST_TOOL_CONTRACTS,
}


def complete_openai_tool_schemas() -> list[dict[str, object]]:
    """Return the complete non-HTTP native host tool schema set."""
    return [contract.schema() for contract in COMPLETE_TOOL_CONTRACTS.values()]


class TerminalInvariantError(ToolPolicyError):
    """A requested finish status failed trusted repository checks."""

    def __init__(self, message: str,
                 details: Optional[dict[str, object]] = None) -> None:
        super().__init__(message)
        self.payload = details


class OpenAIHostToolRuntime(GitToolRuntime):
    """Complete native host runtime before the future HTTP/model loop."""

    tool_contracts = COMPLETE_TOOL_CONTRACTS

    def __init__(
        self,
        workspace_root: Path,
        allowed_files: Iterable[str],
        model: str,
        timeout_seconds: int,
        agent_root: Path,
        recipe: Optional[str] = None,
        interactive: bool = False,
        approval_provider: Optional[ApprovalProvider] = None,
        deadline: Optional[SessionDeadline] = None,
        build_runner: Optional[BuildRunner] = None,
        limits: Optional[FileToolLimits] = None,
        before_operation: Optional[Callable[[str, Path], None]] = None,
        before_replace: Optional[Callable[[Path], None]] = None,
        before_conclusion_replace: Optional[Callable[[Path], None]] = None,
        protected_secrets: Iterable[str] = (),
        event_sink: Optional[
            Callable[[str, Mapping[str, object]], None]
        ] = None,
    ) -> None:
        session_deadline = deadline or SessionDeadline.from_timeout(timeout_seconds)
        self._started_at = session_deadline.clock()
        self._event_sink = event_sink
        super().__init__(
            workspace_root,
            allowed_files,
            model,
            timeout_seconds,
            agent_root=agent_root,
            limits=limits,
            before_operation=before_operation,
            before_replace=before_replace,
            deadline=session_deadline,
        )
        resolved_recipe = workspace_root.name if recipe is None else recipe
        if not isinstance(resolved_recipe, str) or not validate_recipe_name(resolved_recipe):
            raise ValueError("trusted recipe name is invalid")
        self.recipe = resolved_recipe
        self.artifacts = TrustedAgentDirectory(
            agent_root, before_conclusion_replace=before_conclusion_replace)
        self.artifacts.clear_conclusion()
        self.approvals = ApprovalGate(
            interactive, self.deadline, approval_provider, event_sink)
        self._build_runner = build_runner or ControlledBuildRunner(
            self.workspace, self.artifacts, self.deadline)
        secrets = tuple(protected_secrets)
        if any(not isinstance(secret, str) for secret in secrets):
            raise ValueError("protected secrets must be strings")
        self._protected_secrets = tuple(secret for secret in secrets if secret)
        self._validated_generation: Optional[int] = None
        self._terminal_status: Optional[str] = None
        self._terminal_reason = ""
        self._terminal_summary = ""
        self._conclusion_written = False
        self._persist_trusted_git_state()

    @property
    def validated_generation(self) -> Optional[int]:
        """Return the mutation generation of the latest successful build."""
        return self._validated_generation

    @property
    def terminal_status(self) -> Optional[str]:
        """Return the accepted finish status, if any."""
        return self._terminal_status

    def session_result(self) -> SessionResult:
        """Map the trusted terminal state to the existing backend contract."""
        duration = max(0.0, self.deadline.clock() - self._started_at)
        return SessionResult(
            resolved=self._terminal_status is not None,
            duration=duration,
            outcome=(outcome_for_finish(self._terminal_status)
                     if self._terminal_status is not None else None),
        )

    def _check_runtime_available(self, tool: str, arguments: object) -> None:
        self.deadline.require("tool dispatch")
        if self._terminal_status is not None:
            raise ToolPolicyError("session already has a terminal outcome")

    def _authorize_tool_call(self, tool: str,
                             arguments: Mapping[str, object]) -> None:
        if self._arguments_contain_protected_secret(arguments):
            raise ToolPolicyError("tool arguments contain a protected credential")
        if tool in {
            "replace_in_file", "apply_patch_hunks", "write_file", "delete_file",
        }:
            self.approvals.require(
                "file_mutation", tool, self._file_approval_summary(tool, arguments))
        elif tool in {
            "git_stage", "git_unstage", "git_remove", "git_restore_conflict",
            "git_commit", "git_amend",
            "git_cherry_pick_start", "git_cherry_pick_continue",
            "git_cherry_pick_abort", "git_cherry_pick_skip",
        }:
            self.approvals.require(
                "git_mutation", tool, self._git_approval_summary(tool, arguments))
        elif tool == "build_recipe":
            self.approvals.require(
                "build", tool, f"devtool build {self.recipe}")
        # finish approval occurs only after its trusted state checks pass.

    def _arguments_contain_protected_secret(
            self, arguments: Mapping[str, object]) -> bool:
        if not self._protected_secrets:
            return False
        stack = list(arguments.values())
        while stack:
            value = stack.pop()
            if isinstance(value, str) and any(
                    secret in value for secret in self._protected_secrets):
                return True
            if isinstance(value, dict):
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
        return False

    def _file_approval_summary(self, tool: str,
                               arguments: Mapping[str, object]) -> str:
        path = self._required_string(dict(arguments), "path")
        normalized = self.policy.authorize_write(path).repository_path or "<invalid>"
        displayed_path = self._escape_audit_value(normalized)
        if tool == "replace_in_file":
            old_text = self._required_string(dict(arguments), "old_text")
            new_text = self._required_string(dict(arguments), "new_text")
            count = arguments.get("expected_count")
            return (
                f"replace {displayed_path}: old={len(old_text.encode('utf-8'))} bytes, "
                f"new={len(new_text.encode('utf-8'))} bytes, expected={count}"
            )
        if tool == "apply_patch_hunks":
            plan = self._prepare_patch_hunks(arguments)
            return (
                f"patch {displayed_path}: {plan.old_sha256} -> "
                f"{plan.new_sha256}, hunks={plan.hunks_applied}, "
                f"+{plan.lines_added}/-{plan.lines_removed}\n"
                f"{plan.diff_excerpt}"
            )
        if tool == "write_file":
            content = self._required_string(dict(arguments), "content")
            mode = self._required_string(dict(arguments), "mode")
            return (
                f"write {displayed_path}: {mode}, "
                f"{len(content.encode('utf-8'))} bytes"
            )
        return f"delete {displayed_path}"

    def _git_approval_summary(self, tool: str,
                              arguments: Mapping[str, object]) -> str:
        revision = arguments.get("revision")
        if isinstance(revision, str):
            self._validate_revision_token(revision)
            return f"{tool} revision {self._escape_audit_value(revision)}"
        paths_value = arguments.get("paths")
        if isinstance(paths_value, list):
            normalized = [
                self.policy.authorize_write(path).repository_path
                for path in paths_value if isinstance(path, str)
            ]
            displayed = [
                self._escape_audit_value(path) for path in normalized if path
            ]
            return f"{tool} exact paths: {', '.join(displayed)}"
        path = arguments.get("path")
        if isinstance(path, str):
            normalized_path = self.policy.authorize_write(path).repository_path
            side = arguments.get("side")
            displayed_path = self._escape_audit_value(normalized_path or "<invalid>")
            return f"{tool} {side}: {displayed_path}"
        return tool.replace("_", " ")

    def _build_recipe(self, arguments: dict[str, object]) -> _ExecutionResult:
        result = self._build_runner.run(self.recipe)
        payload: dict[str, object] = {
            "exit_status": result.returncode,
            "duration": result.duration,
            "timed_out": result.timed_out,
            "tail": result.tail,
            "truncated": result.truncated,
            "total_output_bytes": result.total_output_bytes,
            "log_path": str(result.log_path),
            "log_truncated": result.log_truncated,
            "generation": self.mutation_generation,
        }
        if result.timed_out:
            raise RuntimeTimeoutError("recipe build exceeded the session deadline", payload)
        if result.returncode != 0:
            error = ToolOperationalError("recipe build failed")
            error.payload = payload
            raise error
        self._validated_generation = self.mutation_generation
        self.trusted_git_state.built_generation = self._validated_generation
        self._persist_trusted_git_state()
        payload["validated_generation"] = self._validated_generation
        return _ExecutionResult(payload)

    def _after_successful_execution(
        self, tool: str, execution: _ExecutionResult,
    ) -> None:
        super()._after_successful_execution(tool, execution)
        transition = execution.payload.get("trusted_transition")
        if isinstance(transition, dict) and self._event_sink is not None:
            self._event_sink("trusted_git_transition", transition)
        if isinstance(transition, dict):
            self._persist_trusted_git_state()

    def _persist_trusted_git_state(self) -> None:
        from .artifacts import current_run_artifacts
        artifact_run = current_run_artifacts()
        if artifact_run is not None:
            artifact_run.atomic_json(
                "trusted-git-state.json", self.trusted_git_state.to_dict())

    def _finish(self, arguments: dict[str, object]) -> _ExecutionResult:
        status_value = self._required_string(arguments, "status")
        reason = self._terminal_text(
            self._required_string(arguments, "reason"), "reason")
        summary_value = arguments.get("summary", "")
        if not isinstance(summary_value, str):
            raise ToolValidationError("field 'summary' must be a string")
        summary = self._terminal_text(summary_value, "summary", allow_empty=True)
        if status_value != "done" and summary:
            raise ToolValidationError("summary is accepted only for done")

        self._verify_finish(status_value)
        self.approvals.require(
            "terminal", "finish", f"{status_value}: {reason}")
        self.deadline.require("terminal outcome creation")
        self._verify_finish(status_value)

        conclusion_path: Optional[Path] = None
        if status_value == "done":
            self.artifacts.clear_conclusion()
        elif status_value == "not_applicable":
            conclusion_path = self.artifacts.write_conclusion({
                "not_applicable": True,
                "reason": reason,
            })
        else:
            conclusion_path = self.artifacts.write_conclusion({
                "needs_human": True,
                "reason": reason,
            })

        self._terminal_status = status_value
        self._terminal_reason = reason
        self._terminal_summary = summary
        self._conclusion_written = conclusion_path is not None
        payload: dict[str, object] = {
            "status": status_value,
            "reason": reason,
        }
        if summary:
            payload["summary"] = summary
        if conclusion_path is not None:
            payload["conclusion_path"] = str(conclusion_path)
        return _ExecutionResult(payload, terminal=True)

    def discard_terminal_artifacts(self) -> None:
        """Remove a conclusion if the enclosing audited session did not resolve."""
        if getattr(self, "_conclusion_written", False):
            self.artifacts.clear_conclusion()
            self._conclusion_written = False

    def validate_fallback_state(self) -> dict[str, object]:
        """Validate and summarize the unchanged authority boundary for fallback."""
        self.deadline.require("provider fallback state validation")
        current_head = self._require_current_trusted_head()
        current_tree = self._commit_tree(current_head)
        if current_tree != self.trusted_git_state.trusted_tree:
            raise ToolPolicyError("trusted tree changed outside typed Git operations")
        operations = self._operation_state()
        if any(operations[name] for name in ("merge", "rebase", "revert")):
            raise ToolPolicyError("unsupported Git operation prevents provider fallback")
        status_result = self._executor.run(
            "status",
            ["status", "--porcelain=v2", "-z", "--branch", "--untracked-files=all"],
        )
        self._require_complete(status_result, "provider fallback status")
        status = self._parse_status(status_result.stdout)
        dirty_paths: set[str] = set()
        for name in ("staged", "unstaged", "untracked", "deleted", "conflicted"):
            values = status.get(name)
            if not isinstance(values, list):
                raise ToolOperationalError("provider fallback status is malformed")
            dirty_paths.update(value for value in values if isinstance(value, str))
        rejected = sorted(dirty_paths - set(self.policy.allowed_files))
        if rejected:
            raise ToolPolicyError(
                "out-of-scope dirty paths prevent provider fallback")
        conflicts = status["conflicted"]
        if not isinstance(conflicts, list):
            raise ToolOperationalError("provider fallback conflicts are malformed")
        return {
            "trusted_head": current_head,
            "trusted_tree": current_tree,
            "allowed_path_digest": self.trusted_git_state.allowed_path_digest,
            "handoff_digest": self.trusted_git_state.handoff_digest,
            "mutation_generation": self.mutation_generation,
            "validated_generation": self.validated_generation,
            "dirty_allowed_path_count": len(dirty_paths),
            "unresolved_conflict_count": len(conflicts),
            "cherry_pick_active": operations["cherry_pick"],
        }

    def _verify_finish(self, status_value: str) -> None:
        self.deadline.require("finish verification")
        operations = self._operation_state()
        active = sorted(name for name, present in operations.items() if present)
        if active:
            raise TerminalInvariantError(
                "Git operation remains in progress", {"operations": active})
        unmerged = self._unmerged_entries()
        if unmerged:
            raise TerminalInvariantError(
                "unmerged files remain", {
                    "paths": [entry["path"] for entry in unmerged[:MAX_GIT_PATHS]],
                })
        if status_value == "done":
            self._verify_done()
        else:
            self._verify_non_code_outcome()

    def _verify_done(self) -> None:
        if self._validated_generation is None:
            raise TerminalInvariantError("no successful recipe build is recorded")
        if self._validated_generation != self.mutation_generation:
            raise TerminalInvariantError(
                "successful build predates the latest mutation", {
                    "validated_generation": self._validated_generation,
                    "current_generation": self.mutation_generation,
                })
        current_head = self._current_head()
        trusted = self.trusted_git_state
        if current_head != trusted.trusted_head:
            raise TerminalInvariantError(
                "current HEAD was not produced by a typed trusted Git operation",
                {
                    "trusted_head": trusted.trusted_head,
                    "current_head": current_head,
                },
            )
        current_tree = self._commit_tree(current_head)
        if current_tree != trusted.trusted_tree:
            raise TerminalInvariantError(
                "current commit tree differs from trusted Git state")
        changed = self._changed_paths_between(
            trusted.session_root_head, current_head)
        unsupported = sorted({
            item.path for item in changed
            if item.old_mode in {"120000", "160000"}
            or item.new_mode in {"120000", "160000"}
        })
        rejected = sorted(
            set(unsupported) | set(self._preflight_changed_paths(changed)))
        if rejected:
            raise TerminalInvariantError(
                "durable changed paths are outside allowed_files", {
                    "rejected_paths": rejected[:MAX_GIT_PATHS],
                })
        self._require_clean_worktree()

    def _verify_non_code_outcome(self) -> None:
        current_head = self._current_head()
        if current_head != self.trusted_git_state.session_root_head:
            raise TerminalInvariantError(
                "non-code outcome requires the session baseline HEAD", {
                    "expected_head": self.trusted_git_state.session_root_head,
                    "current_head": current_head,
                })
        self._require_clean_worktree()

    def _require_clean_worktree(self) -> None:
        result = self._executor.run(
            "status",
            ["status", "--porcelain=v2", "-z", "--branch", "--untracked-files=all"],
        )
        self._require_complete(result, "terminal Git status")
        status = self._parse_status(result.stdout)
        dirty = {
            key: status[key]
            for key in ("staged", "unstaged", "untracked", "deleted", "conflicted")
            if status[key]
        }
        if dirty:
            raise TerminalInvariantError(
                "terminal outcome requires a clean staged and working state", dirty)

    def _terminal_text(self, value: str, label: str,
                       allow_empty: bool = False) -> str:
        if "\x00" in value or any(
                ord(character) < 32 and character not in "\n\r\t"
                for character in value):
            raise ToolValidationError(f"{label} must be plain text")
        if len(value.encode("utf-8")) > MAX_TERMINAL_TEXT_BYTES:
            raise ToolValidationError(f"{label} exceeds its byte limit")
        normalized = " ".join(
            redact_openai_text(value, self._protected_secrets).split())
        if not normalized and not allow_empty:
            raise ToolValidationError(f"{label} must not be empty")
        return normalized


def _bounded_summary(value: str) -> str:
    normalized = " ".join(value.split())
    if len(normalized) <= MAX_APPROVAL_SUMMARY_CHARS:
        return normalized
    return normalized[:MAX_APPROVAL_SUMMARY_CHARS - 3] + "..."
