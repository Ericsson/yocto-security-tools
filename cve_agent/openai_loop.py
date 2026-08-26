# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Bounded multi-turn loop for the native OpenAI-compatible backend."""
import contextlib
import json
import math
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Protocol

from .backend import SessionResult
from .openai_client import (
    AssistantResponse,
    OpenAIAuthenticationError,
    OpenAIClientError,
    OpenAIClientEvent,
    OpenAIConnectionError,
    OpenAIDeadlineExceededError,
    OpenAILocalRequestError,
    OpenAIMalformedJSONError,
    OpenAINonRetryableHTTPError,
    OpenAINotFoundError,
    OpenAIProtocolError,
    OpenAIRateLimitError,
    OpenAIRequestTimeoutError,
    OpenAIResponseSizeError,
    OpenAIRetryableServerError,
)
from .openai_deadline import SessionDeadline
from .openai_progress import ProgressTracker
from .openai_redaction import redact_openai_text
from .openai_tools import ToolResult
from .result import BuildStatus, FailureClass, ResultOutcome, SecurityStatus, WorkflowStatus

DEFAULT_MAX_TOOL_CALLS_PER_RESPONSE = 16
DEFAULT_MAX_CONSECUTIVE_NONPROGRESS = 3
MAX_CONSECUTIVE_NONPROGRESS_LIMIT = 10
MAX_TOOL_ARGUMENT_BYTES = 256 * 1024
MAX_TOOL_ARGUMENT_DEPTH = 32
MAX_TOOL_ARGUMENT_NODES = 20_000
MAX_TRANSCRIPT_EVENT_BYTES = 16 * 1024
MAX_TRANSCRIPT_STRING_CHARS = 4096
MAX_TRANSCRIPT_NODES = 512

_BUILD_RELEVANT_MUTATIONS = frozenset({
    "replace_in_file", "apply_patch_hunks", "write_file", "delete_file",
    "git_restore_conflict", "git_cherry_pick_start", "git_cherry_pick_continue",
    "git_cherry_pick_abort", "git_cherry_pick_skip",
})
_MUTATION_TOOLS = _BUILD_RELEVANT_MUTATIONS | frozenset({
    "git_stage", "git_unstage", "git_remove", "git_commit", "git_amend",
})

_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class ConversationClient(Protocol):
    """One-exchange client surface consumed by the agent loop."""

    def complete(
        self,
        messages: Sequence[dict[str, object]],
        tools: Sequence[dict[str, object]],
    ) -> AssistantResponse:
        """Return one validated assistant response."""


class HostToolRuntime(Protocol):
    """Trusted host runtime surface consumed by the agent loop."""

    @property
    def mutation_generation(self) -> int:
        """Return the current build-relevant mutation generation."""

    @property
    def validated_generation(self) -> Optional[int]:
        """Return the build-validated generation when present."""

    @property
    def terminal_status(self) -> Optional[str]:
        """Return the trusted terminal status when present."""

    def dispatch(self, tool_name: object, arguments: object) -> ToolResult:
        """Validate and execute one typed tool request."""

    def session_result(self) -> SessionResult:
        """Return compatibility state after a trusted terminal result."""


class TranscriptError(RuntimeError):
    """The mandatory native audit transcript is unavailable."""


@dataclass(frozen=True)
class AgentLoopLimits:
    """Independent model-turn, tool-call, and nonprogress bounds."""

    max_model_turns: int
    max_total_tool_calls: int
    max_tool_calls_per_response: int = DEFAULT_MAX_TOOL_CALLS_PER_RESPONSE
    max_consecutive_nonprogress: int = DEFAULT_MAX_CONSECUTIVE_NONPROGRESS

    def __post_init__(self) -> None:
        for name in (
            "max_model_turns", "max_total_tool_calls",
            "max_tool_calls_per_response", "max_consecutive_nonprogress",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_consecutive_nonprogress > MAX_CONSECUTIVE_NONPROGRESS_LIMIT:
            raise ValueError(
                "max_consecutive_nonprogress must not exceed "
                f"{MAX_CONSECUTIVE_NONPROGRESS_LIMIT}")
        if self.max_model_turns > 100:
            raise ValueError("max_model_turns must not exceed 100")
        if self.max_total_tool_calls > 1000:
            raise ValueError("max_total_tool_calls must not exceed 1000")
        if self.max_tool_calls_per_response > 64:
            raise ValueError("max_tool_calls_per_response must not exceed 64")


@dataclass
class AgentLoopSharedState:
    """Trusted counters and evidence retained across provider attempts."""

    progress: ProgressTracker = field(default_factory=ProgressTracker)
    seen_call_ids: set[str] = field(default_factory=set)
    model_turns: int = 0
    tool_calls: int = 0
    mutation_calls: int = 0
    build_calls: int = 0
    provider_retries: int = 0


class JSONLTranscript:
    """Descriptor-anchored, bounded, credential-redacting JSONL audit log."""

    def __init__(
        self,
        path: Path,
        descriptor: int,
        deadline: SessionDeadline,
        started_at: float,
        secrets: Sequence[str] = (),
    ) -> None:
        self.path = path
        self._descriptor = descriptor
        self._deadline = deadline
        self._started_at = started_at
        self._secrets = tuple(secret for secret in secrets if secret)
        self._sequence = 0
        self._closed = False
        self._provider_retries = 0
        self._provider_retry_offset = 0
        self._provider_attempt = "primary"

    @property
    def provider_retries(self) -> int:
        """Return retries observed by this transcript's one shared client."""
        return self._provider_retry_offset + self._provider_retries

    def set_provider_attempt(self, attempt: str, retry_offset: int = 0) -> None:
        if attempt not in {"primary", "fallback"}:
            raise ValueError("invalid provider attempt ID")
        if isinstance(retry_offset, bool) or not isinstance(retry_offset, int) \
                or retry_offset < 0:
            raise ValueError("invalid provider retry offset")
        self._provider_attempt = attempt
        self._provider_retry_offset = retry_offset

    @classmethod
    def create(
        cls,
        agent_root: Path,
        model: str,
        deadline: SessionDeadline,
        secrets: Sequence[str] = (),
        *,
        clock_ns: Callable[[], int] = time.time_ns,
    ) -> "JSONLTranscript":
        """Create one unique mode-0600 transcript below the trusted agent dir."""
        safe_model = _safe_filename_component(redact_openai_text(model, secrets))
        try:
            canonical = agent_root.resolve(strict=True)
            info = canonical.stat()
            if not canonical.is_dir():
                raise OSError("agent transcript root is not a directory")
            root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            root_flags |= getattr(os, "O_CLOEXEC", 0)
            root_flags |= getattr(os, "O_NOFOLLOW", 0)
            root_fd = os.open(canonical, root_flags)
        except (OSError, RuntimeError) as exc:
            raise TranscriptError("unable to open trusted transcript directory") from exc
        try:
            opened = os.fstat(root_fd)
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise TranscriptError("trusted transcript directory changed")
            filename = (
                f"openai-{safe_model}-{os.getpid()}-{clock_ns()}.jsonl"
            )
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor: Optional[int] = None
            try:
                descriptor = os.open(filename, flags, 0o600, dir_fd=root_fd)
                os.fchmod(descriptor, 0o600)
            except OSError as exc:
                if descriptor is not None:
                    with contextlib.suppress(OSError):
                        os.close(descriptor)
                raise TranscriptError("unable to create native transcript") from exc
        finally:
            os.close(root_fd)
        return cls(
            canonical / filename,
            descriptor,
            deadline,
            deadline.clock(),
            secrets,
        )

    def write(self, kind: str, **data: object) -> None:
        """Append and flush one bounded redacted event."""
        if self._closed:
            raise TranscriptError("native transcript is already closed")
        self._sequence += 1
        event: dict[str, object] = {
            "sequence": self._sequence,
            "event": kind,
            "elapsed": max(0.0, self._deadline.clock() - self._started_at),
            "remaining": self._deadline.remaining(),
            "provider_attempt": self._provider_attempt,
        }
        event.update(data)
        safe_event = self._sanitize(event)
        try:
            encoded = (
                json.dumps(
                    safe_event, ensure_ascii=False, separators=(",", ":"),
                    allow_nan=False,
                ) + "\n"
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise TranscriptError("unable to serialize native transcript event") from exc
        if len(encoded) > MAX_TRANSCRIPT_EVENT_BYTES:
            compact = {
                "sequence": self._sequence,
                "event": kind,
                "elapsed": event["elapsed"],
                "remaining": event["remaining"],
                "truncated": True,
            }
            encoded = (
                json.dumps(compact, separators=(",", ":")) + "\n"
            ).encode("utf-8")
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(self._descriptor, view)
                if written <= 0:
                    raise OSError("short transcript write")
                view = view[written:]
        except OSError as exc:
            raise TranscriptError("native transcript write failed") from exc
        # Mirror provider and tool events into the durable per-attempt audit.
        # Loss of that audit is fatal and prevents further privileged work.
        from .artifacts import current_run_artifacts
        artifact_run = current_run_artifacts()
        if artifact_run is not None:
            durable_kind = {
                "model_request": "provider_request_started",
                "assistant_response": "provider_response_received",
                "tool_request": "tool_call_requested",
                "tool_result": "tool_call_completed",
                "terminal_result": "finish_requested",
            }.get(kind, kind)
            artifact_run.event(
                durable_kind,
                provider_event=kind,
                provider_attempt=self._provider_attempt,
                **data,
            )
            if kind == "provider_wait_completed":
                duration = data.get("duration_seconds")
                if (isinstance(duration, (int, float))
                        and not isinstance(duration, bool)
                        and math.isfinite(duration) and duration >= 0):
                    prior = artifact_run.telemetry.durations["provider_wait"] or 0.0
                    artifact_run.telemetry.durations["provider_wait"] = prior + duration
            if kind == "tool_request" and data.get("tool") == "build_recipe":
                artifact_run.event("build_started")
            if kind == "tool_result" and data.get("tool") == "build_recipe":
                build_status = "passed" if data.get("success") is True else "failed"
                artifact_run.atomic_json("build-summary.json", {
                    "schema_version": 1,
                    "status": build_status,
                    "mutation_generation": data.get("mutation_generation"),
                    "validated_generation": data.get("validated_generation"),
                })
                artifact_run.event(
                    "build_completed",
                    status=build_status,
                    mutation_generation=data.get("mutation_generation"),
                    validated_generation=data.get("validated_generation"),
                )
            if kind == "tool_result" and data.get("mutated") is True:
                artifact_run.event(
                    "mutation_committed",
                    tool=data.get("tool"),
                    mutation_generation=data.get("mutation_generation"),
                )
            if kind == "http_failure" and isinstance(data.get("failure"), dict):
                provider_failure = {
                    "schema_version": 1,
                    "status": "failed",
                    "provider_attempt": self._provider_attempt,
                    "failure": data["failure"],
                }
                artifact_run.atomic_json(
                    f"provider-{self._provider_attempt}.json", provider_failure)
                artifact_run.atomic_json("provider-summary.json", provider_failure)
            if kind == "session_end" and data.get("resolved") is True:
                provider_success = {
                    "schema_version": 1,
                    "status": "passed",
                    "provider_attempt": self._provider_attempt,
                    "provider_retries": self.provider_retries,
                }
                artifact_run.atomic_json(
                    f"provider-{self._provider_attempt}.json", provider_success)
                artifact_run.atomic_json("provider-summary.json", provider_success)

    def sync(self) -> None:
        """Durably flush terminal/session boundary events."""
        if self._closed:
            return
        try:
            os.fsync(self._descriptor)
        except OSError as exc:
            raise TranscriptError("native transcript flush failed") from exc

    def close(self) -> None:
        """Close the transcript exactly once."""
        if self._closed:
            return
        self._closed = True
        try:
            os.close(self._descriptor)
        except OSError as exc:
            raise TranscriptError("native transcript close failed") from exc

    def client_event(self, event: OpenAIClientEvent) -> None:
        """Record credential-free transport attempts and retries."""
        kind = "retry" if event.kind == "retry" else f"http_{event.kind}"
        if event.kind == "retry":
            self._provider_retries += 1
        self.write(
            kind,
            attempt=event.attempt,
            status_code=event.status_code,
            delay=event.delay,
            request_id=event.request_id,
            request_features=list(event.request_features),
            failure=(
                event.failure.to_dict() if event.failure is not None else None),
        )

    def runtime_event(self, kind: str, data: Mapping[str, object]) -> None:
        """Record a trusted host-runtime approval event."""
        self.write(kind, **dict(data))

    def _sanitize(self, value: object) -> object:
        stack: list[tuple[object, int]] = [(value, 0)]
        nodes = 0
        while stack:
            current, depth = stack.pop()
            nodes += 1
            if nodes > MAX_TRANSCRIPT_NODES or depth > 8:
                return {"truncated": True}
            if isinstance(current, dict):
                stack.extend((item, depth + 1) for item in current.values())
            elif isinstance(current, (list, tuple)):
                stack.extend((item, depth + 1) for item in current)
        return self._sanitize_value(value, 0)

    def _sanitize_value(self, value: object, depth: int) -> object:
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, float):
            return value if math.isfinite(value) else None
        if isinstance(value, str):
            text = redact_openai_text(value, self._secrets)
            if len(text) > MAX_TRANSCRIPT_STRING_CHARS:
                return text[:MAX_TRANSCRIPT_STRING_CHARS] + "..."
            return text
        if isinstance(value, dict) and depth < 8:
            return {
                str(key)[:128]: self._sanitize_value(item, depth + 1)
                for key, item in list(value.items())[:128]
            }
        if isinstance(value, (list, tuple)) and depth < 8:
            return [
                self._sanitize_value(item, depth + 1)
                for item in list(value)[:128]
            ]
        return "<unsupported>"


class OpenAIAgentLoop:
    """Execute validated assistant calls sequentially under host authority."""

    def __init__(
        self,
        client: ConversationClient,
        runtime: HostToolRuntime,
        transcript: JSONLTranscript,
        deadline: SessionDeadline,
        limits: AgentLoopLimits,
        tool_schemas: Sequence[dict[str, object]],
        system_message: str,
        user_message: str,
        shared_state: AgentLoopSharedState | None = None,
    ) -> None:
        self.client = client
        self.runtime = runtime
        self.transcript = transcript
        self.deadline = deadline
        self.limits = limits
        self.tool_schemas = list(tool_schemas)
        self.messages: list[dict[str, object]] = [
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_message},
        ]
        self._started_at = deadline.clock()
        self._shared = shared_state or AgentLoopSharedState()
        self._turns = self._shared.model_turns
        self._tool_calls = self._shared.tool_calls
        self._seen_call_ids = self._shared.seen_call_ids
        self._progress = self._shared.progress
        self._consecutive_nonprogress = 0
        self._corrective_message_sent = False
        self._state_message_index: Optional[int] = None
        self._mutation_calls = self._shared.mutation_calls
        self._build_calls = self._shared.build_calls

    def run(self, model: str, interactive: bool) -> SessionResult:
        """Run until trusted finish or one independent session bound fires."""
        resolved = False
        reason = "session ended without a verified terminal outcome"
        audit_failed = False
        failure_outcome: Optional[ResultOutcome] = None
        try:
            self.transcript.write(
                "session_start",
                backend="openai",
                model=model,
                interactive=interactive,
                max_model_turns=self.limits.max_model_turns,
                max_total_tool_calls=self.limits.max_total_tool_calls,
                max_tool_calls_per_response=(
                    self.limits.max_tool_calls_per_response),
            )
            resolved, reason = self._run_turns()
        except TranscriptError:
            audit_failed = True
            resolved = False
            reason = (
                "Mandatory native transcript failed; check the Yocto build "
                "workspace permissions.")
        except OpenAIDeadlineExceededError as exc:
            resolved = False
            reason = (
                "Native session deadline exhausted; increase --session-timeout "
                "only after checking the transcript and build log.")
            self._best_effort_event("timeout", reason=reason)
            failure_outcome = _failure_outcome(
                FailureClass.PROVIDER_TIMEOUT, exc.code.value)
        except OpenAIRequestTimeoutError as exc:
            resolved = False
            reason = (
                "Chat Completions request timed out; check the endpoint and "
                "--openai-request-timeout.")
            self._best_effort_event("timeout", reason=reason)
            failure_outcome = _failure_outcome(
                FailureClass.PROVIDER_TIMEOUT, exc.code.value)
        except OpenAIClientError as exc:
            resolved = False
            reason = _user_facing_client_error(exc)
            self._best_effort_event(
                "client_error", error_type=type(exc).__name__, message=reason)
            failure_outcome = _failure_outcome(
                FailureClass.PROVIDER_PROTOCOL, exc.code.value)
        except _NonprogressExhausted:
            resolved = False
            reason = (
                "The model repeatedly made no tool progress; select a model "
                "that reliably supports function tools and inspect the transcript.")
            self._best_effort_event("nonprogress_exhausted", reason=reason)
            failure_outcome = _failure_outcome(
                FailureClass.MODEL_NO_PROGRESS, "model_no_progress")
        except Exception as exc:
            resolved = False
            reason = (
                "Native agent loop failed safely; inspect the transcript for "
                "bounded diagnostics.")
            self._best_effort_event(
                "session_error", error_type=type(exc).__name__, message=reason)
        finally:
            if not audit_failed:
                try:
                    self.transcript.write(
                        "session_end",
                        resolved=resolved,
                        reason=reason,
                        turns=self._turns,
                        tool_calls=self._tool_calls,
                        terminal_status=self.runtime.terminal_status,
                        mutation_generation=self.runtime.mutation_generation,
                        validated_generation=self.runtime.validated_generation,
                    )
                    self.transcript.sync()
                except TranscriptError:
                    resolved = False
                    reason = (
                        "Mandatory native transcript failed; check the Yocto "
                        "build workspace permissions.")
            try:
                self.transcript.close()
            except TranscriptError:
                resolved = False
                reason = (
                    "Mandatory native transcript failed; check the Yocto build "
                    "workspace permissions.")
        duration = max(0.0, self.deadline.clock() - self._started_at)
        self._shared.provider_retries = self.transcript.provider_retries
        if (not resolved and failure_outcome is None
                and ("max-steps" in reason or "max-tool-calls" in reason)):
            failure_outcome = _failure_outcome(
                FailureClass.MODEL_BUDGET, "model_budget_exhausted")
        if not resolved and failure_outcome is None and "truncated" in reason:
            failure_outcome = _failure_outcome(
                FailureClass.PROVIDER_PROTOCOL, "PROVIDER_RESPONSE_TRUNCATED")
        return SessionResult(
            resolved=resolved,
            duration=duration,
            transcript_path=self.transcript.path,
            failure_reason="" if resolved else reason,
            outcome=(self.runtime.session_result().outcome
                     if resolved else failure_outcome),
        )

    def _run_turns(self) -> tuple[bool, str]:
        while self._turns < self.limits.max_model_turns:
            self._require_time("model turn")
            if self._tool_calls >= self.limits.max_total_tool_calls:
                return False, (
                    "Native session reached --openai-max-tool-calls before finish.")
            self._update_state_message()
            self._turns += 1
            self._shared.model_turns = self._turns
            self.transcript.write(
                "model_request",
                turn=self._turns,
                message_count=len(self.messages),
                tool_count=len(self.tool_schemas),
                total_tool_calls=self._tool_calls,
                evidence_digest=self._progress.last_evidence_digest,
                consecutive_nonprogress=self._consecutive_nonprogress,
            )
            provider_started = self.deadline.clock()
            try:
                response = self.client.complete(self.messages, self.tool_schemas)
            finally:
                self.transcript.write(
                    "provider_wait_completed",
                    turn=self._turns,
                    duration_seconds=max(
                        0.0, self.deadline.clock() - provider_started),
                )
            self._append_assistant(response)
            self.transcript.write(
                "assistant_response",
                turn=self._turns,
                content=response.content,
                finish_reason=response.finish_reason,
                tool_calls=[
                    {
                        "id": call.id,
                        "name": call.name,
                        "argument_bytes": len(call.arguments.encode("utf-8")),
                    }
                    for call in response.tool_calls
                ],
            )

            if response.finish_reason in {"length", "content_filter"}:
                if response.finish_reason == "length":
                    return False, (
                        "The model response was truncated; ensure its server-side "
                        "context window can hold the prompt, tool schemas, diffs, "
                        "and diagnostics.")
                return False, (
                    "The endpoint filtered the model response before a tool "
                    "outcome; inspect the transcript and endpoint policy.")
            if response.finish_reason not in {None, "stop", "tool_calls"}:
                return False, (
                    "The endpoint returned an unsupported Chat Completions "
                    "finish_reason; use a compatible non-streaming endpoint."
                )
            if not response.tool_calls:
                stopped = self._handle_text_only_stop()
                if stopped is not None:
                    return False, stopped
                continue
            if len(response.tool_calls) > self.limits.max_tool_calls_per_response:
                return False, (
                    "The model exceeded the per-response tool-call safety limit; "
                    "inspect the transcript and use a model with reliable tool use.")
            if self._tool_calls + len(response.tool_calls) > self.limits.max_total_tool_calls:
                return False, (
                    "Native session reached --openai-max-tool-calls before finish.")
            if any(
                call.name == "finish" and index != len(response.tool_calls) - 1
                for index, call in enumerate(response.tool_calls)
            ):
                self._reject_unsafe_terminal_batch(response)
                self._record_nonprogress()
                continue

            turn_progress = False
            for call in response.tool_calls:
                self._tool_calls += 1
                self._shared.tool_calls = self._tool_calls
                result, dispatched, arguments_key = self._execute_call(call)
                if dispatched and call.name == "build_recipe":
                    self._build_calls += 1
                    self._shared.build_calls = self._build_calls
                if dispatched and call.name in _MUTATION_TOOLS:
                    self._mutation_calls += 1
                    self._shared.mutation_calls = self._mutation_calls
                self._append_tool_result(call.id, result)
                self._write_tool_result(call.id, call.name, result, dispatched)
                event = self._progress.observe(
                    call.name, arguments_key, result, dispatched=dispatched)
                progress_data = event.to_dict()
                progress_data["progress_kind"] = progress_data.pop("kind")
                self.transcript.write(
                    "progress_event", tool=call.name, **progress_data)
                if event.progressed:
                    turn_progress = True
                if result.success and result.terminal:
                    self.transcript.write(
                        "terminal_result",
                        status=self.runtime.terminal_status,
                        mutation_generation=self.runtime.mutation_generation,
                        validated_generation=self.runtime.validated_generation,
                    )
                    self.transcript.sync()
                    verified = self.runtime.session_result().resolved
                    return verified, (
                        "host-verified terminal outcome"
                        if verified else "terminal tool did not map to resolution"
                    )
            if turn_progress:
                self._consecutive_nonprogress = 0
            else:
                self._record_nonprogress()
        return False, "Native session reached --openai-max-steps before finish."

    def _append_assistant(self, response: AssistantResponse) -> None:
        message: dict[str, object] = {
            "role": "assistant",
            "content": response.content,
        }
        if response.tool_calls:
            message["tool_calls"] = [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {
                        "name": call.name,
                        "arguments": call.arguments,
                    },
                }
                for call in response.tool_calls
            ]
        if response.reasoning_replay is not None:
            field, value = response.reasoning_replay
            message[field] = value
        self.messages.append(message)

    def _execute_call(self, call) -> tuple[ToolResult, bool, str]:
        self.transcript.write(
            "tool_request",
            tool_call_id=call.id,
            tool=call.name,
            argument_bytes=len(call.arguments.encode("utf-8")),
        )
        if call.id in self._seen_call_ids:
            return _synthetic_error(
                call.name, "validation", "duplicate or replayed tool-call ID",
                self.runtime.mutation_generation,
            ), False, call.arguments
        self._seen_call_ids.add(call.id)
        try:
            arguments = _decode_tool_arguments(call.arguments)
        except ValueError as exc:
            return _synthetic_error(
                call.name, "validation", str(exc),
                self.runtime.mutation_generation,
            ), False, call.arguments
        key = json.dumps(
            arguments, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        )
        remaining_after_call = self.limits.max_total_tool_calls - self._tool_calls
        reserved_calls = (
            2 if call.name in _BUILD_RELEVANT_MUTATIONS
            else 1 if call.name in _MUTATION_TOOLS else 0
        )
        if reserved_calls and remaining_after_call < reserved_calls:
            return _synthetic_error(
                call.name,
                "policy",
                "late mutation rejected: terminal budget is reserved for "
                + ("build and finish or escalation" if reserved_calls == 2
                   else "finish or escalation"),
                self.runtime.mutation_generation,
            ), False, key
        result = self.runtime.dispatch(call.name, arguments)
        return result, True, key

    def _append_tool_result(self, call_id: str, result: ToolResult) -> None:
        content: dict[str, object] = {
            "success": result.success,
            "mutated": result.mutated,
            "terminal": result.terminal,
            "generation": result.audit.generation,
            "recoverable": _tool_error_recoverable(result),
        }
        if result.success:
            content["data"] = result.payload
        else:
            content["error"] = result.payload
            content["policy_category"] = result.error_kind
        self.messages.append({
            "role": "tool",
            "tool_call_id": call_id,
            "content": json.dumps(
                content, ensure_ascii=False, separators=(",", ":"),
                allow_nan=False,
            ),
        })

    def _write_tool_result(
        self, call_id: str, tool: str, result: ToolResult, dispatched: bool,
    ) -> None:
        error = result.payload.get("error") if not result.success else None
        self.transcript.write(
            "tool_result",
            tool_call_id=call_id,
            tool=tool,
            dispatched=dispatched,
            success=result.success,
            error_kind=result.error_kind,
            error=error,
            recoverable=_tool_error_recoverable(result),
            mutated=result.mutated,
            terminal=result.terminal,
            mutation_generation=result.audit.generation,
            validated_generation=self.runtime.validated_generation,
            payload_keys=sorted(result.payload),
        )

    def _handle_text_only_stop(self) -> Optional[str]:
        if self._corrective_message_sent:
            return (
                "The model stopped twice without calling a typed tool or finish; "
                "select a model that reliably supports function tools.")
        self._corrective_message_sent = True
        correction = (
            "You have not completed a host-verified operation. Call `finish` "
            "with the appropriate status if the work is ready, or call the "
            "next concrete typed inspection, repair, Git, or build tool. Do "
            "not merely describe an operation."
        )
        self.messages.append({"role": "user", "content": correction})
        self.transcript.write("corrective_message", reason="text_only_stop")
        return None

    def _reject_unsafe_terminal_batch(self, response: AssistantResponse) -> None:
        for call in response.tool_calls:
            self._tool_calls += 1
            self._shared.tool_calls = self._tool_calls
            self._seen_call_ids.add(call.id)
            result = _synthetic_error(
                call.name,
                "policy",
                "tool batch was not executed because finish must be the final call",
                self.runtime.mutation_generation,
            )
            self.transcript.write(
                "tool_request",
                tool_call_id=call.id,
                tool=call.name,
                argument_bytes=len(call.arguments.encode("utf-8")),
            )
            self._append_tool_result(call.id, result)
            self._write_tool_result(call.id, call.name, result, False)

    def _record_nonprogress(self) -> None:
        self._consecutive_nonprogress += 1
        remaining = self.limits.max_total_tool_calls - self._tool_calls
        stage = (
            "different_action_required" if self._consecutive_nonprogress > 1
            else "warning")
        warning = {
            "host_no_progress": True,
            "stage": stage,
            "consecutive": self._consecutive_nonprogress,
            "threshold": self.limits.max_consecutive_nonprogress,
            "tool_calls_remaining": max(0, remaining),
            "steps_remaining": max(
                0, self.limits.max_model_turns - self._turns),
            "required": (
                "use a different action class or call finish with a specific "
                "escalation blocker"),
        }
        self.transcript.write("progress_warning", **warning)
        if self._consecutive_nonprogress >= self.limits.max_consecutive_nonprogress:
            raise _NonprogressExhausted

    def _update_state_message(self) -> None:
        summary = self._progress.state_summary(
            mutation_generation=self.runtime.mutation_generation,
            validated_generation=self.runtime.validated_generation,
            consecutive_nonprogress=self._consecutive_nonprogress,
            turns_remaining=self.limits.max_model_turns - self._turns,
            tool_calls_remaining=self.limits.max_total_tool_calls - self._tool_calls,
            mutation_calls=self._mutation_calls,
            build_calls=self._build_calls,
            provider_retries=self.transcript.provider_retries,
            deadline_remaining=self.deadline.remaining(),
        )
        message: dict[str, object] = {"role": "user", "content": summary}
        if self._state_message_index is None:
            self._state_message_index = len(self.messages)
            self.messages.append(message)
        else:
            self.messages[self._state_message_index] = message

    def _require_time(self, operation: str) -> float:
        remaining = self.deadline.remaining()
        if remaining <= 0:
            raise OpenAIDeadlineExceededError(
                f"session deadline exhausted before {operation}")
        return remaining

    def _best_effort_event(self, kind: str, **data: object) -> None:
        with contextlib.suppress(TranscriptError):
            self.transcript.write(kind, **data)


class _NonprogressExhausted(Exception):
    """Internal stable exit for repeated assistant nonprogress."""


def _decode_tool_arguments(value: str) -> dict[str, object]:
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise ValueError("tool arguments are not valid UTF-8") from None
    if len(encoded) > MAX_TOOL_ARGUMENT_BYTES:
        raise ValueError("tool arguments exceed the session byte limit")
    _preflight_json_depth(value)
    try:
        decoded = json.loads(value, parse_constant=_reject_constant)
    except (json.JSONDecodeError, RecursionError, ValueError):
        raise ValueError("tool arguments are not valid strict JSON") from None
    if not isinstance(decoded, dict):
        raise ValueError("tool arguments must decode to an object")
    _validate_argument_tree(decoded)
    return decoded


def _preflight_json_depth(value: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in value:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_TOOL_ARGUMENT_DEPTH:
                raise ValueError("tool arguments exceed the nesting limit")
        elif character in "]}":
            depth -= 1


def _validate_argument_tree(value: object) -> None:
    stack = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_TOOL_ARGUMENT_NODES:
            raise ValueError("tool arguments exceed the node limit")
        if depth > MAX_TOOL_ARGUMENT_DEPTH:
            raise ValueError("tool arguments exceed the nesting limit")
        if current is None or isinstance(current, (str, bool, int)):
            continue
        if isinstance(current, float):
            if not math.isfinite(current):
                raise ValueError("tool arguments contain a non-finite number")
            continue
        if isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
            continue
        if isinstance(current, dict):
            if any(not isinstance(key, str) for key in current):
                raise ValueError("tool argument object keys must be strings")
            stack.extend((item, depth + 1) for item in current.values())
            continue
        raise ValueError("tool arguments contain an unsupported JSON type")


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant: {value}")


def _synthetic_error(
    tool: str, kind: str, message: str, generation: int,
) -> ToolResult:
    from .openai_tools import ToolAudit

    audit = ToolAudit(
        tool=tool,
        success=False,
        mutated=False,
        generation=generation,
        error_kind=kind,
    )
    return ToolResult(
        success=False,
        payload={"error": message},
        mutated=False,
        terminal=False,
        audit=audit,
        error_kind=kind,
    )


def _safe_filename_component(value: str) -> str:
    normalized = _SAFE_FILENAME_RE.sub("-", value).strip(".-")
    return (normalized or "model")[:48]


def _user_facing_client_error(error: OpenAIClientError) -> str:
    """Map transport internals to concise credential-free operator guidance."""
    if isinstance(error, OpenAIAuthenticationError):
        return (
            "Chat Completions authentication failed; set the key in the "
            "environment variable named by --openai-api-key-env or "
            "CVE_AGENT_OPENAI_API_KEY_ENV (default: OPENAI_API_KEY).")
    if isinstance(error, OpenAINotFoundError):
        return (
            "The Chat Completions endpoint or model was not found; check "
            "--openai-base-url for one API root and verify --model or "
            "CVE_AGENT_OPENAI_MODEL.")
    if isinstance(error, OpenAIConnectionError):
        return (
            "Could not connect to the Chat Completions endpoint; check "
            "--openai-base-url and that the server is running.")
    if isinstance(error, (OpenAIMalformedJSONError, OpenAIProtocolError)):
        return (
            "The endpoint returned an incompatible Chat Completions response; "
            "it must return non-streaming JSON with assistant tool_calls and IDs.")
    if isinstance(error, OpenAIResponseSizeError):
        return (
            "The endpoint response exceeded the native safety limit; reduce "
            "endpoint output or model context usage.")
    if isinstance(error, OpenAIRateLimitError):
        return (
            "The endpoint remained rate limited; retry later or inspect its "
            "capacity policy.")
    if isinstance(error, OpenAIRetryableServerError):
        return (
            "The endpoint remained unavailable after bounded retries; inspect "
            "the server and retry later.")
    if isinstance(error, OpenAINonRetryableHTTPError):
        return (
            "The endpoint rejected the Chat Completions request; verify its "
            "portable tools/messages compatibility.")
    if isinstance(error, OpenAILocalRequestError):
        return (
            "The native request exceeded a local safety or schema limit; "
            "inspect the transcript and reduce supplied context.")
    return "The Chat Completions request failed safely; inspect the transcript."


def _tool_error_recoverable(result: ToolResult) -> bool:
    """Tell the model explicitly whether another corrective call is useful."""
    if result.success:
        return False
    return result.error_kind in {"validation", "policy", "approval", "operation"}


def _failure_outcome(failure: FailureClass, code: str) -> ResultOutcome:
    """Create one classified unresolved native-session outcome."""
    return ResultOutcome(
        WorkflowStatus.FAILED,
        BuildStatus.NOT_RUN,
        SecurityStatus.NOT_EVALUATED,
        failure,
        code,
    )
