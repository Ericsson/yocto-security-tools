# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Durable, bounded, redacted artifacts for every CVE agent attempt."""
from __future__ import annotations

import contextlib
import contextvars
import hashlib
import json
import os
import re
import stat
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Callable

from shared.paths import data_dir

from .openai_redaction import redact_openai_text

ARTIFACT_SCHEMA_VERSION = 1
TRANSCRIPT_SCHEMA_VERSION = 1
MAX_ARTIFACT_STRING_BYTES = 4096
MAX_ARTIFACT_NODES = 1024
MAX_ERROR_BYTES = 1024
MAX_HUMAN_REPORT_BYTES = 64 * 1024
MAX_ARTIFACT_MANIFEST_BYTES = 256 * 1024
MAX_ARTIFACT_MANIFEST_ENTRIES = 256
MAX_VERIFIED_ARTIFACT_BYTES = 64 * 1024 * 1024
_SAFE_ID_RE = re.compile(r"[^A-Za-z0-9._-]+")
_CURRENT_RUN: contextvars.ContextVar[RunArtifacts | None] = contextvars.ContextVar(
    "cve_agent_current_artifact_run", default=None)


class ArtifactError(RuntimeError):
    """A mandatory durable audit artifact could not be maintained."""


def verify_artifact_manifest(
    directory: Path,
    required_names: Sequence[str] = (),
) -> bool:
    """Verify one complete, bounded, single-directory artifact manifest."""
    manifest_name = "artifact-manifest.sha256"
    manifest = _read_regular_file(
        directory / manifest_name, MAX_ARTIFACT_MANIFEST_BYTES)
    if manifest is None:
        return False
    try:
        lines = manifest.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError:
        return False
    if not lines or len(lines) > MAX_ARTIFACT_MANIFEST_ENTRIES:
        return False

    expected: dict[str, str] = {}
    for line in lines:
        digest, separator, name = line.partition("  ")
        if (not separator or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
                or not _safe_artifact_name(name) or name in expected):
            return False
        expected[name] = digest

    if any(not _safe_artifact_name(name) for name in required_names):
        return False
    if not set(required_names) <= set(expected):
        return False
    try:
        children = list(directory.iterdir())
    except OSError:
        return False
    actual = {child.name for child in children if child.name != manifest_name}
    if actual != set(expected):
        return False
    for name, digest in expected.items():
        content = _read_regular_file(
            directory / name, MAX_VERIFIED_ARTIFACT_BYTES)
        if content is None or hashlib.sha256(content).hexdigest() != digest:
            return False
    return True


def _safe_artifact_name(name: str) -> bool:
    return bool(
        name
        and name not in {".", "..", "artifact-manifest.sha256"}
        and "/" not in name
        and "\\" not in name
        and "\x00" not in name
        and name.isascii()
        and len(name) <= 255
    )


def _read_regular_file(path: Path, maximum_bytes: int) -> bytes | None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > maximum_bytes):
            return None
        chunks = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        if (len(content) != before.st_size
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns):
            return None
        return content
    except OSError:
        return None
    finally:
        os.close(descriptor)


@dataclass
class Telemetry:
    """Versioned counters and durations; unknown provider values remain null."""

    durations: dict[str, float | None] = field(default_factory=lambda: {
        name: 0.0 for name in (
            "corrector_setup", "preflight", "provider_wait", "tool_execution",
            "build", "ptest", "patch_transfer", "cleanup", "total",
        )
    })
    counters: dict[str, int] = field(default_factory=lambda: {
        name: 0 for name in (
            "model_turns", "tool_calls", "read_calls", "mutation_calls",
            "build_calls", "duplicate_call_count", "provider_retries",
        )
    })
    input_tokens: int | None = None
    output_tokens: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": ARTIFACT_SCHEMA_VERSION,
            "durations_seconds": dict(self.durations),
            "counters": dict(self.counters),
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        }


class RunArtifacts:
    """Own one unique result directory and its mandatory JSONL transcript."""

    def __init__(
        self,
        path: Path,
        run_id: str,
        cve_id: str,
        backend: str,
        profile: str | None,
        model: str,
        transcript: IO[bytes],
        *,
        wall_clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        secrets: tuple[str, ...] = (),
    ) -> None:
        self.path = path
        self.run_id = run_id
        self.cve_id = cve_id
        self.backend = backend
        self.profile = profile
        self.model = model
        self.transcript_path = path / "agent-transcript.jsonl"
        self._transcript = transcript
        self._wall_clock = wall_clock or (lambda: datetime.now(timezone.utc))
        self._monotonic = monotonic
        self._started = monotonic()
        self._sequence = 0
        self._closed = False
        self._secrets = tuple(secret for secret in secrets if secret)
        self._provider_finalized = False
        self._build_finalized = False
        self.telemetry = Telemetry()

    @classmethod
    def create(
        cls,
        cve_id: str,
        backend: str,
        profile: str | None,
        model: str,
        *,
        root: Path | None = None,
        secrets: tuple[str, ...] = (),
    ) -> RunArtifacts:
        """Create the restrictive result directory before repository access."""
        safe_cve = _safe_component(cve_id)
        base = root or data_dir() / "results" / "cases"
        try:
            base.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(base, 0o700)
            case_root = base / safe_cve
            case_root.mkdir(mode=0o700)
        except FileExistsError:
            os.chmod(case_root, 0o700)
        except OSError as error:
            raise ArtifactError("unable to create durable result root") from error
        run_id = (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            + f"-{os.getpid()}-{uuid.uuid4().hex[:12]}"
        )
        path = case_root / run_id
        try:
            path.mkdir(mode=0o700)
            descriptor = os.open(
                path / "agent-transcript.jsonl",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            os.fchmod(descriptor, 0o600)
            transcript = os.fdopen(descriptor, "wb", buffering=0)
        except OSError as error:
            raise ArtifactError("unable to create mandatory durable transcript") from error
        run = cls(
            path, run_id, cve_id, backend, profile, model, transcript,
            secrets=secrets,
        )
        try:
            run._initialize()
        except BaseException:
            with contextlib.suppress(OSError):
                transcript.close()
            raise
        return run

    def _initialize(self) -> None:
        manifest = {
            "schema_version": ARTIFACT_SCHEMA_VERSION,
            "run_id": self.run_id,
            "cve_id": self.cve_id,
            "backend": self.backend,
            "backend_profile": self.profile,
            "model": self.model,
            "created_at": self._wall_clock().isoformat(),
        }
        self.atomic_json("run-manifest.json", manifest)
        self.atomic_json("preflight.json", {"schema_version": 1, "status": "pending"})
        self.atomic_json("provider-summary.json", {"schema_version": 1, "status": "pending"})
        self.atomic_json("build-summary.json", {"schema_version": 1, "status": "not_run"})
        self.atomic_json("result.json", {"schema_version": 2, "status": "running"})
        self.event(
            "run_started",
            backend=self.backend,
            backend_profile=self.profile,
            model=self.model,
        )
        self.event("configuration_resolved", backend=self.backend, model=self.model)

    def activate(self) -> contextvars.Token[RunArtifacts | None]:
        return _CURRENT_RUN.set(self)

    @staticmethod
    def deactivate(token: contextvars.Token[RunArtifacts | None]) -> None:
        _CURRENT_RUN.reset(token)

    def add_secret(self, secret: str) -> None:
        if secret and secret not in self._secrets:
            self._secrets += (secret,)

    def event(self, kind: str, **fields: object) -> None:
        """Append one independently parseable, flushed, redacted event."""
        if self._closed:
            raise ArtifactError("durable transcript is closed")
        self._sequence += 1
        event = {
            "schema_version": TRANSCRIPT_SCHEMA_VERSION,
            "sequence": self._sequence,
            "timestamp": self._wall_clock().isoformat(),
            "elapsed_seconds": max(0.0, self._monotonic() - self._started),
            "attempt": 1,
            "event": kind,
            **fields,
        }
        safe = _sanitize(event, self._secrets)
        try:
            encoded = (json.dumps(
                safe, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
            ) + "\n").encode("utf-8")
            self._transcript.write(encoded)
            self._transcript.flush()
            if kind in {
                "mutation_committed", "build_completed", "finish_requested",
                "run_failed", "result_finalized", "cleanup_completed",
            }:
                os.fsync(self._transcript.fileno())
        except (OSError, TypeError, ValueError, UnicodeError) as error:
            raise ArtifactError("mandatory durable transcript write failed") from error
        self._account(kind, fields)

    def _account(self, kind: str, fields: Mapping[str, object]) -> None:
        counters = self.telemetry.counters
        if kind in {"model_request", "provider_request_started"}:
            counters["model_turns"] += 1
        if kind in {"tool_call", "tool_call_requested"}:
            counters["tool_calls"] += 1
            tool = fields.get("tool") or fields.get("name")
            if isinstance(tool, str):
                if tool.startswith("read") or tool in {"git_status", "git_diff"}:
                    counters["read_calls"] += 1
                if tool in {
                    "replace_in_file", "apply_patch_hunks", "write_file",
                    "delete_file", "git_commit", "git_amend",
                    "git_cherry_pick_start", "git_cherry_pick_continue",
                }:
                    counters["mutation_calls"] += 1
                if tool == "build_recipe":
                    counters["build_calls"] += 1
        if kind in {"retry", "http_retry"}:
            counters["provider_retries"] += 1
        if kind == "progress_warning":
            counters["duplicate_call_count"] += 1

    def atomic_json(self, name: str, value: object) -> None:
        """Write bounded structured JSON via mode-0600 atomic replacement."""
        target = self.path / name
        temporary = self.path / f".{name}.{uuid.uuid4().hex}.tmp"
        safe = _sanitize(value, self._secrets)
        try:
            encoded = (json.dumps(
                safe, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False,
            ) + "\n").encode("utf-8")
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    output.write(encoded)
                    output.flush()
                    os.fsync(output.fileno())
            except BaseException:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
                raise
            os.replace(temporary, target)
            if isinstance(value, Mapping):
                status = value.get("status")
                if name == "provider-summary.json" and status != "pending":
                    self._provider_finalized = True
                if name == "build-summary.json" and status not in {"pending", "not_run"}:
                    self._build_finalized = True
        except (OSError, TypeError, ValueError, UnicodeError) as error:
            with contextlib.suppress(OSError):
                temporary.unlink()
            raise ArtifactError(f"unable to finalize artifact {name}") from error

    def atomic_text(self, name: str, value: str) -> None:
        """Write one bounded redacted human-readable mode-0600 artifact."""
        if (not isinstance(value, str) or "/" in name or "\\" in name
                or name in {"", ".", ".."}):
            raise ArtifactError("invalid text artifact")
        redacted = redact_openai_text(value, self._secrets)
        try:
            encoded = redacted.encode("utf-8", errors="strict")
        except UnicodeError as error:
            raise ArtifactError("unable to encode text artifact") from error
        if len(encoded) > MAX_HUMAN_REPORT_BYTES:
            raise ArtifactError("text artifact exceeds its size limit")
        target = self.path / name
        temporary = self.path / f".{name}.{uuid.uuid4().hex}.tmp"
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            try:
                os.fchmod(descriptor, 0o600)
                with os.fdopen(descriptor, "wb") as output:
                    output.write(encoded)
                    output.flush()
                    os.fsync(output.fileno())
            except BaseException:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
                raise
            os.replace(temporary, target)
        except OSError as error:
            with contextlib.suppress(OSError):
                temporary.unlink()
            raise ArtifactError(f"unable to finalize artifact {name}") from error

    def finalize(self, result: object, error: BaseException | None = None) -> None:
        """Finalize result, telemetry, secret scan, and artifact hashes."""
        primary: BaseException | None = None
        try:
            if error is not None:
                self.event(
                    "run_failed",
                    error_class=type(error).__name__,
                    error_code="unexpected_exception",
                    message=_bounded_error(error, self._secrets),
                )
            result_value = (
                result.to_dict() if hasattr(result, "to_dict") else result)
            if not self._provider_finalized:
                self.atomic_json("provider-summary.json", {
                    "schema_version": 1,
                    "status": "not_run",
                    "input_tokens": None,
                    "output_tokens": None,
                })
            if not self._build_finalized:
                self.atomic_json("build-summary.json", {
                    "schema_version": 1,
                    "status": "not_run",
                })
            if not (self.path / "semantic-validation.json").is_file():
                self.atomic_json("semantic-validation.json", {
                    "schema_version": 1,
                    "status": "not_evaluated",
                    "reason_code": "workflow_did_not_reach_semantic_validation",
                    "reason": (
                        "semantic validation was not reached before workflow exit"),
                })
                self.atomic_text(
                    "semantic-validation.txt",
                    "Semantic security status: not_evaluated\n"
                    "Reason: workflow did not reach semantic validation\n",
                )
            self.telemetry.durations["total"] = max(
                0.0, self._monotonic() - self._started)
            self.atomic_json("result.json", result_value)
            self.atomic_json("telemetry.json", self.telemetry.to_dict())
            self.event("result_finalized", has_error=error is not None)
            self.event("cleanup_completed")
            try:
                self._scan_for_secrets()
            except ArtifactError:
                self.event(
                    "run_failed",
                    error_class="ArtifactError",
                    error_code="artifact_secret_detected",
                )
                raise
        except BaseException as artifact_error:
            primary = artifact_error
        finally:
            try:
                self._transcript.flush()
                os.fsync(self._transcript.fileno())
                self._transcript.close()
                self._closed = True
                self._write_hash_manifest()
            except BaseException as artifact_error:
                primary = primary or artifact_error
        if primary is not None:
            if isinstance(primary, ArtifactError):
                raise primary
            raise ArtifactError("durable artifact finalization failed") from primary

    def _scan_for_secrets(self) -> None:
        if not self._secrets:
            return
        for child in self.path.iterdir():
            if not child.is_file():
                continue
            try:
                data = child.read_bytes()
            except OSError as error:
                raise ArtifactError("unable to scan retained artifacts") from error
            if any(secret.encode("utf-8") in data for secret in self._secrets):
                descriptor = os.open(
                    child,
                    os.O_WRONLY | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0),
                )
                with os.fdopen(descriptor, "wb") as output:
                    output.write(b"[REDACTED: secret scan hit]\n")
                    output.flush()
                    os.fsync(output.fileno())
                raise ArtifactError("retained artifact secret scan failed")

    def _write_hash_manifest(self) -> None:
        lines = []
        for child in sorted(self.path.iterdir(), key=lambda item: item.name):
            if not child.is_file() or child.name == "artifact-manifest.sha256":
                continue
            digest = hashlib.sha256(child.read_bytes()).hexdigest()
            lines.append(f"{digest}  {child.name}\n")
        target = self.path / "artifact-manifest.sha256"
        descriptor = os.open(
            target,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            output.writelines(lines)
            output.flush()
            os.fsync(output.fileno())


def current_run_artifacts() -> RunArtifacts | None:
    return _CURRENT_RUN.get()


def recover_jsonl(path: Path) -> int:
    """Remove only an invalid trailing partial record; reject interior damage."""
    data = path.read_bytes()
    lines = data.splitlines(keepends=True)
    valid_bytes = 0
    for index, line in enumerate(lines):
        try:
            json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            if index != len(lines) - 1:
                raise ArtifactError("durable transcript has interior corruption") from error
            descriptor = os.open(path, os.O_WRONLY)
            try:
                os.ftruncate(descriptor, valid_bytes)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return index
        valid_bytes += len(line)
    return len(lines)


def _safe_component(value: str) -> str:
    safe = _SAFE_ID_RE.sub("_", value)[:128].strip("._")
    if not safe:
        raise ArtifactError("invalid artifact identifier")
    return safe


def _bounded_error(error: BaseException, secrets: tuple[str, ...]) -> str:
    text = redact_openai_text(str(error), secrets)
    return " ".join(text.split())[:MAX_ERROR_BYTES] or "operation failed"


def _sanitize(value: object, secrets: tuple[str, ...], depth: int = 0,
              nodes: list[int] | None = None) -> object:
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > MAX_ARTIFACT_NODES or depth > 10:
        return {"truncated": True}
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        text = redact_openai_text(value, secrets)
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) <= MAX_ARTIFACT_STRING_BYTES:
            return text
        return {
            "excerpt": encoded[:1024].decode("utf-8", errors="replace"),
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "bytes": len(encoded),
            "truncated": True,
        }
    if isinstance(value, Mapping):
        return {
            str(key)[:128]: _sanitize(item, secrets, depth + 1, nodes)
            for key, item in list(value.items())[:128]
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(item, secrets, depth + 1, nodes) for item in value[:128]]
    return f"<{type(value).__name__}>"
