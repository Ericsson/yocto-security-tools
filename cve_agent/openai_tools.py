# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Bounded filesystem tools for the native OpenAI-compatible backend.

The runtime accepts only decoded JSON objects and exposes no shell, command,
glob, regular-expression, subprocess, or Python-evaluation primitive. Every
path is authorized again at execution time and all model-visible results are
bounded and JSON serializable.
"""
import contextlib
import errno
import hashlib
import json
import os
import stat
import unicodedata
import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Optional

from shared import TEXT_ENCODING, TEXT_ERRORS

from .openai_deadline import RuntimeTimeoutError

MAX_TOOL_ARGUMENT_BYTES = 512 * 1024
MAX_PATH_BYTES = 4096
MAX_FILE_READ_BYTES = 16 * 1024
MAX_INSPECTABLE_FILE_BYTES = 4 * 1024 * 1024
MAX_WRITE_BYTES = 256 * 1024
MAX_DIRECTORY_ENTRIES = 128
MAX_SEARCH_FILES = 64
MAX_SEARCH_BYTES = 512 * 1024
MAX_SEARCH_MATCHES = 64
MAX_SEARCH_LINE_BYTES = 4096
MAX_SEARCH_EXCERPT_CHARS = 256
MAX_MODEL_RESULT_BYTES = 64 * 1024
MAX_EXPECTED_OCCURRENCES = 1_000_000
MAX_QUERY_BYTES = 1024
MAX_PATCH_FILE_BYTES = 8 * 1024 * 1024
MAX_PATCH_HUNKS = 8
MAX_PATCH_CONTEXT_BYTES = 64 * 1024
MAX_PATCH_REPLACEMENT_BYTES = 64 * 1024
MAX_PATCH_TOTAL_CONTEXT_BYTES = 128 * 1024
MAX_PATCH_TOTAL_REPLACEMENT_BYTES = 128 * 1024
MAX_PATCH_CHANGED_LINES = 2048
MAX_PATCH_DIFF_BYTES = 4096

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)


def _is_git_internal_component(component: str) -> bool:
    """Recognize Git metadata names across case-folding Unicode filesystems."""
    return unicodedata.normalize("NFKC", component).casefold() == ".git"


class ToolValidationError(ValueError):
    """Decoded tool arguments do not match the declared contract."""


class ToolPolicyError(PermissionError):
    """A valid request is outside the runtime's authorization policy."""


class ToolOperationalError(RuntimeError):
    """An authorized filesystem operation could not be completed."""

    payload: Optional[dict[str, object]] = None


class ToolApprovalError(PermissionError):
    """A host operator denied an otherwise valid side effect."""


@dataclass(frozen=True)
class FileToolLimits:
    """Per-session limits capped by the module's schema-visible maxima."""

    max_tool_argument_bytes: int = MAX_TOOL_ARGUMENT_BYTES
    max_path_bytes: int = MAX_PATH_BYTES
    max_file_read_bytes: int = MAX_FILE_READ_BYTES
    max_inspectable_file_bytes: int = MAX_INSPECTABLE_FILE_BYTES
    max_write_bytes: int = MAX_WRITE_BYTES
    max_directory_entries: int = MAX_DIRECTORY_ENTRIES
    max_search_files: int = MAX_SEARCH_FILES
    max_search_bytes: int = MAX_SEARCH_BYTES
    max_search_matches: int = MAX_SEARCH_MATCHES
    max_search_line_bytes: int = MAX_SEARCH_LINE_BYTES
    max_search_excerpt_chars: int = MAX_SEARCH_EXCERPT_CHARS
    max_model_result_bytes: int = MAX_MODEL_RESULT_BYTES
    max_query_bytes: int = MAX_QUERY_BYTES
    max_patch_file_bytes: int = MAX_PATCH_FILE_BYTES

    def __post_init__(self) -> None:
        ceilings = {
            "max_tool_argument_bytes": MAX_TOOL_ARGUMENT_BYTES,
            "max_path_bytes": MAX_PATH_BYTES,
            "max_file_read_bytes": MAX_FILE_READ_BYTES,
            "max_inspectable_file_bytes": MAX_INSPECTABLE_FILE_BYTES,
            "max_write_bytes": MAX_WRITE_BYTES,
            "max_directory_entries": MAX_DIRECTORY_ENTRIES,
            "max_search_files": MAX_SEARCH_FILES,
            "max_search_bytes": MAX_SEARCH_BYTES,
            "max_search_matches": MAX_SEARCH_MATCHES,
            "max_search_line_bytes": MAX_SEARCH_LINE_BYTES,
            "max_search_excerpt_chars": MAX_SEARCH_EXCERPT_CHARS,
            "max_model_result_bytes": MAX_MODEL_RESULT_BYTES,
            "max_query_bytes": MAX_QUERY_BYTES,
            "max_patch_file_bytes": MAX_PATCH_FILE_BYTES,
        }
        for name, ceiling in ceilings.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
            if value < 1 or value > ceiling:
                raise ValueError(f"{name} must be between 1 and {ceiling}")
        if self.max_model_result_bytes < 1024:
            raise ValueError("max_model_result_bytes must be at least 1024")
        if self.max_file_read_bytes > self.max_inspectable_file_bytes:
            raise ValueError(
                "max_file_read_bytes cannot exceed max_inspectable_file_bytes")


@dataclass(frozen=True)
class ToolAudit:
    """Content-free audit details safe to persist or log."""

    tool: str
    success: bool
    mutated: bool
    generation: int
    error_kind: Optional[str] = None
    path: Optional[str] = None
    paths: tuple[str, ...] = ()
    revision: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable audit object."""
        result: dict[str, object] = {
            "tool": self.tool,
            "success": self.success,
            "mutated": self.mutated,
            "generation": self.generation,
        }
        if self.error_kind is not None:
            result["error_kind"] = self.error_kind
        if self.path is not None:
            result["path"] = self.path
        if self.paths:
            result["paths"] = list(self.paths)
        if self.revision is not None:
            result["revision"] = self.revision
        return result


@dataclass(frozen=True)
class ToolResult:
    """Structured outcome returned to the future model/tool loop."""

    success: bool
    payload: dict[str, object]
    mutated: bool
    terminal: bool
    audit: ToolAudit
    error_kind: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        """Return the complete model-visible JSON result."""
        result: dict[str, object] = {
            "success": self.success,
            "payload": self.payload,
            "mutated": self.mutated,
            "terminal": self.terminal,
            "audit": self.audit.to_dict(),
        }
        if self.error_kind is not None:
            result["error_kind"] = self.error_kind
        return result


@dataclass(frozen=True)
class FieldContract:
    """One JSON object field shared by schema generation and validation."""

    json_type: str
    description: str
    required: bool = False
    minimum: Optional[int] = None
    maximum: Optional[int] = None
    enum: tuple[str, ...] = ()
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min_items: Optional[int] = None
    max_items: Optional[int] = None
    item_type: Optional[str] = None
    item_fields: Optional[Mapping[str, "FieldContract"]] = None

    def schema(self) -> dict[str, object]:
        """Build the JSON schema fragment for this field."""
        result: dict[str, object] = {
            "type": self.json_type,
            "description": self.description,
        }
        if self.minimum is not None:
            result["minimum"] = self.minimum
        if self.maximum is not None:
            result["maximum"] = self.maximum
        if self.enum:
            result["enum"] = list(self.enum)
        if self.min_length is not None:
            result["minLength"] = self.min_length
        if self.max_length is not None:
            result["maxLength"] = self.max_length
        if self.min_items is not None:
            result["minItems"] = self.min_items
        if self.max_items is not None:
            result["maxItems"] = self.max_items
        if self.item_fields is not None:
            required = [
                name for name, field in self.item_fields.items() if field.required
            ]
            result["items"] = {
                "type": "object",
                "properties": {
                    name: field.schema() for name, field in self.item_fields.items()
                },
                "required": required,
                "additionalProperties": False,
            }
        elif self.item_type is not None:
            result["items"] = {"type": self.item_type}
        return result


@dataclass(frozen=True)
class ToolContract:
    """One callable tool contract and its dispatcher handler name."""

    name: str
    description: str
    fields: Mapping[str, FieldContract]
    handler: str

    def schema(self) -> dict[str, object]:
        """Build an OpenAI-compatible function schema."""
        required = [name for name, field in self.fields.items() if field.required]
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        name: field.schema() for name, field in self.fields.items()
                    },
                    "required": required,
                    "additionalProperties": False,
                },
            },
        }


TOOL_CONTRACTS: dict[str, ToolContract] = {
    "list_directory": ToolContract(
        "list_directory",
        "List one authorized directory without recursive traversal.",
        {
            "path": FieldContract(
                "string", "Workspace-relative directory path.", required=True),
        },
        "_list_directory",
    ),
    "read_file": ToolContract(
        "read_file",
        "Read a bounded byte range and return the complete file SHA-256.",
        {
            "path": FieldContract(
                "string", "Workspace-relative path or authorized absolute context path.",
                required=True),
            "offset": FieldContract(
                "integer", "Zero-based byte offset.", minimum=0,
                maximum=MAX_INSPECTABLE_FILE_BYTES),
            "max_bytes": FieldContract(
                "integer", "Maximum bytes to return.", minimum=1,
                maximum=MAX_FILE_READ_BYTES),
        },
        "_read_file",
    ),
    "search_text": ToolContract(
        "search_text",
        "Search for a literal string in an explicit list of authorized files.",
        {
            "query": FieldContract(
                "string", "Non-empty literal text, never a regular expression.",
                required=True, min_length=1),
            "paths": FieldContract(
                "array", "Explicit authorized file paths.", required=True,
                min_items=1, max_items=MAX_SEARCH_FILES, item_type="string"),
            "start_file": FieldContract(
                "integer", "Continuation file index.", minimum=0,
                maximum=MAX_SEARCH_FILES),
            "start_offset": FieldContract(
                "integer", "Continuation byte offset in start_file.", minimum=0,
                maximum=MAX_INSPECTABLE_FILE_BYTES),
            "start_line": FieldContract(
                "integer", "One-based continuation line number.", minimum=1,
                maximum=MAX_INSPECTABLE_FILE_BYTES),
        },
        "_search_text",
    ),
    "replace_in_file": ToolContract(
        "replace_in_file",
        "Replace exact text only when the occurrence count matches.",
        {
            "path": FieldContract(
                "string", "Exact authorized workspace-relative file path.",
                required=True),
            "old_text": FieldContract(
                "string", "Non-empty exact text to replace.", required=True,
                min_length=1),
            "new_text": FieldContract(
                "string", "Exact replacement text.", required=True),
            "expected_count": FieldContract(
                "integer", "Required occurrence count.", required=True,
                minimum=0, maximum=MAX_EXPECTED_OCCURRENCES),
        },
        "_replace_in_file",
    ),
    "apply_patch_hunks": ToolContract(
        "apply_patch_hunks",
        "Atomically replace unique exact contexts in one large authorized UTF-8 file.",
        {
            "path": FieldContract(
                "string", "Exact authorized workspace-relative file path.",
                required=True),
            "expected_sha256": FieldContract(
                "string", "Lowercase SHA-256 of the complete current file.",
                required=True, min_length=64, max_length=64),
            "hunks": FieldContract(
                "array", "Ordered non-overlapping exact context replacements.",
                required=True, min_items=1, max_items=MAX_PATCH_HUNKS,
                item_fields={
                    "old_text": FieldContract(
                        "string", "Unique exact UTF-8 context.", required=True,
                        min_length=1, max_length=MAX_PATCH_CONTEXT_BYTES),
                    "replacement": FieldContract(
                        "string", "Exact UTF-8 replacement.", required=True,
                        max_length=MAX_PATCH_REPLACEMENT_BYTES),
                }),
        },
        "_apply_patch_hunks",
    ),
    "write_file": ToolContract(
        "write_file",
        "Create or replace one exact authorized file with explicit clobber mode.",
        {
            "path": FieldContract(
                "string", "Exact authorized workspace-relative file path.",
                required=True),
            "content": FieldContract(
                "string", "Complete UTF-8 file content.", required=True),
            "mode": FieldContract(
                "string", "Whether creation or replacement is required.",
                required=True, enum=("create_only", "replace_only")),
        },
        "_write_file",
    ),
    "delete_file": ToolContract(
        "delete_file",
        "Delete one exact authorized regular file.",
        {
            "path": FieldContract(
                "string", "Exact authorized workspace-relative file path.",
                required=True),
        },
        "_delete_file",
    ),
}


def openai_tool_schemas() -> list[dict[str, object]]:
    """Return function schemas generated from the dispatcher contracts."""
    return [contract.schema() for contract in TOOL_CONTRACTS.values()]


@dataclass(frozen=True)
class _AuthorizedRoot:
    path: Path
    device: int
    inode: int
    absolute_reads: bool


@dataclass(frozen=True)
class AuthorizedPath:
    """A normalized path associated with one canonical authorized root."""

    root: _AuthorizedRoot
    relative: PurePosixPath
    repository_path: Optional[str]

    @property
    def display_path(self) -> Path:
        """Return the lexical host path for hooks and diagnostics."""
        if str(self.relative) == ".":
            return self.root.path
        return self.root.path.joinpath(*self.relative.parts)


class FileToolPathPolicy:
    """Canonical-root and exact-write authorization for file tools."""

    def __init__(self, workspace_root: Path, allowed_files: Iterable[str],
                 agent_root: Optional[Path] = None,
                 limits: Optional[FileToolLimits] = None) -> None:
        self.limits = limits or FileToolLimits()
        self._workspace = self._make_root(
            workspace_root, absolute_reads=False)
        self._read_roots = [self._workspace]
        if agent_root is not None:
            agent = self._make_root(agent_root, absolute_reads=True)
            if agent.path != self._workspace.path:
                self._read_roots.append(agent)
        self.allowed_files = frozenset(
            self._normalize_relative(path, allow_root=False)
            for path in allowed_files)

    @staticmethod
    def _make_root(path: Path, absolute_reads: bool) -> _AuthorizedRoot:
        try:
            canonical = path.resolve(strict=True)
            info = canonical.stat()
        except (OSError, RuntimeError) as exc:
            raise ValueError("authorized root must be an existing directory") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("authorized root must be a directory")
        return _AuthorizedRoot(
            canonical, info.st_dev, info.st_ino, absolute_reads)

    def _normalize_relative(self, path: str, allow_root: bool) -> str:
        if not isinstance(path, str):
            raise ToolValidationError("path must be a string")
        if not path:
            raise ToolPolicyError("empty paths are not allowed")
        if "\x00" in path:
            raise ToolPolicyError("paths containing NUL are not allowed")
        if (len(path.encode("utf-8", errors="surrogatepass"))
                > self.limits.max_path_bytes):
            raise ToolPolicyError("path exceeds the configured length limit")
        if "\\" in path:
            raise ToolPolicyError("backslash path separators are not allowed")
        if len(path) >= 2 and path[0].isalpha() and path[1] == ":":
            raise ToolPolicyError("platform-specific drive paths are not allowed")
        if path.startswith("/"):
            raise ToolPolicyError("absolute path is not workspace-relative")
        if "//" in path or (path.endswith("/") and path != "/"):
            raise ToolPolicyError("ambiguous path separators are not allowed")

        parts: list[str] = []
        for part in path.split("/"):
            if part in {"", "."}:
                continue
            if part == "..":
                raise ToolPolicyError("parent traversal is not allowed")
            if _is_git_internal_component(part):
                raise ToolPolicyError("access to .git internals is not allowed")
            parts.append(part)
        if not parts:
            if allow_root:
                return "."
            raise ToolPolicyError("path must name a file")
        return PurePosixPath(*parts).as_posix()

    def authorize_read(self, path: str) -> AuthorizedPath:
        """Authorize a workspace-relative or explicit-root absolute read."""
        if not isinstance(path, str):
            raise ToolValidationError("path must be a string")
        if path.startswith("/"):
            return self._authorize_absolute_read(path)
        normalized = self._normalize_relative(path, allow_root=True)
        repository_path = None if normalized == "." else normalized
        return AuthorizedPath(
            self._workspace, PurePosixPath(normalized), repository_path)

    def _authorize_absolute_read(self, path: str) -> AuthorizedPath:
        if "\x00" in path:
            raise ToolPolicyError("paths containing NUL are not allowed")
        if "\\" in path or "//" in path[1:]:
            raise ToolPolicyError("ambiguous path separators are not allowed")
        if (len(path.encode("utf-8", errors="surrogatepass"))
                > self.limits.max_path_bytes):
            raise ToolPolicyError("path exceeds the configured length limit")
        raw_parts = path.split("/")[1:]
        if any(part == ".." for part in raw_parts):
            raise ToolPolicyError("parent traversal is not allowed")
        if any(_is_git_internal_component(part) for part in raw_parts):
            raise ToolPolicyError("access to .git internals is not allowed")
        normalized = Path("/", *(part for part in raw_parts if part not in {"", "."}))
        for root in self._read_roots:
            if not root.absolute_reads:
                continue
            try:
                relative = normalized.relative_to(root.path)
            except ValueError:
                continue
            relative_text = "." if not relative.parts else PurePosixPath(*relative.parts).as_posix()
            return AuthorizedPath(root, PurePosixPath(relative_text), None)
        raise ToolPolicyError("absolute path is outside authorized read roots")

    def authorize_write(self, path: str) -> AuthorizedPath:
        """Authorize exact matching against normalized session allowed_files."""
        if not isinstance(path, str):
            raise ToolValidationError("path must be a string")
        if path.startswith("/"):
            raise ToolPolicyError("writes require a workspace-relative path")
        normalized = self._normalize_relative(path, allow_root=False)
        if PurePosixPath(normalized).name == "conclusion.json":
            raise ToolPolicyError(
                "conclusion.json may be created only by the finish tool")
        if normalized not in self.allowed_files:
            raise ToolPolicyError("path is not in the session allowed_files set")
        return AuthorizedPath(
            self._workspace, PurePosixPath(normalized), normalized)

    def open_regular(self, authorized: AuthorizedPath) -> tuple[int, os.stat_result]:
        """Open a regular file without following any path symlink."""
        parent_fd, name = self._open_parent(authorized)
        try:
            self._reject_symlink(parent_fd, name)
            try:
                before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError as exc:
                self._translate_open_error(exc)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ToolPolicyError("path is not a regular file")
            flags = os.O_RDONLY | _CLOEXEC | _NOFOLLOW | _NONBLOCK
            try:
                fd = os.open(name, flags, dir_fd=parent_fd)
            except OSError as exc:
                self._translate_open_error(exc)
            try:
                info = os.fstat(fd)
            except OSError as exc:
                os.close(fd)
                raise ToolOperationalError("filesystem inspection failed") from exc
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                os.close(fd)
                raise ToolPolicyError("path is not a regular file")
            return fd, info
        finally:
            os.close(parent_fd)

    def open_directory(self, authorized: AuthorizedPath) -> int:
        """Open a directory without following any path symlink."""
        if str(authorized.relative) == ".":
            return self._open_root(authorized.root)
        parent_fd, name = self._open_parent(authorized)
        try:
            self._reject_symlink(parent_fd, name)
            flags = os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW
            try:
                fd = os.open(name, flags, dir_fd=parent_fd)
            except OSError as exc:
                self._translate_open_error(exc)
            try:
                info = os.fstat(fd)
            except OSError as exc:
                os.close(fd)
                raise ToolOperationalError("filesystem inspection failed") from exc
            if not stat.S_ISDIR(info.st_mode):
                os.close(fd)
                raise ToolPolicyError("path is not a directory")
            return fd
        finally:
            os.close(parent_fd)

    def open_write_parent(self, authorized: AuthorizedPath) -> tuple[int, str]:
        """Open the anchored parent directory for a mutation."""
        return self._open_parent(authorized)

    def _open_parent(self, authorized: AuthorizedPath) -> tuple[int, str]:
        parts = authorized.relative.parts
        if not parts or str(authorized.relative) == ".":
            raise ToolPolicyError("path must name a file")
        current_fd = self._open_root(authorized.root)
        try:
            for part in parts[:-1]:
                self._reject_symlink(current_fd, part)
                flags = os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW
                try:
                    next_fd = os.open(part, flags, dir_fd=current_fd)
                except OSError as exc:
                    self._translate_open_error(exc)
                try:
                    info = os.fstat(next_fd)
                except OSError as exc:
                    os.close(next_fd)
                    raise ToolOperationalError("filesystem inspection failed") from exc
                if not stat.S_ISDIR(info.st_mode):
                    os.close(next_fd)
                    raise ToolPolicyError("a path parent is not a directory")
                os.close(current_fd)
                current_fd = next_fd
            return current_fd, parts[-1]
        except Exception:
            os.close(current_fd)
            raise

    @staticmethod
    def _open_root(root: _AuthorizedRoot) -> int:
        flags = os.O_RDONLY | _DIRECTORY | _CLOEXEC | _NOFOLLOW
        try:
            fd = os.open(root.path, flags)
        except OSError as exc:
            FileToolPathPolicy._translate_open_error(exc)
        try:
            info = os.fstat(fd)
        except OSError as exc:
            os.close(fd)
            raise ToolOperationalError("authorized root inspection failed") from exc
        if (info.st_dev, info.st_ino) != (root.device, root.inode):
            os.close(fd)
            raise ToolPolicyError("authorized root changed during the session")
        return fd

    @staticmethod
    def _reject_symlink(parent_fd: int, name: str) -> None:
        try:
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(info.st_mode):
            raise ToolPolicyError("symlink paths are not allowed")

    @staticmethod
    def _translate_open_error(exc: OSError) -> None:
        if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ToolPolicyError("symlink or non-directory path component denied") from exc
        if exc.errno == errno.ENOENT:
            raise ToolOperationalError("path does not exist") from exc
        raise ToolOperationalError("filesystem open failed") from exc


@dataclass(frozen=True)
class _ExecutionResult:
    payload: dict[str, object]
    mutated: bool = False
    terminal: bool = False
    advances_generation: bool = True


@dataclass(frozen=True)
class _PatchPlan:
    authorized: AuthorizedPath
    expected_info: os.stat_result
    original: bytes
    replacement: bytes
    old_sha256: str
    new_sha256: str
    hunks_applied: int
    lines_added: int
    lines_removed: int
    diff_excerpt: str


class FileToolRuntime:
    """Central dispatcher and bounded host-side filesystem executor."""

    tool_contracts: Mapping[str, ToolContract] = TOOL_CONTRACTS

    def __init__(
        self,
        workspace_root: Path,
        allowed_files: Iterable[str],
        agent_root: Optional[Path] = None,
        limits: Optional[FileToolLimits] = None,
        before_operation: Optional[Callable[[str, Path], None]] = None,
        before_replace: Optional[Callable[[Path], None]] = None,
    ) -> None:
        self.limits = limits or FileToolLimits()
        self.policy = FileToolPathPolicy(
            workspace_root, allowed_files, agent_root=agent_root,
            limits=self.limits)
        self._before_operation = before_operation
        self._before_replace = before_replace
        self._mutation_generation = 0
        self._typed_mutation_paths: set[str] = set()

    @property
    def mutation_generation(self) -> int:
        """Return the monotonic generation of build-relevant mutations."""
        return self._mutation_generation

    def dispatch(self, tool_name: object, arguments: object) -> ToolResult:
        """Validate and execute one decoded model tool call without leaking errors."""
        safe_name = (
            tool_name if isinstance(tool_name, str) and tool_name in self.tool_contracts
            else "<unknown>"
        )
        audit_fields: dict[str, object] = {}
        try:
            audit_fields = self._audit_fields(arguments)
            self._check_runtime_available(safe_name, arguments)
            if not isinstance(tool_name, str) or tool_name not in self.tool_contracts:
                raise ToolValidationError("unknown tool name")
            contract = self.tool_contracts[tool_name]
            validated = self._validate_arguments(contract, arguments)
            self._authorize_tool_call(tool_name, validated)
            handler = getattr(self, contract.handler)
            execution: _ExecutionResult = handler(validated)
            if execution.mutated:
                self._record_typed_mutation_paths(execution.payload)
            if execution.mutated and execution.advances_generation:
                self._mutation_generation += 1
            self._after_successful_execution(tool_name, execution)
            result = ToolResult(
                success=True,
                payload=execution.payload,
                mutated=execution.mutated,
                terminal=execution.terminal,
                audit=self._make_audit(
                    tool_name, True, execution.mutated, audit_fields),
            )
        except ToolValidationError as exc:
            result = self._error_result(
                safe_name, "validation", str(exc), audit_fields,
                getattr(exc, "payload", None))
        except ToolPolicyError as exc:
            result = self._error_result(
                safe_name, "policy", str(exc), audit_fields,
                getattr(exc, "payload", None))
        except ToolOperationalError as exc:
            result = self._error_result(
                safe_name, "operation", str(exc), audit_fields,
                getattr(exc, "payload", None))
        except ToolApprovalError as exc:
            result = self._error_result(
                safe_name, "approval", str(exc), audit_fields)
        except RuntimeTimeoutError as exc:
            result = self._error_result(
                safe_name, "timeout", str(exc), audit_fields, exc.payload)
        except (OSError, UnicodeError):
            result = self._error_result(
                safe_name, "operation", "filesystem operation failed", audit_fields)
        except Exception:
            # A malformed decoded object or an unexpected host failure must not
            # tear down the future model loop or expose exception details.
            result = self._error_result(
                safe_name, "operation", "tool execution failed safely", audit_fields)
        return self._bound_result(result)

    def _check_runtime_available(self, tool: str, arguments: object) -> None:
        """Allow composed runtimes to reject calls before validation/execution."""

    def _authorize_tool_call(self, tool: str,
                             arguments: Mapping[str, object]) -> None:
        """Allow composed runtimes to gate side effects after validation."""

    def _after_successful_execution(
        self, tool: str, execution: _ExecutionResult,
    ) -> None:
        """Allow composed runtimes to synchronize trusted post-state."""

    def _record_typed_mutation_paths(
        self, payload: Mapping[str, object],
    ) -> None:
        """Remember exact authorized paths changed through typed operations."""
        candidates: list[str] = []
        path = payload.get("path")
        if isinstance(path, str):
            candidates.append(path)
        for key in ("changed_paths", "removed"):
            values = payload.get(key)
            if isinstance(values, list):
                candidates.extend(value for value in values if isinstance(value, str))
        for candidate in candidates:
            try:
                authorized = self.policy.authorize_write(candidate)
            except (ToolPolicyError, ToolValidationError):
                continue
            if authorized.repository_path is not None:
                self._typed_mutation_paths.add(authorized.repository_path)

    def _error_result(self, tool: str, kind: str, message: str,
                      audit_fields: Mapping[str, object],
                      extra_payload: Optional[dict[str, object]] = None) -> ToolResult:
        payload: dict[str, object] = {"error": message}
        if extra_payload:
            payload.update(extra_payload)
        return ToolResult(
            success=False,
            payload=payload,
            mutated=False,
            terminal=False,
            error_kind=kind,
            audit=self._make_audit(
                tool, False, False, audit_fields, error_kind=kind),
        )

    def _make_audit(self, tool: str, success: bool, mutated: bool,
                    fields: Mapping[str, object],
                    error_kind: Optional[str] = None) -> ToolAudit:
        path = fields.get("path")
        revision = fields.get("revision")
        paths = fields.get("paths", ())
        return ToolAudit(
            tool=tool,
            success=success,
            mutated=mutated,
            generation=self._mutation_generation,
            error_kind=error_kind,
            path=path if isinstance(path, str) else None,
            paths=(paths if isinstance(paths, tuple)
                   and all(isinstance(item, str) for item in paths) else ()),
            revision=revision if isinstance(revision, str) else None,
        )

    def _validate_arguments(self, contract: ToolContract,
                            arguments: object) -> dict[str, object]:
        if not isinstance(arguments, dict):
            raise ToolValidationError("tool arguments must be a JSON object")
        try:
            encoded = json.dumps(
                arguments, ensure_ascii=False, separators=(",", ":"),
                allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise ToolValidationError(
                "tool arguments must contain only JSON values") from exc
        if len(encoded) > self.limits.max_tool_argument_bytes:
            raise ToolValidationError("tool arguments exceed the configured size limit")
        if any(not isinstance(key, str) for key in arguments):
            raise ToolValidationError("tool argument field names must be strings")

        unexpected = set(arguments) - set(contract.fields)
        if unexpected:
            raise ToolValidationError("unexpected tool argument field")
        missing = [
            name for name, field in contract.fields.items()
            if field.required and name not in arguments
        ]
        if missing:
            raise ToolValidationError(f"missing required field: {missing[0]}")

        validated = dict(arguments)
        for name, value in validated.items():
            FileToolRuntime._validate_field(name, value, contract.fields[name])
        return validated

    @staticmethod
    def _validate_field(name: str, value: object,
                        contract: FieldContract) -> None:
        if contract.json_type == "string":
            if not isinstance(value, str):
                raise ToolValidationError(f"field '{name}' must be a string")
            if contract.min_length is not None and len(value) < contract.min_length:
                raise ToolValidationError(
                    f"field '{name}' must not be empty")
            if contract.max_length is not None and len(value) > contract.max_length:
                raise ToolValidationError(
                    f"field '{name}' exceeds its length limit")
            if contract.enum and value not in contract.enum:
                raise ToolValidationError(
                    f"field '{name}' must be one of: {', '.join(contract.enum)}")
            return
        if contract.json_type == "integer":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ToolValidationError(f"field '{name}' must be an integer")
            if contract.minimum is not None and value < contract.minimum:
                raise ToolValidationError(
                    f"field '{name}' must be at least {contract.minimum}")
            if contract.maximum is not None and value > contract.maximum:
                raise ToolValidationError(
                    f"field '{name}' must be at most {contract.maximum}")
            return
        if contract.json_type == "array":
            if not isinstance(value, list):
                raise ToolValidationError(f"field '{name}' must be an array")
            if contract.min_items is not None and len(value) < contract.min_items:
                raise ToolValidationError(
                    f"field '{name}' must contain at least one item")
            if contract.max_items is not None and len(value) > contract.max_items:
                raise ToolValidationError(
                    f"field '{name}' exceeds its item limit")
            if contract.item_type == "string" and any(
                    not isinstance(item, str) for item in value):
                raise ToolValidationError(
                    f"field '{name}' items must be strings")
            if contract.item_fields is not None:
                for item in value:
                    if not isinstance(item, dict) or any(
                            not isinstance(key, str) for key in item):
                        raise ToolValidationError(
                            f"field '{name}' items must be objects")
                    unexpected = set(item) - set(contract.item_fields)
                    if unexpected:
                        raise ToolValidationError(
                            f"field '{name}' item has an unexpected field")
                    missing = [
                        child_name for child_name, child in contract.item_fields.items()
                        if child.required and child_name not in item
                    ]
                    if missing:
                        raise ToolValidationError(
                            f"field '{name}' item is missing: {missing[0]}")
                    for child_name, child_value in item.items():
                        FileToolRuntime._validate_field(
                            child_name, child_value,
                            contract.item_fields[child_name])
            return
        raise ToolValidationError(f"field '{name}' has an unsupported contract")

    @classmethod
    def _audit_fields(cls, arguments: object) -> dict[str, object]:
        if not isinstance(arguments, dict):
            return {}
        value = arguments.get("path")
        if not isinstance(value, str):
            return {}
        # JSON escaping prevents control characters in unusual but valid POSIX
        # filenames from becoming audit-log syntax. File contents are omitted.
        return {"path": cls._escape_audit_value(value)}

    @staticmethod
    def _escape_audit_value(value: str) -> str:
        escaped = json.dumps(value, ensure_ascii=True)[1:-1]
        return escaped if len(escaped) <= 256 else escaped[:253] + "..."

    def _bound_result(self, result: ToolResult) -> ToolResult:
        try:
            encoded = json.dumps(
                result.to_dict(), ensure_ascii=False, separators=(",", ":"),
                allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError):
            encoded = b"x" * (self.limits.max_model_result_bytes + 1)
        if len(encoded) <= self.limits.max_model_result_bytes:
            return result
        payload = {
            "message": "tool result exceeded the model-visible size limit",
            "truncated": True,
        }
        return ToolResult(
            success=result.success,
            payload=payload,
            mutated=result.mutated,
            terminal=result.terminal,
            error_kind=result.error_kind,
            audit=result.audit,
        )

    def _reauthorize(self, tool: str, path: str, write: bool) -> AuthorizedPath:
        authorize = self.policy.authorize_write if write else self.policy.authorize_read
        initial = authorize(path)
        if self._before_operation is not None:
            self._before_operation(tool, initial.display_path)
        return authorize(path)

    def _list_directory(self, arguments: dict[str, object]) -> _ExecutionResult:
        path = self._required_string(arguments, "path")
        authorized = self._reauthorize("list_directory", path, write=False)
        directory_fd = self.policy.open_directory(authorized)
        try:
            entries: list[dict[str, str]] = []
            with os.scandir(directory_fd) as iterator:
                for entry in iterator:
                    if _is_git_internal_component(entry.name):
                        continue
                    if len(entries) >= self.limits.max_directory_entries:
                        raise ToolOperationalError(
                            "directory exceeds the configured entry limit")
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISREG(info.st_mode):
                        kind = "file"
                    elif stat.S_ISDIR(info.st_mode):
                        kind = "directory"
                    elif stat.S_ISLNK(info.st_mode):
                        kind = "symlink"
                    else:
                        kind = "other"
                    entries.append({"name": entry.name, "type": kind})
        finally:
            os.close(directory_fd)
        entries.sort(key=lambda item: item["name"])
        return _ExecutionResult({
            "path": path,
            "entries": entries,
            "entry_count": len(entries),
            "truncated": False,
        })

    def _read_file(self, arguments: dict[str, object]) -> _ExecutionResult:
        path = self._required_string(arguments, "path")
        offset = self._optional_integer(arguments, "offset", 0)
        max_bytes = self._optional_integer(
            arguments, "max_bytes", self.limits.max_file_read_bytes)
        if max_bytes > self.limits.max_file_read_bytes:
            raise ToolValidationError(
                "field 'max_bytes' exceeds the session read limit")
        authorized = self._reauthorize("read_file", path, write=False)
        fd, info = self.policy.open_regular(authorized)
        try:
            if info.st_size > self.limits.max_inspectable_file_bytes:
                raise ToolOperationalError(
                    "file exceeds the configured inspection size limit")
            if offset > info.st_size:
                raise ToolOperationalError("read offset is beyond end of file")
            data = self._read_up_to(fd, info.st_size + 1)
        finally:
            os.close(fd)
        if len(data) != info.st_size:
            raise ToolOperationalError("file changed while it was being read")
        selected = data[offset:offset + max_bytes]
        if self._looks_binary(selected):
            raise ToolOperationalError("binary file content is not returned")
        content = selected.decode(TEXT_ENCODING, errors=TEXT_ERRORS)
        try:
            selected.decode(TEXT_ENCODING, errors="strict")
            replacements = False
        except UnicodeDecodeError:
            replacements = True
        next_offset = offset + len(selected)
        truncated = next_offset < info.st_size
        return _ExecutionResult({
            "path": path,
            "content": content,
            "offset": offset,
            "bytes_returned": len(selected),
            "file_size": info.st_size,
            "truncated": truncated,
            "next_offset": next_offset if truncated else None,
            "decode_replacements": replacements,
            "sha256": hashlib.sha256(data).hexdigest(),
        })

    def _search_text(self, arguments: dict[str, object]) -> _ExecutionResult:
        query = self._required_string(arguments, "query")
        if not query:
            raise ToolValidationError("field 'query' must not be empty")
        if (len(query.encode(TEXT_ENCODING, errors="surrogatepass"))
                > self.limits.max_query_bytes):
            raise ToolValidationError("field 'query' exceeds its size limit")
        paths_value = arguments["paths"]
        if not isinstance(paths_value, list) or not paths_value:
            raise ToolValidationError("field 'paths' must contain at least one path")
        paths = [self._string_item(item, "paths") for item in paths_value]
        if len(paths) > self.limits.max_search_files:
            raise ToolValidationError("field 'paths' exceeds the session file limit")
        start_file = self._optional_integer(arguments, "start_file", 0)
        start_offset = self._optional_integer(arguments, "start_offset", 0)
        start_line = self._optional_integer(arguments, "start_line", 1)
        if start_file > len(paths):
            raise ToolValidationError("field 'start_file' exceeds the paths list")

        matches: list[dict[str, object]] = []
        skipped: list[dict[str, object]] = []
        bytes_scanned = 0
        files_scanned = 0
        continuation: Optional[dict[str, int]] = None
        current_line = start_line

        for file_index in range(start_file, len(paths)):
            path = paths[file_index]
            offset = start_offset if file_index == start_file else 0
            current_line = start_line if file_index == start_file else 1
            authorized = self._reauthorize("search_text", path, write=False)
            fd, info = self.policy.open_regular(authorized)
            try:
                if info.st_size > self.limits.max_inspectable_file_bytes:
                    skipped.append({
                        "file_index": file_index,
                        "reason": "oversized",
                    })
                    continue
                if offset > info.st_size:
                    raise ToolOperationalError(
                        "search continuation offset is beyond end of file")
                remaining = self.limits.max_search_bytes - bytes_scanned
                if remaining <= 0:
                    continuation = {
                        "start_file": file_index,
                        "start_offset": offset,
                        "start_line": current_line,
                    }
                    break
                os.lseek(fd, offset, os.SEEK_SET)
                data = self._read_up_to(fd, remaining)
            finally:
                os.close(fd)

            files_scanned += 1
            bytes_scanned += len(data)
            if self._looks_binary(data):
                skipped.append({"file_index": file_index, "reason": "binary"})
                continue

            more_in_file = offset + len(data) < info.st_size
            scan_data = data
            if more_in_file:
                last_newline = max(scan_data.rfind(b"\n"), scan_data.rfind(b"\r"))
                if last_newline >= 0:
                    scan_data = scan_data[:last_newline + 1]

            consumed = 0
            for raw_line in scan_data.splitlines(keepends=True):
                line_offset = offset + consumed
                consumed += len(raw_line)
                if len(raw_line) > self.limits.max_search_line_bytes:
                    current_line += 1
                    continue
                line = raw_line.decode(TEXT_ENCODING, errors=TEXT_ERRORS)
                visible_line = line.rstrip("\r\n")
                column_offset = 0
                while True:
                    found = visible_line.find(query, column_offset)
                    if found < 0:
                        break
                    excerpt = visible_line[:self.limits.max_search_excerpt_chars]
                    matches.append({
                        "file_index": file_index,
                        "line": current_line,
                        "column": found + 1,
                        "byte_offset": line_offset,
                        "text": excerpt,
                        "line_truncated": len(visible_line) > len(excerpt),
                    })
                    column_offset = found + max(1, len(query))
                    if len(matches) >= self.limits.max_search_matches:
                        continuation = {
                            "start_file": file_index,
                            "start_offset": offset + consumed,
                            "start_line": current_line + 1,
                        }
                        break
                current_line += 1
                if continuation is not None:
                    break
            if continuation is not None:
                break
            if more_in_file:
                continuation = {
                    "start_file": file_index,
                    "start_offset": offset + len(scan_data),
                    "start_line": current_line,
                }
                break

        return _ExecutionResult({
            "query": query,
            "matches": matches,
            "match_count": len(matches),
            "files_scanned": files_scanned,
            "bytes_scanned": bytes_scanned,
            "skipped": skipped,
            "truncated": continuation is not None,
            "continuation": continuation,
        })

    def _replace_in_file(self, arguments: dict[str, object]) -> _ExecutionResult:
        path = self._required_string(arguments, "path")
        old_text = self._required_string(arguments, "old_text")
        new_text = self._required_string(arguments, "new_text")
        expected = self._required_integer(arguments, "expected_count")
        if not old_text:
            raise ToolValidationError("field 'old_text' must not be empty")
        authorized = self._reauthorize("replace_in_file", path, write=True)
        fd, info = self.policy.open_regular(authorized)
        try:
            if info.st_size > self.limits.max_write_bytes:
                raise ToolOperationalError("file exceeds the configured write size limit")
            data = self._read_up_to(fd, self.limits.max_write_bytes + 1)
        finally:
            os.close(fd)
        if len(data) > self.limits.max_write_bytes:
            raise ToolOperationalError("file exceeds the configured write size limit")
        if b"\x00" in data:
            raise ToolOperationalError("binary files cannot be replaced as text")
        try:
            text = data.decode(TEXT_ENCODING, errors="strict")
        except UnicodeDecodeError as exc:
            raise ToolOperationalError(
                "file is not valid UTF-8 and cannot be safely replaced") from exc
        actual = text.count(old_text)
        if actual != expected:
            raise ToolOperationalError(
                f"occurrence count mismatch: expected {expected}, found {actual}")
        replaced = text.replace(old_text, new_text)
        encoded = self._encode_write(replaced)
        if encoded == data:
            return _ExecutionResult({
                "path": path,
                "occurrences": actual,
                "bytes_written": 0,
                "changed": False,
            })
        authorized = self.policy.authorize_write(path)
        self._atomic_write(
            authorized, encoded, mode="replace_only", expected_info=info)
        return _ExecutionResult({
            "path": path,
            "occurrences": actual,
            "bytes_written": len(encoded),
            "changed": True,
        }, mutated=True)

    def _apply_patch_hunks(self, arguments: dict[str, object]) -> _ExecutionResult:
        plan = self._prepare_patch_hunks(arguments)
        self._atomic_write(
            plan.authorized,
            plan.replacement,
            mode="replace_only",
            expected_info=plan.expected_info,
            max_bytes=self.limits.max_patch_file_bytes,
        )
        try:
            self._verify_patch_postcondition(plan)
        except (ToolOperationalError, ToolPolicyError):
            self._restore_failed_patch(plan)
            raise
        return _ExecutionResult({
            "path": plan.authorized.repository_path,
            "old_sha256": plan.old_sha256,
            "new_sha256": plan.new_sha256,
            "hunks_applied": plan.hunks_applied,
            "lines_added": plan.lines_added,
            "lines_removed": plan.lines_removed,
            "diff_excerpt": plan.diff_excerpt,
            "diff_truncated": (
                len(plan.diff_excerpt.encode("utf-8")) >= MAX_PATCH_DIFF_BYTES),
            "mutation_generation": self.mutation_generation + 1,
        }, mutated=True)

    def _prepare_patch_hunks(self, arguments: Mapping[str, object]) -> _PatchPlan:
        path = self._required_string(arguments, "path")
        expected_sha256 = self._required_string(arguments, "expected_sha256")
        if (len(expected_sha256) != 64
                or any(character not in "0123456789abcdef"
                       for character in expected_sha256)):
            raise ToolValidationError(
                "expected_sha256 must be 64 lowercase hexadecimal characters")
        hunks_value = arguments.get("hunks")
        if not isinstance(hunks_value, list) or not hunks_value:
            raise ToolValidationError("hunks must contain at least one item")
        if len(hunks_value) > MAX_PATCH_HUNKS:
            raise ToolValidationError("hunk count exceeds its limit")

        hunks: list[tuple[bytes, bytes]] = []
        total_context = 0
        total_replacement = 0
        lines_removed = 0
        lines_added = 0
        for item in hunks_value:
            if not isinstance(item, dict):
                raise ToolValidationError("hunk must be an object")
            old_text = self._required_string(item, "old_text")
            replacement = self._required_string(item, "replacement")
            if not old_text:
                raise ToolValidationError("hunk old_text must not be empty")
            try:
                old = old_text.encode(TEXT_ENCODING, errors="strict")
                new = replacement.encode(TEXT_ENCODING, errors="strict")
            except UnicodeEncodeError as exc:
                raise ToolValidationError("hunk text must be valid UTF-8") from exc
            if b"\r" in old or b"\r" in new:
                raise ToolValidationError("patch hunks support LF newlines only")
            if len(old) > MAX_PATCH_CONTEXT_BYTES:
                raise ToolValidationError("hunk context exceeds its byte limit")
            if len(new) > MAX_PATCH_REPLACEMENT_BYTES:
                raise ToolValidationError("hunk replacement exceeds its byte limit")
            total_context += len(old)
            total_replacement += len(new)
            lines_removed += self._patch_line_count(old)
            lines_added += self._patch_line_count(new)
            hunks.append((old, new))
        if total_context > MAX_PATCH_TOTAL_CONTEXT_BYTES:
            raise ToolValidationError("total hunk context exceeds its byte limit")
        if total_replacement > MAX_PATCH_TOTAL_REPLACEMENT_BYTES:
            raise ToolValidationError("total hunk replacement exceeds its byte limit")
        if lines_removed + lines_added > MAX_PATCH_CHANGED_LINES:
            raise ToolValidationError("patch changed-line count exceeds its limit")

        authorized = self._reauthorize("apply_patch_hunks", path, write=True)
        fd, info = self.policy.open_regular(authorized)
        try:
            if info.st_size > self.limits.max_patch_file_bytes:
                raise ToolOperationalError("patch target exceeds its output size limit")
            original = self._read_up_to(fd, self.limits.max_patch_file_bytes + 1)
        finally:
            os.close(fd)
        if len(original) > self.limits.max_patch_file_bytes:
            raise ToolOperationalError("patch target exceeds its output size limit")
        if self._looks_binary(original):
            raise ToolOperationalError("patch target is not supported UTF-8 text")
        try:
            original.decode(TEXT_ENCODING, errors="strict")
        except UnicodeDecodeError as exc:
            raise ToolOperationalError("patch target is not valid UTF-8") from exc
        if b"\r" in original:
            raise ToolOperationalError("patch target does not use LF-only newlines")
        old_sha256 = hashlib.sha256(original).hexdigest()
        if old_sha256 != expected_sha256:
            raise ToolOperationalError("patch target SHA-256 mismatch")

        located: list[tuple[int, int, bytes, bytes]] = []
        previous_end = 0
        for old, new in hunks:
            occurrences = original.count(old)
            if occurrences == 0:
                raise ToolOperationalError("patch hunk context mismatch")
            if occurrences != 1:
                raise ToolOperationalError("patch hunk context is ambiguous")
            start = original.find(old)
            end = start + len(old)
            if start < previous_end:
                raise ToolValidationError(
                    "patch hunks overlap or are out of source order")
            previous_end = end
            located.append((start, end, old, new))

        pieces: list[bytes] = []
        cursor = 0
        for start, end, _, replacement_bytes in located:
            pieces.append(original[cursor:start])
            pieces.append(replacement_bytes)
            cursor = end
        pieces.append(original[cursor:])
        output = b"".join(pieces)
        if output == original:
            raise ToolValidationError("patch hunks do not change the target")
        if len(output) > self.limits.max_patch_file_bytes:
            raise ToolValidationError("patched output exceeds its size limit")
        new_sha256 = hashlib.sha256(output).hexdigest()
        return _PatchPlan(
            authorized=authorized,
            expected_info=info,
            original=original,
            replacement=output,
            old_sha256=old_sha256,
            new_sha256=new_sha256,
            hunks_applied=len(located),
            lines_added=lines_added,
            lines_removed=lines_removed,
            diff_excerpt=self._patch_diff_excerpt(path, located),
        )

    @staticmethod
    def _patch_line_count(value: bytes) -> int:
        return len(value.splitlines()) if value else 0

    @staticmethod
    def _patch_diff_excerpt(
        path: str, located: Sequence[tuple[int, int, bytes, bytes]],
    ) -> str:
        chunks = [f"--- {path}\n+++ {path}\n"]
        for index, (_, _, old, new) in enumerate(located, start=1):
            chunks.append(f"@@ bounded-hunk {index} @@\n")
            chunks.extend(
                f"-{line}\n" for line in old.decode("utf-8").splitlines())
            chunks.extend(
                f"+{line}\n" for line in new.decode("utf-8").splitlines())
        encoded = "".join(chunks).encode("utf-8")
        if len(encoded) <= MAX_PATCH_DIFF_BYTES:
            return encoded.decode("utf-8")
        return encoded[:MAX_PATCH_DIFF_BYTES].decode("utf-8", errors="ignore")

    def _verify_patch_postcondition(self, plan: _PatchPlan) -> None:
        authorized = self.policy.authorize_write(
            plan.authorized.repository_path or "")
        fd, info = self.policy.open_regular(authorized)
        try:
            if info.st_size != len(plan.replacement):
                raise ToolOperationalError("patch postcondition size mismatch")
            actual = self._read_up_to(fd, len(plan.replacement) + 1)
        finally:
            os.close(fd)
        if actual != plan.replacement:
            raise ToolOperationalError("patch postcondition content mismatch")
        if hashlib.sha256(actual).hexdigest() != plan.new_sha256:
            raise ToolOperationalError("patch postcondition hash mismatch")

    def _restore_failed_patch(self, plan: _PatchPlan) -> None:
        try:
            authorized = self.policy.authorize_write(
                plan.authorized.repository_path or "")
            fd, current_info = self.policy.open_regular(authorized)
            os.close(fd)
            self._atomic_write(
                authorized,
                plan.original,
                mode="replace_only",
                expected_info=current_info,
                max_bytes=self.limits.max_patch_file_bytes,
            )
        except (OSError, ToolOperationalError, ToolPolicyError) as exc:
            raise ToolOperationalError(
                "patch postcondition failed and rollback was not safe") from exc

    def _write_file(self, arguments: dict[str, object]) -> _ExecutionResult:
        path = self._required_string(arguments, "path")
        content = self._required_string(arguments, "content")
        mode = self._required_string(arguments, "mode")
        data = self._encode_write(content)
        authorized = self._reauthorize("write_file", path, write=True)
        self._atomic_write(authorized, data, mode=mode)
        return _ExecutionResult({
            "path": path,
            "mode": mode,
            "bytes_written": len(data),
        }, mutated=True)

    def _delete_file(self, arguments: dict[str, object]) -> _ExecutionResult:
        path = self._required_string(arguments, "path")
        authorized = self._reauthorize("delete_file", path, write=True)
        parent_fd, name = self.policy.open_write_parent(authorized)
        try:
            try:
                info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return _ExecutionResult({"path": path, "deleted": False})
            if stat.S_ISLNK(info.st_mode):
                raise ToolPolicyError("symlink deletion is not allowed")
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ToolPolicyError("only regular files may be deleted")
            os.unlink(name, dir_fd=parent_fd)
            self._sync_directory(parent_fd)
        finally:
            os.close(parent_fd)
        return _ExecutionResult(
            {"path": path, "deleted": True}, mutated=True)

    def _atomic_write(self, authorized: AuthorizedPath, data: bytes,
                      mode: str,
                      expected_info: Optional[os.stat_result] = None,
                      max_bytes: Optional[int] = None) -> None:
        write_limit = self.limits.max_write_bytes if max_bytes is None else max_bytes
        if len(data) > write_limit:
            raise ToolValidationError("file content exceeds the configured write limit")
        parent_fd, target_name = self.policy.open_write_parent(authorized)
        temp_name = f".cve-agent-{uuid.uuid4().hex}.tmp"
        temp_created = False
        try:
            target_info = self._target_info(parent_fd, target_name)
            if mode == "create_only" and target_info is not None:
                raise ToolOperationalError("create_only target already exists")
            if mode == "replace_only" and target_info is None:
                raise ToolOperationalError("replace_only target does not exist")
            if target_info is not None:
                if stat.S_ISLNK(target_info.st_mode):
                    raise ToolPolicyError("writable target must not be a symlink")
                if (not stat.S_ISREG(target_info.st_mode)
                        or target_info.st_nlink != 1):
                    raise ToolPolicyError("writable target must be a regular file")
            if expected_info is not None and not self._same_file_version(
                    target_info, expected_info):
                raise ToolOperationalError("target changed before replacement")

            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _CLOEXEC | _NOFOLLOW
            temp_fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
            temp_created = True
            try:
                self._write_all(temp_fd, data)
                if target_info is not None:
                    os.fchmod(temp_fd, stat.S_IMODE(target_info.st_mode))
                os.fsync(temp_fd)
            finally:
                os.close(temp_fd)

            if self._before_replace is not None:
                self._before_replace(authorized.display_path)

            current_info = self._target_info(parent_fd, target_name)
            if mode == "create_only" and current_info is not None:
                raise ToolOperationalError("create_only target appeared before replacement")
            if mode == "replace_only" and current_info is None:
                raise ToolOperationalError("replace_only target disappeared before replacement")
            if current_info is not None and (
                    not stat.S_ISREG(current_info.st_mode)
                    or current_info.st_nlink != 1):
                raise ToolPolicyError("writable target became unsafe")
            comparison = expected_info if expected_info is not None else target_info
            if comparison is not None and not self._same_file_version(
                    current_info, comparison):
                raise ToolOperationalError("target changed before replacement")

            self._replace_in_parent(
                parent_fd, temp_name, target_name, authorized.display_path.parent)
            temp_created = False
            self._sync_directory(parent_fd)
        finally:
            if temp_created:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temp_name, dir_fd=parent_fd)
            os.close(parent_fd)

    @staticmethod
    def _target_info(parent_fd: int, name: str) -> Optional[os.stat_result]:
        try:
            return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None

    @staticmethod
    def _same_file_version(current: Optional[os.stat_result],
                           expected: os.stat_result) -> bool:
        if current is None:
            return False
        return (
            current.st_dev,
            current.st_ino,
            current.st_size,
            current.st_mtime_ns,
            current.st_nlink,
        ) == (
            expected.st_dev,
            expected.st_ino,
            expected.st_size,
            expected.st_mtime_ns,
            expected.st_nlink,
        )

    @staticmethod
    def _replace_in_parent(parent_fd: int, temp_name: str,
                           target_name: str, parent_path: Path) -> None:
        try:
            os.replace(
                temp_name, target_name,
                src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        except (TypeError, NotImplementedError):
            # Python platforms without dir_fd replacement fall back to lexical
            # paths. Re-check that the lexical parent still names the anchored
            # directory and that the target is not a symlink. A hostile
            # external process still retains a narrow check/replace race.
            expected_parent = os.fstat(parent_fd)
            try:
                actual_parent = os.stat(parent_path, follow_symlinks=False)
            except OSError as exc:
                raise ToolOperationalError(
                    "atomic replacement parent is unavailable") from exc
            if (stat.S_ISLNK(actual_parent.st_mode)
                    or (actual_parent.st_dev, actual_parent.st_ino)
                    != (expected_parent.st_dev, expected_parent.st_ino)):
                raise ToolPolicyError(
                    "atomic replacement parent changed during execution") from None
            try:
                target_info = os.stat(
                    parent_path / target_name, follow_symlinks=False)
            except FileNotFoundError:
                target_info = None
            if target_info is not None and stat.S_ISLNK(target_info.st_mode):
                raise ToolPolicyError(
                    "writable target became a symlink") from None
            os.replace(parent_path / temp_name, parent_path / target_name)

    @staticmethod
    def _sync_directory(parent_fd: int) -> None:
        # Some filesystems do not support directory fsync. The file itself was
        # fsynced before replacement and the mutation already happened.
        with contextlib.suppress(OSError):
            os.fsync(parent_fd)

    @staticmethod
    def _read_up_to(fd: int, limit: int) -> bytes:
        chunks: list[bytes] = []
        remaining = limit
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    @staticmethod
    def _looks_binary(data: bytes) -> bool:
        if b"\x00" in data:
            return True
        if not data:
            return False
        controls = sum(
            byte < 32 and byte not in {9, 10, 13}
            for byte in data)
        return controls * 10 > len(data) * 3

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = os.write(fd, view[written:])
            if count <= 0:
                raise ToolOperationalError("atomic write made no progress")
            written += count

    def _encode_write(self, text: str) -> bytes:
        try:
            data = text.encode(TEXT_ENCODING, errors="strict")
        except UnicodeEncodeError as exc:
            raise ToolValidationError("file content is not valid UTF-8 text") from exc
        if len(data) > self.limits.max_write_bytes:
            raise ToolValidationError("file content exceeds the configured write limit")
        return data

    @staticmethod
    def _required_string(arguments: Mapping[str, object], name: str) -> str:
        value = arguments[name]
        if not isinstance(value, str):
            raise ToolValidationError(f"field '{name}' must be a string")
        return value

    @staticmethod
    def _required_integer(arguments: Mapping[str, object], name: str) -> int:
        value = arguments[name]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ToolValidationError(f"field '{name}' must be an integer")
        return value

    @staticmethod
    def _optional_integer(arguments: Mapping[str, object],
                          name: str, default: int) -> int:
        if name not in arguments:
            return default
        return FileToolRuntime._required_integer(arguments, name)

    @staticmethod
    def _string_item(value: object, field: str) -> str:
        if not isinstance(value, str):
            raise ToolValidationError(f"field '{field}' items must be strings")
        return value
