# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Versioned portable provider capabilities and retained failure evidence."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from enum import Enum

PROVIDER_CAPABILITY_SCHEMA_VERSION = 1
MAX_PROVIDER_PATH_BYTES = 128
MAX_PROVIDER_REQUEST_BYTES = 1024 * 1024
MAX_PROVIDER_RESPONSE_BYTES = 1024 * 1024

_PATH_RE = re.compile(r"^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*$", re.ASCII)


class ProviderErrorCode(str, Enum):
    AUTH = "PROVIDER_AUTH"
    MODEL_NOT_FOUND = "PROVIDER_MODEL_NOT_FOUND"
    REQUEST_REJECTED = "PROVIDER_REQUEST_REJECTED"
    TOOL_PROTOCOL_UNSUPPORTED = "PROVIDER_TOOL_PROTOCOL_UNSUPPORTED"
    REASONING_PROTOCOL_UNSUPPORTED = "PROVIDER_REASONING_PROTOCOL_UNSUPPORTED"
    RESPONSE_TRUNCATED = "PROVIDER_RESPONSE_TRUNCATED"
    MALFORMED_RESPONSE = "PROVIDER_MALFORMED_RESPONSE"
    RESPONSE_TOO_LARGE = "PROVIDER_RESPONSE_TOO_LARGE"
    CONNECT_TIMEOUT = "PROVIDER_CONNECT_TIMEOUT"
    READ_TIMEOUT = "PROVIDER_READ_TIMEOUT"
    RATE_LIMIT = "PROVIDER_RATE_LIMIT"
    SERVER_ERROR = "PROVIDER_SERVER_ERROR"
    CONNECTION_LOST = "PROVIDER_CONNECTION_LOST"
    DEADLINE_EXHAUSTED = "PROVIDER_DEADLINE_EXHAUSTED"


@dataclass(frozen=True)
class ProviderCapabilities:
    """Strict allowlisted Chat Completions dialect for one profile."""

    chat_completions_path: str = "chat/completions"
    supports_tools: bool = True
    supports_parallel_tool_calls: bool = True
    supports_tool_choice: bool = True
    tool_choice_values: tuple[str, ...] = ("auto",)
    output_token_field: str = "max_tokens"
    reasoning_request_field: str = "reasoning_effort"
    reasoning_response_field: str = "none"
    requires_reasoning_replay: bool = False
    supports_response_usage: bool = True
    supports_request_ids: bool = True
    max_request_bytes: int = MAX_PROVIDER_REQUEST_BYTES
    max_response_bytes: int = MAX_PROVIDER_RESPONSE_BYTES
    schema_version: int = PROVIDER_CAPABILITY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        path = self.chat_completions_path.strip("/")
        if (not path or len(path.encode("ascii", errors="ignore"))
                != len(path.encode("utf-8"))
                or len(path.encode("ascii")) > MAX_PROVIDER_PATH_BYTES
                or not _PATH_RE.fullmatch(path)
                or not path.endswith("chat/completions")):
            raise ValueError("chat_completions_path must be a bounded relative API path")
        object.__setattr__(self, "chat_completions_path", path)
        for name in (
            "supports_tools", "supports_parallel_tool_calls", "supports_tool_choice",
            "requires_reasoning_replay", "supports_response_usage",
            "supports_request_ids",
        ):
            if not isinstance(getattr(self, name), bool):
                raise ValueError(f"{name} must be a strict boolean")
        if (not isinstance(self.tool_choice_values, tuple)
                or not self.tool_choice_values
                or len(self.tool_choice_values) > 3
                or any(value not in {"auto", "none", "required"}
                       for value in self.tool_choice_values)
                or len(set(self.tool_choice_values)) != len(self.tool_choice_values)):
            raise ValueError("tool_choice_values contains an unsupported value")
        if self.supports_tool_choice and "auto" not in self.tool_choice_values:
            raise ValueError("tool_choice_values must include auto")
        if not self.supports_tool_choice and self.tool_choice_values != ("auto",):
            raise ValueError("tool_choice_values require supports_tool_choice")
        if self.supports_parallel_tool_calls and not self.supports_tools:
            raise ValueError("parallel tool calls require tool support")
        if self.supports_tool_choice and not self.supports_tools:
            raise ValueError("tool_choice requires tool support")
        if self.output_token_field not in {"max_tokens", "max_completion_tokens"}:
            raise ValueError("output_token_field is unsupported")
        if self.reasoning_request_field not in {"none", "reasoning_effort"}:
            raise ValueError("reasoning_request_field is unsupported")
        if self.reasoning_response_field not in {
                "none", "reasoning", "reasoning_content"}:
            raise ValueError("reasoning_response_field is unsupported")
        if (self.requires_reasoning_replay
                and self.reasoning_response_field == "none"):
            raise ValueError("reasoning replay requires a response field")
        for name, ceiling in (
            ("max_request_bytes", MAX_PROVIDER_REQUEST_BYTES),
            ("max_response_bytes", MAX_PROVIDER_RESPONSE_BYTES),
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
            if value < 1024 or value > ceiling:
                raise ValueError(f"{name} must be between 1024 and {ceiling}")
        if self.schema_version != PROVIDER_CAPABILITY_SCHEMA_VERSION:
            raise ValueError("unsupported provider capability schema version")

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.to_dict(), sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["tool_choice_values"] = list(self.tool_choice_values)
        return value


@dataclass(frozen=True)
class ProviderFailureEvidence:
    """Bounded credential-free facts retained for a provider failure."""

    code: ProviderErrorCode
    status_code: int | None = None
    request_id: str | None = None
    retry_after: float | None = None
    response_sha256: str | None = None
    response_excerpt: str | None = None
    request_features: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code.value,
            "status_code": self.status_code,
            "request_id": self.request_id,
            "retry_after": self.retry_after,
            "response_sha256": self.response_sha256,
            "response_excerpt": self.response_excerpt,
            "request_features": list(self.request_features),
        }
