# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Bounded non-streaming OpenAI-compatible Chat Completions client.

The client performs one transport exchange and validates one assistant
message. It deliberately does not decode function arguments into tool input,
dispatch tools, or maintain a multi-turn conversation.

``requests.Response.iter_content()`` yields transparently decompressed bytes.
The response limit is therefore enforced on decoded bytes, not merely on a
possibly compressed ``Content-Length`` value. A declared wire length above
the same limit is also rejected conservatively before reading.
"""
import hashlib
import json
import math
import os
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Optional, Protocol

import requests

from .openai_backend import OpenAIConfig
from .openai_deadline import SessionDeadline
from .openai_provider import (
    ProviderCapabilities,
    ProviderErrorCode,
    ProviderFailureEvidence,
)
from .openai_redaction import redact_openai_text

DEFAULT_MAX_MESSAGES = 128
DEFAULT_MAX_TOOLS = 64
DEFAULT_MAX_REQUEST_BYTES = 1024 * 1024
DEFAULT_MAX_MESSAGE_BYTES = 256 * 1024
DEFAULT_MAX_TOOL_SCHEMA_BYTES = 64 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024
DEFAULT_MAX_RESPONSE_HEADERS = 128
DEFAULT_MAX_RESPONSE_HEADER_BYTES = 64 * 1024
DEFAULT_MAX_CONTENT_BYTES = 512 * 1024
DEFAULT_MAX_ARGUMENT_BYTES = 256 * 1024
DEFAULT_MAX_JSON_DEPTH = 32
DEFAULT_MAX_JSON_NODES = 20_000
DEFAULT_MAX_CHOICES = 8
DEFAULT_MAX_TOOL_CALLS = 64
DEFAULT_MAX_IDENTIFIER_BYTES = 256
DEFAULT_MAX_ERROR_SNIPPET_BYTES = 512
RESPONSE_CHUNK_BYTES = 16 * 1024

MAX_HTTP_ATTEMPTS = 5
MAX_RETRY_DELAY_SECONDS = 10.0
_RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})


class OpenAIClientError(RuntimeError):
    """Base class for safe native Chat Completions client failures."""

    code = ProviderErrorCode.REQUEST_REJECTED

    def __init__(
        self, message: str, evidence: ProviderFailureEvidence | None = None,
    ) -> None:
        super().__init__(message)
        self.evidence = evidence


class OpenAILocalRequestError(OpenAIClientError, ValueError):
    """Local request data or client limits are invalid."""


class OpenAIConnectionError(OpenAIClientError):
    """The HTTP connection failed before a response was completed."""

    code = ProviderErrorCode.CONNECTION_LOST


class OpenAIRequestTimeoutError(OpenAIClientError, TimeoutError):
    """A configured transport timeout expired."""

    code = ProviderErrorCode.READ_TIMEOUT


class OpenAIConnectTimeoutError(OpenAIRequestTimeoutError):
    """The connection phase exceeded its timeout."""

    code = ProviderErrorCode.CONNECT_TIMEOUT


class OpenAIReadTimeoutError(OpenAIRequestTimeoutError):
    """The response-read phase exceeded its timeout."""

    code = ProviderErrorCode.READ_TIMEOUT


class OpenAIDeadlineExceededError(OpenAIRequestTimeoutError):
    """The shared session deadline cannot accommodate more HTTP work."""

    code = ProviderErrorCode.DEADLINE_EXHAUSTED


class OpenAIAuthenticationError(OpenAIClientError):
    """The endpoint rejected authentication or authorization."""

    code = ProviderErrorCode.AUTH


class OpenAINotFoundError(OpenAIClientError):
    """The configured endpoint or model was not found."""

    code = ProviderErrorCode.MODEL_NOT_FOUND


class OpenAIRateLimitError(OpenAIClientError):
    """The endpoint remained rate limited after allowed attempts."""

    code = ProviderErrorCode.RATE_LIMIT


class OpenAIRetryableServerError(OpenAIClientError):
    """A selected transient server failure exhausted retry attempts."""

    code = ProviderErrorCode.SERVER_ERROR


class OpenAINonRetryableHTTPError(OpenAIClientError):
    """An HTTP response is not eligible for retry."""

    code = ProviderErrorCode.REQUEST_REJECTED


class OpenAIMalformedJSONError(OpenAIClientError):
    """The bounded response is not valid UTF-8 JSON."""

    code = ProviderErrorCode.MALFORMED_RESPONSE


class OpenAIProtocolError(OpenAIClientError):
    """The decoded server response violates the supported schema."""

    code = ProviderErrorCode.MALFORMED_RESPONSE


class OpenAIToolProtocolError(OpenAIProtocolError):
    """The provider's tool-call dialect is unsupported."""

    code = ProviderErrorCode.TOOL_PROTOCOL_UNSUPPORTED


class OpenAIReasoningProtocolError(OpenAIProtocolError):
    """Configured reasoning fields cannot be sent or replayed safely."""

    code = ProviderErrorCode.REASONING_PROTOCOL_UNSUPPORTED


class OpenAIResponseTruncatedError(OpenAIProtocolError):
    """The provider explicitly truncated a response or tool call."""

    code = ProviderErrorCode.RESPONSE_TRUNCATED


class OpenAIResponseSizeError(OpenAIClientError):
    """The decoded response exceeds the configured byte bound."""

    code = ProviderErrorCode.RESPONSE_TOO_LARGE


@dataclass(frozen=True)
class OpenAIClientLimits:
    """Hard-capped request and response allocation limits."""

    max_messages: int = DEFAULT_MAX_MESSAGES
    max_tools: int = DEFAULT_MAX_TOOLS
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_tool_schema_bytes: int = DEFAULT_MAX_TOOL_SCHEMA_BYTES
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    max_response_headers: int = DEFAULT_MAX_RESPONSE_HEADERS
    max_response_header_bytes: int = DEFAULT_MAX_RESPONSE_HEADER_BYTES
    max_content_bytes: int = DEFAULT_MAX_CONTENT_BYTES
    max_argument_bytes: int = DEFAULT_MAX_ARGUMENT_BYTES
    max_json_depth: int = DEFAULT_MAX_JSON_DEPTH
    max_json_nodes: int = DEFAULT_MAX_JSON_NODES
    max_choices: int = DEFAULT_MAX_CHOICES
    max_tool_calls: int = DEFAULT_MAX_TOOL_CALLS
    max_identifier_bytes: int = DEFAULT_MAX_IDENTIFIER_BYTES
    max_error_snippet_bytes: int = DEFAULT_MAX_ERROR_SNIPPET_BYTES

    def __post_init__(self) -> None:
        ceilings = {
            "max_messages": DEFAULT_MAX_MESSAGES,
            "max_tools": DEFAULT_MAX_TOOLS,
            "max_request_bytes": DEFAULT_MAX_REQUEST_BYTES,
            "max_message_bytes": DEFAULT_MAX_MESSAGE_BYTES,
            "max_tool_schema_bytes": DEFAULT_MAX_TOOL_SCHEMA_BYTES,
            "max_response_bytes": DEFAULT_MAX_RESPONSE_BYTES,
            "max_response_headers": DEFAULT_MAX_RESPONSE_HEADERS,
            "max_response_header_bytes": DEFAULT_MAX_RESPONSE_HEADER_BYTES,
            "max_content_bytes": DEFAULT_MAX_CONTENT_BYTES,
            "max_argument_bytes": DEFAULT_MAX_ARGUMENT_BYTES,
            "max_json_depth": DEFAULT_MAX_JSON_DEPTH,
            "max_json_nodes": DEFAULT_MAX_JSON_NODES,
            "max_choices": DEFAULT_MAX_CHOICES,
            "max_tool_calls": DEFAULT_MAX_TOOL_CALLS,
            "max_identifier_bytes": DEFAULT_MAX_IDENTIFIER_BYTES,
            "max_error_snippet_bytes": DEFAULT_MAX_ERROR_SNIPPET_BYTES,
        }
        for name, ceiling in ceilings.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
            if value < 1 or value > ceiling:
                raise ValueError(f"{name} must be between 1 and {ceiling}")


@dataclass(frozen=True)
class OpenAIRetryPolicy:
    """Small retry policy for connection, rate-limit, and gateway failures."""

    max_attempts: int = 3
    initial_backoff: float = 0.25
    backoff_multiplier: float = 2.0
    max_delay: float = 2.0

    def __post_init__(self) -> None:
        if (isinstance(self.max_attempts, bool)
                or not isinstance(self.max_attempts, int)
                or self.max_attempts < 1
                or self.max_attempts > MAX_HTTP_ATTEMPTS):
            raise ValueError(
                f"max_attempts must be between 1 and {MAX_HTTP_ATTEMPTS}")
        for name in ("initial_backoff", "backoff_multiplier", "max_delay"):
            value = getattr(self, name)
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or value < 0):
                raise ValueError(f"{name} must be a finite nonnegative number")
        if self.backoff_multiplier < 1:
            raise ValueError("backoff_multiplier must be at least 1")
        if self.max_delay > MAX_RETRY_DELAY_SECONDS:
            raise ValueError(
                f"max_delay must not exceed {MAX_RETRY_DELAY_SECONDS}")


@dataclass(frozen=True)
class TokenUsage:
    """Portable optional token counts returned by compatible endpoints."""

    prompt_tokens: Optional[int]
    completion_tokens: Optional[int]
    total_tokens: Optional[int]


@dataclass(frozen=True)
class FunctionToolCall:
    """One bounded function call whose arguments remain untrusted JSON text."""

    id: str
    name: str
    arguments: str
    arguments_were_object: bool = False


@dataclass(frozen=True)
class AssistantResponse:
    """Validated first assistant choice from one Chat Completions response."""

    content: Optional[str]
    tool_calls: tuple[FunctionToolCall, ...]
    finish_reason: Optional[str]
    usage: Optional[TokenUsage]
    reasoning_replay: Optional[tuple[str, str]] = None


@dataclass(frozen=True)
class OpenAIClientEvent:
    """Credential-free transport event suitable for audit/transcript sinks."""

    kind: str
    attempt: int
    status_code: Optional[int] = None
    delay: Optional[float] = None
    failure: ProviderFailureEvidence | None = None
    request_id: str | None = None
    request_features: tuple[str, ...] = ()


class HTTPResponse(Protocol):
    """Minimal streamed response surface used from ``requests``."""

    status_code: int
    headers: Mapping[str, str]

    def iter_content(self, chunk_size: int,
                     decode_unicode: bool = False) -> Iterable[bytes]:
        """Yield decoded response-body byte chunks."""

    def close(self) -> None:
        """Release the connection and response resources."""


class HTTPTransport(Protocol):
    """Injectable subset of ``requests`` used by the client."""

    def post(self, url: str, **kwargs: object) -> HTTPResponse:
        """Issue one streamed POST request."""


EventSink = Callable[[OpenAIClientEvent], None]


class OpenAIChatCompletionsClient:
    """Send and validate one bounded non-streaming Chat Completions request."""

    def __init__(
        self,
        config: OpenAIConfig,
        deadline: SessionDeadline,
        *,
        limits: Optional[OpenAIClientLimits] = None,
        retry_policy: Optional[OpenAIRetryPolicy] = None,
        transport: Optional[HTTPTransport] = None,
        environ: Optional[Mapping[str, str]] = None,
        sleep: Callable[[float], None] = time.sleep,
        event_sink: Optional[EventSink] = None,
        capabilities: ProviderCapabilities | None = None,
    ) -> None:
        self.config = config
        self.deadline = deadline
        self.capabilities = capabilities or ProviderCapabilities()
        configured_limits = limits or OpenAIClientLimits()
        self.limits = replace(
            configured_limits,
            max_request_bytes=min(
                configured_limits.max_request_bytes,
                self.capabilities.max_request_bytes),
            max_response_bytes=min(
                configured_limits.max_response_bytes,
                self.capabilities.max_response_bytes),
        )
        self.retry_policy = retry_policy or OpenAIRetryPolicy()
        self._transport = requests if transport is None else transport
        self._environ = os.environ if environ is None else environ
        self._sleep = sleep
        self._event_sink = event_sink
        self._last_request_features: tuple[str, ...] = ()

    def __repr__(self) -> str:
        """Return configuration diagnostics without environment values."""
        return (
            f"{type(self).__name__}(base_url={self.config.base_url!r}, "
            f"model={self.config.model!r}, "
            f"api_key_env={self.config.api_key_env!r})"
        )

    @property
    def _chat_completions_url(self) -> str:
        return f"{self.config.base_url}/{self.capabilities.chat_completions_path}"

    def complete(
        self,
        messages: Sequence[dict[str, object]],
        tools: Sequence[dict[str, object]],
    ) -> AssistantResponse:
        """Perform one request without executing any returned tool calls."""
        request_bytes = self._build_request(messages, tools)
        headers, secret = self._headers()

        for attempt in range(1, self.retry_policy.max_attempts + 1):
            remaining = self._remaining("Chat Completions request")
            timeout = (
                min(float(self.config.connect_timeout), remaining),
                min(float(self.config.request_timeout), remaining),
            )
            self._emit(OpenAIClientEvent(
                "attempt", attempt,
                request_features=self._last_request_features))
            response: Optional[HTTPResponse] = None
            try:
                proxy_override = (
                    {"http": None, "https": None, "all": None}
                    if self.config.is_loopback else None
                )
                request_options: dict[str, object] = {
                    "data": request_bytes,
                    "headers": headers,
                    "timeout": timeout,
                    "stream": True,
                    "allow_redirects": False,
                }
                if proxy_override is not None:
                    request_options["proxies"] = proxy_override
                response = self._transport.post(
                    self._chat_completions_url,
                    **request_options,
                )
                body = self._read_response(response)
                status = response.status_code
            except requests.RequestException as exc:
                timeout_kind = _transport_timeout_kind(exc)
                if timeout_kind is not None:
                    self._emit(OpenAIClientEvent("timeout", attempt))
                    error_type = (
                        OpenAIConnectTimeoutError
                        if timeout_kind == "connect" else OpenAIReadTimeoutError)
                    timeout_error = error_type("Chat Completions request timed out")
                    timeout_error.evidence = ProviderFailureEvidence(
                        timeout_error.code,
                        request_features=self._last_request_features)
                    self._emit(OpenAIClientEvent(
                        "failure", attempt, failure=timeout_error.evidence))
                    raise timeout_error from None
                self._emit(OpenAIClientEvent("connection_error", attempt))
                if response is not None or attempt >= self.retry_policy.max_attempts:
                    connection_error = OpenAIConnectionError(
                        "Chat Completions connection failed")
                    connection_error.evidence = ProviderFailureEvidence(
                        connection_error.code,
                        request_features=self._last_request_features)
                    self._emit(OpenAIClientEvent(
                        "failure", attempt, failure=connection_error.evidence))
                    raise connection_error from None
                self._retry_sleep(attempt, None)
                continue
            except OpenAIConnectionError as caught:
                self._emit(OpenAIClientEvent("connection_error", attempt))
                if response is not None or attempt >= self.retry_policy.max_attempts:
                    caught.evidence = ProviderFailureEvidence(
                        caught.code, request_features=self._last_request_features)
                    self._emit(OpenAIClientEvent(
                        "failure", attempt, failure=caught.evidence))
                    raise caught
                self._retry_sleep(attempt, None)
                continue
            except OpenAIClientError as caught:
                status_code = (
                    response.status_code
                    if response is not None
                    and isinstance(response.status_code, int)
                    and not isinstance(response.status_code, bool)
                    else None
                )
                response_headers = response.headers if response is not None else {}
                caught.evidence = ProviderFailureEvidence(
                    caught.code,
                    status_code=status_code,
                    request_id=self._safe_request_id(response_headers),
                    retry_after=self._retry_after(response_headers),
                    request_features=self._last_request_features,
                )
                self._emit(OpenAIClientEvent(
                    "failure", attempt, status_code=status_code,
                    failure=caught.evidence))
                raise
            finally:
                if response is not None:
                    try:
                        response.close()
                    except Exception:
                        raise OpenAIConnectionError(
                            "Chat Completions response cleanup failed") from None

            if isinstance(status, bool) or not isinstance(status, int):
                raise OpenAIProtocolError("HTTP response status is not an integer")
            self._emit(OpenAIClientEvent(
                "response", attempt, status_code=status,
                request_id=self._safe_request_id(response.headers),
                request_features=self._last_request_features))
            if status == 200:
                try:
                    return self._parse_response(body)
                except OpenAIClientError as error:
                    error.evidence = self._response_evidence(
                        error.code, status, response.headers, body, secret)
                    self._emit(OpenAIClientEvent(
                        "failure", attempt, status_code=status,
                        failure=error.evidence))
                    raise

            http_error = self._http_error(status, response.headers, body, secret)
            if status in _RETRYABLE_STATUSES and attempt < self.retry_policy.max_attempts:
                retry_after = self._retry_after(response.headers)
                self._retry_sleep(attempt, retry_after, status)
                continue
            self._emit(OpenAIClientEvent(
                "failure", attempt, status_code=status,
                failure=http_error.evidence))
            raise http_error

        raise OpenAIConnectionError("Chat Completions attempts exhausted")

    def _build_request(
        self,
        messages: Sequence[dict[str, object]],
        tools: Sequence[dict[str, object]],
    ) -> bytes:
        if isinstance(messages, (str, bytes)) or not isinstance(messages, Sequence):
            raise OpenAILocalRequestError("messages must be a sequence")
        if isinstance(tools, (str, bytes)) or not isinstance(tools, Sequence):
            raise OpenAILocalRequestError("tools must be a sequence")
        if not messages:
            raise OpenAILocalRequestError("at least one message is required")
        if len(messages) > self.limits.max_messages:
            raise OpenAILocalRequestError("message count exceeds the configured limit")
        if len(tools) > self.limits.max_tools:
            raise OpenAILocalRequestError("tool count exceeds the configured limit")
        if len(self.config.model.encode("utf-8")) > self.limits.max_identifier_bytes:
            raise OpenAILocalRequestError("model identifier exceeds the configured limit")

        normalized_messages: list[dict[str, object]] = []
        normalized_tools: list[dict[str, object]] = []
        estimated = len(self.config.model.encode("utf-8")) + 128
        portable_fields: dict[str, object] = {}
        if self.config.temperature is not None:
            portable_fields["temperature"] = self.config.temperature
        if self.config.top_p is not None:
            portable_fields["top_p"] = self.config.top_p
        if self.config.reasoning_effort is not None:
            if self.capabilities.reasoning_request_field == "none":
                raise OpenAIReasoningProtocolError(
                    "configured reasoning effort is unsupported by provider profile")
            portable_fields[
                self.capabilities.reasoning_request_field] = self.config.reasoning_effort
        if portable_fields:
            estimated += len(json.dumps(
                portable_fields, separators=(",", ":"),
                allow_nan=False).encode("utf-8"))
        for message in messages:
            normalized, encoded = self._bounded_input_object(
                message, self.limits.max_message_bytes, "message")
            estimated += len(encoded) + 1
            if estimated > self.limits.max_request_bytes:
                raise OpenAILocalRequestError(
                    "serialized request exceeds the configured byte limit")
            normalized_messages.append(normalized)
        for tool in tools:
            normalized, encoded = self._bounded_input_object(
                tool, self.limits.max_tool_schema_bytes, "tool schema")
            estimated += len(encoded) + 1
            if estimated > self.limits.max_request_bytes:
                raise OpenAILocalRequestError(
                    "serialized request exceeds the configured byte limit")
            normalized_tools.append(normalized)

        body: dict[str, object] = {
            "model": self.config.model,
            "messages": normalized_messages,
            "stream": False,
            self.capabilities.output_token_field: self.config.max_output_tokens,
        }
        body.update(portable_fields)
        if normalized_tools:
            if not self.capabilities.supports_tools:
                raise OpenAIToolProtocolError(
                    "provider profile does not support function tools")
            body["tools"] = normalized_tools
            if self.capabilities.supports_tool_choice:
                body["tool_choice"] = "auto"
        try:
            encoded_request = json.dumps(
                body, ensure_ascii=False, separators=(",", ":"),
                allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise OpenAILocalRequestError(
                "request contains unsupported JSON values") from exc
        if len(encoded_request) > self.limits.max_request_bytes:
            raise OpenAILocalRequestError(
                "serialized request exceeds the configured byte limit")
        features = [
            self.capabilities.output_token_field,
            "non_streaming",
        ]
        if normalized_tools:
            features.append("tools")
        if "tool_choice" in body:
            features.append("tool_choice:auto")
        if self.config.reasoning_effort is not None:
            features.append(
                f"reasoning:{self.capabilities.reasoning_request_field}")
        self._last_request_features = tuple(features)
        return encoded_request

    def _bounded_input_object(
        self, value: object, byte_limit: int, label: str,
    ) -> tuple[dict[str, object], bytes]:
        if not isinstance(value, dict):
            raise OpenAILocalRequestError(f"each {label} must be an object")
        self._validate_json_tree(
            value, self.limits.max_json_depth,
            self.limits.max_json_nodes, OpenAILocalRequestError)
        try:
            encoded = json.dumps(
                value, ensure_ascii=False, separators=(",", ":"),
                allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise OpenAILocalRequestError(
                f"{label} contains unsupported JSON values") from exc
        if len(encoded) > byte_limit:
            raise OpenAILocalRequestError(
                f"serialized {label} exceeds the configured byte limit")
        return dict(value), encoded

    def _headers(self) -> tuple[dict[str, str], Optional[str]]:
        headers = {"Content-Type": "application/json"}
        value = self._environ.get(self.config.api_key_env)
        secret = value.strip() if value is not None else ""
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
        return headers, secret or None

    def _read_response(self, response: HTTPResponse) -> bytes:
        self._remaining("Chat Completions response read")
        self._validate_response_headers(response.headers)
        content_length = self._header(response.headers, "Content-Length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except (TypeError, ValueError):
                declared = -1
            if declared > self.limits.max_response_bytes:
                raise OpenAIResponseSizeError(
                    "response exceeds the configured byte limit")

        body = bytearray()
        try:
            chunks = response.iter_content(
                chunk_size=RESPONSE_CHUNK_BYTES, decode_unicode=False)
            for chunk in chunks:
                self._remaining("Chat Completions response read")
                if not chunk:
                    continue
                if not isinstance(chunk, bytes):
                    raise OpenAIProtocolError(
                        "HTTP response stream yielded non-byte content")
                if len(body) + len(chunk) > self.limits.max_response_bytes:
                    raise OpenAIResponseSizeError(
                        "response exceeds the configured byte limit")
                body.extend(chunk)
        except (OpenAIClientError, requests.RequestException):
            raise
        except (OSError, ValueError):
            raise OpenAIConnectionError(
                "Chat Completions response read failed") from None
        return bytes(body)

    def _validate_response_headers(self, headers: Mapping[str, str]) -> None:
        count = 0
        total = 0
        try:
            items = headers.items()
            for name, value in items:
                count += 1
                if count > self.limits.max_response_headers:
                    raise OpenAIProtocolError(
                        "HTTP response header count exceeds the limit")
                if not isinstance(name, str) or not isinstance(value, str):
                    raise OpenAIProtocolError(
                        "HTTP response headers must contain strings")
                total += len(name.encode("utf-8")) + len(value.encode("utf-8"))
                if total > self.limits.max_response_header_bytes:
                    raise OpenAIProtocolError(
                        "HTTP response headers exceed the byte limit")
        except OpenAIProtocolError:
            raise
        except (AttributeError, RuntimeError, UnicodeError):
            raise OpenAIProtocolError("HTTP response headers are malformed") from None

    def _parse_response(self, body: bytes) -> AssistantResponse:
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            raise OpenAIMalformedJSONError(
                "response is not valid UTF-8 JSON") from None
        self._preflight_json_depth(text)
        try:
            decoded = json.loads(text, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, RecursionError, ValueError):
            raise OpenAIMalformedJSONError("response is not valid JSON") from None
        self._validate_json_tree(
            decoded, self.limits.max_json_depth,
            self.limits.max_json_nodes, OpenAIProtocolError)
        if not isinstance(decoded, dict):
            raise OpenAIProtocolError("response top level must be an object")

        choices = decoded.get("choices")
        if not isinstance(choices, list) or not choices:
            raise OpenAIProtocolError("response choices must be a nonempty list")
        if len(choices) > self.limits.max_choices:
            raise OpenAIProtocolError("response choice count exceeds the limit")
        choice = choices[0]
        if not isinstance(choice, dict):
            raise OpenAIProtocolError("selected response choice must be an object")
        message = choice.get("message")
        if not isinstance(message, dict):
            raise OpenAIProtocolError("selected choice message must be an object")
        role = message.get("role")
        if role != "assistant":
            raise OpenAIProtocolError("selected message role must be assistant")

        content = message.get("content")
        if content is not None and not isinstance(content, str):
            raise OpenAIProtocolError(
                "assistant content must be a string or null")
        if (isinstance(content, str)
                and len(content.encode("utf-8")) > self.limits.max_content_bytes):
            raise OpenAIProtocolError("assistant content exceeds the byte limit")

        tool_calls = self._parse_tool_calls(message.get("tool_calls", []))
        if content is None and not tool_calls:
            raise OpenAIProtocolError(
                "assistant message must contain content or tool calls")
        finish_reason = choice.get("finish_reason")
        if finish_reason is not None:
            if not isinstance(finish_reason, str):
                raise OpenAIProtocolError("finish_reason must be a string or null")
            self._bounded_identifier(finish_reason, "finish_reason", allow_empty=True)
        reasoning_replay: tuple[str, str] | None = None
        reasoning_field = self.capabilities.reasoning_response_field
        if reasoning_field != "none":
            reasoning_value = message.get(reasoning_field)
            if reasoning_value is not None:
                if not isinstance(reasoning_value, str):
                    raise OpenAIReasoningProtocolError(
                        "reasoning response field must be a string")
                if len(reasoning_value.encode("utf-8")) > self.limits.max_content_bytes:
                    raise OpenAIReasoningProtocolError(
                        "reasoning response exceeds the byte limit")
                if self.capabilities.requires_reasoning_replay:
                    reasoning_replay = (reasoning_field, reasoning_value)
            elif self.capabilities.requires_reasoning_replay and tool_calls:
                raise OpenAIReasoningProtocolError(
                    "tool response omitted required reasoning replay field")
        usage = (
            self._parse_usage(decoded.get("usage"))
            if self.capabilities.supports_response_usage else None)
        return AssistantResponse(
            content=content,
            tool_calls=tuple(tool_calls),
            finish_reason=finish_reason,
            usage=usage,
            reasoning_replay=reasoning_replay,
        )

    def _parse_tool_calls(self, value: object) -> list[FunctionToolCall]:
        if not isinstance(value, list):
            raise OpenAIToolProtocolError("tool_calls must be a list")
        limit = self.limits.max_tool_calls
        if len(value) > limit:
            raise OpenAIToolProtocolError(
                "tool-call count exceeds the configured limit")
        if len(value) > 1 and not self.capabilities.supports_parallel_tool_calls:
            raise OpenAIToolProtocolError(
                "provider returned parallel tool calls contrary to its profile")
        calls: list[FunctionToolCall] = []
        identifiers: set[str] = set()
        for item in value:
            if not isinstance(item, dict):
                raise OpenAIToolProtocolError("each tool call must be an object")
            identifier = self._tool_identifier(
                item.get("id"), "tool-call ID")
            if identifier in identifiers:
                raise OpenAIToolProtocolError("duplicate tool-call ID")
            identifiers.add(identifier)
            if item.get("type") != "function":
                raise OpenAIToolProtocolError("tool-call type must be function")
            function = item.get("function")
            if not isinstance(function, dict):
                raise OpenAIToolProtocolError(
                    "tool-call function must be an object")
            name = self._tool_identifier(
                function.get("name"), "function name")
            arguments_value = function.get("arguments")
            was_object = False
            if isinstance(arguments_value, str):
                arguments = arguments_value
            elif isinstance(arguments_value, dict):
                # Ollama-compatible servers may return the already-decoded
                # argument object. Canonical JSON keeps the dispatcher boundary
                # identical while recording that accommodation explicitly.
                self._validate_json_tree(
                    arguments_value, self.limits.max_json_depth,
                    self.limits.max_json_nodes, OpenAIToolProtocolError)
                try:
                    arguments = json.dumps(
                        arguments_value, ensure_ascii=False,
                        separators=(",", ":"), allow_nan=False)
                except (TypeError, ValueError, UnicodeError, RecursionError):
                    raise OpenAIToolProtocolError(
                        "object-valued function arguments are not valid JSON") from None
                was_object = True
            else:
                raise OpenAIToolProtocolError(
                    "function arguments must be a JSON string or object")
            if len(arguments.encode("utf-8")) > self.limits.max_argument_bytes:
                raise OpenAIToolProtocolError(
                    "function arguments exceed the byte limit")
            calls.append(FunctionToolCall(
                id=identifier,
                name=name,
                arguments=arguments,
                arguments_were_object=was_object,
            ))
        return calls

    def _tool_identifier(self, value: object, label: str) -> str:
        try:
            return self._bounded_identifier(value, label)
        except OpenAIProtocolError as exc:
            raise OpenAIToolProtocolError(str(exc)) from None

    def _parse_usage(self, value: object) -> Optional[TokenUsage]:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise OpenAIProtocolError("usage must be an object when present")

        def count(name: str) -> Optional[int]:
            item = value.get(name)
            if item is None:
                return None
            if isinstance(item, bool) or not isinstance(item, int) or item < 0:
                raise OpenAIProtocolError(
                    f"usage field {name} must be a nonnegative integer")
            return item

        return TokenUsage(
            prompt_tokens=count("prompt_tokens"),
            completion_tokens=count("completion_tokens"),
            total_tokens=count("total_tokens"),
        )

    def _bounded_identifier(
        self, value: object, label: str, allow_empty: bool = False,
    ) -> str:
        if not isinstance(value, str):
            raise OpenAIProtocolError(f"{label} must be a string")
        if not value and not allow_empty:
            raise OpenAIProtocolError(f"{label} must not be empty")
        if (len(value.encode("utf-8")) > self.limits.max_identifier_bytes
                or any(not character.isprintable() for character in value)):
            raise OpenAIProtocolError(f"{label} is not a bounded printable value")
        return value

    def _http_error(
        self, status: int, headers: Mapping[str, str], body: bytes,
        secret: Optional[str],
    ) -> OpenAIClientError:
        snippet = self._safe_snippet(body, secret)
        suffix = f": {snippet}" if snippet else ""
        error: OpenAIClientError
        if status in {401, 403}:
            error = OpenAIAuthenticationError(
                f"Chat Completions authentication failed ({status}){suffix}")
        elif status == 404:
            error = OpenAINotFoundError(
                f"Chat Completions endpoint or model not found (404){suffix}")
        elif status == 429:
            error = OpenAIRateLimitError(
                f"Chat Completions rate limit persisted (429){suffix}")
        elif status in {502, 503, 504}:
            error = OpenAIRetryableServerError(
                f"Chat Completions transient server failure ({status}){suffix}")
        else:
            error = OpenAINonRetryableHTTPError(
                f"Chat Completions HTTP failure ({status}){suffix}")
        error.evidence = self._response_evidence(
            error.code, status, headers, body, secret)
        return error

    def _response_evidence(
        self,
        code: ProviderErrorCode,
        status: int,
        headers: Mapping[str, str],
        body: bytes,
        secret: str | None,
    ) -> ProviderFailureEvidence:
        request_id = self._safe_request_id(headers)
        return ProviderFailureEvidence(
            code=code,
            status_code=status,
            request_id=request_id,
            retry_after=self._retry_after(headers),
            response_sha256=hashlib.sha256(body).hexdigest(),
            response_excerpt=self._safe_snippet(body, secret),
            request_features=self._last_request_features,
        )

    def _safe_request_id(self, headers: Mapping[str, str]) -> str | None:
        if not self.capabilities.supports_request_ids:
            return None
        for name in ("x-request-id", "request-id", "traceparent"):
            candidate = self._header(headers, name)
            if (candidate is not None and candidate.isprintable()
                    and len(candidate.encode("utf-8")) <= 256):
                return candidate
        return None

    def _safe_snippet(self, body: bytes, secret: Optional[str]) -> str:
        # The complete body is already capped by max_response_bytes. Redact
        # before truncating so a secret crossing the snippet boundary cannot
        # leak as an unredacted prefix.
        text = body.decode("utf-8", errors="replace")
        text = redact_openai_text(text, (secret,) if secret else ())
        text = "".join(
            character if character.isprintable() else " "
            for character in text
        )
        normalized = " ".join(text.split())
        return normalized[:self.limits.max_error_snippet_bytes]

    def _retry_after(self, headers: Mapping[str, str]) -> Optional[float]:
        value = self._header(headers, "Retry-After")
        if value is None:
            return None
        try:
            delay = float(value.strip())
        except (AttributeError, ValueError):
            return None
        if not math.isfinite(delay) or delay < 0:
            return None
        return min(delay, self.retry_policy.max_delay)

    @staticmethod
    def _header(headers: Mapping[str, str], name: str) -> Optional[str]:
        expected = name.lower()
        for key, value in headers.items():
            if isinstance(key, str) and key.lower() == expected:
                return value
        return None

    def _retry_sleep(
        self, attempt: int, retry_after: Optional[float],
        status: Optional[int] = None,
    ) -> None:
        exponential = (
            self.retry_policy.initial_backoff
            * self.retry_policy.backoff_multiplier ** (attempt - 1)
        )
        delay = min(
            retry_after if retry_after is not None else exponential,
            self.retry_policy.max_delay,
        )
        if delay <= 0:
            return
        remaining = self._remaining("Chat Completions retry delay")
        if delay >= remaining:
            raise OpenAIDeadlineExceededError(
                "session deadline exhausted before HTTP retry")
        self._emit(OpenAIClientEvent(
            "retry", attempt, status_code=status, delay=delay))
        self._sleep(delay)
        self._remaining("Chat Completions retry")

    def _remaining(self, operation: str) -> float:
        remaining = self.deadline.remaining()
        if remaining <= 0:
            raise OpenAIDeadlineExceededError(
                f"session deadline exhausted before {operation}")
        return remaining

    def _emit(self, event: OpenAIClientEvent) -> None:
        if self._event_sink is not None:
            self._event_sink(event)

    def _preflight_json_depth(self, text: str) -> None:
        depth = 0
        in_string = False
        escaped = False
        for character in text:
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
                if depth > self.limits.max_json_depth:
                    raise OpenAIProtocolError(
                        "response JSON nesting exceeds the configured limit")
            elif character in "]}":
                depth -= 1
                if depth < 0:
                    break

    @staticmethod
    def _validate_json_tree(
        value: object,
        max_depth: int,
        max_nodes: int,
        error_type: type[OpenAIClientError],
    ) -> None:
        stack = [(value, 1)]
        nodes = 0
        while stack:
            current, depth = stack.pop()
            nodes += 1
            if nodes > max_nodes:
                raise error_type("JSON value exceeds the configured node limit")
            if depth > max_depth:
                raise error_type("JSON value exceeds the configured nesting limit")
            if current is None or isinstance(current, (str, bool, int)):
                continue
            if isinstance(current, float):
                if not math.isfinite(current):
                    raise error_type("JSON value contains a non-finite number")
                continue
            if isinstance(current, list):
                stack.extend((item, depth + 1) for item in current)
                continue
            if isinstance(current, dict):
                if any(not isinstance(key, str) for key in current):
                    raise error_type("JSON object keys must be strings")
                stack.extend((item, depth + 1) for item in current.values())
                continue
            raise error_type("value contains an unsupported JSON type")


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant: {value}")


def _transport_timeout_kind(error: requests.RequestException) -> str | None:
    """Recognize connect/read timeout wrappers without exposing their text."""
    pending: list[BaseException] = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, requests.ConnectTimeout):
            return "connect"
        if isinstance(current, (requests.ReadTimeout, TimeoutError)):
            return "read"
        if isinstance(current, requests.Timeout):
            return "read"
        if type(current).__name__ == "ConnectTimeoutError":
            return "connect"
        if type(current).__name__ == "ReadTimeoutError":
            return "read"
        for nested in (current.__cause__, current.__context__):
            if isinstance(nested, BaseException):
                pending.append(nested)
        pending.extend(
            item for item in current.args if isinstance(item, BaseException)
        )
    return None
