# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Bounded native Ollama preparation for named OpenAI backend profiles."""
from __future__ import annotations

import json
import math
import os
import re
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import SplitResult, urlsplit, urlunsplit

import requests

from .backend import BackendConfigurationError
from .openai_backend import OpenAIConfig
from .openai_deadline import RuntimeTimeoutError, SessionDeadline
from .openai_host_tools import ApprovalGate
from .openai_profile import (
    MAX_KEEP_ALIVE_SECONDS,
    MAX_NUM_CTX,
    OllamaProfile,
    OpenAIProfileError,
    normalize_ollama_model,
)
from .openai_tools import ToolApprovalError

MAX_OLLAMA_RESPONSE_BYTES = 1024 * 1024
MAX_OLLAMA_REQUEST_BYTES = 16 * 1024
MAX_OLLAMA_RESPONSE_HEADERS = 128
MAX_OLLAMA_RESPONSE_HEADER_BYTES = 64 * 1024
MAX_OLLAMA_JSON_DEPTH = 24
MAX_OLLAMA_JSON_NODES = 10_000
OLLAMA_CHUNK_BYTES = 16 * 1024
_KEEP_ALIVE_RE = re.compile(r"^([0-9]+)(ms|s|m|h)$", re.ASCII)


class OllamaConfigurationError(BackendConfigurationError):
    """A profile's native Ollama settings violate the endpoint policy."""


class OllamaPreparationError(RuntimeError):
    """Native Ollama preparation failed without exposing provider data."""


@dataclass(frozen=True)
class OllamaConfig:
    """Fully resolved native Ollama endpoint and preparation policy."""

    api_base_url: str
    source_model: str
    target_model: str
    num_ctx: int
    create_if_missing: bool
    recreate_if_mismatch: bool
    require_tools: bool
    preload: bool
    keep_alive: str | int
    verify_context: bool

    def __post_init__(self) -> None:
        normalize_ollama_model(self.source_model)
        normalize_ollama_model(self.target_model)
        if (isinstance(self.num_ctx, bool) or not isinstance(self.num_ctx, int)
                or self.num_ctx < 1 or self.num_ctx > MAX_NUM_CTX):
            raise OllamaConfigurationError(
                f"num_ctx must be between 1 and {MAX_NUM_CTX}")
        for name in (
            "create_if_missing", "recreate_if_mismatch", "require_tools",
            "preload", "verify_context",
        ):
            if not isinstance(getattr(self, name), bool):
                raise OllamaConfigurationError(f"{name} must be boolean")
        if (self.create_if_missing or self.recreate_if_mismatch) and (
                normalize_ollama_model(self.source_model)
                == normalize_ollama_model(self.target_model)):
            raise OllamaConfigurationError(
                "source_model and target_model must differ when creation is enabled")
        _validate_keep_alive(self.keep_alive)

    @classmethod
    def from_profile(
        cls,
        profile: OllamaProfile,
        openai_config: OpenAIConfig,
    ) -> OllamaConfig:
        """Bind profile-only settings to the validated inference origin."""
        api_root = _resolve_api_root(profile.api_base_url, openai_config.base_url)
        if (normalize_ollama_model(openai_config.model)
                != normalize_ollama_model(profile.target_model)):
            raise OllamaConfigurationError(
                "[openai] model must match [ollama] target_model; a conflicting "
                "--model override is not permitted")
        return cls(
            api_base_url=api_root,
            source_model=profile.source_model,
            target_model=profile.target_model,
            num_ctx=profile.num_ctx,
            create_if_missing=profile.create_if_missing,
            recreate_if_mismatch=profile.recreate_if_mismatch,
            require_tools=profile.require_tools,
            preload=profile.preload,
            keep_alive=profile.keep_alive,
            verify_context=profile.verify_context,
        )


class HTTPResponse(Protocol):
    status_code: int
    headers: Mapping[str, str]

    def iter_content(self, chunk_size: int,
                     decode_unicode: bool = False) -> Iterable[bytes]: ...

    def close(self) -> None: ...


class HTTPTransport(Protocol):
    def request(self, method: str, url: str, **kwargs: object) -> HTTPResponse: ...


EventSink = Callable[[str, Mapping[str, object]], None]


class OllamaPreparationClient:
    """Inspect and, when authorized, provision one dedicated Ollama alias."""

    def __init__(
        self,
        config: OllamaConfig,
        openai_config: OpenAIConfig,
        deadline: SessionDeadline,
        *,
        transport: HTTPTransport | None = None,
        environ: Mapping[str, str] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        event_sink: EventSink | None = None,
        approvals: ApprovalGate | None = None,
    ) -> None:
        expected_root = _resolve_api_root(config.api_base_url, openai_config.base_url)
        if expected_root != config.api_base_url:
            raise OllamaConfigurationError("Ollama api_base_url is not normalized")
        if (normalize_ollama_model(config.target_model)
                != normalize_ollama_model(openai_config.model)):
            raise OllamaConfigurationError(
                "Ollama target model must match the OpenAI model")
        self.config = config
        self.openai_config = openai_config
        self.deadline = deadline
        self._transport = requests if transport is None else transport
        self._environ = os.environ if environ is None else environ
        self._sleep = sleep
        self._event_sink = event_sink
        self._approvals = approvals

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(api_base_url={self.config.api_base_url!r}, "
            f"target_model={self.config.target_model!r})"
        )

    def prepare(self) -> None:
        """Run the idempotent inspection/provision/preload/verification sequence."""
        self._emit("ollama_preparation_start", {
            "target_model": self.config.target_model,
            "num_ctx": self.config.num_ctx,
        })
        try:
            target = self._show(self.config.target_model)
            changed = False
            if target is None:
                if not self.config.create_if_missing:
                    raise OllamaPreparationError(
                        "Ollama target model is missing and create_if_missing is false")
                source = self._require_source()
                self._validate_architecture_limit(source)
                self._approve("create")
                self._create()
                changed = True
                self._emit("ollama_model_create", {
                    "target_model": self.config.target_model,
                    "num_ctx": self.config.num_ctx,
                })
                target = self._require_verified_target()
            else:
                mismatch = self._target_mismatch(target)
                if mismatch is not None:
                    if not self.config.recreate_if_mismatch:
                        raise OllamaPreparationError(
                            f"Ollama target model does not match the profile: {mismatch}")
                    source = self._require_source()
                    self._validate_architecture_limit(source)
                    self._approve("recreate")
                    self._create()
                    changed = True
                    self._emit("ollama_model_recreate", {
                        "target_model": self.config.target_model,
                        "num_ctx": self.config.num_ctx,
                    })
                    target = self._require_verified_target()
            self._validate_architecture_limit(target)
            if not changed:
                self._emit("ollama_preparation_noop", {
                    "target_model": self.config.target_model,
                })
            if self.config.preload:
                self._preload()
                self._emit("ollama_preload", {
                    "target_model": self.config.target_model,
                    "num_ctx": self.config.num_ctx,
                    "keep_alive": self.config.keep_alive,
                })
            if self.config.verify_context:
                self._verify_loaded_context()
                self._emit("ollama_context_verification", {
                    "target_model": self.config.target_model,
                    "context_length": self.config.num_ctx,
                })
            self._emit("ollama_preparation_complete", {
                "target_model": self.config.target_model,
                "changed": changed,
            })
        except (OllamaPreparationError, RuntimeTimeoutError, ToolApprovalError) as exc:
            self._emit("ollama_preparation_failure", {
                "error_type": type(exc).__name__,
                "reason": _bounded_reason(str(exc)),
            })
            if isinstance(exc, OllamaPreparationError):
                raise
            if isinstance(exc, ToolApprovalError):
                raise OllamaPreparationError(
                    "operator denied Ollama model alias preparation") from None
            raise OllamaPreparationError(
                "Ollama preparation exhausted the overall session deadline") from None

    def _show(self, model: str) -> dict[str, object] | None:
        status, body = self._request(
            "POST", "/api/show", {"model": model, "verbose": False},
            allow_not_found=True, retryable=True)
        if status == 404:
            return None
        reported = body.get("model", body.get("name"))
        if (reported is not None
                and (not isinstance(reported, str)
                     or normalize_ollama_model(reported) != normalize_ollama_model(model))):
            raise OllamaPreparationError(
                "Ollama /api/show returned a different model identity")
        return body

    def _require_source(self) -> dict[str, object]:
        source = self._show(self.config.source_model)
        if source is None:
            raise OllamaPreparationError(
                "Ollama source model is not installed; install it explicitly before retrying")
        return source

    def _require_verified_target(self) -> dict[str, object]:
        target = self._show(self.config.target_model)
        if target is None:
            raise OllamaPreparationError(
                "Ollama did not expose the target model after alias creation")
        mismatch = self._target_mismatch(target)
        if mismatch is not None:
            raise OllamaPreparationError(
                f"Ollama target verification failed after creation: {mismatch}")
        return target

    def _target_mismatch(self, payload: Mapping[str, object]) -> str | None:
        self._validate_architecture_limit(payload)
        configured = _parameter_num_ctx(payload.get("parameters"))
        if configured != self.config.num_ctx:
            return "num_ctx differs"
        if self.config.require_tools:
            capabilities = payload.get("capabilities")
            if (not isinstance(capabilities, list)
                    or "tools" not in {
                        item.casefold() for item in capabilities if isinstance(item, str)
                    }):
                return "tools capability is absent"
        return None

    def _validate_architecture_limit(self, payload: Mapping[str, object]) -> None:
        model_info = payload.get("model_info")
        if not isinstance(model_info, dict):
            return
        limits = [
            value for key, value in model_info.items()
            if isinstance(key, str) and key.casefold().endswith(".context_length")
            and not isinstance(value, bool) and isinstance(value, int) and value > 0
        ]
        if limits and self.config.num_ctx > min(limits):
            raise OllamaPreparationError(
                "requested num_ctx exceeds the architecture context maximum")

    def _approve(self, operation: str) -> None:
        if self._approvals is not None:
            self._approvals.require(
                "ollama_model_alias",
                f"ollama_{operation}",
                f"{operation} dedicated alias {self.config.target_model} "
                f"from {self.config.source_model} with num_ctx={self.config.num_ctx}",
            )

    def _create(self) -> None:
        self._request("POST", "/api/create", {
            "model": self.config.target_model,
            "from": self.config.source_model,
            "parameters": {"num_ctx": self.config.num_ctx},
            "stream": False,
        })

    def _preload(self) -> None:
        self._request("POST", "/api/generate", {
            "model": self.config.target_model,
            "prompt": "",
            "stream": False,
            "keep_alive": self.config.keep_alive,
            "options": {"num_ctx": self.config.num_ctx},
        }, retryable=True)

    def _verify_loaded_context(self) -> None:
        _, payload = self._request("GET", "/api/ps", None, retryable=True)
        models = payload.get("models")
        if not isinstance(models, list):
            raise OllamaPreparationError("Ollama /api/ps response has no model list")
        expected = normalize_ollama_model(self.config.target_model)
        for item in models:
            if not isinstance(item, dict):
                continue
            name = item.get("name", item.get("model"))
            if not isinstance(name, str):
                continue
            try:
                matches = normalize_ollama_model(name) == expected
            except (OpenAIProfileError, ValueError):
                matches = False
            if matches:
                length = item.get("context_length")
                if (isinstance(length, int) and not isinstance(length, bool)
                        and length == self.config.num_ctx):
                    return
                raise OllamaPreparationError(
                    "loaded Ollama target context_length does not match num_ctx")
        raise OllamaPreparationError(
            "Ollama target is not loaded after the configured preload step")

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, object] | None,
        *,
        allow_not_found: bool = False,
        retryable: bool = False,
    ) -> tuple[int, dict[str, object]]:
        request_data: bytes | None = None
        if body is not None:
            try:
                request_data = json.dumps(
                    body, ensure_ascii=False, separators=(",", ":"),
                    allow_nan=False).encode("utf-8")
            except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
                raise OllamaPreparationError(
                    "Ollama preparation request could not be serialized") from exc
            if len(request_data) > MAX_OLLAMA_REQUEST_BYTES:
                raise OllamaPreparationError("Ollama preparation request exceeds its limit")

        headers = {"Content-Type": "application/json", "Accept-Encoding": "identity"}
        secret_value = self._environ.get(self.openai_config.api_key_env)
        if secret_value is not None and secret_value.strip():
            headers["Authorization"] = f"Bearer {secret_value.strip()}"
        attempts = 2 if retryable else 1
        for attempt in range(1, attempts + 1):
            remaining = self.deadline.require("Ollama preparation request")
            timeout = (
                min(float(self.openai_config.connect_timeout), remaining),
                min(float(self.openai_config.request_timeout), remaining),
            )
            response: HTTPResponse | None = None
            try:
                options: dict[str, object] = {
                    "headers": headers,
                    "timeout": timeout,
                    "stream": True,
                    "allow_redirects": False,
                }
                if request_data is not None:
                    options["data"] = request_data
                if self.openai_config.is_loopback:
                    options["proxies"] = {"http": None, "https": None, "all": None}
                response = self._transport.request(
                    method, f"{self.config.api_base_url}{path}", **options)
                status = response.status_code
                raw = self._read_response(response)
            except requests.RequestException:
                if attempt < attempts:
                    self._bounded_sleep(0.1)
                    continue
                raise OllamaPreparationError(
                    "Ollama preparation connection failed or timed out") from None
            except (OllamaPreparationError, RuntimeTimeoutError):
                raise
            except (OSError, ValueError):
                raise OllamaPreparationError(
                    "Ollama preparation response could not be read") from None
            finally:
                if response is not None:
                    try:
                        response.close()
                    except Exception:
                        raise OllamaPreparationError(
                            "Ollama preparation response cleanup failed") from None
            if isinstance(status, bool) or not isinstance(status, int):
                raise OllamaPreparationError("Ollama returned an invalid HTTP status")
            if status in {301, 302, 303, 307, 308}:
                raise OllamaPreparationError("Ollama preparation redirects are forbidden")
            if status in {502, 503, 504} and attempt < attempts:
                self._bounded_sleep(0.1)
                continue
            if status == 404 and allow_not_found:
                return status, {}
            if status < 200 or status >= 300:
                raise OllamaPreparationError(
                    f"Ollama preparation request failed with HTTP status {status}")
            return status, _decode_json_object(raw)
        raise OllamaPreparationError("Ollama preparation attempts were exhausted")

    def _read_response(self, response: HTTPResponse) -> bytes:
        header_count = 0
        header_bytes = 0
        try:
            for name, value in response.headers.items():
                if not isinstance(name, str) or not isinstance(value, str):
                    raise OllamaPreparationError("Ollama response headers are malformed")
                header_count += 1
                header_bytes += len(name.encode("utf-8")) + len(value.encode("utf-8"))
                if (header_count > MAX_OLLAMA_RESPONSE_HEADERS
                        or header_bytes > MAX_OLLAMA_RESPONSE_HEADER_BYTES):
                    raise OllamaPreparationError("Ollama response headers exceed limits")
        except OllamaPreparationError:
            raise
        except (AttributeError, RuntimeError, UnicodeError):
            raise OllamaPreparationError("Ollama response headers are malformed") from None
        length = _header(response.headers, "Content-Length")
        if length is not None:
            try:
                if int(length) > MAX_OLLAMA_RESPONSE_BYTES:
                    raise OllamaPreparationError("Ollama response exceeds the byte limit")
            except ValueError:
                pass
        result = bytearray()
        for chunk in response.iter_content(OLLAMA_CHUNK_BYTES, decode_unicode=False):
            self.deadline.require("Ollama preparation response read")
            if not isinstance(chunk, bytes):
                raise OllamaPreparationError("Ollama response stream is malformed")
            if len(result) + len(chunk) > MAX_OLLAMA_RESPONSE_BYTES:
                raise OllamaPreparationError("Ollama response exceeds the byte limit")
            result.extend(chunk)
        return bytes(result)

    def _bounded_sleep(self, delay: float) -> None:
        remaining = self.deadline.require("Ollama retry delay")
        self._sleep(min(delay, remaining))

    def _emit(self, kind: str, data: Mapping[str, object]) -> None:
        if self._event_sink is not None:
            self._event_sink(kind, data)


def _resolve_api_root(explicit: str | None, openai_url: str) -> str:
    inference = urlsplit(openai_url)
    if explicit is None:
        if inference.path != "/v1":
            raise OllamaConfigurationError(
                "api_base_url is required unless the OpenAI base URL ends in an "
                "unambiguous /v1 root")
        native = SplitResult(inference.scheme, inference.netloc, "", "", "")
    else:
        if not isinstance(explicit, str) or not explicit or any(c.isspace() for c in explicit):
            raise OllamaConfigurationError("Ollama api_base_url must be a non-empty URL")
        try:
            native = urlsplit(explicit)
            _ = native.port
        except ValueError as exc:
            raise OllamaConfigurationError("Ollama api_base_url is malformed") from exc
    if native.scheme not in {"http", "https"} or not native.hostname:
        raise OllamaConfigurationError("Ollama api_base_url must use http or https")
    if native.username is not None or native.password is not None:
        raise OllamaConfigurationError("Ollama api_base_url must not contain credentials")
    if native.query or native.fragment:
        raise OllamaConfigurationError(
            "Ollama api_base_url must not contain a query string or fragment")
    if native.path not in {"", "/"}:
        raise OllamaConfigurationError(
            "Ollama api_base_url must be the native API root without /v1 or /api")
    if explicit is not None and ("\\" in explicit or "%" in native.netloc):
        raise OllamaConfigurationError(
            "Ollama api_base_url contains an unsupported path form")
    if (_origin(inference) != _origin(native)):
        raise OllamaConfigurationError(
            "Ollama native and OpenAI endpoints must have exactly the same origin")
    return urlunsplit(SplitResult(native.scheme, native.netloc, "", "", ""))


def _origin(parsed: SplitResult) -> tuple[str, str, int]:
    scheme = parsed.scheme.casefold()
    default_port = 443 if scheme == "https" else 80
    return scheme, (parsed.hostname or "").casefold(), parsed.port or default_port


def _parameter_num_ctx(value: object) -> int | None:
    if not isinstance(value, str) or len(value) > 64 * 1024:
        return None
    match = re.search(r"(?m)^\s*num_ctx(?:\s+|\s*=\s*)([0-9]+)\s*$", value)
    return int(match.group(1)) if match is not None else None


def _validate_keep_alive(value: object) -> None:
    if isinstance(value, bool):
        raise OllamaConfigurationError("keep_alive must be a bounded Ollama duration")
    if isinstance(value, int):
        if value in {-1, 0} or 1 <= value <= MAX_KEEP_ALIVE_SECONDS:
            return
        raise OllamaConfigurationError("keep_alive seconds exceed the seven-day limit")
    if not isinstance(value, str):
        raise OllamaConfigurationError("keep_alive must be a bounded Ollama duration")
    match = _KEEP_ALIVE_RE.fullmatch(value)
    if match is None:
        raise OllamaConfigurationError("keep_alive must be a bounded Ollama duration")
    multiplier = {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[match.group(2)]
    count = int(match.group(1))
    if count <= 0 or count * multiplier > MAX_KEEP_ALIVE_SECONDS:
        raise OllamaConfigurationError("keep_alive duration exceeds the seven-day limit")


def _decode_json_object(raw: bytes) -> dict[str, object]:
    try:
        text = raw.decode("utf-8", errors="strict")
        decoded = json.loads(text, parse_constant=lambda value: _reject_constant(value))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        raise OllamaPreparationError("Ollama response is not valid bounded JSON") from None
    _validate_json_tree(decoded)
    if not isinstance(decoded, dict):
        raise OllamaPreparationError("Ollama response top level must be an object")
    return decoded


def _validate_json_tree(value: object) -> None:
    stack = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_OLLAMA_JSON_NODES or depth > MAX_OLLAMA_JSON_DEPTH:
            raise OllamaPreparationError("Ollama response JSON exceeds structural limits")
        if isinstance(current, dict):
            stack.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, float) and not math.isfinite(current):
            raise OllamaPreparationError("Ollama response contains a non-finite number")
        elif current is not None and not isinstance(current, (str, int, float, bool)):
            raise OllamaPreparationError("Ollama response contains an unsupported value")


def _reject_constant(value: str) -> object:
    raise ValueError(f"invalid JSON constant: {value}")


def _header(headers: Mapping[str, str], expected: str) -> str | None:
    for name, value in headers.items():
        if isinstance(name, str) and name.casefold() == expected.casefold():
            return value
    return None


def _bounded_reason(reason: str) -> str:
    return " ".join(reason.split())[:512]
