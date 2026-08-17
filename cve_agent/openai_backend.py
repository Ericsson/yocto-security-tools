# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Configuration contract for the native OpenAI-compatible backend.

The bounded single-exchange HTTP client lives in :mod:`openai_client`. The
bounded multi-turn orchestration lives in :mod:`openai_loop` and uses only
the typed host runtime from :mod:`openai_host_tools`.
"""
import contextlib
import ipaddress
import logging
import math
import os
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .backend import (
    AIBackend,
    BackendConfigurationError,
    SessionResult,
)

DEFAULT_OPENAI_BASE_URL = "http://127.0.0.1:11434/v1"
DEFAULT_MAX_STEPS = 20
DEFAULT_MAX_TOOL_CALLS = 100
DEFAULT_MAX_OUTPUT_TOKENS = 8192
DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_REQUEST_TIMEOUT = 120

MAX_STEPS_LIMIT = 100
MAX_TOOL_CALLS_LIMIT = 1000
MAX_OUTPUT_TOKENS_LIMIT = 131072
MAX_CONNECT_TIMEOUT = 300
MAX_REQUEST_TIMEOUT = 3600
MAX_MODEL_IDENTITY_BYTES = 256

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


class OpenAIConfigurationError(BackendConfigurationError):
    """Invalid native OpenAI-compatible backend configuration."""


@dataclass(frozen=True)
class OpenAIConfig:
    """Validated immutable configuration for an OpenAI-compatible endpoint."""

    base_url: str
    model: str
    api_key_env: str
    max_steps: int
    max_tool_calls: int
    max_output_tokens: int
    connect_timeout: int
    request_timeout: int
    allow_remote_endpoint: bool
    allow_insecure_remote_http: bool
    temperature: Optional[float] = None
    top_p: Optional[float] = None
    reasoning_effort: Optional[str] = None

    def __post_init__(self) -> None:
        """Enforce the same safety contract for direct dataclass construction."""
        if not isinstance(self.allow_remote_endpoint, bool):
            raise OpenAIConfigurationError("remote endpoint opt-in must be boolean")
        if not isinstance(self.allow_insecure_remote_http, bool):
            raise OpenAIConfigurationError("remote HTTP opt-in must be boolean")
        try:
            model = validate_openai_model(self.model)
        except ValueError as exc:
            raise OpenAIConfigurationError(str(exc)) from exc
        if not isinstance(self.base_url, str):
            raise OpenAIConfigurationError("OpenAI base URL must be a string")
        if not isinstance(self.api_key_env, str):
            raise OpenAIConfigurationError(
                "API-key environment-variable name must be a string")
        normalized_url = _validate_base_url(
            self.base_url,
            self.allow_remote_endpoint,
            self.allow_insecure_remote_http,
        )
        api_key_env = self.api_key_env.strip()
        _validate_api_key_env(api_key_env, {}, required=False)
        bounds = {
            "max_steps": ("maximum model turns", MAX_STEPS_LIMIT),
            "max_tool_calls": ("maximum total tool calls", MAX_TOOL_CALLS_LIMIT),
            "max_output_tokens": ("maximum output tokens", MAX_OUTPUT_TOKENS_LIMIT),
            "connect_timeout": ("connect timeout", MAX_CONNECT_TIMEOUT),
            "request_timeout": ("request timeout", MAX_REQUEST_TIMEOUT),
        }
        for field, (label, upper) in bounds.items():
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int):
                raise OpenAIConfigurationError(f"{label} must be an integer")
            if value < 1 or value > upper:
                raise OpenAIConfigurationError(
                    f"{label} must be between 1 and {upper}")
        temperature = _validate_optional_float(
            self.temperature, "temperature", 0.0, 2.0, exclusive_lower=False)
        top_p = _validate_optional_float(
            self.top_p, "top_p", 0.0, 1.0, exclusive_lower=True)
        reasoning_effort = self.reasoning_effort
        if reasoning_effort is not None:
            if not isinstance(reasoning_effort, str):
                raise OpenAIConfigurationError("reasoning effort must be a string")
            reasoning_effort = reasoning_effort.strip()
            if reasoning_effort not in {"none", "low", "medium", "high", "max"}:
                raise OpenAIConfigurationError(
                    "reasoning effort must be one of: none, low, medium, high, max")
        object.__setattr__(self, "model", model)
        object.__setattr__(self, "base_url", normalized_url)
        object.__setattr__(self, "api_key_env", api_key_env)
        object.__setattr__(self, "temperature", temperature)
        object.__setattr__(self, "top_p", top_p)
        object.__setattr__(self, "reasoning_effort", reasoning_effort)

    @property
    def chat_completions_url(self) -> str:
        """Return the chat-completions endpoint without path duplication."""
        return f"{self.base_url}/chat/completions"

    @property
    def is_loopback(self) -> bool:
        """Return whether the validated endpoint is local to this host."""
        hostname = urlsplit(self.base_url).hostname
        return hostname is not None and _is_loopback(hostname)

    @classmethod
    def from_sources(
        cls,
        options: Optional[Mapping[str, object]] = None,
        environ: Optional[Mapping[str, str]] = None,
        profile_openai: Optional[Mapping[str, str]] = None,
        profile_chat: Optional[Mapping[str, object]] = None,
    ) -> "OpenAIConfig":
        """Resolve CLI, profile, environment, and defaults in that order."""
        options = options or {}
        environ = os.environ if environ is None else environ
        profile_openai = profile_openai or {}
        profile_chat = profile_chat or {}

        model = _resolve_model(
            _prefer_profile(options.get("model"), profile_openai, "model"), environ)
        base_url = _resolve_string(
            _prefer_profile(options.get("openai_base_url"), profile_openai, "base_url"),
            environ,
            "CVE_AGENT_OPENAI_BASE_URL",
            "OPENAI_BASE_URL",
            DEFAULT_OPENAI_BASE_URL,
        )
        api_key_cli = options.get("openai_api_key_env")
        api_key_profile = profile_openai.get("api_key_env")
        api_key_from_env = environ.get("CVE_AGENT_OPENAI_API_KEY_ENV")
        api_key_env = _resolve_string(
            api_key_cli if api_key_cli is not None else api_key_profile,
            environ,
            "CVE_AGENT_OPENAI_API_KEY_ENV",
            None,
            "OPENAI_API_KEY",
        )
        api_key_explicit = (
            api_key_cli is not None or api_key_profile is not None
            or api_key_from_env is not None)
        _validate_api_key_env(api_key_env, environ, required=api_key_explicit)

        max_steps = _resolve_bounded_int(
            _prefer_profile(options.get("openai_max_steps"), profile_openai, "max_steps"),
            environ,
            "CVE_AGENT_OPENAI_MAX_STEPS", DEFAULT_MAX_STEPS,
            "maximum model turns", MAX_STEPS_LIMIT)
        max_tool_calls = _resolve_bounded_int(
            _prefer_profile(
                options.get("openai_max_tool_calls"), profile_openai, "max_tool_calls"),
            environ,
            "CVE_AGENT_OPENAI_MAX_TOOL_CALLS", DEFAULT_MAX_TOOL_CALLS,
            "maximum total tool calls", MAX_TOOL_CALLS_LIMIT)
        max_output_tokens = _resolve_bounded_int(
            _prefer_profile(
                options.get("openai_max_output_tokens"), profile_openai,
                "max_output_tokens"), environ,
            "CVE_AGENT_OPENAI_MAX_OUTPUT_TOKENS", DEFAULT_MAX_OUTPUT_TOKENS,
            "maximum output tokens", MAX_OUTPUT_TOKENS_LIMIT)
        connect_timeout = _resolve_bounded_int(
            _prefer_profile(
                options.get("openai_connect_timeout"), profile_openai, "connect_timeout"),
            environ,
            "CVE_AGENT_OPENAI_CONNECT_TIMEOUT", DEFAULT_CONNECT_TIMEOUT,
            "connect timeout", MAX_CONNECT_TIMEOUT)
        request_timeout = _resolve_bounded_int(
            _prefer_profile(
                options.get("openai_request_timeout"), profile_openai, "request_timeout"),
            environ,
            "CVE_AGENT_OPENAI_REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT,
            "request timeout", MAX_REQUEST_TIMEOUT)
        allow_remote = _resolve_bool(
            _prefer_profile(
                options.get("openai_allow_remote_endpoint"), profile_openai,
                "allow_remote_endpoint"), environ,
            "CVE_AGENT_OPENAI_ALLOW_REMOTE", False)
        allow_insecure_remote = _resolve_bool(
            _prefer_profile(
                options.get("openai_allow_insecure_remote_http"), profile_openai,
                "allow_insecure_remote_http"), environ,
            "CVE_AGENT_OPENAI_ALLOW_INSECURE_REMOTE_HTTP", False)
        normalized_url = _validate_base_url(
            base_url, allow_remote, allow_insecure_remote)
        temperature = _resolve_optional_float(
            _prefer_profile(
                options.get("openai_temperature"), profile_chat, "temperature"),
            environ, "CVE_AGENT_OPENAI_TEMPERATURE", "temperature", 0, 2,
            exclusive_lower=False)
        top_p = _resolve_optional_float(
            _prefer_profile(options.get("openai_top_p"), profile_chat, "top_p"),
            environ, "CVE_AGENT_OPENAI_TOP_P", "top_p", 0, 1,
            exclusive_lower=True)
        reasoning_effort = _resolve_reasoning_effort(
            _prefer_profile(
                options.get("openai_reasoning_effort"), profile_chat,
                "reasoning_effort"), environ)

        return cls(
            base_url=normalized_url,
            model=model,
            api_key_env=api_key_env,
            max_steps=max_steps,
            max_tool_calls=max_tool_calls,
            max_output_tokens=max_output_tokens,
            connect_timeout=connect_timeout,
            request_timeout=request_timeout,
            allow_remote_endpoint=allow_remote,
            allow_insecure_remote_http=allow_insecure_remote,
            temperature=temperature,
            top_p=top_p,
            reasoning_effort=reasoning_effort,
        )

    from_options = from_sources


def _resolve_model(value: object, environ: Mapping[str, str]) -> str:
    model = _string_value(value)
    if model is None:
        model = environ.get("CVE_AGENT_OPENAI_MODEL")
    if model is None:
        raise OpenAIConfigurationError(
            "backend 'openai' requires a model; use --model MODEL or set "
            "CVE_AGENT_OPENAI_MODEL")
    try:
        return validate_openai_model(model)
    except ValueError as exc:
        raise OpenAIConfigurationError(str(exc)) from exc


def _prefer_profile(
    cli_value: object,
    profile: Mapping[str, object],
    key: str,
) -> object:
    return cli_value if cli_value is not None else profile.get(key)


def _resolve_optional_float(
    value: object,
    environ: Mapping[str, str],
    env_name: str,
    label: str,
    lower: float,
    upper: float,
    *,
    exclusive_lower: bool,
) -> Optional[float]:
    raw = value if value is not None else environ.get(env_name)
    if raw is None:
        return None
    return _validate_optional_float(
        raw, label, lower, upper, exclusive_lower=exclusive_lower)


def _validate_optional_float(
    value: object,
    label: str,
    lower: float,
    upper: float,
    *,
    exclusive_lower: bool,
) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise OpenAIConfigurationError(f"{label} must be a finite number")
    try:
        resolved = float(value)
    except ValueError as exc:
        raise OpenAIConfigurationError(f"{label} must be a finite number") from exc
    below = resolved <= lower if exclusive_lower else resolved < lower
    if not math.isfinite(resolved) or below or resolved > upper:
        relation = "greater than 0 and at most 1" if exclusive_lower else "between 0 and 2"
        raise OpenAIConfigurationError(f"{label} must be {relation}")
    return resolved


def _resolve_reasoning_effort(
    value: object,
    environ: Mapping[str, str],
) -> Optional[str]:
    raw = value if value is not None else environ.get("CVE_AGENT_OPENAI_REASONING_EFFORT")
    if raw is None:
        return None
    if not isinstance(raw, str):
        raise OpenAIConfigurationError("reasoning effort must be a string")
    normalized = raw.strip()
    if normalized not in {"none", "low", "medium", "high", "max"}:
        raise OpenAIConfigurationError(
            "reasoning effort must be one of: none, low, medium, high, max")
    return normalized


def validate_openai_model(model: str) -> str:
    """Return one bounded printable model identity safe for audit trailers."""
    if not isinstance(model, str):
        raise ValueError("model identity must be a string")
    identity = model.strip()
    if not identity:
        raise ValueError(
            "backend 'openai' requires a model; use --model MODEL or set "
            "CVE_AGENT_OPENAI_MODEL")
    if (len(identity.encode("utf-8")) > MAX_MODEL_IDENTITY_BYTES
            or not identity.isprintable() or "\n" in identity or "\r" in identity):
        raise ValueError("model identity must be a bounded printable line")
    return identity


def _resolve_string(value: object, environ: Mapping[str, str],
                    private_name: str, standard_name: Optional[str],
                    default: str) -> str:
    resolved = _string_value(value)
    if resolved is None:
        resolved = environ.get(private_name)
    if resolved is None and standard_name is not None:
        resolved = environ.get(standard_name)
    return default if resolved is None else resolved.strip()


def _string_value(value: object) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise OpenAIConfigurationError("string configuration value expected")
    return value


def _resolve_bounded_int(value: object, environ: Mapping[str, str],
                         env_name: str, default: int, label: str,
                         upper_bound: int) -> int:
    raw = value if value is not None else environ.get(env_name, default)
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        raise OpenAIConfigurationError(f"{label} must be an integer")
    try:
        resolved = int(raw)
    except ValueError as exc:
        raise OpenAIConfigurationError(f"{label} must be an integer") from exc
    if resolved < 1 or resolved > upper_bound:
        raise OpenAIConfigurationError(
            f"{label} must be between 1 and {upper_bound}")
    return resolved


def _resolve_bool(value: object, environ: Mapping[str, str],
                  env_name: str, default: bool) -> bool:
    raw = value if value is not None else environ.get(env_name)
    if raw is None:
        return default
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        normalized = raw.strip().lower()
        if normalized in _TRUE_VALUES:
            return True
        if normalized in _FALSE_VALUES:
            return False
    raise OpenAIConfigurationError(
        f"{env_name} must be one of: true, false, 1, 0, yes, no, on, off")


def _validate_api_key_env(api_key_env: str, environ: Mapping[str, str],
                          required: bool) -> None:
    if not _ENV_NAME_RE.fullmatch(api_key_env):
        raise OpenAIConfigurationError(
            "API-key environment-variable name must be a valid identifier")
    if required and api_key_env not in environ:
        raise OpenAIConfigurationError(
            f"API-key environment variable '{api_key_env}' is not set; export "
            "it or choose another name with --openai-api-key-env")


def _validate_base_url(base_url: str, allow_remote: bool,
                       allow_insecure_remote: bool) -> str:
    if not base_url or any(character.isspace() for character in base_url):
        raise OpenAIConfigurationError("OpenAI base URL must be a non-empty URL")
    try:
        parsed = urlsplit(base_url)
        port = parsed.port
    except ValueError as exc:
        raise OpenAIConfigurationError(
            "malformed OpenAI API root; check --openai-base-url or "
            "CVE_AGENT_OPENAI_BASE_URL") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise OpenAIConfigurationError("OpenAI base URL scheme must be http or https")
    if not parsed.hostname:
        raise OpenAIConfigurationError("OpenAI base URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise OpenAIConfigurationError("OpenAI base URL must not contain credentials")
    if parsed.query or "?" in base_url:
        raise OpenAIConfigurationError("OpenAI base URL must not contain a query string")
    if parsed.fragment or "#" in base_url:
        raise OpenAIConfigurationError("OpenAI base URL must not contain a fragment")
    if port is not None and port < 1:
        raise OpenAIConfigurationError("OpenAI base URL port must be between 1 and 65535")
    if "%" in parsed.netloc:
        raise OpenAIConfigurationError("OpenAI base URL contains an unsupported host form")

    normalized_path = parsed.path.rstrip("/")
    if "\\" in normalized_path or ";" in normalized_path or "//" in normalized_path:
        raise OpenAIConfigurationError("OpenAI base URL contains an unsupported path form")
    if normalized_path.endswith("/chat/completions"):
        raise OpenAIConfigurationError(
            "OpenAI base URL must be an API root, not a chat/completions endpoint")
    if any(part in {".", ".."} for part in normalized_path.split("/")):
        raise OpenAIConfigurationError("OpenAI base URL path must not contain dot segments")

    loopback = _is_loopback(parsed.hostname)
    if not loopback and not allow_remote:
        raise OpenAIConfigurationError(
            "non-loopback OpenAI endpoint requires --openai-allow-remote or "
            "CVE_AGENT_OPENAI_ALLOW_REMOTE=true")
    if (not loopback and parsed.scheme.lower() == "http"
            and not allow_insecure_remote):
        raise OpenAIConfigurationError(
            "insecure HTTP to a non-loopback OpenAI endpoint requires "
            "--openai-allow-insecure-remote-http or "
            "CVE_AGENT_OPENAI_ALLOW_INSECURE_REMOTE_HTTP=true")

    normalized = SplitResult(
        parsed.scheme.lower(), parsed.netloc, normalized_path, "", "")
    return urlunsplit(normalized)


def _is_loopback(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


class OpenAICompatibleBackend(AIBackend):
    """Built-in native backend for OpenAI-compatible chat APIs."""

    name = "openai"
    default_model = None

    def __init__(
        self,
        *,
        client_factory: Optional[Callable[..., Any]] = None,
        runtime_factory: Optional[Callable[..., Any]] = None,
        transcript_factory: Optional[Callable[..., Any]] = None,
        ollama_factory: Optional[Callable[..., Any]] = None,
        approval_provider: Optional[Any] = None,
    ) -> None:
        self._config: Optional[OpenAIConfig] = None
        self._profile: Any = None
        self._ollama_config: Any = None
        self._client_factory = client_factory
        self._runtime_factory = runtime_factory
        self._transcript_factory = transcript_factory
        self._ollama_factory = ollama_factory
        self._approval_provider = approval_provider

    @property
    def config(self) -> OpenAIConfig:
        """Return configured values after :meth:`configure` has run."""
        if self._config is None:
            raise OpenAIConfigurationError("backend 'openai' is not configured")
        return self._config

    def is_available(self) -> bool:
        """Return local implementation availability without probing an endpoint."""
        return True

    def tool_preamble(self) -> str:
        """Describe the native closed tool contract and authority boundary."""
        return (
            "Only the advertised native typed tools exist. There is no shell "
            "or arbitrary command runner. Shell examples in the shared "
            "instructions describe semantic workflow requirements only; map "
            "them to the typed file, Git, build, and finish tools instead of "
            "emitting commands. First use `read_file` on the generated context "
            "path from the user message, then use only typed tools. Use "
            "`build_recipe` for mandatory build verification. When continuing "
            "a resolved cherry-pick, `git_cherry_pick_continue` accepts a "
            "concise `resolution_note`; trusted host code owns the commit "
            "message and provenance trailer. After a later repair and successful "
            "build, use `git_amend` with exact paths and `message_mode=no_edit`; "
            "use `git_commit` with exact paths and a bounded message for a "
            "separate follow-up. These recording operations do not stale a build "
            "that already validated the same source content. `finish` is "
            "the only way to claim completion or create a `not_applicable` or "
            "`needs_human` conclusion; never create, edit, or delete "
            "`conclusion.json` with generic file tools. Treat a tool error as "
            "recoverable only when its structured result permits correction. "
            "Never claim that an operation happened until you observed its "
            "matching tool result. The host alone verifies terminal state and "
            "creates any conclusion artifact.\n\n"
        )

    def resolve_model(self, requested: Optional[str],
                      environ: Optional[Mapping[str, str]] = None) -> str:
        """Resolve only the OpenAI-specific model sources, with no Claude default."""
        return _resolve_model(
            requested, os.environ if environ is None else environ)

    def configure(self, options: Mapping[str, object],
                  environ: Optional[Mapping[str, str]] = None) -> None:
        """Validate and retain the immutable native-backend configuration."""
        from .openai_ollama import OllamaConfig
        from .openai_profile import load_openai_profile

        environ = os.environ if environ is None else environ
        self._config = None
        self._profile = None
        self._ollama_config = None
        profile_name = options.get("backend_profile")
        if profile_name is not None and not isinstance(profile_name, str):
            raise OpenAIConfigurationError("OpenAI backend profile must be a string")
        profile = (
            load_openai_profile(profile_name, environ)
            if isinstance(profile_name, str) else None
        )
        if profile is not None:
            profile_url = profile.openai.get("base_url")
            if profile_url is not None:
                _validate_base_url(profile_url, True, True)
            profile_model = profile.openai.get("model")
            if profile_model is not None:
                validate_openai_model(profile_model)
        config = OpenAIConfig.from_sources(
            options,
            environ,
            None if profile is None else profile.openai,
            None if profile is None else profile.chat,
        )
        ollama_config = (
            OllamaConfig.from_profile(profile.ollama, config)
            if profile is not None and profile.ollama is not None
            else None
        )
        self._profile = profile
        self._config = config
        self._ollama_config = ollama_config

    def setup(self, **kwargs) -> None:
        """Validate local configuration without probing the network."""
        if self._config is None:
            raise OpenAIConfigurationError("backend 'openai' is not configured")

    def run_session(self, prompt: str, workspace_path: Path,
                    allowed_files: set, model: str,
                    timeout: int, interactive: bool) -> SessionResult:
        """Run the bounded native function-calling session."""
        if self._config is None:
            raise OpenAIConfigurationError("backend 'openai' is not configured")
        from . import get_agent_dir
        from .openai_client import OpenAIChatCompletionsClient
        from .openai_deadline import SessionDeadline
        from .openai_host_tools import (
            ApprovalGate,
            OpenAIHostToolRuntime,
            complete_openai_tool_schemas,
        )
        from .openai_loop import AgentLoopLimits, JSONLTranscript, OpenAIAgentLoop
        from .openai_ollama import OllamaPreparationClient

        started = time.monotonic()
        deadline = SessionDeadline.from_timeout(timeout)
        try:
            session_model = validate_openai_model(model)
        except ValueError as exc:
            return SessionResult(
                resolved=False,
                duration=time.monotonic() - started,
                failure_reason=f"Invalid native model configuration: {exc}",
            )
        session_config = replace(self._config, model=session_model)
        try:
            agent_dir = get_agent_dir(workspace_path)
        except OSError:
            logging.error(
                "OpenAI session could not create its trusted agent directory")
            return SessionResult(
                resolved=False,
                duration=time.monotonic() - started,
                failure_reason=(
                    "Could not create the native session artifact directory; "
                    "check the Yocto build workspace permissions."),
            )

        secret = os.environ.get(self._config.api_key_env, "").strip()
        from .artifacts import current_run_artifacts
        artifact_run = current_run_artifacts()
        if artifact_run is not None:
            artifact_run.add_secret(secret)
        transcript_factory = self._transcript_factory or JSONLTranscript.create
        try:
            transcript = transcript_factory(
                agent_dir, session_model, deadline, (secret,) if secret else ())
        except Exception:
            logging.error(
                "OpenAI session refused to run without its mandatory transcript")
            return SessionResult(
                resolved=False,
                duration=time.monotonic() - started,
                failure_reason=(
                    "Could not create the mandatory native transcript; check "
                    "the Yocto build workspace permissions."),
            )

        try:
            if self._profile is not None:
                transcript.write(
                    "profile_loaded",
                    backend="openai",
                    selector=f"openai-{self._profile.name}",
                    profile=self._profile.name,
                    sha256=self._profile.sha256,
                )
            if self._ollama_config is not None:
                approvals = ApprovalGate(
                    interactive,
                    deadline,
                    self._approval_provider,
                    transcript.runtime_event,
                )
                ollama_factory = self._ollama_factory or OllamaPreparationClient
                preparer = ollama_factory(
                    self._ollama_config,
                    session_config,
                    deadline,
                    environ=os.environ,
                    event_sink=transcript.runtime_event,
                    approvals=approvals,
                )
                preparer.prepare()
        except Exception as exc:
            return self._preparation_failure(
                transcript, deadline, started, exc, secret)

        try:
            runtime_factory = self._runtime_factory or OpenAIHostToolRuntime
            runtime = runtime_factory(
                workspace_path,
                allowed_files,
                session_model,
                timeout,
                agent_dir,
                recipe=workspace_path.name,
                interactive=interactive,
                deadline=deadline,
                event_sink=transcript.runtime_event,
                protected_secrets=(secret,) if secret else (),
            )
            client_factory = self._client_factory or OpenAIChatCompletionsClient
            client = client_factory(
                session_config,
                deadline,
                event_sink=transcript.client_event,
            )
            system_message = self.assembled_instructions()
            loop = OpenAIAgentLoop(
                client,
                runtime,
                transcript,
                deadline,
                AgentLoopLimits(
                    max_model_turns=self._config.max_steps,
                    max_total_tool_calls=self._config.max_tool_calls,
                ),
                complete_openai_tool_schemas(),
                system_message,
                prompt,
            )
        except Exception as exc:
            return self._initialization_failure(
                transcript, deadline, started, type(exc).__name__)
        result = loop.run(session_model, interactive)
        if not result.resolved:
            try:
                runtime.discard_terminal_artifacts()
            except (OSError, RuntimeError):
                logging.error(
                    "OpenAI session could not remove an untrusted terminal artifact")
        return result

    def _preparation_failure(
        self,
        transcript,
        deadline,
        started: float,
        error: Exception,
        secret: str,
    ) -> SessionResult:
        from .openai_redaction import redact_openai_text

        reason = redact_openai_text(str(error), (secret,) if secret else ())
        reason = " ".join(reason.split())[:512]
        safe_reason = reason or "native provider preparation failed"
        try:
            transcript.write(
                "session_start",
                backend="openai",
                profile=None if self._profile is None else self._profile.name,
                initialization=True,
            )
            transcript.write(
                "session_error",
                error_type=type(error).__name__,
                stage="ollama_preparation",
                message=safe_reason,
            )
            transcript.write(
                "session_end", resolved=False, reason=safe_reason)
            transcript.sync()
        except (OSError, RuntimeError, TypeError, ValueError):
            logging.error("OpenAI preparation transcript finalization failed")
        with contextlib.suppress(OSError, RuntimeError):
            transcript.close()
        return SessionResult(
            resolved=False,
            duration=max(0.0, deadline.clock() - started),
            transcript_path=transcript.path,
            failure_reason=f"Ollama preparation failed: {safe_reason}",
        )

    @staticmethod
    def _initialization_failure(
        transcript, deadline, started: float, error_type: str,
    ) -> SessionResult:
        try:
            transcript.write(
                "session_start", backend="openai", initialization=True)
            transcript.write(
                "session_error", error_type=error_type,
                message="native session initialization failed safely")
            transcript.write(
                "session_end", resolved=False,
                reason="native session initialization failed safely")
            transcript.sync()
        except (OSError, RuntimeError, TypeError, ValueError):
            logging.error("OpenAI initialization transcript finalization failed")
        with contextlib.suppress(OSError, RuntimeError):
            transcript.close()
        return SessionResult(
            resolved=False,
            duration=max(0.0, deadline.clock() - started),
            transcript_path=transcript.path,
            failure_reason=(
                "Native session initialization failed; inspect the transcript "
                "for bounded diagnostics."),
        )
