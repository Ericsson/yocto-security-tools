# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Strict, local-only configuration for named native OpenAI profiles."""
from __future__ import annotations

import configparser
import hashlib
import logging
import math
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from .backend import BackendConfigurationError, resolve_backend_selector

MAX_PROFILE_BYTES = 64 * 1024
MAX_NUM_CTX = 1_048_576
MAX_MODEL_BYTES = 256
MAX_KEEP_ALIVE_SECONDS = 7 * 24 * 60 * 60

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$", re.ASCII)
_DURATION_RE = re.compile(r"^([0-9]+)(ms|s|m|h)$", re.ASCII)
_INTEGER_RE = re.compile(r"^-?[0-9]+$", re.ASCII)
_OLLAMA_MODEL_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._/-]*(?::[A-Za-z0-9][A-Za-z0-9._-]*)?$",
    re.ASCII,
)
_TRUE_VALUES = frozenset({"true", "yes", "on", "1"})
_FALSE_VALUES = frozenset({"false", "no", "off", "0"})

_OPENAI_KEYS = frozenset({
    "base_url", "model", "api_key_env", "max_steps", "max_tool_calls",
    "max_output_tokens", "connect_timeout", "request_timeout",
    "allow_remote_endpoint", "allow_insecure_remote_http",
})
_CHAT_KEYS = frozenset({"temperature", "top_p", "reasoning_effort"})
_OLLAMA_KEYS = frozenset({
    "api_base_url", "source_model", "target_model", "num_ctx",
    "create_if_missing", "recreate_if_mismatch", "require_tools", "preload",
    "keep_alive", "verify_context",
})
_ALLOWED_KEYS = {
    "openai": _OPENAI_KEYS,
    "chat": _CHAT_KEYS,
    "ollama": _OLLAMA_KEYS,
}
_FORBIDDEN_SECRET_KEYS = frozenset({
    "api_key", "token", "authorization", "headers", "extra_headers",
    "extra_body",
})

_OPENAI_INTEGER_BOUNDS = {
    "max_steps": (1, 100),
    "max_tool_calls": (1, 1000),
    "max_output_tokens": (1, 131072),
    "connect_timeout": (1, 300),
    "request_timeout": (1, 3600),
}


class OpenAIProfileError(BackendConfigurationError):
    """A named profile could not be loaded safely or validated."""


class _StrictProfileParser(configparser.ConfigParser):
    """Preserve key case so non-schema variants cannot be normalized silently."""

    def optionxform(self, optionstr: str) -> str:
        return optionstr


@dataclass(frozen=True)
class OllamaProfile:
    """Validated profile-only values for native Ollama preparation."""

    api_base_url: str | None
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
        if self.api_base_url is not None and not isinstance(self.api_base_url, str):
            raise OpenAIProfileError("Ollama api_base_url must be a string")
        normalize_ollama_model(self.source_model)
        normalize_ollama_model(self.target_model)
        if (isinstance(self.num_ctx, bool) or not isinstance(self.num_ctx, int)
                or self.num_ctx < 1 or self.num_ctx > MAX_NUM_CTX):
            raise OpenAIProfileError(f"num_ctx must be between 1 and {MAX_NUM_CTX}")
        for name in (
            "create_if_missing", "recreate_if_mismatch", "require_tools",
            "preload", "verify_context",
        ):
            if not isinstance(getattr(self, name), bool):
                raise OpenAIProfileError(f"{name} must be a strict boolean")
        if (self.create_if_missing or self.recreate_if_mismatch) and (
                normalize_ollama_model(self.source_model)
                == normalize_ollama_model(self.target_model)):
            raise OpenAIProfileError(
                "source_model and target_model must differ when creation is enabled")
        if isinstance(self.keep_alive, bool) or not isinstance(self.keep_alive, (str, int)):
            raise OpenAIProfileError("keep_alive must be a bounded Ollama duration")
        parsed_keep_alive = _parse_keep_alive(str(self.keep_alive))
        object.__setattr__(self, "keep_alive", parsed_keep_alive)


@dataclass(frozen=True)
class OpenAIProfile:
    """One securely loaded profile with bounded audit metadata."""

    name: str
    path: Path
    sha256: str
    openai: Mapping[str, str]
    chat: Mapping[str, object]
    ollama: OllamaProfile | None


def default_openai_config_dir() -> Path:
    """Return the source-tree profile directory without consulting ``cwd``."""
    return Path(__file__).resolve().parent.parent / "etc"


def resolve_openai_profile_path(
    profile_name: str,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Resolve one fixed profile filename below the configured absolute root."""
    selection = resolve_backend_selector(f"openai-{profile_name}")
    if selection.profile != profile_name:
        raise OpenAIProfileError("invalid OpenAI profile name")
    environ = os.environ if environ is None else environ
    override = environ.get("CVE_AGENT_OPENAI_CONFIG_DIR")
    if override is None:
        directory = default_openai_config_dir()
    else:
        if "\x00" in override or not Path(override).is_absolute():
            raise OpenAIProfileError(
                "CVE_AGENT_OPENAI_CONFIG_DIR must be an absolute directory path")
        directory = Path(override)
    return directory / f"openai-{profile_name}.cfg"


def load_openai_profile(
    profile_name: str,
    environ: Mapping[str, str] | None = None,
) -> OpenAIProfile:
    """Open, read exactly once, parse, and fully validate a named profile."""
    path = resolve_openai_profile_path(profile_name, environ)
    raw = _read_profile_file(path)
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise OpenAIProfileError(
            f"OpenAI profile '{profile_name}' is not valid UTF-8") from exc
    if re.search(r"(?m)^\s*\[DEFAULT\]\s*(?:[#;].*)?$", text):
        raise OpenAIProfileError("OpenAI profiles must not contain a [DEFAULT] section")
    parser = _StrictProfileParser(
        interpolation=None,
        strict=True,
        empty_lines_in_values=False,
    )
    try:
        parser.read_string(text, source=path.name)
    except configparser.Error as exc:
        raise OpenAIProfileError(
            f"OpenAI profile '{profile_name}' is malformed: {type(exc).__name__}") from exc
    if parser.defaults():
        raise OpenAIProfileError("OpenAI profiles must not contain a [DEFAULT] section")
    sections = parser.sections()
    unknown_sections = set(sections) - set(_ALLOWED_KEYS)
    if unknown_sections:
        raise OpenAIProfileError(
            f"unknown OpenAI profile section: {sorted(unknown_sections)[0]}")
    for required in ("openai",):
        if required not in sections:
            raise OpenAIProfileError(f"OpenAI profile is missing [{required}]")

    values: dict[str, dict[str, str]] = {}
    for section in sections:
        section_values = dict(parser.items(section, raw=True))
        unknown_keys = set(section_values) - _ALLOWED_KEYS[section]
        if unknown_keys:
            key = sorted(unknown_keys)[0]
            if key.lower() in _FORBIDDEN_SECRET_KEYS:
                raise OpenAIProfileError(
                    f"secret-bearing or custom request key '{key}' is forbidden")
            raise OpenAIProfileError(f"unknown key '{key}' in [{section}]")
        values[section] = section_values

    openai = values["openai"]
    _validate_openai_values(openai)
    chat = _parse_chat_values(values.get("chat", {}))
    ollama = _parse_ollama_values(values["ollama"]) if "ollama" in values else None
    return OpenAIProfile(
        name=profile_name,
        path=path,
        sha256=hashlib.sha256(raw).hexdigest(),
        openai=MappingProxyType(dict(openai)),
        chat=MappingProxyType(chat),
        ollama=ollama,
    )


def _read_profile_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OpenAIProfileError(f"requested OpenAI profile was not found: {path}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OpenAIProfileError("OpenAI profile must be a regular file")
        if info.st_mode & stat.S_IWOTH:
            raise OpenAIProfileError("OpenAI profile must not be world-writable")
        if info.st_mode & stat.S_IWGRP:
            logging.warning("OpenAI profile %s is group-writable", path)
        if info.st_size > MAX_PROFILE_BYTES:
            raise OpenAIProfileError("OpenAI profile exceeds the 64 KiB limit")
        chunks: list[bytes] = []
        remaining = MAX_PROFILE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(remaining, 16 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_PROFILE_BYTES:
            raise OpenAIProfileError("OpenAI profile exceeds the 64 KiB limit")
        return raw
    except OSError as exc:
        raise OpenAIProfileError("OpenAI profile could not be read safely") from exc
    finally:
        os.close(descriptor)


def _validate_openai_values(values: Mapping[str, str]) -> None:
    for key, value in values.items():
        if not value.strip():
            raise OpenAIProfileError(f"[{key}] profile value must not be empty")
    if "model" in values:
        _bounded_line(values["model"], "OpenAI model")
    if "api_key_env" in values and not _ENV_NAME_RE.fullmatch(values["api_key_env"].strip()):
        raise OpenAIProfileError("api_key_env must name a valid environment variable")
    for key, (lower, upper) in _OPENAI_INTEGER_BOUNDS.items():
        if key in values:
            _parse_int(values[key], key, lower, upper)
    for key in ("allow_remote_endpoint", "allow_insecure_remote_http"):
        if key in values:
            _parse_bool(values[key], key)


def _parse_chat_values(values: Mapping[str, str]) -> dict[str, object]:
    parsed: dict[str, object] = {}
    if "temperature" in values:
        parsed["temperature"] = _parse_float(values["temperature"], "temperature", 0, 2)
    if "top_p" in values:
        result = _parse_float(values["top_p"], "top_p", 0, 1)
        if result <= 0:
            raise OpenAIProfileError("top_p must be greater than 0 and at most 1")
        parsed["top_p"] = result
    if "reasoning_effort" in values:
        effort = values["reasoning_effort"].strip()
        if effort not in {"none", "low", "medium", "high", "max"}:
            raise OpenAIProfileError(
                "reasoning_effort must be one of: none, low, medium, high, max")
        parsed["reasoning_effort"] = effort
    return parsed


def _parse_ollama_values(values: Mapping[str, str]) -> OllamaProfile:
    for key in ("source_model", "target_model", "num_ctx"):
        if key not in values:
            raise OpenAIProfileError(f"[ollama] requires {key}")
    source = _bounded_line(values["source_model"], "Ollama source model")
    target = _bounded_line(values["target_model"], "Ollama target model")
    num_ctx = _parse_int(values["num_ctx"], "num_ctx", 1, MAX_NUM_CTX)
    create = _parse_bool(values.get("create_if_missing", "false"), "create_if_missing")
    recreate = _parse_bool(
        values.get("recreate_if_mismatch", "false"), "recreate_if_mismatch")
    if (create or recreate) and normalize_ollama_model(source) == normalize_ollama_model(target):
        raise OpenAIProfileError(
            "source_model and target_model must differ when creation is enabled")
    keep_alive = _parse_keep_alive(values.get("keep_alive", "0"))
    return OllamaProfile(
        api_base_url=values.get("api_base_url"),
        source_model=source,
        target_model=target,
        num_ctx=num_ctx,
        create_if_missing=create,
        recreate_if_mismatch=recreate,
        require_tools=_parse_bool(values.get("require_tools", "false"), "require_tools"),
        preload=_parse_bool(values.get("preload", "false"), "preload"),
        keep_alive=keep_alive,
        verify_context=_parse_bool(values.get("verify_context", "false"), "verify_context"),
    )


def normalize_ollama_model(value: str) -> str:
    """Normalize only Ollama's implicit ``:latest`` tag for exact comparison."""
    model = _bounded_line(value, "Ollama model")
    if (not _OLLAMA_MODEL_RE.fullmatch(model) or ".." in model
            or "//" in model or model.endswith("/")):
        raise OpenAIProfileError("Ollama model must be a bounded ASCII model tag")
    model = model.casefold()
    final_component = model.rsplit("/", 1)[-1]
    return model if ":" in final_component else f"{model}:latest"


def _bounded_line(value: str, label: str) -> str:
    if not isinstance(value, str):
        raise OpenAIProfileError(f"{label} must be a string")
    result = value.strip()
    if (not result or len(result.encode("utf-8")) > MAX_MODEL_BYTES
            or not result.isprintable() or "\r" in result or "\n" in result):
        raise OpenAIProfileError(f"{label} must be a bounded printable line")
    return result


def _parse_bool(value: str, label: str) -> bool:
    normalized = value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise OpenAIProfileError(f"{label} must be a strict boolean")


def _parse_int(value: str, label: str, lower: int, upper: int) -> int:
    text = value.strip()
    if not _INTEGER_RE.fullmatch(text):
        raise OpenAIProfileError(f"{label} must be an integer")
    result = int(text)
    if result < lower or result > upper:
        raise OpenAIProfileError(f"{label} must be between {lower} and {upper}")
    return result


def _parse_float(value: str, label: str, lower: float, upper: float) -> float:
    try:
        result = float(value.strip())
    except ValueError as exc:
        raise OpenAIProfileError(f"{label} must be a finite number") from exc
    if not math.isfinite(result) or result < lower or result > upper:
        raise OpenAIProfileError(f"{label} must be between {lower} and {upper}")
    return result


def _parse_keep_alive(value: str) -> str | int:
    text = value.strip()
    if _INTEGER_RE.fullmatch(text):
        seconds = int(text)
        if seconds in {-1, 0} or 1 <= seconds <= MAX_KEEP_ALIVE_SECONDS:
            return seconds
        raise OpenAIProfileError("keep_alive seconds exceed the seven-day limit")
    match = _DURATION_RE.fullmatch(text)
    if match is None:
        raise OpenAIProfileError("keep_alive must be a bounded Ollama duration")
    count = int(match.group(1))
    unit = match.group(2)
    multiplier = {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[unit]
    if count <= 0 or count * multiplier > MAX_KEEP_ALIVE_SECONDS:
        raise OpenAIProfileError("keep_alive duration exceeds the seven-day limit")
    return text
