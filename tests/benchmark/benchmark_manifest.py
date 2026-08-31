# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Immutable configuration identity for resumable benchmark campaigns."""
from __future__ import annotations

import csv
import dataclasses
import hashlib
import json
import os
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path

from cve_agent import DEFAULT_SESSION_TIMEOUT
from cve_agent.backend import get_backend, resolve_backend_selector

MANIFEST_SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 256 * 1024


class BenchmarkManifestError(ValueError):
    """A benchmark manifest is missing, unsafe, or incompatible."""


def _sha256_json(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _openai_identity(
    selector: str,
    profile_name: str | None,
    requested_model: str | None,
    environ: Mapping[str, str],
) -> dict[str, object]:
    from cve_agent.openai_backend import OpenAIConfig
    from cve_agent.openai_profile import load_openai_profile
    from cve_agent.openai_provider import ProviderCapabilities

    profile = (
        load_openai_profile(profile_name, environ)
        if profile_name is not None else None
    )
    config = OpenAIConfig.from_sources(
        {"model": requested_model},
        environ,
        None if profile is None else profile.openai,
        None if profile is None else profile.chat,
    )
    capabilities = (
        ProviderCapabilities() if profile is None else profile.capabilities)
    identity: dict[str, object] = {
        "selector": selector,
        "backend": "openai",
        "profile": profile_name,
        "profile_sha256": None if profile is None else profile.sha256,
        "model": config.model,
        "configuration": dataclasses.asdict(config),
        "capabilities": capabilities.to_dict(),
    }
    if profile is not None and profile.fallback is not None:
        fallback = load_openai_profile(profile.fallback.profile, environ)
        fallback_config = OpenAIConfig.from_sources(
            {}, environ, fallback.openai, fallback.chat)
        identity["fallback"] = {
            "profile": fallback.name,
            "profile_sha256": fallback.sha256,
            "model": fallback_config.model,
            "configuration": dataclasses.asdict(fallback_config),
            "capabilities": fallback.capabilities.to_dict(),
        }
    identity["config_id"] = _sha256_json(identity)
    return identity


def resolve_backend_identity(
    selector: str,
    requested_model: str | None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Resolve one backend selector to a stable, credential-free identity."""
    environment = os.environ if environ is None else environ
    selection = resolve_backend_selector(selector)
    if selection.backend == "openai":
        return _openai_identity(
            selection.selector, selection.profile, requested_model, environment)

    backend = get_backend(selection.backend)
    model = backend.resolve_model(requested_model, environment)
    identity: dict[str, object] = {
        "selector": selection.selector,
        "backend": selection.backend,
        "profile": selection.profile,
        "profile_sha256": None,
        "model": model,
    }
    identity["config_id"] = _sha256_json(identity)
    return identity


def build_run_manifest(
    roster_path: Path,
    metadata_path: Path,
    agent_selector: str,
    agent_models: Sequence[str | None],
    judge_selector: str,
    judge_model: str | None,
    *,
    session_timeout: int | None,
    run_timeout: int,
    environ: Mapping[str, str] | None = None,
) -> dict[str, object]:
    """Build the immutable identity for one benchmark results directory."""
    environment = os.environ if environ is None else environ
    agent = [
        resolve_backend_identity(agent_selector, model, environment)
        for model in agent_models
    ]
    judge = resolve_backend_identity(judge_selector, judge_model, environment)
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "roster_sha256": hashlib.sha256(roster_path.read_bytes()).hexdigest(),
        "cve_metadata_sha256": hashlib.sha256(metadata_path.read_bytes()).hexdigest(),
        "agent": agent,
        "agent_session_timeout": (
            DEFAULT_SESSION_TIMEOUT if session_timeout is None else session_timeout),
        "agent_run_timeout": run_timeout,
        "judge": judge,
    }


def _read_manifest(path: Path) -> dict[str, object]:
    try:
        info = path.lstat()
    except OSError as error:
        raise BenchmarkManifestError("benchmark manifest cannot be inspected") from error
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise BenchmarkManifestError("benchmark manifest must be a regular non-symlink file")
    if info.st_uid != os.getuid():
        raise BenchmarkManifestError("benchmark manifest is not owned by the current user")
    if info.st_size > MAX_MANIFEST_BYTES:
        raise BenchmarkManifestError("benchmark manifest exceeds its size limit")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BenchmarkManifestError("benchmark manifest is not valid JSON") from error
    if not isinstance(value, dict):
        raise BenchmarkManifestError("benchmark manifest must contain a JSON object")
    return value


def _has_result_rows(results_dir: Path) -> bool:
    for name in ("agent_results.csv", "judge_results.csv"):
        path = results_dir / name
        if not path.is_file():
            continue
        try:
            with path.open(newline="", encoding="utf-8") as handle:
                if next(csv.DictReader(handle), None) is not None:
                    return True
        except (OSError, UnicodeError, csv.Error) as error:
            raise BenchmarkManifestError(
                f"cannot inspect existing benchmark rows in {name}") from error
    return False


def _write_manifest(path: Path, manifest: Mapping[str, object]) -> None:
    encoded = (json.dumps(
        manifest, sort_keys=True, indent=2, allow_nan=False,
    ) + "\n").encode("utf-8")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except OSError as error:
        raise BenchmarkManifestError("cannot write benchmark manifest") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def ensure_run_manifest(
    results_dir: Path,
    expected: Mapping[str, object],
    *,
    resume: bool,
) -> None:
    """Create a manifest once or reject a resume with different configuration."""
    path = results_dir / "run-manifest.json"
    if not path.exists() and not path.is_symlink():
        if resume and _has_result_rows(results_dir):
            raise BenchmarkManifestError(
                "cannot resume benchmark rows without an immutable run manifest")
        _write_manifest(path, expected)
        return

    current = _read_manifest(path)
    if current == dict(expected):
        return
    changed = sorted(
        key for key in set(current) | set(expected)
        if current.get(key) != expected.get(key)
    )
    detail = ", ".join(changed) if changed else "unknown fields"
    raise BenchmarkManifestError(
        f"benchmark resume configuration mismatch ({detail})")
