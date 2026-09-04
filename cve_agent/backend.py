# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Pluggable AI backend interface for CVE agent sessions."""
import logging
import os
import re
import subprocess
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from shared import TEXT_ENCODING, TEXT_ERRORS, build_git_env

from .result import ResultOutcome


class BackendConfigurationError(ValueError):
    """Invalid backend configuration supplied by the operator."""


class BackendRuntimeUnavailableError(RuntimeError):
    """A configured backend has no runnable session implementation."""


_OPENAI_PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$", re.ASCII)

# --- --verify-backend support -----------------------------------------

#: Fixed marker string a backend must echo back verbatim to prove it can
#: actually respond (not just that its CLI binary is on PATH).
VERIFY_MARKER = "cve-agent-verify-v1"
#: Wall-clock budget for a verification round trip, independent of
#: --session-timeout (which governs real, much longer conflict-resolution
#: sessions).
VERIFY_TIMEOUT = 30
VERIFY_PROMPT = f"Reply with exactly {VERIFY_MARKER} and nothing else."


@dataclass
class VerifyResult:
    """Outcome of :meth:`AIBackend.verify`."""

    ok: bool
    detail: str = ""


def _verify_cli_marker(cmd: list[str], timeout: int = VERIFY_TIMEOUT,
                       extra_env: Optional[Mapping[str, str]] = None
                       ) -> VerifyResult:
    """Run a bare CLI invocation and check the fixed marker comes back.

    Runs in a hermetic temporary directory — no BBPATH, no git repository,
    no file or git operations — since this only has to prove the backend's
    CLI can respond to a prompt at all. Uses :func:`shared.build_git_env` as
    the base environment (safe defaults, no interactive prompts) with
    ``extra_env`` layered on top for backend-specific auth variables that
    ``build_git_env`` deliberately filters out.
    """
    env = build_git_env()
    if extra_env:
        env.update(extra_env)
    with tempfile.TemporaryDirectory(prefix="cve-agent-verify-") as scratch:
        try:
            result = subprocess.run(
                cmd, cwd=scratch, env=env, timeout=timeout, check=False,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                encoding=TEXT_ENCODING, errors=TEXT_ERRORS)
        except FileNotFoundError:
            return VerifyResult(False, f"'{cmd[0]}' not found on PATH")
        except subprocess.TimeoutExpired:
            return VerifyResult(False, f"timed out after {timeout}s")
    output = result.stdout or ""
    if result.returncode != 0:
        return VerifyResult(False, f"exited {result.returncode}")
    if VERIFY_MARKER not in output:
        return VerifyResult(False, "responded without the expected marker")
    return VerifyResult(True, "")


@dataclass(frozen=True)
class BackendSelection:
    """One user-facing selector resolved to a canonical backend and profile."""

    selector: str
    backend: str
    profile: Optional[str] = None


def resolve_backend_selector(selector: str) -> BackendSelection:
    """Resolve the reserved ``openai-<profile>`` selector namespace once."""
    if not isinstance(selector, str) or not selector:
        raise BackendConfigurationError("backend selector must be a non-empty string")
    if selector == "openai":
        return BackendSelection(selector, "openai")
    if selector.startswith("openai-"):
        profile = selector[len("openai-"):]
        if (not _OPENAI_PROFILE_RE.fullmatch(profile)
                or ".." in profile):
            raise BackendConfigurationError(
                "OpenAI profile names must be 1-64 lowercase ASCII characters "
                "from a-z, 0-9, '.', '_', and '-', must start with a letter or "
                "digit, and must not contain '..'")
        return BackendSelection(selector, "openai", profile)
    return BackendSelection(selector, selector)


@dataclass
class SessionResult:
    """Outcome of an AI session.

    ``credits``/``credits_unit`` capture the backend's own end-of-session cost
    report when it emits one (kiro-cli prints ``Credits: 5.86 • Time: …``).
    They are backend-agnostic and default to ``None`` — only backends that
    surface a parseable cost figure populate them. ``duration`` remains the
    authoritative wall-clock time measured by the agent.
    """
    resolved: bool
    duration: float
    transcript_path: Optional[Path] = None
    failure_reason: str = ""
    credits: Optional[float] = None
    credits_unit: Optional[str] = None
    outcome: Optional[ResultOutcome] = None


class AIBackend:
    """Abstract interface for AI session backends.

    Subclass this and implement run_session() to add a new AI backend.
    Place the file in extra/ for auto-discovery.
    """
    name: str = ""
    default_model: Optional[str] = "claude-sonnet-5"

    def run_session(self, prompt: str, workspace_path: Path,
                   allowed_files: set, model: str,
                   timeout: int, interactive: bool) -> SessionResult:
        """Run an AI session to resolve conflicts."""
        raise NotImplementedError

    def is_available(self) -> bool:
        """Check if this backend's prerequisites are met."""
        raise NotImplementedError

    def setup(self, **kwargs) -> None:
        """Perform any one-time setup."""

    def configure(self, options: Mapping[str, object],
                  environ: Optional[Mapping[str, str]] = None) -> None:
        """Validate and store backend-specific configuration.

        This optional hook is deliberately concrete so existing external
        backends do not need to implement it. Backend-specific options stay
        out of :meth:`run_session`, whose signature is part of the plugin API.
        """

    def resolve_model(self, requested: Optional[str],
                      environ: Optional[Mapping[str, str]] = None) -> str:
        """Resolve a requested model while preserving the historic default."""
        if requested:
            return requested
        if self.default_model is None:
            raise BackendConfigurationError(
                f"backend '{self.name}' requires an explicit model")
        return self.default_model

    def tool_preamble(self) -> str:
        """Backend-specific tool-name guidance to prepend to AGENT_INSTRUCTIONS.md.

        AGENT_INSTRUCTIONS.md is shared verbatim across backends and
        intentionally avoids naming concrete tools (different backends
        expose different tool names for file I/O and shell execution).
        Override this to supply that mapping — e.g. "use `fs_read` for file
        inspection" for kiro-cli, "use `Read`/`Bash` for file inspection"
        for Claude Code. Returns "" by default (no preamble), which is fine
        for backends whose runtime already documents its own tool names to
        the model independently of these instructions.
        """
        return ""

    def assembled_instructions(self) -> str:
        """Return this backend's preamble followed by pure shared guidance."""
        from . import read_shared_agent_instructions

        return self.tool_preamble() + read_shared_agent_instructions()

    def verify(self) -> VerifyResult:
        """Run a trivial no-op check that this backend can actually respond.

        Used by ``--verify-backend`` to catch a missing/misconfigured/
        unauthenticated backend before a real (much longer) CVE workflow
        starts. The default implementation falls back to :meth:`is_available`
        (a presence check only), so third-party ``extra/`` plugin backends
        keep working unmodified. Built-in backends (kiro, claude, openai)
        override this with a real invocation.
        """
        if not self.is_available():
            return VerifyResult(False, "prerequisites not met (CLI missing?)")
        return VerifyResult(True, "presence check only (no functional probe)")


_BACKENDS: dict[str, AIBackend] = {}


def _ensure_builtin_backends() -> None:
    """Register built-in backends that live in their own modules.

    Imported lazily (not at module bottom) because those modules import
    AIBackend/SessionResult from here — an import at the bottom of this
    module makes ``import cve_agent.claude_backend`` fail with a circular
    import whenever it is imported before ``cve_agent.backend``.

    A backend already registered under the same name (an ``extra/`` plugin
    loaded first) is left in place, so plugin override semantics hold.
    """
    if "kiro" not in _BACKENDS:
        from .kiro_backend import KiroBackend
        _BACKENDS["kiro"] = KiroBackend()
    if "claude" not in _BACKENDS:
        from .claude_backend import ClaudeBackend
        _BACKENDS["claude"] = ClaudeBackend()
    if "openai" not in _BACKENDS:
        from .openai_backend import OpenAICompatibleBackend
        _BACKENDS["openai"] = OpenAICompatibleBackend()


def register_backend(backend: AIBackend) -> None:
    """Register an additional AI backend."""
    _BACKENDS[backend.name] = backend


def get_backend(name: str = "kiro") -> AIBackend:
    """Get backend by name."""
    _ensure_builtin_backends()
    if name not in _BACKENDS:
        raise ValueError(
            f"Unknown backend '{name}'. Available: {list(_BACKENDS.keys())}")
    return _BACKENDS[name]


def available_backends() -> list:
    """List registered backend names."""
    _ensure_builtin_backends()
    return list(_BACKENDS.keys())


def load_extra_backends() -> None:
    """Discover and register AI backend plugins from extra/ directory.

    Must be called explicitly — not run at import time.
    Uses CVE_EXTRA_BACKENDS_DIR env var, or falls back to the project's
    extra/ directory. Symlinks are resolved before loading.
    """
    import importlib.util
    project_root = Path(__file__).resolve().parent.parent
    extra_dir = os.environ.get('CVE_EXTRA_BACKENDS_DIR',
                               str(project_root / 'extra'))
    extra_path = Path(extra_dir).resolve()
    if not extra_path.is_dir():
        return
    # Security: refuse to load from world-writable or unowned directories
    dir_stat = extra_path.stat()
    if dir_stat.st_mode & 0o002:
        logging.warning("Backend plugin dir %s is world-writable, skipping",
                        extra_path)
        return
    if dir_stat.st_uid != os.getuid():
        logging.warning("Backend plugin dir %s not owned by current user, skipping",
                        extra_path)
        return
    for py_file in sorted(extra_path.glob('*.py')):
        if py_file.name.startswith('_'):
            continue
        # Security: refuse to load symlinks (eliminates TOCTOU race)
        if py_file.is_symlink():
            logging.warning("Backend plugin %s is a symlink, skipping", py_file.name)
            continue
        try:
            file_stat = py_file.stat()
        except OSError:
            logging.debug("Cannot stat %s, skipping", py_file.name)
            continue
        if file_stat.st_mode & 0o002:
            logging.warning("Backend plugin %s is world-writable, skipping",
                            py_file.name)
            continue
        if file_stat.st_uid != os.getuid():
            logging.warning("Backend plugin %s not owned by current user, skipping",
                            py_file.name)
            continue
        try:
            spec = importlib.util.spec_from_file_location(
                f"extra_backend.{py_file.stem}", py_file)
            if spec is None or spec.loader is None:
                continue
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
        except Exception as e:
            logging.debug("Extra backend load %s: %s", py_file.name, e)
