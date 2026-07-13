# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Pluggable AI backend interface for CVE agent sessions."""
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from shared import build_git_env

from .git import has_in_progress_operation


@dataclass
class SessionResult:
    """Outcome of an AI session."""
    resolved: bool
    duration: float
    transcript_path: Optional[Path] = None


class AIBackend:
    """Abstract interface for AI session backends.

    Subclass this and implement run_session() to add a new AI backend.
    Place the file in extra/ for auto-discovery.
    """
    name: str = ""

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


class KiroBackend(AIBackend):
    """Default backend using kiro-cli."""
    name = "kiro"

    def is_available(self) -> bool:
        import shutil
        return shutil.which("kiro-cli") is not None

    def run_session(self, prompt: str, workspace_path: Path,
                   allowed_files: set, model: str,
                   timeout: int, interactive: bool) -> SessionResult:
        agent_name = ('yocto-cve-backport-interactive' if interactive
                      else 'yocto-cve-backport')
        env = build_git_env()
        cmd = ['kiro-cli', 'chat', '--agent', agent_name, '--model', model]
        if not interactive:
            cmd.append('--no-interactive')
            cmd.append('--trust-tools=fs_read,fs_write,execute_bash')
        cmd.append(prompt)

        start = time.monotonic()
        timed_out = False
        try:
            subprocess.run(cmd, cwd=workspace_path, env=env,
                         check=False, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        except FileNotFoundError:
            logging.error("kiro-cli not found. Install it or add to PATH.")
        except KeyboardInterrupt:
            pass

        duration = time.monotonic() - start
        if timed_out:
            return SessionResult(resolved=False, duration=duration)

        resolved = self._check_resolution(workspace_path)
        return SessionResult(resolved=resolved, duration=duration)

    def _check_resolution(self, workspace_path: Path) -> bool:
        if has_in_progress_operation(workspace_path):
            return False
        result = subprocess.run(
            ['git', 'status', '--porcelain'],
            cwd=workspace_path, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return False
        for line in result.stdout.splitlines():
            if line and len(line) >= 2 and (line[0] == 'U' or line[1] == 'U'):
                return False
        return True

    def setup(self, **kwargs) -> None:
        from .setup import ensure_agents
        ensure_agents(interactive=kwargs.get('interactive', True))


_BACKENDS: dict[str, AIBackend] = {"kiro": KiroBackend()}


def _ensure_builtin_backends() -> None:
    """Register built-in backends that live in their own modules.

    Imported lazily (not at module bottom) because those modules import
    AIBackend/SessionResult from here — an import at the bottom of this
    module makes ``import cve_agent.claude_backend`` fail with a circular
    import whenever it is imported before ``cve_agent.backend``.
    """
    if "claude" not in _BACKENDS:
        from .claude_backend import ClaudeBackend
        _BACKENDS["claude"] = ClaudeBackend()


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
