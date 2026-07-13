# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Kiro AI backend for CVE agent sessions.

Drives ``kiro-cli`` with the packaged ``yocto-cve-backport`` agent. This is
the default backend; :mod:`cve_agent.claude_backend` mirrors its behaviour
for the ``claude`` CLI.
"""
import logging
import subprocess
import time
from pathlib import Path

from shared import build_git_env

from .backend import AIBackend, SessionResult
from .git import has_in_progress_operation


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
