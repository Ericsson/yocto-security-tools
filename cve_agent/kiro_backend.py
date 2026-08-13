# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Kiro AI backend for CVE agent sessions.

Drives ``kiro-cli`` with the packaged ``yocto-cve-backport`` agent. This is
the default backend; :mod:`cve_agent.claude_backend` mirrors its behaviour
for the ``claude`` CLI.
"""
import logging
import shlex
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from shared import build_git_env
from shared.git_runner import run_capture

from .backend import AIBackend, SessionResult
from .git import has_in_progress_operation
from .metrics import parse_kiro_credits


class KiroBackend(AIBackend):
    """Default backend using kiro-cli."""
    name = "kiro"

    def is_available(self) -> bool:
        return shutil.which("kiro-cli") is not None

    def tool_preamble(self) -> str:
        """kiro-cli's fs_read/fs_write/execute_bash tool-name mapping.

        See :meth:`AIBackend.tool_preamble`. Mirrors the tool names
        configured in ``cve_agent/agents/yocto-cve-backport*.json``.
        """
        return (
            "Your file/directory inspection tool is `fs_read`; your "
            "file-writing/editing tool is `fs_write`; your "
            "bash-equivalent command runner is `execute_bash`. Use `fs_write` "
            "to create or edit files — source-file edits, `conclusion.json`, "
            "and appending to `.git/MERGE_MSG` — never shell redirection "
            "(`>`/`>>`) or heredocs, which the command guard rejects.\n\n"
        )

    def run_session(self, prompt: str, workspace_path: Path,
                   allowed_files: set, model: str,
                   timeout: int, interactive: bool) -> SessionResult:
        cmd = self._build_kiro_cmd(prompt, agent_name=None, model=model,
                                  interactive=interactive)
        env = build_git_env()

        transcript_path: Optional[Path] = None
        run_cmd: list = cmd
        if interactive:
            transcript_path = self._transcript_path(workspace_path)
            if transcript_path is not None:
                wrapped = self._wrap_with_script(cmd, transcript_path)
                if wrapped is None:
                    transcript_path = None
                else:
                    run_cmd = wrapped

        start = time.monotonic()
        timed_out = False
        captured = ""
        # Interactive sessions have a human at the terminal — never kill them
        # with a timeout.  Non-interactive (CI) runs use the configured limit.
        effective_timeout: Optional[int] = None if interactive else timeout
        try:
            if interactive:
                subprocess.run(run_cmd, cwd=workspace_path, env=env,
                             check=False, timeout=effective_timeout)
            else:
                captured = self._run_capturing_tee(
                    run_cmd, workspace_path, env, effective_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        except FileNotFoundError:
            logging.error("kiro-cli not found. Install it or add to PATH.")
        except KeyboardInterrupt:
            pass

        duration = time.monotonic() - start
        if timed_out:
            return SessionResult(resolved=False, duration=duration,
                                transcript_path=transcript_path)

        # Interactive output isn't captured inline (full-screen TUI needs the
        # real TTY); read the tee'd transcript instead. Non-interactive runs
        # already have the streamed stdout in ``captured``.
        if interactive and transcript_path is not None:
            try:
                captured = transcript_path.read_text(
                    encoding="utf-8", errors="replace")
            except OSError as exc:
                logging.debug("Could not read transcript %s: %s",
                              transcript_path, exc)

        resolved = self._check_resolution(workspace_path)
        result = SessionResult(resolved=resolved, duration=duration,
                              transcript_path=transcript_path)
        credits = parse_kiro_credits(captured)
        if credits is not None:
            result.credits = credits
            result.credits_unit = "credits"
        return result

    @staticmethod
    def _run_capturing_tee(cmd: list, workspace_path: Path, env: dict,
                           timeout: Optional[int]) -> str:
        """Run ``cmd`` capturing combined stdout+stderr while streaming it live.

        kiro-cli's ``--no-interactive`` output is plain text (no TUI), so it
        can be piped without breaking the session. A reader thread echoes each
        line to the real stdout as it arrives (preserving the live CI log) and
        accumulates it so the trailing ``Credits: … • Time: …`` summary can be
        parsed once the process exits.

        Raises:
            subprocess.TimeoutExpired: if the process outlives ``timeout``; the
                process (group) is killed first so it can't keep mutating the
                workspace while the caller inspects git state.
            FileNotFoundError: if kiro-cli is not on PATH.
        """
        proc = subprocess.Popen(
            cmd, cwd=workspace_path, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1)
        chunks: list[str] = []

        def _pump() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                chunks.append(line)
                sys.stdout.write(line)
                sys.stdout.flush()

        reader = threading.Thread(target=_pump, daemon=True)
        reader.start()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            reader.join(timeout=5)
            raise
        reader.join(timeout=5)
        return "".join(chunks)

    @staticmethod
    def _build_kiro_cmd(prompt: str, agent_name: Optional[str], model: str,
                        interactive: bool) -> list:
        """Build the plain (unwrapped) kiro-cli argv list.

        Tool trust is defined entirely in the agent config JSON
        (``allowedTools`` / ``toolsSettings.execute_bash.allowedCommands``)
        — no ``--trust-tools``/``--trust-all-tools`` flag is passed here.
        That keeps permissions in one place: passing ``--trust-tools`` would
        only be redundant for tools already in the agent's ``allowedTools``,
        and passing it for ``execute_bash`` would bypass the JSON's
        per-command ``allowedCommands`` allow-list entirely (session-level
        tool trust outranks it), which is exactly the gating this agent
        relies on for unattended CI runs.
        """
        if agent_name is None:
            agent_name = ('yocto-cve-backport-interactive' if interactive
                          else 'yocto-cve-backport')
        cmd = ['kiro-cli', 'chat', '--agent', agent_name, '--model', model]
        if not interactive:
            cmd.append('--no-interactive')
        cmd.append(prompt)
        return cmd

    @staticmethod
    def _transcript_path(workspace_path: Path) -> Optional[Path]:
        """Build a per-session transcript file path under the agent dir.

        Returns None (no transcript) if the directory can't be created,
        e.g. under a read-only or nonexistent workspace path.
        """
        from . import get_agent_dir
        try:
            agent_dir = get_agent_dir(workspace_path)
        except OSError as exc:
            logging.warning(
                "Could not create transcript directory under %s (%s); "
                "interactive session will not be transcribed.",
                workspace_path, exc)
            return None
        return agent_dir / f"kiro-session-{int(time.time())}.log"

    @staticmethod
    def _wrap_with_script(cmd: list, transcript_path: Path) -> Optional[list]:
        """Wrap ``cmd`` with ``script`` to capture stdin+stdout to a file.

        Interactive kiro-cli is a full-screen TUI that needs a real
        controlling TTY, so its own stdio can't be redirected to pipes
        without breaking the session. ``script`` allocates a pseudo-terminal
        for the child, keeps the real TTY attached for the user, and tees
        everything (both what the user types and what kiro-cli prints) into
        ``transcript_path``. Falls back to running ``cmd`` unwrapped (no
        transcript) if ``script`` isn't installed.
        """
        if shutil.which("script") is None:
            logging.warning(
                "'script' not found on PATH; interactive session will not "
                "be transcribed to a log file.")
            return None
        # -q: no start/done banner polluting the transcript
        # -e: propagate the wrapped command's exit code
        # -B: log both stdin and stdout (combined) to the transcript
        # -c: command to run instead of an interactive shell
        return ["script", "-qe", "-B", str(transcript_path),
                "-c", shlex.join(cmd)]

    def _check_resolution(self, workspace_path: Path) -> bool:
        if has_in_progress_operation(workspace_path):
            return False
        result = run_capture(['git', 'status', '--porcelain'],
                             cwd=workspace_path)
        if result.returncode != 0:
            return False
        for line in result.stdout.splitlines():
            if line and len(line) >= 2 and (line[0] == 'U' or line[1] == 'U'):
                return False
        return True

    def setup(self, **kwargs) -> None:
        from .setup import ensure_agents
        ensure_agents(interactive=kwargs.get('interactive', True))
