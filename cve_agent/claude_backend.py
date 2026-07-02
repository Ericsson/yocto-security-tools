# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Claude Code AI backend for CVE agent sessions.

Drives the ``claude`` CLI (Claude Code) directly — no kiro-cli in the loop.
Mirrors :class:`cve_agent.backend.KiroBackend`: it builds a headless command,
runs it in the recipe workspace, and reports whether the conflict was resolved.

The authoritative file-scope guard remains the git pre-commit hook plus the
post-session revert installed by :func:`cve_agent.session.guarded_session`.
The ``--allowedTools`` / ``--disallowedTools`` lists below are defense-in-depth
mirrors of ``cve_agent/agents/yocto-cve-backport.json``.
"""
import contextlib
import logging
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

from shared import build_git_env

from .backend import AIBackend, SessionResult
from .git import has_in_progress_operation

# Packaged agent instructions, injected as the Claude system prompt for parity
# with the kiro agent (whose ``prompt`` field points at the same file).
_AGENT_INSTRUCTIONS = Path(__file__).resolve().parent / "AGENT_INSTRUCTIONS.md"

# Map kiro-style model names to Claude Code aliases. Valid Claude aliases and
# full model IDs pass through unchanged; an empty value falls back to "sonnet".
_MODEL_ALIASES = {
    "claude-sonnet-4.6": "sonnet",
    "claude-sonnet-4-6": "sonnet",
    "claude-opus-4.6": "opus",
    "claude-opus-4-6": "opus",
    "claude-haiku-4.5": "haiku",
    "claude-haiku-4-5": "haiku",
}

# Tool allow-list — mirrors execute_bash.allowedCommands plus fs_read/fs_write
# from cve_agent/agents/yocto-cve-backport.json.
_ALLOWED_TOOLS = (
    "Read", "Edit", "Write", "MultiEdit",
    "Bash(git status:*)",
    "Bash(git diff:*)",
    "Bash(git log:*)",
    "Bash(git show:*)",
    "Bash(git add:*)",
    "Bash(git cherry-pick:*)",
    "Bash(git am:*)",
    "Bash(git rev-parse:*)",
    "Bash(git merge-base:*)",
    "Bash(devtool build:*)",
    "Bash(cat:*)",
    "Bash(head:*)",
    "Bash(tail:*)",
)

# Secrets / system paths: deny read AND write. Absolute paths use Claude Code's
# leading "//" glob form; "~" expands to the user's home directory.
_DENIED_READ_WRITE = (
    "//etc/**",
    "//proc/**",
    "//sys/**",
    "~/.ssh/**",
    "~/.aws/**",
    "~/.kiro/**",
    "~/.gitconfig",
    "~/.netrc",
)

# Project source and tests: deny writes only (mirrors fs_write.deniedPaths).
_DENIED_WRITE = (
    "**/cve_agent/**/*.py",
    "**/cve_corrector/**/*.py",
    "**/cve_metadata_extractor/**/*.py",
    "**/shared/**/*.py",
    "**/tests/**",
)

# Auth/config env vars the `claude` CLI needs but build_git_env() filters out.
# The prefixes cover ANTHROPIC_*/CLAUDE_CODE_* (API key, auth token, base URL,
# Bedrock/Vertex toggles); the explicit names cover the cloud-credential vars
# used by the Bedrock and Vertex deployments.
_CLAUDE_ENV_PREFIXES = ("ANTHROPIC_", "CLAUDE_CODE_")
_CLAUDE_ENV_VARS = (
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE",
    "GOOGLE_APPLICATION_CREDENTIALS", "CLOUD_ML_REGION",
)


def _claude_auth_env() -> dict[str, str]:
    """Collect Claude/cloud auth env vars that build_git_env() filters out."""
    return {
        key: value for key, value in os.environ.items()
        if key in _CLAUDE_ENV_VARS or key.startswith(_CLAUDE_ENV_PREFIXES)
    }


class ClaudeBackend(AIBackend):
    """Backend that drives the Claude Code CLI (``claude``) directly."""
    name = "claude"

    def is_available(self) -> bool:
        return shutil.which("claude") is not None

    def _map_model(self, model: str) -> str:
        if not model:
            return "sonnet"
        # Known kiro-style name -> alias; otherwise assume a valid alias or id.
        return _MODEL_ALIASES.get(model, model)

    def _build_command(self, prompt: str, agent_dir: Path,
                       model: str, interactive: bool) -> list[str]:
        cmd = ["claude"]
        if not interactive:
            cmd.append("-p")
        cmd += ["--model", self._map_model(model)]
        cmd += ["--permission-mode", "acceptEdits" if not interactive else "default"]
        # The context file and agent artifacts live outside the session cwd.
        cmd += ["--add-dir", str(agent_dir)]
        if _AGENT_INSTRUCTIONS.is_file():
            cmd += ["--append-system-prompt",
                    _AGENT_INSTRUCTIONS.read_text(encoding="utf-8")]
        else:
            logging.warning(
                "Agent instructions not found (%s); running without a system "
                "prompt. File scope is still enforced by the pre-commit hook.",
                _AGENT_INSTRUCTIONS)
        for tool in _ALLOWED_TOOLS:
            cmd += ["--allowedTools", tool]
        for path in _DENIED_READ_WRITE:
            for tool in ("Read", "Edit", "Write"):
                cmd += ["--disallowedTools", f"{tool}({path})"]
        for path in _DENIED_WRITE:
            for tool in ("Edit", "Write"):
                cmd += ["--disallowedTools", f"{tool}({path})"]
        # "--" marks end-of-options: without it, claude's arg parser folds the
        # trailing prompt word-by-word into the preceding --disallowedTools
        # list instead of treating it as the prompt (reproduced: each word of
        # the prompt showed up as its own bogus "Permission deny rule" error,
        # and headless -p mode then failed with "Input must be provided
        # either through stdin or as a prompt argument").
        cmd.append("--")
        cmd.append(prompt)
        return cmd

    def run_session(self, prompt: str, workspace_path: Path,
                   allowed_files: set, model: str,
                   timeout: int, interactive: bool) -> SessionResult:
        from . import get_agent_dir

        agent_dir = get_agent_dir(workspace_path)
        # Start from the git-safe env (used by claude's child git processes),
        # then restore the Claude/cloud auth vars build_git_env() filters out.
        env = build_git_env()
        env.update(_claude_auth_env())
        cmd = self._build_command(prompt, agent_dir, model, interactive)

        pre_head = self._current_head(workspace_path)
        start = time.monotonic()
        interrupted = None
        try:
            proc = subprocess.Popen(cmd, cwd=workspace_path, env=env,
                                    start_new_session=True)
        except FileNotFoundError:
            logging.error(
                "claude CLI not found. Install Claude Code or add it to PATH.")
            proc = None

        if proc is not None:
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                interrupted = "timed out"
                self._kill_process_group(proc)
            except KeyboardInterrupt:
                interrupted = "was interrupted"
                self._kill_process_group(proc)

        duration = time.monotonic() - start
        resolved = self._check_resolution(workspace_path)
        if interrupted and resolved:
            # The session was killed before it exited normally — it may have
            # already finished its git commit right before being killed, in
            # which case HEAD moved and the resolution is real. But a clean
            # tree with an unmoved HEAD means the session never got anywhere
            # (e.g. a hard hang before touching git); don't credit that as
            # resolved just because nothing was ever staged.
            if self._current_head(workspace_path) == pre_head:
                logging.warning(
                    "claude session %s after %.1fs with no new commit in "
                    "%s; treating as unresolved despite a clean git status",
                    interrupted, duration, workspace_path)
                resolved = False
            else:
                logging.warning(
                    "claude session %s after %.1fs but had already "
                    "committed a resolution in %s before being killed",
                    interrupted, duration, workspace_path)
        return SessionResult(resolved=resolved, duration=duration)

    @staticmethod
    def _kill_process_group(proc: subprocess.Popen) -> None:
        """SIGKILL the whole process group, not just the direct child.

        ``proc`` was started with ``start_new_session=True`` so its pid is
        also its process group id. Killing only the direct child would leave
        a grandchild git process (e.g. one claude shelled out to for
        ``cherry-pick --continue``) free to keep mutating the workspace while
        the post-timeout resolution check reads git state right after.
        """
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5)

    def _current_head(self, workspace_path: Path) -> str:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=workspace_path, capture_output=True, text=True, check=False)
        return result.stdout.strip() if result.returncode == 0 else ""

    def _check_resolution(self, workspace_path: Path) -> bool:
        if has_in_progress_operation(workspace_path):
            return False
        result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=workspace_path, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return False
        for line in result.stdout.splitlines():
            if line and len(line) >= 2 and (line[0] == "U" or line[1] == "U"):
                return False
        return True
