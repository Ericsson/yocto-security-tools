# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Consolidated git/subprocess runner used by cve_corrector and cve_agent.

Provides two levels of abstraction:
- run_capture(): low-level, returns CompletedProcess (for corrector)
- run_git_stdout(): high-level git-only, returns stdout str (for agent)
"""
import subprocess
from pathlib import Path
from typing import Optional

from shared import build_git_env


def is_git_cmd(cmd: list[str]) -> bool:
    """Check if a command is a git command that needs the restricted env."""
    return bool(cmd) and str(cmd[0]) == 'git'


def run_capture(cmd: list[str],
                cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    """Execute command and capture output.

    Automatically injects the restricted git environment for git commands.

    Args:
        cmd: Command and arguments to execute.
        cwd: Working directory for the command.

    Returns:
        CompletedProcess with stdout/stderr as strings.
    """
    env = build_git_env() if is_git_cmd(cmd) else None
    return subprocess.run(cmd, cwd=cwd, capture_output=True,
                          text=True, check=False, env=env)


def run_git_stdout(args: list[str], cwd: Path) -> str:
    """Run git command and return stdout, or empty string on failure.

    Args:
        args: Git arguments (without 'git' prefix).
        cwd: Working directory.

    Returns:
        Stripped stdout on success, empty string on failure or missing cwd.
    """
    if not cwd.exists():
        return ""
    result = subprocess.run(
        ['git'] + args, cwd=cwd, env=build_git_env(),
        capture_output=True, text=True, check=False
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def run_git_display(args: list[str], cwd: Path) -> None:
    """Run git command with output printed directly (no pager).

    Args:
        args: Git arguments (without 'git' prefix).
        cwd: Working directory.
    """
    subprocess.run(
        ['git', '--no-pager'] + args, cwd=cwd, env=build_git_env(),
        check=False
    )
