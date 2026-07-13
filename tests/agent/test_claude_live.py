# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Live smoke tests against a real, installed ``claude`` CLI.

These catch what mocked tests cannot: drift between the flags ClaudeBackend
emits and what the installed Claude Code release actually accepts, and
whether a real session can resolve a real cherry-pick conflict end to end.
No Yocto build environment is needed.

They are doubly opt-in — skipped unless BOTH hold:

- a ``claude`` binary is on PATH (already authenticated), and
- ``CLAUDE_LIVE_TESTS=1`` is set (a live session spends real tokens).

Run with::

    CLAUDE_LIVE_TESTS=1 pytest -m live -v

``CLAUDE_LIVE_MODEL`` overrides the model (default: sonnet).
"""
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from cve_agent import get_agent_dir
from cve_agent.claude_backend import ClaudeBackend, _claude_auth_env
from shared import build_git_env

_MODEL = os.environ.get("CLAUDE_LIVE_MODEL", "sonnet")

pytestmark = [
    pytest.mark.live,
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("claude") is None,
                       reason="claude CLI not on PATH"),
    pytest.mark.skipif(os.environ.get("CLAUDE_LIVE_TESTS") != "1",
                       reason="set CLAUDE_LIVE_TESTS=1 to run live claude tests"),
]


def _git(cwd: Path, *args: str) -> None:
    env = build_git_env()
    env.update({"GIT_AUTHOR_NAME": "live-test", "GIT_AUTHOR_EMAIL": "t@t",
                "GIT_COMMITTER_NAME": "live-test", "GIT_COMMITTER_EMAIL": "t@t"})
    subprocess.run(["git", *args], cwd=cwd, env=env, check=True,
                   capture_output=True, text=True)


def _git_stdout(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, env=build_git_env(),
                            capture_output=True, text=True, check=True)
    return result.stdout.strip()


def test_cli_accepts_every_emitted_flag(tmp_path):
    """Run the exact command ClaudeBackend builds, with a trivial prompt.

    If any flag we emit (--permission-mode, --append-system-prompt,
    --allowedTools/--disallowedTools, the "--" end-of-options marker...) is
    renamed or removed in a Claude Code release, this fails immediately with
    the CLI's own error message — the mocked suite would keep passing.
    """
    agent_dir = tmp_path / "agent"
    agent_dir.mkdir()
    cmd = ClaudeBackend()._build_command(
        "Reply with exactly: FLAGCHECK-OK", agent_dir, _MODEL, interactive=False)
    env = build_git_env()
    env.update(_claude_auth_env())

    proc = subprocess.run(cmd, cwd=tmp_path, env=env, capture_output=True,
                          text=True, timeout=240)

    assert proc.returncode == 0, (
        f"claude rejected the emitted command:\n{proc.stderr}")
    assert "FLAGCHECK-OK" in proc.stdout


def test_resolves_real_cherry_pick_conflict(tmp_path):
    """Full production shape: conflicted cherry-pick, context file in the
    agent dir (exercises --add-dir), run_session drives a real claude, and
    the verdict comes from real git state."""
    workspace = tmp_path / "workspace" / "sources" / "demo"
    workspace.mkdir(parents=True)

    _git(workspace, "init", "-b", "main")
    conflict_file = workspace / "file.c"
    conflict_file.write_text("int value = 1;\n", encoding="utf-8")
    _git(workspace, "add", "-A")
    _git(workspace, "commit", "-m", "base")

    # Upstream fix on a branch: changes the same line as the local patch.
    _git(workspace, "checkout", "-b", "fix")
    conflict_file.write_text("int value = 2;  /* upstream CVE fix */\n",
                             encoding="utf-8")
    _git(workspace, "commit", "-am", "Fix CVE: bound value")
    fix_sha = _git_stdout(workspace, "rev-parse", "HEAD")

    _git(workspace, "checkout", "main")
    conflict_file.write_text("int value = 3;  /* local patch */\n",
                             encoding="utf-8")
    _git(workspace, "commit", "-am", "Local patch")
    pre_head = _git_stdout(workspace, "rev-parse", "HEAD")

    result = subprocess.run(["git", "cherry-pick", fix_sha], cwd=workspace,
                            env=build_git_env(), capture_output=True, text=True)
    assert result.returncode != 0, "expected a cherry-pick conflict"

    agent_dir = get_agent_dir(workspace)
    context_file = agent_dir / "context.md"
    context_file.write_text(
        "# CVE Backport Context\n\n"
        "A cherry-pick of the upstream CVE fix is in progress and file.c has "
        "a conflict.\n\n"
        "## Allowed Files\n\n- file.c\n\n"
        "## Task\n\n"
        "Resolve the conflict keeping the upstream fix (`int value = 2;`), "
        "then run `git add file.c` and `git cherry-pick --continue`. "
        "Do not modify any other file.\n",
        encoding="utf-8")

    session = ClaudeBackend().run_session(
        f"Read the file {context_file} and follow it.",
        workspace, {"file.c"}, _MODEL, timeout=600, interactive=False)

    content = conflict_file.read_text(encoding="utf-8")
    assert session.resolved is True
    assert "<<<<<<<" not in content and ">>>>>>>" not in content
    assert "int value = 2;" in content
    assert _git_stdout(workspace, "rev-parse", "HEAD") != pre_head, (
        "cherry-pick was never committed")
