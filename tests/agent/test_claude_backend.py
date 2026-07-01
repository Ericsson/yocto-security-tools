# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the Claude Code (`claude` CLI) AI backend."""
import subprocess
from pathlib import Path

import pytest

from cve_agent.backend import available_backends, get_backend
from cve_agent.claude_backend import (
    _DENIED_READ_WRITE,
    _DENIED_WRITE,
    ClaudeBackend,
)


def _make_workspace(tmp_path: Path) -> Path:
    """Create a devtool-style workspace: <build>/workspace/sources/<recipe>."""
    workspace = tmp_path / "workspace" / "sources" / "openssl"
    workspace.mkdir(parents=True)
    return workspace


def _completed(cmd, stdout=""):
    return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")


def test_claude_backend_registered():
    assert "claude" in available_backends()
    backend = get_backend("claude")
    assert backend.name == "claude"
    assert isinstance(backend, ClaudeBackend)


def test_is_available_true(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/claude")
    assert ClaudeBackend().is_available() is True


def test_is_available_false(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda name: None)
    assert ClaudeBackend().is_available() is False


@pytest.mark.parametrize("given,expected", [
    ("claude-sonnet-4.6", "sonnet"),
    ("claude-sonnet-4-6", "sonnet"),
    ("claude-opus-4.6", "opus"),
    ("", "sonnet"),
    ("sonnet", "sonnet"),
    ("opus", "opus"),
    ("haiku", "haiku"),
    ("claude-3-5-sonnet-20241022", "claude-3-5-sonnet-20241022"),
])
def test_map_model(given, expected):
    assert ClaudeBackend()._map_model(given) == expected


def test_run_session_noninteractive_command(tmp_path, monkeypatch):
    workspace = _make_workspace(tmp_path)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return _completed(cmd)

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", fake_run)

    result = ClaudeBackend().run_session(
        "Read the file /x/context.md and follow it.",
        workspace, {"crypto/foo.c"}, "claude-sonnet-4.6", 300, False)

    assert result.resolved is True
    assert result.duration >= 0

    claude_cmd, claude_kwargs = next(
        (c, k) for c, k in calls if c[0] == "claude")

    # Headless print mode, model mapped, auto-accept edits.
    assert claude_cmd[1] == "-p"
    assert claude_cmd[claude_cmd.index("--model") + 1] == "sonnet"
    assert claude_cmd[claude_cmd.index("--permission-mode") + 1] == "acceptEdits"

    # Context file lives outside cwd, so the agent dir must be shared.
    assert "--add-dir" in claude_cmd
    # System prompt carries the packaged agent instructions.
    assert "--append-system-prompt" in claude_cmd

    # Tool allow-list and deny-list are present (defense-in-depth).
    assert "Edit" in claude_cmd
    assert "Bash(git status:*)" in claude_cmd
    assert "Read(//etc/**)" in claude_cmd
    assert "Edit(**/cve_agent/**/*.py)" in claude_cmd

    # Prompt is passed positionally as the final argument.
    assert claude_cmd[-1] == "Read the file /x/context.md and follow it."

    # Safe subprocess usage in the recipe workspace.
    assert claude_kwargs["cwd"] == workspace
    assert claude_kwargs.get("shell", False) is False


def test_run_session_denies_every_sensitive_path(tmp_path, monkeypatch):
    """Every deny entry from the kiro manifest translation must be emitted."""
    workspace = _make_workspace(tmp_path)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return _completed(cmd)

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", fake_run)
    ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 60, False)

    claude_cmd = next(c for c in calls if c[0] == "claude")
    for path in _DENIED_READ_WRITE:
        for tool in ("Read", "Edit", "Write"):
            assert f"{tool}({path})" in claude_cmd
    for path in _DENIED_WRITE:
        for tool in ("Edit", "Write"):
            assert f"{tool}({path})" in claude_cmd


def test_run_session_passes_claude_auth_env(tmp_path, monkeypatch):
    """Claude auth vars that build_git_env() strips must reach the subprocess."""
    workspace = _make_workspace(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-123")
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return _completed(cmd)

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", fake_run)
    ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 60, False)

    _, claude_kwargs = next((c, k) for c, k in calls if c[0] == "claude")
    assert claude_kwargs["env"]["ANTHROPIC_API_KEY"] == "sk-test-123"
    assert claude_kwargs["env"]["CLAUDE_CODE_USE_BEDROCK"] == "1"


def test_run_session_missing_binary_does_not_crash(tmp_path, monkeypatch):
    """A missing claude binary is handled gracefully (parity with kiro)."""
    workspace = _make_workspace(tmp_path)

    def fake_run(cmd, **kwargs):
        if cmd[0] == "claude":
            raise FileNotFoundError(cmd[0])
        return _completed(cmd)

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", fake_run)
    result = ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 60, False)
    assert result.duration >= 0


def test_run_session_keyboard_interrupt_does_not_crash(tmp_path, monkeypatch):
    """Ctrl-C during a session is swallowed, not propagated (parity with kiro)."""
    workspace = _make_workspace(tmp_path)

    def fake_run(cmd, **kwargs):
        if cmd[0] == "claude":
            raise KeyboardInterrupt
        return _completed(cmd)

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", fake_run)
    result = ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 60, False)
    assert result.duration >= 0


def test_run_session_interactive_omits_print(tmp_path, monkeypatch):
    workspace = _make_workspace(tmp_path)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return _completed(cmd)

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", fake_run)

    ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 60, True)

    claude_cmd = next(c for c in calls if c[0] == "claude")
    assert "-p" not in claude_cmd
    assert claude_cmd[claude_cmd.index("--permission-mode") + 1] == "default"


def test_run_session_timeout_returns_unresolved(tmp_path, monkeypatch):
    workspace = _make_workspace(tmp_path)

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 1))

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", fake_run)

    result = ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 1, False)
    assert result.resolved is False
    assert result.duration >= 0


@pytest.mark.parametrize("porcelain,expected", [
    ("", True),
    (" M crypto/foo.c\n", True),
    ("UU crypto/foo.c\n", False),
    ("AU crypto/foo.c\n", False),
])
def test_check_resolution(tmp_path, monkeypatch, porcelain, expected):
    workspace = _make_workspace(tmp_path)

    def fake_run(cmd, **kwargs):
        return _completed(cmd, stdout=porcelain)

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", fake_run)
    assert ClaudeBackend()._check_resolution(workspace) is expected
