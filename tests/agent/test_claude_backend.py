# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the Claude Code (`claude` CLI) AI backend."""
import signal
import subprocess
import sys
from pathlib import Path

import pytest

import cve_agent
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


class _FakePopen:
    """Minimal stand-in for subprocess.Popen driving the `claude` process."""

    def __init__(self, cmd, wait_effect=None, **kwargs):
        self.cmd = cmd
        self.kwargs = kwargs
        self.pid = 4321
        self._wait_effect = wait_effect
        self.wait_calls = 0

    def wait(self, timeout=None):
        self.wait_calls += 1
        if self.wait_calls == 1 and self._wait_effect is not None:
            raise self._wait_effect
        return 0


def _popen_ctor(calls, wait_effect=None):
    """Fake subprocess.Popen constructor recording (cmd, kwargs) into `calls`.

    `wait_effect`, if given, is raised from the *first* proc.wait() call
    (simulating a timeout or Ctrl-C); the follow-up proc.wait() made by
    ClaudeBackend._kill_process_group() always succeeds.
    """
    def _ctor(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return _FakePopen(cmd, wait_effect=wait_effect, **kwargs)
    return _ctor


def _git_stub(porcelain="", head="deadbeef"):
    """Fake subprocess.run for the `git status`/`git rev-parse HEAD` calls
    ClaudeBackend makes around the claude session (unrelated to the Popen
    call driving `claude` itself)."""
    def _run(cmd, **kwargs):
        if cmd[:2] == ["git", "rev-parse"]:
            return _completed(cmd, stdout=f"{head}\n")
        return _completed(cmd, stdout=porcelain)
    return _run


def test_claude_backend_registered():
    assert "claude" in available_backends()
    backend = get_backend("claude")
    assert backend.name == "claude"
    assert isinstance(backend, ClaudeBackend)


def test_claude_backend_module_imports_standalone():
    """Regression: importing cve_agent.claude_backend BEFORE cve_agent.backend
    used to raise ImportError — backend.py's module-bottom registration import
    re-entered the partially initialized claude_backend module. A fresh
    interpreter is the only reliable way to test import order.
    """
    project_root = Path(cve_agent.__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "-c", "import cve_agent.claude_backend"],
        capture_output=True, text=True, check=False, cwd=project_root)
    assert result.returncode == 0, result.stderr


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
    popen_calls = []

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.Popen",
                        _popen_ctor(popen_calls))
    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", _git_stub())

    result = ClaudeBackend().run_session(
        "Read the file /x/context.md and follow it.",
        workspace, {"crypto/foo.c"}, "claude-sonnet-4.6", 300, False)

    assert result.resolved is True
    assert result.duration >= 0

    claude_cmd, claude_kwargs = popen_calls[0]

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

    # Prompt is passed positionally as the final argument, after a "--"
    # end-of-options marker (without it, claude's parser folds a multi-word
    # trailing prompt word-by-word into the preceding --disallowedTools list).
    assert claude_cmd[-2] == "--"
    assert claude_cmd[-1] == "Read the file /x/context.md and follow it."

    # Safe subprocess usage in the recipe workspace, in its own process
    # group so a timeout can kill the whole tree rather than just claude.
    assert claude_kwargs["cwd"] == workspace
    assert claude_kwargs.get("shell", False) is False
    assert claude_kwargs["start_new_session"] is True


def test_run_session_denies_every_sensitive_path(tmp_path, monkeypatch):
    """Every deny entry from the kiro manifest translation must be emitted."""
    workspace = _make_workspace(tmp_path)
    popen_calls = []

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.Popen",
                        _popen_ctor(popen_calls))
    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", _git_stub())
    ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 60, False)

    claude_cmd, _ = popen_calls[0]
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
    popen_calls = []

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.Popen",
                        _popen_ctor(popen_calls))
    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", _git_stub())
    ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 60, False)

    _, claude_kwargs = popen_calls[0]
    assert claude_kwargs["env"]["ANTHROPIC_API_KEY"] == "sk-test-123"
    assert claude_kwargs["env"]["CLAUDE_CODE_USE_BEDROCK"] == "1"


def test_run_session_excludes_unrelated_secrets(tmp_path, monkeypatch):
    """Restoring Claude auth vars must not reopen the filtered environment:
    secrets outside the Claude/cloud allow-set stay out of the session env.
    (The inverse of test_run_session_passes_claude_auth_env.)
    """
    workspace = _make_workspace(tmp_path)
    secrets = {
        "GITHUB_TOKEN": "ghp_secret",
        "OPENAI_API_KEY": "sk-other-vendor",
        "GPG_PASSPHRASE": "hunter2",
        "DATABASE_URL": "postgres://user:pass@host/db",
        "MY_APP_SECRET": "s3cr3t",
    }
    for key, value in secrets.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-123")
    popen_calls = []

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.Popen",
                        _popen_ctor(popen_calls))
    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", _git_stub())
    ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 60, False)

    _, claude_kwargs = popen_calls[0]
    session_env = claude_kwargs["env"]
    for key in secrets:
        assert key not in session_env
    assert session_env["ANTHROPIC_API_KEY"] == "sk-test-123"


def test_run_session_missing_binary_does_not_crash(tmp_path, monkeypatch):
    """A missing claude binary is handled gracefully (parity with kiro)."""
    workspace = _make_workspace(tmp_path)

    def raise_not_found(cmd, **kwargs):
        raise FileNotFoundError(cmd[0])

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.Popen", raise_not_found)
    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", _git_stub())
    result = ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 60, False)
    assert result.duration >= 0


def test_run_session_keyboard_interrupt_does_not_crash(tmp_path, monkeypatch):
    """Ctrl-C during a session is swallowed, not propagated (parity with kiro),
    the process group is still killed so nothing is left running, and — same
    as a timeout — a clean-but-unmoved-HEAD tree must not be credited as
    resolved just because Ctrl-C landed before claude touched git at all.
    """
    workspace = _make_workspace(tmp_path)
    popen_calls = []
    killed = []

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.Popen",
                        _popen_ctor(popen_calls, wait_effect=KeyboardInterrupt()))
    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run",
                        _git_stub(head="unmoved-head"))
    monkeypatch.setattr("cve_agent.claude_backend.os.killpg",
                        lambda pid, sig: killed.append((pid, sig)))

    result = ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 60, False)
    assert result.duration >= 0
    assert result.resolved is False
    assert killed == [(4321, signal.SIGKILL)]


def test_run_session_interactive_omits_print(tmp_path, monkeypatch):
    workspace = _make_workspace(tmp_path)
    popen_calls = []

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.Popen",
                        _popen_ctor(popen_calls))
    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", _git_stub())

    ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 60, True)

    claude_cmd, _ = popen_calls[0]
    assert "-p" not in claude_cmd
    assert claude_cmd[claude_cmd.index("--permission-mode") + 1] == "default"


def test_run_session_timeout_returns_unresolved(tmp_path, monkeypatch):
    """claude times out AND the workspace genuinely still has conflicts."""
    workspace = _make_workspace(tmp_path)

    monkeypatch.setattr(
        "cve_agent.claude_backend.subprocess.Popen",
        _popen_ctor([], wait_effect=subprocess.TimeoutExpired("claude", 1)))
    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run",
                        _git_stub(porcelain="UU crypto/asn1/tasn_dec.c\n"))

    result = ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 1, False)
    assert result.resolved is False
    assert result.duration >= 0


def test_run_session_timeout_but_already_resolved(tmp_path, monkeypatch):
    """claude finishes its git commit right before the kill signal lands.

    A subprocess timeout only means the claude process didn't exit in time —
    not that its work was lost. If HEAD actually advanced (a real commit was
    made) and the tree is clean, that must be reported as resolved rather
    than triggering a wasted retry.
    """
    workspace = _make_workspace(tmp_path)
    heads = iter(["before-head", "after-head"])

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["git", "rev-parse"]:
            return _completed(cmd, stdout=f"{next(heads)}\n")
        return _completed(cmd, stdout="")

    monkeypatch.setattr(
        "cve_agent.claude_backend.subprocess.Popen",
        _popen_ctor([], wait_effect=subprocess.TimeoutExpired("claude", 1)))
    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", fake_run)

    result = ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 1, False)
    assert result.resolved is True
    assert result.duration >= 0


def test_run_session_timeout_with_no_progress_is_unresolved(tmp_path, monkeypatch):
    """A hard hang that never touched git must not be reported as resolved
    just because the tree happens to be clean. Same HEAD before and after
    means no commit was made, so nothing was actually fixed — this is the
    scenario a bare "clean tree => resolved" check on timeout would miss.
    """
    workspace = _make_workspace(tmp_path)

    monkeypatch.setattr(
        "cve_agent.claude_backend.subprocess.Popen",
        _popen_ctor([], wait_effect=subprocess.TimeoutExpired("claude", 1)))
    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run",
                        _git_stub(porcelain="", head="same-head"))

    result = ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 1, False)
    assert result.resolved is False


def test_run_session_timeout_kills_process_group(tmp_path, monkeypatch):
    """On timeout, the whole process group must be killed, not just the
    direct child — otherwise an orphaned grandchild git process (e.g. one
    claude shelled out to for `cherry-pick --continue`) can keep mutating
    the workspace while the post-timeout resolution check runs.
    """
    workspace = _make_workspace(tmp_path)
    killed = []

    monkeypatch.setattr(
        "cve_agent.claude_backend.subprocess.Popen",
        _popen_ctor([], wait_effect=subprocess.TimeoutExpired("claude", 1)))
    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", _git_stub())
    monkeypatch.setattr("cve_agent.claude_backend.os.killpg",
                        lambda pid, sig: killed.append((pid, sig)))

    ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 1, False)
    assert killed == [(4321, signal.SIGKILL)]


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


@pytest.mark.parametrize("marker", ["CHERRY_PICK_HEAD", "MERGE_HEAD"])
def test_check_resolution_mid_operation_is_unresolved(tmp_path, monkeypatch, marker):
    """Staging a conflicted file clears the U marker in porcelain output, but
    the cherry-pick/merge itself isn't finalized until --continue commits it.
    Without this check, a session that staged-but-never-continued looks
    identical to a genuinely finished one — exactly what happened in a real
    run: claude got blocked mid-session and the false "resolved" verdict let
    the workflow proceed past a fix that was never actually committed.
    """
    workspace = _make_workspace(tmp_path)
    git_dir = workspace / ".git"
    git_dir.mkdir()
    (git_dir / marker).write_text("deadbeef\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        return _completed(cmd, stdout="")  # staged: no U markers left

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", fake_run)
    assert ClaudeBackend()._check_resolution(workspace) is False


def test_check_resolution_clean_with_no_git_dir(tmp_path, monkeypatch):
    """Sanity: the marker check must not error when .git doesn't exist."""
    workspace = _make_workspace(tmp_path)

    def fake_run(cmd, **kwargs):
        return _completed(cmd, stdout="")

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", fake_run)
    assert ClaudeBackend()._check_resolution(workspace) is True


def test_current_head_returns_empty_on_failure(tmp_path, monkeypatch):
    workspace = _make_workspace(tmp_path)

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 128, stdout="", stderr="not a repo")

    monkeypatch.setattr("cve_agent.claude_backend.subprocess.run", fake_run)
    assert ClaudeBackend()._current_head(workspace) == ""
