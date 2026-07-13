# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Contract tests for the Claude backend using a stub ``claude`` CLI.

The unit tests in test_claude_backend.py mock ``subprocess.Popen`` and so
verify the command list we *build*. These tests instead spawn a real
subprocess — a stub ``claude`` executable that records the argv, environment,
and working directory it actually receives — verifying the full spawn path
(PATH lookup, argument encoding, environment filtering) without needing the
real binary or an API key.
"""
import os
import subprocess
from pathlib import Path

import pytest

from cve_agent.claude_backend import (
    _ALLOWED_TOOLS,
    _CLAUDE_ENV_PREFIXES,
    _CLAUDE_ENV_VARS,
    ClaudeBackend,
)


@pytest.fixture
def fake_claude(tmp_path, monkeypatch):
    """Install a stub ``claude`` on PATH recording argv/env/cwd; returns dir.

    argv is recorded NUL-separated so multi-word arguments (the prompt)
    survive round-tripping exactly as the process received them.

    Real Claude/cloud credentials are scrubbed first: the stub dumps the
    child environment to a plaintext file under tmp_path, and a developer's
    genuine ANTHROPIC_API_KEY must never be recorded there. Tests that
    assert on auth passthrough set their own dummy values.
    """
    for key in list(os.environ):
        if key in _CLAUDE_ENV_VARS or key.startswith(_CLAUDE_ENV_PREFIXES):
            monkeypatch.delenv(key, raising=False)
    record_dir = tmp_path / "claude-record"
    record_dir.mkdir()
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir()
    stub = bin_dir / "claude"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        f"printf '%s\\0' \"$@\" > '{record_dir}/argv'\n"
        f"env > '{record_dir}/env'\n"
        f"pwd > '{record_dir}/cwd'\n"
        "exit 0\n",
        encoding="utf-8")
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    return record_dir


def _make_workspace(tmp_path: Path) -> Path:
    """Create a devtool-style workspace: <build>/workspace/sources/<recipe>."""
    workspace = tmp_path / "workspace" / "sources" / "openssl"
    workspace.mkdir(parents=True)
    return workspace


def _recorded_argv(record_dir: Path) -> list[str]:
    raw = (record_dir / "argv").read_text(encoding="utf-8")
    return raw.split("\0")[:-1]  # drop trailing empty field after final NUL


def _recorded_env(record_dir: Path) -> dict[str, str]:
    env = {}
    for line in (record_dir / "env").read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            env[key] = value
    return env


def test_stub_receives_expected_argv(fake_claude, tmp_path):
    """The spawned process sees flags, mapped model, and an intact prompt."""
    workspace = _make_workspace(tmp_path)
    prompt = "Read the context file and resolve the conflict in tasn_dec.c."

    result = ClaudeBackend().run_session(
        prompt, workspace, {"crypto/foo.c"}, "claude-sonnet-4.6", 60, False)

    argv = _recorded_argv(fake_claude)
    assert argv[0] == "-p"
    assert argv[argv.index("--model") + 1] == "sonnet"
    assert argv[argv.index("--permission-mode") + 1] == "acceptEdits"
    assert "--append-system-prompt" in argv
    assert "--add-dir" in argv

    # The multi-word prompt must arrive as ONE argument after "--" — this is
    # exactly the encoding bug a mocked Popen cannot catch.
    assert argv[-2] == "--"
    assert argv[-1] == prompt

    # Every allowed tool must survive the spawn as its own argument.
    for tool in _ALLOWED_TOOLS:
        assert tool in argv

    # Stub exits 0 with no git repo present: rev-parse/status fail closed.
    assert result.duration >= 0


def test_stub_env_has_auth_but_not_secrets(fake_claude, tmp_path, monkeypatch):
    """The real child env keeps Claude/cloud auth and drops other secrets."""
    workspace = _make_workspace(tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-123")
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-other-vendor")
    monkeypatch.setenv("MY_APP_SECRET", "hunter2")

    ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 60, False)

    env = _recorded_env(fake_claude)
    assert env.get("ANTHROPIC_API_KEY") == "sk-test-123"
    assert env.get("CLAUDE_CODE_USE_BEDROCK") == "1"
    assert "GITHUB_TOKEN" not in env
    assert "OPENAI_API_KEY" not in env
    assert "MY_APP_SECRET" not in env


def test_stub_runs_in_workspace_cwd(fake_claude, tmp_path):
    """claude must be spawned inside the recipe workspace directory."""
    workspace = _make_workspace(tmp_path)

    ClaudeBackend().run_session("prompt", workspace, set(), "sonnet", 60, False)

    recorded = Path((fake_claude / "cwd").read_text(encoding="utf-8").strip())
    assert recorded.resolve() == workspace.resolve()


@pytest.mark.integration
def test_resolution_verdict_from_real_git_state(fake_claude, tmp_path):
    """End-to-end through a real spawn AND real git: a clean committed
    workspace yields resolved=True from actual `git status` output, not a
    mocked porcelain string."""
    workspace = _make_workspace(tmp_path)
    env = os.environ.copy()
    env.update({"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"})
    subprocess.run(["git", "init"], cwd=workspace, check=True,
                   capture_output=True, env=env)
    (workspace / "file.c").write_text("int x = 1;\n", encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=workspace, check=True,
                   capture_output=True, env=env)
    subprocess.run(["git", "commit", "-m", "base"], cwd=workspace, check=True,
                   capture_output=True, env=env)

    result = ClaudeBackend().run_session(
        "prompt", workspace, set(), "sonnet", 60, False)

    assert result.resolved is True
    assert result.duration >= 0
