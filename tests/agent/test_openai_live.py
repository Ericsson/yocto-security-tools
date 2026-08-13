# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Opt-in, nondeterministic Ollama smoke test for the native agent stack."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from cve_agent import get_agent_dir
from cve_agent.openai_backend import OpenAICompatibleBackend

pytestmark = pytest.mark.live


def _git(repo: Path, *arguments: str) -> None:
    result = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)


def test_live_ollama_read_only_workspace_smoke(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Probe real tool use only when explicitly enabled by an operator.

    Model behavior is nondeterministic, so this is a developer smoke test and
    never a CI gate. It does not install Ollama or pull a model.
    """
    if os.environ.get("CVE_AGENT_LIVE_OPENAI_TEST") != "1":
        pytest.skip("set CVE_AGENT_LIVE_OPENAI_TEST=1 with an existing tool-capable model")
    model = os.environ.get("CVE_AGENT_OPENAI_MODEL", "").strip()
    if not model:
        pytest.skip("set CVE_AGENT_OPENAI_MODEL to an installed tool-capable model")

    repo = tmp_path / "build" / "workspace" / "sources" / "live-smoke"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Live Smoke")
    _git(repo, "config", "user.email", "live-smoke@example.com")
    target = repo / "probe.txt"
    target.write_text("harmless disposable content\n", encoding="utf-8")
    _git(repo, "add", "--", target.name)
    _git(repo, "commit", "-m", "disposable baseline")
    agent = get_agent_dir(repo)
    context = agent / "context.md"
    context.write_text(
        "Read probe.txt. Do not modify anything. Then call finish with "
        "status needs_human and a short smoke-test reason.\n",
        encoding="utf-8",
    )

    # A dedicated blank variable prevents accidentally forwarding a developer's
    # OPENAI_API_KEY to a local smoke endpoint.
    monkeypatch.setenv("CVE_AGENT_LIVE_TEST_NO_KEY", "")
    backend = OpenAICompatibleBackend()
    backend.configure(
        {
            "model": model,
            "openai_base_url": os.environ.get(
                "CVE_AGENT_OPENAI_BASE_URL", "http://127.0.0.1:11434/v1"
            ),
            "openai_api_key_env": "CVE_AGENT_LIVE_TEST_NO_KEY",
            "openai_max_steps": 4,
            "openai_max_tool_calls": 8,
            "openai_connect_timeout": 5,
            "openai_request_timeout": 20,
        },
        os.environ,
    )
    result = backend.run_session(
        f"Read {context}, inspect probe.txt without modifying it, then finish needs_human.",
        repo,
        {target.name},
        model,
        30,
        False,
    )

    assert result.resolved and result.transcript_path is not None
    assert target.read_text(encoding="utf-8") == "harmless disposable content\n"
    assert not subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    events = [
        json.loads(line) for line in result.transcript_path.read_text(encoding="utf-8").splitlines()
    ]
    tool_names = [event.get("tool") for event in events if event["event"] == "tool_result"]
    assert "read_file" in tool_names
    assert events[-1]["event"] == "session_end"
