# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Integration tests for the native backend loop and real host runtime."""
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

from cve_agent import get_agent_dir
from cve_agent.openai_backend import OpenAICompatibleBackend
from cve_agent.openai_client import (
    AssistantResponse,
    FunctionToolCall,
    OpenAIClientEvent,
    OpenAIConnectionError,
)
from cve_agent.openai_host_tools import (
    BUILD_LOG_NAME,
    BuildCommandResult,
    OpenAIHostToolRuntime,
)
from cve_agent.orchestrator import _read_conclusion, _read_escalation


def _git(repo: Path, *args: str) -> None:
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True,
        check=False, env={**os.environ, "GIT_EDITOR": "true"})
    if result.returncode:
        raise AssertionError(result.stderr or result.stdout)


class ScriptedClient:
    def __init__(self, actions, event_sink=None) -> None:
        self.actions = list(actions)
        self.event_sink = event_sink
        self.requests = []

    def complete(self, messages, tools):
        self.requests.append((list(messages), list(tools)))
        if self.event_sink is not None:
            self.event_sink(OpenAIClientEvent("attempt", len(self.requests)))
        action = self.actions.pop(0)
        if isinstance(action, Exception):
            raise action
        return action


class FakeBuildRunner:
    def __init__(self, agent: Path) -> None:
        self.agent = agent
        self.calls = []

    def run(self, recipe: str) -> BuildCommandResult:
        self.calls.append(recipe)
        return BuildCommandResult(
            returncode=0,
            duration=0.1,
            timed_out=False,
            tail="build complete",
            truncated=False,
            total_output_bytes=14,
            log_path=self.agent / BUILD_LOG_NAME,
        )


def _call(identifier, name, arguments="{}"):
    return FunctionToolCall(identifier, name, arguments)


def _response(*calls):
    return AssistantResponse(None, tuple(calls), "tool_calls", None)


def _repository(tmp_path):
    repo = tmp_path / "build" / "workspace" / "sources" / "recipe"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "Native Test")
    _git(repo, "config", "user.email", "native@example.com")
    (repo / "a.c").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "--", "a.c")
    _git(repo, "commit", "-m", "base")
    agent = get_agent_dir(repo)
    context = agent / "context.md"
    context.write_text("trusted generated context\n", encoding="utf-8")
    return repo, agent, context


def _backend(actions, agent, *, build_runner=None):
    holder = {}

    def client_factory(config, deadline, event_sink=None):
        client = ScriptedClient(actions, event_sink)
        holder["client"] = client
        return client

    def runtime_factory(*args, **kwargs):
        if build_runner is not None:
            kwargs["build_runner"] = build_runner
        runtime = OpenAIHostToolRuntime(*args, **kwargs)
        holder["runtime"] = runtime
        return runtime

    backend = OpenAICompatibleBackend(
        client_factory=client_factory,
        runtime_factory=runtime_factory,
    )
    backend.configure({
        "model": "scripted-model",
        "openai_max_steps": 10,
        "openai_max_tool_calls": 20,
    }, {})
    return backend, holder


def test_scripted_backend_uses_real_file_git_build_and_finish_runtime(tmp_path):
    repo, agent, context = _repository(tmp_path)
    runner = FakeBuildRunner(agent)
    actions = [
        _response(
            _call("context", "read_file", json.dumps({"path": str(context)})),
            _call("status", "git_status"),
            _call("build", "build_recipe")),
        _response(_call(
            "finish", "finish",
            '{"status":"done","reason":"verified","summary":"build passed"}')),
    ]
    backend, holder = _backend(actions, agent, build_runner=runner)
    prompt = f"Read the file {context} and follow all instructions in it."
    result = backend.run_session(
        prompt, repo, {"a.c"}, "scripted-model", 30, False)

    assert result.resolved and result.transcript_path is not None
    assert runner.calls == ["recipe"]
    assert holder["runtime"].terminal_status == "done"
    first = holder["client"].requests[0][0]
    assert first[0]["role"] == "system"
    assert "There is no shell" in first[0]["content"]
    assert "semantic workflow requirements" in first[0]["content"]
    assert first[1] == {"role": "user", "content": prompt}
    assert not (agent / "conclusion.json").exists()
    transcript_events = [
        json.loads(line)
        for line in result.transcript_path.read_text(encoding="utf-8").splitlines()
    ]
    assert any(event["event"] == "http_attempt" for event in transcript_events)


def test_real_runtime_creates_trusted_noncode_conclusion_for_orchestrator(tmp_path):
    repo, agent, context = _repository(tmp_path)
    actions = [
        _response(_call(
            "context", "read_file", json.dumps({"path": str(context)}))),
        _response(_call(
            "finish", "finish",
            '{"status":"needs_human","reason":"prerequisite is out of scope"}')),
    ]
    backend, _ = _backend(actions, agent)
    result = backend.run_session(
        f"Read {context}", repo, {"a.c"}, "scripted-model", 30, False)
    assert result.resolved
    with patch("cve_agent.orchestrator.get_agent_dir", return_value=agent):
        escalation = _read_escalation(repo)
        assert escalation is not None
        assert escalation.reason == "prerequisite is out of scope"
        assert _read_conclusion(repo) is None


def test_backend_client_failure_is_safe_unresolved_and_transcribed(tmp_path):
    repo, agent, context = _repository(tmp_path)
    secret = "sk-backend-secret"
    backend, _ = _backend(
        [OpenAIConnectionError(f"connection failed Bearer {secret}")], agent)
    result = backend.run_session(
        f"Read {context}", repo, {"a.c"}, "scripted-model", 30, False)
    assert not result.resolved and result.transcript_path is not None
    transcript = result.transcript_path.read_text(encoding="utf-8")
    assert secret not in transcript
    assert "client_error" in transcript


def test_backend_refuses_to_run_when_transcript_creation_fails(tmp_path):
    repo, agent, context = _repository(tmp_path)
    called = False

    def transcript_factory(*args, **kwargs):
        raise OSError("audit storage unavailable")

    def client_factory(*args, **kwargs):
        nonlocal called
        called = True
        return ScriptedClient([])

    backend = OpenAICompatibleBackend(
        client_factory=client_factory,
        transcript_factory=transcript_factory,
    )
    backend.configure({"model": "scripted-model"}, {})
    result = backend.run_session(
        f"Read {context}", repo, {"a.c"}, "scripted-model", 30, False)
    assert not result.resolved and result.transcript_path is None
    assert called is False
