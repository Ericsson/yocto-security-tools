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
    OpenAIChatCompletionsClient,
    OpenAIClientEvent,
    OpenAIConnectionError,
)
from cve_agent.openai_host_tools import (
    BUILD_LOG_NAME,
    BuildCommandResult,
    OpenAIHostToolRuntime,
)
from cve_agent.openai_ollama import OllamaPreparationClient
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


def test_named_profile_without_ollama_section_makes_no_native_api_calls(
    tmp_path, monkeypatch,
):
    repo, agent, context = _repository(tmp_path)
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    profile = profiles / "openai-chat-only.cfg"
    profile.write_text(
        "[openai]\nmodel = scripted-model\nbase_url = http://localhost:11434/v1\n",
        encoding="utf-8",
    )
    profile.chmod(0o600)
    monkeypatch.setenv("CVE_AGENT_OPENAI_CONFIG_DIR", str(profiles))
    native_called = False

    def ollama_factory(*args, **kwargs):
        nonlocal native_called
        native_called = True
        raise AssertionError("profile without [ollama] must remain transport-free")

    def client_factory(config, deadline, event_sink=None):
        client = ScriptedClient([
            _response(_call(
                "context", "read_file", json.dumps({"path": str(context)}))),
            _response(_call(
                "finish", "finish",
                '{"status":"needs_human","reason":"inspection complete"}')),
        ], event_sink)
        return client

    backend = OpenAICompatibleBackend(
        client_factory=client_factory,
        ollama_factory=ollama_factory,
    )
    backend.configure({"backend_profile": "chat-only", "model": None}, os.environ)
    result = backend.run_session(
        f"Read {context}", repo, {"a.c"}, "scripted-model", 30, False)
    assert result.resolved
    assert native_called is False


def test_preparation_failure_returns_transcript_and_never_enters_model_loop(
    tmp_path, monkeypatch,
):
    repo, _agent, context = _repository(tmp_path)
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    profile = profiles / "openai-prep-failure.cfg"
    profile.write_text("""\
[openai]
model = target-model
base_url = http://localhost:11434/v1

[ollama]
source_model = source-model
target_model = target-model
num_ctx = 4096
create_if_missing = false
""", encoding="utf-8")
    profile.chmod(0o600)
    monkeypatch.setenv("CVE_AGENT_OPENAI_CONFIG_DIR", str(profiles))
    model_called = False

    class FailingPreparer:
        def prepare(self):
            raise RuntimeError("bounded setup failure")

    def ollama_factory(*args, **kwargs):
        return FailingPreparer()

    def client_factory(*args, **kwargs):
        nonlocal model_called
        model_called = True
        raise AssertionError("model client must not be constructed")

    backend = OpenAICompatibleBackend(
        client_factory=client_factory,
        ollama_factory=ollama_factory,
    )
    backend.configure({"backend_profile": "prep-failure", "model": None}, os.environ)
    result = backend.run_session(
        f"Read {context}", repo, {"a.c"}, "target-model", 30, False)
    assert not result.resolved
    assert result.transcript_path is not None
    assert model_called is False
    assert "Ollama preparation failed" in result.failure_reason
    transcript = result.transcript_path.read_text(encoding="utf-8")
    assert "profile_loaded" in transcript
    assert "ollama_preparation" in transcript
    assert "bounded setup failure" in transcript


class _HTTPResponse:
    def __init__(self, status, payload):
        self.status_code = status
        self.headers = {}
        self.body = json.dumps(payload).encode("utf-8")

    def iter_content(self, chunk_size, decode_unicode=False):
        yield self.body

    def close(self):
        pass


class _OllamaTransport:
    def __init__(self, order):
        self.order = order
        self.calls = []
        show = {
            "parameters": "num_ctx 32768\n",
            "capabilities": ["completion", "tools"],
            "model_info": {"qwen.context_length": 65536},
        }
        self.actions = [
            _HTTPResponse(404, {}),
            _HTTPResponse(200, show),
            _HTTPResponse(200, {}),
            _HTTPResponse(200, show),
            _HTTPResponse(200, {}),
            _HTTPResponse(200, {
                "models": [{
                    "name": "profile-model:latest",
                    "context_length": 32768,
                }],
            }),
        ]

    def request(self, method, url, **kwargs):
        self.order.append("ollama")
        self.calls.append((method, url, kwargs))
        return self.actions.pop(0)


class _ChatTransport:
    def __init__(self, order, context):
        self.order = order
        self.context = context
        self.calls = []
        self.actions = [
            _HTTPResponse(200, {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "context",
                                "type": "function",
                                "function": {
                                    "name": "read_file",
                                    "arguments": json.dumps({"path": str(context)}),
                                },
                            },
                            {
                                "id": "status",
                                "type": "function",
                                "function": {"name": "git_status", "arguments": "{}"},
                            },
                            {
                                "id": "build",
                                "type": "function",
                                "function": {"name": "build_recipe", "arguments": "{}"},
                            },
                        ],
                    },
                    "finish_reason": "tool_calls",
                }],
            }),
            _HTTPResponse(200, {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [{
                            "id": "finish",
                            "type": "function",
                            "function": {
                                "name": "finish",
                                "arguments": json.dumps({
                                    "status": "done",
                                    "reason": "verified",
                                    "summary": "profile flow passed",
                                }),
                            },
                        }],
                    },
                    "finish_reason": "tool_calls",
                }],
            }),
        ]

    def post(self, url, **kwargs):
        self.order.append("chat")
        self.calls.append((url, kwargs))
        return self.actions.pop(0)


def test_profile_preparation_precedes_deterministic_typed_tool_loop(
    tmp_path, monkeypatch,
):
    repo, agent, context = _repository(tmp_path)
    runner = FakeBuildRunner(agent)
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    profile_path = profiles / "openai-integration.cfg"
    profile_path.write_text("""\
[openai]
base_url = http://localhost:11434/v1
model = profile-model
api_key_env = PROFILE_API_KEY
max_steps = 8
max_tool_calls = 16

[chat]
temperature = 0.0
top_p = 0.95
reasoning_effort = none

[ollama]
source_model = source-model
target_model = profile-model
num_ctx = 32768
create_if_missing = true
recreate_if_mismatch = true
require_tools = true
preload = true
keep_alive = 30m
verify_context = true
""", encoding="utf-8")
    profile_path.chmod(0o600)
    monkeypatch.setenv("CVE_AGENT_OPENAI_CONFIG_DIR", str(profiles))
    monkeypatch.setenv("PROFILE_API_KEY", "integration-secret")

    order = []
    ollama_transport = _OllamaTransport(order)
    chat_transport = _ChatTransport(order, context)

    def ollama_factory(config, openai_config, deadline, **kwargs):
        return OllamaPreparationClient(
            config,
            openai_config,
            deadline,
            transport=ollama_transport,
            environ=os.environ,
            sleep=lambda _delay: None,
            event_sink=kwargs.get("event_sink"),
            approvals=kwargs.get("approvals"),
        )

    def client_factory(config, deadline, event_sink=None):
        return OpenAIChatCompletionsClient(
            config,
            deadline,
            transport=chat_transport,
            environ=os.environ,
            event_sink=event_sink,
        )

    def runtime_factory(*args, **kwargs):
        kwargs["build_runner"] = runner
        return OpenAIHostToolRuntime(*args, **kwargs)

    backend = OpenAICompatibleBackend(
        client_factory=client_factory,
        runtime_factory=runtime_factory,
        ollama_factory=ollama_factory,
    )
    backend.configure({"backend_profile": "integration", "model": None}, os.environ)
    result = backend.run_session(
        f"Read {context}", repo, {"a.c"}, "profile-model", 30, False)

    assert result.resolved and result.transcript_path is not None
    assert order[:6] == ["ollama"] * 6
    assert order[6:] == ["chat", "chat"]
    request = json.loads(chat_transport.calls[0][1]["data"])
    assert request["model"] == "profile-model"
    assert request["temperature"] == 0.0
    assert request["top_p"] == 0.95
    assert request["reasoning_effort"] == "none"
    assert runner.calls == ["recipe"]
    assert all(
        call[2]["headers"]["Authorization"] == "Bearer integration-secret"
        for call in ollama_transport.calls
    )
    events = [
        json.loads(line)
        for line in result.transcript_path.read_text(encoding="utf-8").splitlines()
    ]
    profile_event = next(event for event in events if event["event"] == "profile_loaded")
    assert profile_event["backend"] == "openai"
    assert profile_event["profile"] == "integration"
    assert len(profile_event["sha256"]) == 64
    assert next(event for event in events if event["event"] == "session_start")[
        "backend"] == "openai"
    assert "integration-secret" not in result.transcript_path.read_text(encoding="utf-8")
    assert _git_status(repo) == ""


def _git_status(repo: Path) -> str:
    result = subprocess.run(
        ["git", "status", "--porcelain"], cwd=repo,
        capture_output=True, text=True, check=True)
    return result.stdout
