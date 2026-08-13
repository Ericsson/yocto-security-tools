# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for native multi-turn tool orchestration and transcript auditing."""
import copy
import json
import os
import stat
from pathlib import Path

import pytest

from cve_agent.backend import SessionResult
from cve_agent.openai_client import (
    AssistantResponse,
    FunctionToolCall,
    OpenAIAuthenticationError,
    OpenAIConnectionError,
    OpenAINotFoundError,
    OpenAIProtocolError,
    OpenAIRequestTimeoutError,
)
from cve_agent.openai_deadline import SessionDeadline
from cve_agent.openai_loop import (
    AgentLoopLimits,
    JSONLTranscript,
    OpenAIAgentLoop,
)
from cve_agent.openai_tools import ToolAudit, ToolResult


class FakeClock:
    def __init__(self) -> None:
        self.now = 10.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class ScriptedClient:
    def __init__(self, *actions: object) -> None:
        self.actions = list(actions)
        self.requests: list[
            tuple[list[dict[str, object]], list[dict[str, object]]]
        ] = []

    def complete(self, messages, tools):
        self.requests.append((copy.deepcopy(list(messages)), copy.deepcopy(list(tools))))
        action = self.actions.pop(0)
        if isinstance(action, Exception):
            raise action
        assert isinstance(action, AssistantResponse)
        return action


class FakeRuntime:
    def __init__(self, handler=None) -> None:
        self.handler = handler
        self.calls: list[tuple[str, object]] = []
        self.mutation_generation = 0
        self.validated_generation = None
        self.terminal_status = None
        self.finish_attempts = 0

    def dispatch(self, tool_name, arguments):
        self.calls.append((tool_name, arguments))
        if self.handler is not None:
            custom = self.handler(self, tool_name, arguments)
            if custom is not None:
                return custom
        if tool_name == "finish":
            self.finish_attempts += 1
            self.terminal_status = arguments.get("status")
            return self.result(tool_name, terminal=True)
        if tool_name in {"write_file", "git_stage", "git_cherry_pick_continue"}:
            self.mutation_generation += 1
            return self.result(tool_name, mutated=True)
        if tool_name in {"git_commit", "git_amend"}:
            return self.result(tool_name, mutated=True)
        if tool_name == "build_recipe":
            self.validated_generation = self.mutation_generation
            return self.result(tool_name, payload={"exit_status": 0})
        if tool_name.startswith("git_") or tool_name in {"read_file", "list_directory"}:
            return self.result(tool_name, payload={"observed": tool_name})
        return self.result(
            tool_name, success=False, error_kind="validation",
            payload={"error": "unknown tool name"})

    def result(self, tool, *, success=True, mutated=False, terminal=False,
               error_kind=None, payload=None):
        audit = ToolAudit(
            tool=tool, success=success, mutated=mutated,
            generation=self.mutation_generation, error_kind=error_kind)
        return ToolResult(
            success=success,
            payload={} if payload is None else payload,
            mutated=mutated,
            terminal=terminal,
            audit=audit,
            error_kind=error_kind,
        )

    def session_result(self):
        return SessionResult(
            resolved=self.terminal_status is not None, duration=0.0)


def _call(identifier: str, name: str, arguments: str = "{}") -> FunctionToolCall:
    return FunctionToolCall(identifier, name, arguments)


def _response(*calls: FunctionToolCall, content=None,
              finish_reason="tool_calls") -> AssistantResponse:
    return AssistantResponse(content, tuple(calls), finish_reason, None)


def _run(
    tmp_path: Path,
    actions: list[object],
    *,
    runtime: FakeRuntime | None = None,
    limits: AgentLoopLimits | None = None,
    clock: FakeClock | None = None,
    timeout: float = 60,
    secret: str = "",
):
    agent = tmp_path / "agent"
    agent.mkdir(parents=True, exist_ok=True)
    clock = clock or FakeClock()
    deadline = SessionDeadline.from_timeout(timeout, clock)
    transcript = JSONLTranscript.create(
        agent, "model/with unsafe spaces", deadline,
        (secret,) if secret else (), clock_ns=lambda: 12345)
    client = ScriptedClient(*actions)
    runtime = runtime or FakeRuntime()
    loop = OpenAIAgentLoop(
        client,
        runtime,
        transcript,
        deadline,
        limits or AgentLoopLimits(10, 30),
        [{"type": "function", "function": {"name": "read_file"}}],
        "native preamble and shared instructions",
        "Read /trusted/agent/context.md",
    )
    result = loop.run("model/with unsafe spaces", False)
    events = []
    if result.transcript_path and result.transcript_path.exists():
        events = [
            json.loads(line)
            for line in result.transcript_path.read_text(encoding="utf-8").splitlines()
        ]
    return result, client, runtime, loop, transcript, events


def test_initial_messages_and_context_instruction_are_trusted(tmp_path):
    actions = [_response(_call("read", "read_file", '{"path":"/trusted/agent/context.md"}')),
               _response(_call("finish", "finish", '{"status":"needs_human","reason":"x"}'))]
    result, client, _, _, _, _ = _run(tmp_path, actions)
    assert result.resolved
    first_messages = client.requests[0][0]
    assert first_messages == [
        {"role": "system", "content": "native preamble and shared instructions"},
        {"role": "user", "content": "Read /trusted/agent/context.md"},
    ]
    assert client.requests[0][1][0]["function"]["name"] == "read_file"


def test_read_then_terminal_outcome(tmp_path):
    actions = [
        _response(_call("one", "read_file", '{"path":"context.md"}')),
        _response(_call(
            "two", "finish",
            '{"status":"not_applicable","reason":"feature absent"}')),
    ]
    result, client, runtime, _, _, events = _run(tmp_path, actions)
    assert result.resolved and runtime.terminal_status == "not_applicable"
    second = client.requests[1][0]
    assert second[-2]["role"] == "assistant"
    assert second[-1]["role"] == "tool"
    assert second[-1]["tool_call_id"] == "one"
    assert any(event["event"] == "terminal_result" for event in events)


def test_realistic_inspect_edit_stage_build_finish_sequence(tmp_path):
    actions = [
        _response(_call("c1", "read_file", '{"path":"context.md"}')),
        _response(_call("c2", "git_status")),
        _response(_call(
            "c3", "write_file",
            '{"path":"a.c","content":"fixed","mode":"replace_only"}')),
        _response(_call("c4", "git_stage", '{"paths":["a.c"]}')),
        _response(_call("c5", "git_cherry_pick_continue")),
        _response(_call("c6", "build_recipe")),
        _response(_call(
            "c7", "finish",
            '{"status":"done","reason":"built","summary":"fixed"}')),
    ]
    result, _, runtime, _, _, _ = _run(tmp_path, actions)
    assert result.resolved
    assert [name for name, _ in runtime.calls] == [
        "read_file", "git_status", "write_file", "git_stage",
        "git_cherry_pick_continue", "build_recipe", "finish",
    ]
    assert runtime.validated_generation == runtime.mutation_generation


def test_multiple_calls_preserve_assistant_and_tool_result_order(tmp_path):
    actions = [
        _response(
            _call("a", "read_file", '{"path":"a.c"}'),
            _call("b", "git_status"),
            content="I will inspect both."),
        _response(_call(
            "done", "finish", '{"status":"needs_human","reason":"x"}')),
    ]
    result, client, runtime, _, _, _ = _run(tmp_path, actions)
    assert result.resolved
    conversation = client.requests[1][0]
    assert [message["role"] for message in conversation[-3:]] == [
        "assistant", "tool", "tool"]
    assert [message["tool_call_id"] for message in conversation[-2:]] == ["a", "b"]
    assert [name for name, _ in runtime.calls[:2]] == ["read_file", "git_status"]


def test_malformed_unknown_wrong_fields_and_policy_denial_are_tool_results(tmp_path):
    def handler(runtime, name, arguments):
        if name == "read_file" and arguments == {"bad": True}:
            return runtime.result(
                name, success=False, error_kind="validation",
                payload={"error": "unexpected field"})
        if name == "write_file":
            return runtime.result(
                name, success=False, error_kind="policy",
                payload={"error": "path denied"})
        return None

    runtime = FakeRuntime(handler)
    actions = [
        _response(_call("bad-json", "read_file", "{")),
        _response(_call("unknown", "run_shell", '{"command":"id"}')),
        _response(_call("wrong", "read_file", '{"bad":true}')),
        _response(_call(
            "denied", "write_file",
            '{"path":"outside","content":"x","mode":"create_only"}')),
        _response(_call(
            "finish", "finish", '{"status":"needs_human","reason":"denied"}')),
    ]
    result, client, runtime, _, _, _ = _run(
        tmp_path, actions, runtime=runtime,
        limits=AgentLoopLimits(10, 30, max_consecutive_nonprogress=10))
    assert result.resolved
    assert [name for name, _ in runtime.calls] == [
        "run_shell", "read_file", "write_file", "finish"]
    tool_messages = [
        message for request, _ in client.requests for message in request
        if message.get("role") == "tool"
    ]
    categories = {
        json.loads(message["content"])["policy_category"]
        for message in tool_messages
    }
    assert {"validation", "policy"} <= categories


def test_replayed_call_id_is_rejected_without_dispatch(tmp_path):
    actions = [
        _response(_call("same", "read_file", '{"path":"a.c"}')),
        _response(_call("same", "git_status")),
        _response(_call(
            "finish", "finish", '{"status":"needs_human","reason":"x"}')),
    ]
    result, client, runtime, _, _, _ = _run(tmp_path, actions)
    assert result.resolved
    assert [name for name, _ in runtime.calls] == ["read_file", "finish"]
    replay_result = json.loads(client.requests[2][0][-1]["content"])
    assert replay_result["policy_category"] == "validation"
    assert "replayed" in replay_result["error"]["error"]


def test_text_plus_tool_call_is_retained(tmp_path):
    actions = [
        _response(_call(
            "finish", "finish", '{"status":"needs_human","reason":"x"}'),
            content="Host verification requested."),
    ]
    result, _, _, loop, _, events = _run(tmp_path, actions)
    assert result.resolved
    assert loop.messages[2]["content"] == "Host verification requested."
    assert next(event for event in events if event["event"] == "assistant_response")[
        "content"] == "Host verification requested."


def test_one_text_stop_gets_one_correction_then_can_succeed(tmp_path):
    actions = [
        _response(content="I am finished.", finish_reason="stop"),
        _response(_call(
            "finish", "finish", '{"status":"needs_human","reason":"x"}')),
    ]
    result, client, _, _, _, events = _run(tmp_path, actions)
    assert result.resolved
    assert client.requests[1][0][-1]["role"] == "user"
    assert "Call `finish`" in client.requests[1][0][-1]["content"]
    assert sum(event["event"] == "corrective_message" for event in events) == 1


def test_two_text_stops_end_unresolved(tmp_path):
    result, client, _, _, _, events = _run(tmp_path, [
        _response(content="done", finish_reason="stop"),
        _response(content="still done", finish_reason="stop"),
    ])
    assert not result.resolved and len(client.requests) == 2
    assert "stopped twice" in events[-1]["reason"]
    assert "function tools" in events[-1]["reason"]


@pytest.mark.parametrize("finish_reason", ["length", "content_filter", "function_call"])
def test_truncated_filtered_or_unsupported_finish_reason_never_executes(
        tmp_path, finish_reason):
    runtime = FakeRuntime()
    result, _, runtime, _, _, _ = _run(
        tmp_path,
        [_response(_call("finish", "finish"), finish_reason=finish_reason)],
        runtime=runtime)
    assert not result.resolved and runtime.calls == []


def test_independent_turn_total_per_response_and_nonprogress_bounds(tmp_path):
    turn_result, turn_client, _, _, _, _ = _run(
        tmp_path / "turn", [_response(_call("a", "git_status"))],
        limits=AgentLoopLimits(1, 10))
    assert not turn_result.resolved and len(turn_client.requests) == 1

    total_result, _, total_runtime, _, _, _ = _run(
        tmp_path / "total",
        [_response(_call("a", "read_file"), _call("b", "git_status"))],
        limits=AgentLoopLimits(2, 1))
    assert not total_result.resolved and total_runtime.calls == []

    per_result, _, per_runtime, _, _, _ = _run(
        tmp_path / "per",
        [_response(_call("a", "read_file"), _call("b", "git_status"))],
        limits=AgentLoopLimits(2, 10, max_tool_calls_per_response=1))
    assert not per_result.resolved and per_runtime.calls == []

    repeated = [
        _response(_call(f"id-{index}", "run_shell", '{}'))
        for index in range(3)
    ]
    nonprogress, client, _, _, _, events = _run(
        tmp_path / "nonprogress", repeated,
        limits=AgentLoopLimits(10, 10, max_consecutive_nonprogress=3))
    assert not nonprogress.resolved and len(client.requests) == 3
    assert "no tool progress" in events[-1]["reason"]
    assert "transcript" in events[-1]["reason"]


def test_deadline_exhaustion_prevents_next_model_request(tmp_path):
    clock = FakeClock()

    def handler(runtime, name, arguments):
        clock.advance(3)
        return runtime.result(name, payload={"observed": True})

    result, client, _, _, _, events = _run(
        tmp_path,
        [_response(_call("read", "read_file"))],
        runtime=FakeRuntime(handler), clock=clock, timeout=2)
    assert not result.resolved and len(client.requests) == 1
    assert any(event["event"] == "timeout" for event in events)


def test_finish_before_later_call_rejects_entire_batch_then_recovers(tmp_path):
    actions = [
        _response(
            _call("finish-first", "finish", '{"status":"needs_human","reason":"x"}'),
            _call("after", "write_file", '{"path":"a.c"}')),
        _response(_call(
            "finish-last", "finish", '{"status":"needs_human","reason":"x"}')),
    ]
    result, _, runtime, _, _, events = _run(tmp_path, actions)
    assert result.resolved
    assert [name for name, _ in runtime.calls] == ["finish"]
    rejected = [
        event for event in events
        if event["event"] == "tool_result" and not event["dispatched"]
    ]
    assert [event["tool_call_id"] for event in rejected] == [
        "finish-first", "after"]


def test_rejected_terminal_claim_can_be_corrected_then_succeed(tmp_path):
    def handler(runtime, name, arguments):
        if name == "finish" and runtime.finish_attempts == 0:
            runtime.finish_attempts += 1
            return runtime.result(
                name, success=False, error_kind="policy",
                payload={"error": "no successful recipe build is recorded"})
        return None

    runtime = FakeRuntime(handler)
    actions = [
        _response(_call(
            "early", "finish",
            '{"status":"done","reason":"x","summary":"x"}')),
        _response(_call(
            "edit", "write_file",
            '{"path":"a.c","content":"x","mode":"replace_only"}')),
        _response(_call("build", "build_recipe")),
        _response(_call(
            "done", "finish",
            '{"status":"done","reason":"built","summary":"fixed"}')),
    ]
    result, _, runtime, _, _, _ = _run(tmp_path, actions, runtime=runtime)
    assert result.resolved and runtime.terminal_status == "done"
    assert runtime.finish_attempts == 2


@pytest.mark.parametrize("status_value", ["done", "not_applicable", "needs_human"])
def test_all_host_terminal_statuses_map_to_resolved(tmp_path, status_value):
    arguments = {"status": status_value, "reason": "verified"}
    if status_value == "done":
        arguments["summary"] = "built"
    response = _response(_call(
        "finish", "finish", json.dumps(arguments, separators=(",", ":"))))
    result, _, runtime, _, _, _ = _run(tmp_path, [response])
    assert result.resolved and runtime.terminal_status == status_value


@pytest.mark.parametrize(
    ("error", "guidance"),
    [
        (OpenAIConnectionError("private connection detail"), "server is running"),
        (OpenAIAuthenticationError("private auth response"),
         "--openai-api-key-env"),
        (OpenAINotFoundError("private model response"), "CVE_AGENT_OPENAI_MODEL"),
        (OpenAIProtocolError("private schema response"), "assistant tool_calls"),
    ],
)
def test_expected_client_errors_map_to_safe_unresolved_result(
        tmp_path, error, guidance):
    result, _, _, _, _, events = _run(tmp_path, [error], secret="super-secret")
    assert not result.resolved
    assert guidance in result.failure_reason
    assert str(error) not in result.failure_reason
    assert "super-secret" not in result.transcript_path.read_text(encoding="utf-8")
    assert any(event["event"] == "client_error" for event in events)


def test_transcript_is_mode_0600_valid_ordered_redacted_and_closed(tmp_path):
    secret = "sk-transcript-secret"
    actions = [
        _response(
            _call("read", "read_file", '{"path":"context.md"}'),
            content=(f"Bearer {secret} " + "x" * 6000)),
        _response(_call(
            "finish", "finish", '{"status":"needs_human","reason":"x"}')),
    ]
    result, _, _, _, transcript, events = _run(
        tmp_path, actions, secret=secret)
    assert result.resolved
    assert stat.S_IMODE(result.transcript_path.stat().st_mode) == 0o600
    assert "model-with-unsafe-spaces" in result.transcript_path.name
    raw = result.transcript_path.read_text(encoding="utf-8")
    assert secret not in raw and "Bearer [REDACTED]" in raw
    assert [event["sequence"] for event in events] == list(range(1, len(events) + 1))
    names = [event["event"] for event in events]
    assert names[0] == "session_start" and names[-1] == "session_end"
    assert names.index("assistant_response") < names.index("tool_request")
    assert names.index("tool_request") < names.index("tool_result")
    assert transcript._closed is True


def test_transcript_filename_redacts_configured_secret(tmp_path):
    agent = tmp_path / "agent"
    agent.mkdir()
    secret = "sk-filename-secret"
    deadline = SessionDeadline.from_timeout(10)
    transcript = JSONLTranscript.create(
        agent, secret, deadline, (secret,), clock_ns=lambda: 12345)
    try:
        assert secret not in transcript.path.name
        assert "REDACTED" in transcript.path.name
    finally:
        transcript.close()


def test_transcript_write_failure_fails_session_closed(tmp_path):
    agent = tmp_path / "agent"
    agent.mkdir()
    clock = FakeClock()
    deadline = SessionDeadline.from_timeout(30, clock)
    transcript = JSONLTranscript.create(
        agent, "model", deadline, clock_ns=lambda: 1)
    os.close(transcript._descriptor)
    client = ScriptedClient(_response(_call("finish", "finish")))
    loop = OpenAIAgentLoop(
        client, FakeRuntime(), transcript, deadline,
        AgentLoopLimits(2, 2), [], "system", "user")
    result = loop.run("model", False)
    assert not result.resolved and client.requests == []
    assert transcript._closed is True


def test_no_arbitrary_command_surface_in_schemas_or_dispatch(tmp_path):
    actions = [
        _response(_call("shell", "execute_bash", '{"command":"rm -rf /"}')),
        _response(_call(
            "finish", "finish", '{"status":"needs_human","reason":"denied"}')),
    ]
    result, client, runtime, _, _, _ = _run(tmp_path, actions)
    assert result.resolved
    schema_names = {
        item["function"]["name"] for item in client.requests[0][1]
    }
    assert "execute_bash" not in schema_names and "run_shell" not in schema_names
    assert runtime.calls[0][0] == "execute_bash"
    assert runtime.calls[0][1] == {"command": "rm -rf /"}
    assert json.loads(client.requests[1][0][-1]["content"])[
        "policy_category"] == "validation"
    assert json.loads(client.requests[1][0][-1]["content"])[
        "recoverable"] is True


def test_transport_timeout_has_explicit_timeout_event(tmp_path):
    result, _, _, _, _, events = _run(
        tmp_path, [OpenAIRequestTimeoutError("request timed out")])
    assert not result.resolved
    assert any(event["event"] == "timeout" for event in events)


def test_unexpected_tool_exception_fails_safely_and_closes_transcript(tmp_path):
    def handler(runtime, name, arguments):
        raise RuntimeError("host detail must not escape")

    result, _, _, _, transcript, events = _run(
        tmp_path,
        [_response(_call("read", "read_file", '{"path":"a.c"}'))],
        runtime=FakeRuntime(handler))
    assert not result.resolved and transcript._closed is True
    assert any(event["event"] == "session_error" for event in events)
    assert "host detail must not escape" not in result.transcript_path.read_text()
