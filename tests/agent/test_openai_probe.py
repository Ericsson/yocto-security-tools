# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the harmless opt-in provider conformance sequence."""
import json

import pytest

from cve_agent.openai_client import AssistantResponse, FunctionToolCall
from cve_agent.openai_probe import ProviderConformanceProbe, ProviderProbeError
from cve_agent.openai_provider import ProviderCapabilities, ProviderErrorCode


class ScriptedProbeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def complete(self, messages, tools):
        self.requests.append((list(messages), list(tools)))
        return self.responses.pop(0)


def _text(value="OK"):
    return AssistantResponse(value, (), "stop", None)


def _tool(arguments, *, reasoning=None):
    return AssistantResponse(
        None,
        (FunctionToolCall("probe-1", "probe_echo", arguments),),
        "tool_calls",
        None,
        reasoning,
    )


def test_probe_runs_fixed_bounded_tool_conversation_without_source_data():
    marker = "cve-agent-provider-probe-v1"
    client = ScriptedProbeClient([
        _text(), _tool(json.dumps({"value": marker})), _text("continued"), _text("DONE"),
    ])

    result = ProviderConformanceProbe(client, ProviderCapabilities()).run()

    assert result.status == "passed"
    assert len(client.requests) == 4
    serialized = json.dumps(client.requests)
    assert marker in serialized
    assert "repository" not in serialized.lower()
    assert "source" not in serialized.lower()
    assert client.requests[0][1] == []
    assert client.requests[1][1][0]["function"]["name"] == "probe_echo"
    continuation = client.requests[2][0]
    assert continuation[-1]["role"] == "tool"
    assert continuation[-1]["tool_call_id"] == "probe-1"


@pytest.mark.parametrize("arguments", ["{", "{}", '{"value":"wrong"}'])
def test_probe_rejects_malformed_or_incorrect_tool_arguments(arguments):
    client = ScriptedProbeClient([_text(), _tool(arguments)])

    with pytest.raises(ProviderProbeError, match="arguments"):
        ProviderConformanceProbe(client, ProviderCapabilities()).run()


def test_probe_requires_and_replays_configured_reasoning_field():
    marker = "cve-agent-provider-probe-v1"
    capabilities = ProviderCapabilities(
        reasoning_response_field="reasoning_content",
        requires_reasoning_replay=True,
    )
    client = ScriptedProbeClient([
        _text(),
        _tool(json.dumps({"value": marker}), reasoning=("reasoning_content", "opaque")),
        _text("continued"),
        _text("DONE"),
    ])

    result = ProviderConformanceProbe(client, capabilities).run()

    assert result.reasoning_round_trip is True
    assert client.requests[2][0][-2]["reasoning_content"] == "opaque"


def test_probe_fails_if_required_reasoning_replay_is_absent():
    marker = "cve-agent-provider-probe-v1"
    client = ScriptedProbeClient([_text(), _tool(json.dumps({"value": marker}))])
    capabilities = ProviderCapabilities(
        reasoning_response_field="reasoning", requires_reasoning_replay=True)

    with pytest.raises(ProviderProbeError, match="reasoning replay") as exc_info:
        ProviderConformanceProbe(client, capabilities).run()
    assert exc_info.value.code is ProviderErrorCode.REASONING_PROTOCOL_UNSUPPORTED
