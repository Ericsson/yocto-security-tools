# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Harmless opt-in provider conformance probe for portable tool conversations."""
from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from .openai_client import AssistantResponse
from .openai_provider import ProviderCapabilities, ProviderErrorCode

PROBE_SCHEMA_VERSION = 1
_PROBE_MARKER = "cve-agent-provider-probe-v1"


class ProbeClient(Protocol):
    def complete(
        self,
        messages: Sequence[dict[str, object]],
        tools: Sequence[dict[str, object]],
    ) -> AssistantResponse: ...


class ProviderProbeError(RuntimeError):
    """The selected endpoint/model failed the harmless conformance sequence."""

    def __init__(self, message: str, code: ProviderErrorCode) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class ProviderProbeResult:
    status: str
    basic_chat: bool
    tool_call: bool
    tool_continuation: bool
    final_response: bool
    reasoning_round_trip: bool | None

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": PROBE_SCHEMA_VERSION,
            "status": self.status,
            "basic_chat": self.basic_chat,
            "tool_call": self.tool_call,
            "tool_continuation": self.tool_continuation,
            "final_response": self.final_response,
            "reasoning_round_trip": self.reasoning_round_trip,
        }


class ProviderConformanceProbe:
    """Exercise chat/tools/replay using fixed strings and no repository data."""

    def __init__(
        self, client: ProbeClient, capabilities: ProviderCapabilities,
    ) -> None:
        self.client = client
        self.capabilities = capabilities

    def run(self) -> ProviderProbeResult:
        basic = self.client.complete(
            [{"role": "user", "content": f"Reply exactly OK to {_PROBE_MARKER}"}],
            [],
        )
        if basic.tool_calls or not basic.content:
            raise ProviderProbeError(
                "basic chat probe did not return text",
                ProviderErrorCode.MALFORMED_RESPONSE)
        tools: list[dict[str, object]] = [{
            "type": "function",
            "function": {
                "name": "probe_echo",
                "description": "Return the fixed harmless provider probe marker.",
                "parameters": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                    "additionalProperties": False,
                },
            },
        }]
        messages: list[dict[str, object]] = [{
            "role": "user",
            "content": (
                "Call probe_echo once with value " + _PROBE_MARKER
                + "; do not answer in prose."),
        }]
        call_response = self.client.complete(messages, tools)
        if len(call_response.tool_calls) != 1:
            raise ProviderProbeError(
                "tool probe did not return exactly one call",
                ProviderErrorCode.TOOL_PROTOCOL_UNSUPPORTED)
        call = call_response.tool_calls[0]
        if call.name != "probe_echo":
            raise ProviderProbeError(
                "tool probe returned the wrong function",
                ProviderErrorCode.TOOL_PROTOCOL_UNSUPPORTED)
        try:
            arguments = json.loads(call.arguments)
        except (json.JSONDecodeError, ValueError):
            raise ProviderProbeError(
                "tool probe returned malformed arguments",
                ProviderErrorCode.TOOL_PROTOCOL_UNSUPPORTED) from None
        if arguments != {"value": _PROBE_MARKER}:
            raise ProviderProbeError(
                "tool probe returned unexpected arguments",
                ProviderErrorCode.TOOL_PROTOCOL_UNSUPPORTED)
        assistant: dict[str, object] = {
            "role": "assistant",
            "content": call_response.content,
            "tool_calls": [{
                "id": call.id,
                "type": "function",
                "function": {"name": call.name, "arguments": call.arguments},
            }],
        }
        reasoning_round_trip: bool | None = None
        if call_response.reasoning_replay is not None:
            field, value = call_response.reasoning_replay
            assistant[field] = value
            reasoning_round_trip = True
        elif self.capabilities.requires_reasoning_replay:
            raise ProviderProbeError(
                "tool probe omitted required reasoning replay",
                ProviderErrorCode.REASONING_PROTOCOL_UNSUPPORTED)
        messages.extend([
            assistant,
            {
                "role": "tool",
                "tool_call_id": call.id,
                "content": json.dumps({"value": _PROBE_MARKER}),
            },
        ])
        continuation = self.client.complete(messages, tools)
        if continuation.tool_calls or not continuation.content:
            raise ProviderProbeError(
                "tool-result continuation did not return final text",
                ProviderErrorCode.TOOL_PROTOCOL_UNSUPPORTED)
        final = self.client.complete(
            [{"role": "user", "content": f"End {_PROBE_MARKER} with DONE"}], [])
        if final.tool_calls or not final.content:
            raise ProviderProbeError(
                "final response probe did not return text",
                ProviderErrorCode.MALFORMED_RESPONSE)
        return ProviderProbeResult(
            "passed", True, True, True, True, reasoning_round_trip)
