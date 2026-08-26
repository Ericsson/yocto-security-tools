# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Opt-in live probe for the portable Chat Completions tool-call contract."""
import os

import pytest

from cve_agent.openai_backend import OpenAIConfig
from cve_agent.openai_client import OpenAIChatCompletionsClient
from cve_agent.openai_deadline import SessionDeadline

pytestmark = pytest.mark.live


def test_live_endpoint_returns_portable_function_tool_call():
    """Require one OpenAI-shaped tool call from an explicitly enabled endpoint."""
    if os.environ.get("CVE_AGENT_OPENAI_LIVE") != "1":
        pytest.skip("set CVE_AGENT_OPENAI_LIVE=1 to contact a configured endpoint")
    model = os.environ.get("CVE_AGENT_OPENAI_MODEL", "").strip()
    if not model:
        pytest.skip("set CVE_AGENT_OPENAI_MODEL to the tool-capable model to probe")

    config = OpenAIConfig.from_sources({"model": model}, os.environ)
    client = OpenAIChatCompletionsClient(
        config, SessionDeadline.from_timeout(60))
    response = client.complete(
        [{
            "role": "user",
            "content": (
                "Call the compatibility_probe tool exactly once with value "
                "set to portable. Do not answer with prose."
            ),
        }],
        [{
            "type": "function",
            "function": {
                "name": "compatibility_probe",
                "description": "Confirm portable function-tool support.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "value": {"type": "string"},
                    },
                    "required": ["value"],
                    "additionalProperties": False,
                },
            },
        }],
    )

    assert response.tool_calls
    assert response.tool_calls[0].name == "compatibility_probe"
