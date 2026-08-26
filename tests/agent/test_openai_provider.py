# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for explicit OpenAI-compatible provider capabilities."""
import pytest

from cve_agent.openai_provider import (
    PROVIDER_CAPABILITY_SCHEMA_VERSION,
    ProviderCapabilities,
    ProviderErrorCode,
    ProviderFailureEvidence,
)


def test_default_capabilities_are_versioned_stable_and_bounded():
    capabilities = ProviderCapabilities()

    assert capabilities.schema_version == PROVIDER_CAPABILITY_SCHEMA_VERSION
    assert capabilities.chat_completions_path == "chat/completions"
    assert capabilities.output_token_field == "max_tokens"
    assert len(capabilities.digest) == 64
    assert capabilities.digest == ProviderCapabilities().digest
    assert capabilities.to_dict()["tool_choice_values"] == ["auto"]


def test_provider_error_taxonomy_is_exact_and_stable():
    assert {code.value for code in ProviderErrorCode} == {
        "PROVIDER_AUTH",
        "PROVIDER_MODEL_NOT_FOUND",
        "PROVIDER_REQUEST_REJECTED",
        "PROVIDER_TOOL_PROTOCOL_UNSUPPORTED",
        "PROVIDER_REASONING_PROTOCOL_UNSUPPORTED",
        "PROVIDER_RESPONSE_TRUNCATED",
        "PROVIDER_MALFORMED_RESPONSE",
        "PROVIDER_RESPONSE_TOO_LARGE",
        "PROVIDER_CONNECT_TIMEOUT",
        "PROVIDER_READ_TIMEOUT",
        "PROVIDER_RATE_LIMIT",
        "PROVIDER_SERVER_ERROR",
        "PROVIDER_CONNECTION_LOST",
        "PROVIDER_DEADLINE_EXHAUSTED",
    }


@pytest.mark.parametrize("overrides", [
    {"chat_completions_path": "https://evil.example/v1/chat/completions"},
    {"chat_completions_path": "../chat/completions"},
    {"chat_completions_path": "v1/chát/completions"},
    {"output_token_field": "tokens"},
    {"reasoning_request_field": "extra_body"},
    {"reasoning_response_field": "thoughts"},
    {"requires_reasoning_replay": True},
    {"supports_tools": False, "supports_parallel_tool_calls": True},
    {"supports_tools": False, "supports_parallel_tool_calls": False,
     "supports_tool_choice": True},
    {"supports_tool_choice": True, "tool_choice_values": ("required",)},
    {"tool_choice_values": ("auto", "vendor")},
    {"max_request_bytes": 1023},
    {"max_response_bytes": 1024 * 1024 + 1},
    {"schema_version": 2},
])
def test_unsupported_capability_combinations_fail_closed(overrides):
    with pytest.raises(ValueError):
        ProviderCapabilities(**overrides)


def test_reasoning_replay_capability_has_explicit_fields():
    capabilities = ProviderCapabilities(
        reasoning_request_field="reasoning_effort",
        reasoning_response_field="reasoning_content",
        requires_reasoning_replay=True,
        output_token_field="max_completion_tokens",
    )

    assert capabilities.requires_reasoning_replay is True
    assert capabilities.reasoning_response_field == "reasoning_content"


def test_failure_evidence_serializes_only_allowlisted_bounded_facts():
    evidence = ProviderFailureEvidence(
        ProviderErrorCode.RATE_LIMIT,
        status_code=429,
        request_id="request-1",
        retry_after=2.0,
        response_sha256="a" * 64,
        response_excerpt="rate limited",
        request_features=("tools", "max_tokens"),
    )

    assert evidence.to_dict() == {
        "code": "PROVIDER_RATE_LIMIT",
        "status_code": 429,
        "request_id": "request-1",
        "retry_after": 2.0,
        "response_sha256": "a" * 64,
        "response_excerpt": "rate limited",
        "request_features": ["tools", "max_tokens"],
    }
