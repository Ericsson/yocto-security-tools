# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Deterministic tests for bounded native Ollama profile preparation."""
import json
from collections.abc import Callable, Iterable

import pytest
import requests

from cve_agent.openai_backend import OpenAIConfig
from cve_agent.openai_deadline import SessionDeadline
from cve_agent.openai_host_tools import (
    ApprovalDecision,
    ApprovalGate,
    ApprovalRequest,
)
from cve_agent.openai_ollama import (
    MAX_OLLAMA_RESPONSE_BYTES,
    OllamaConfig,
    OllamaConfigurationError,
    OllamaPreparationClient,
    OllamaPreparationError,
)
from cve_agent.openai_profile import OllamaProfile, OpenAIProfileError


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class FakeResponse:
    def __init__(
        self,
        status: int = 200,
        payload: object = None,
        *,
        body: bytes | None = None,
        chunks: Iterable[bytes] | None = None,
        before_chunk: Callable[[], None] | None = None,
    ) -> None:
        self.status_code = status
        self.headers: dict[str, str] = {}
        if payload is None:
            payload = {}
        self.body = json.dumps(payload).encode() if body is None else body
        self.chunks = list(chunks) if chunks is not None else [self.body]
        self.before_chunk = before_chunk
        self.closed = False

    def iter_content(self, chunk_size: int, decode_unicode: bool = False):
        for chunk in self.chunks:
            if self.before_chunk is not None:
                self.before_chunk()
            yield chunk

    def close(self) -> None:
        self.closed = True


class FakeTransport:
    def __init__(self, *actions: object) -> None:
        self.actions = list(actions)
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    def request(self, method: str, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append((method, url, kwargs))
        action = self.actions.pop(0)
        if isinstance(action, Exception):
            raise action
        assert isinstance(action, FakeResponse)
        return action


class FakeApprovalProvider:
    def __init__(self, decision: ApprovalDecision) -> None:
        self.decision = decision
        self.requests: list[ApprovalRequest] = []

    def request(self, request: ApprovalRequest, timeout: float) -> ApprovalDecision:
        self.requests.append(request)
        return self.decision


def _openai(**overrides: object) -> OpenAIConfig:
    values: dict[str, object] = {
        "model": "target-model",
        "openai_base_url": "http://localhost:11434/v1",
    }
    values.update(overrides)
    environ: dict[str, str] = {}
    key_name = values.get("openai_api_key_env")
    if isinstance(key_name, str):
        environ[key_name] = "validation-placeholder"
    return OpenAIConfig.from_sources(values, environ)


def _profile(**overrides: object) -> OllamaProfile:
    values: dict[str, object] = {
        "api_base_url": "http://localhost:11434",
        "source_model": "source-model",
        "target_model": "target-model",
        "num_ctx": 32768,
        "create_if_missing": True,
        "recreate_if_mismatch": True,
        "require_tools": True,
        "preload": False,
        "keep_alive": "30m",
        "verify_context": False,
    }
    values.update(overrides)
    return OllamaProfile(**values)


def _config(**overrides: object) -> tuple[OpenAIConfig, OllamaConfig]:
    openai = _openai()
    return openai, OllamaConfig.from_profile(_profile(**overrides), openai)


def _show(num_ctx: int = 32768, *, tools: bool = True,
          context_max: int = 65536) -> dict[str, object]:
    return {
        "parameters": f"temperature 0.0\nnum_ctx {num_ctx}\n",
        "capabilities": ["completion", "tools"] if tools else ["completion"],
        "model_info": {"qwen.context_length": context_max},
    }


def _client(
    transport: FakeTransport,
    *,
    profile: OllamaProfile | None = None,
    openai: OpenAIConfig | None = None,
    events: list[tuple[str, dict[str, object]]] | None = None,
    approvals: ApprovalGate | None = None,
    environ: dict[str, str] | None = None,
    clock: FakeClock | None = None,
) -> OllamaPreparationClient:
    openai = openai or _openai()
    config = OllamaConfig.from_profile(profile or _profile(), openai)
    clock = clock or FakeClock()
    sink = None
    if events is not None:
        def sink(kind, data):
            events.append((kind, dict(data)))
    return OllamaPreparationClient(
        config,
        openai,
        SessionDeadline.from_timeout(30, clock),
        transport=transport,
        environ={} if environ is None else environ,
        sleep=lambda _delay: None,
        event_sink=sink,
        approvals=approvals,
    )


def _body(call: tuple[str, str, dict[str, object]]) -> dict[str, object]:
    return json.loads(call[2]["data"])


def test_matching_target_is_idempotent_noop():
    events: list[tuple[str, dict[str, object]]] = []
    transport = FakeTransport(FakeResponse(payload=_show()))
    _client(transport, events=events).prepare()
    assert [(method, url.rsplit("/", 2)[-2:]) for method, url, _ in transport.calls] == [
        ("POST", ["api", "show"]),
    ]
    assert "ollama_preparation_noop" in [event[0] for event in events]
    assert events[-1][0] == "ollama_preparation_complete"


def test_missing_target_creates_exact_alias_then_verifies():
    transport = FakeTransport(
        FakeResponse(404),
        FakeResponse(payload=_show()),
        FakeResponse(payload={"status": "success"}),
        FakeResponse(payload=_show()),
    )
    _client(transport).prepare()
    assert [call[1].rsplit("/", 2)[-1] for call in transport.calls] == [
        "show", "show", "create", "show",
    ]
    assert _body(transport.calls[0]) == {"model": "target-model", "verbose": False}
    assert _body(transport.calls[1]) == {"model": "source-model", "verbose": False}
    assert _body(transport.calls[2]) == {
        "model": "target-model",
        "from": "source-model",
        "parameters": {"num_ctx": 32768},
        "stream": False,
    }
    assert all("pull" not in call[1] for call in transport.calls)


def test_missing_target_without_create_fails_without_source_or_pull():
    transport = FakeTransport(FakeResponse(404))
    with pytest.raises(OllamaPreparationError, match="create_if_missing is false"):
        _client(transport, profile=_profile(create_if_missing=False)).prepare()
    assert len(transport.calls) == 1


def test_mismatch_fails_or_recreates_according_to_closed_policy():
    disabled = FakeTransport(FakeResponse(payload=_show(num_ctx=4096)))
    with pytest.raises(OllamaPreparationError, match="num_ctx differs"):
        _client(
            disabled, profile=_profile(recreate_if_mismatch=False)).prepare()
    assert len(disabled.calls) == 1

    enabled = FakeTransport(
        FakeResponse(payload=_show(num_ctx=4096)),
        FakeResponse(payload=_show()),
        FakeResponse(payload={}),
        FakeResponse(payload=_show()),
    )
    _client(enabled).prepare()
    assert any(call[1].endswith("/api/create") for call in enabled.calls)


def test_missing_source_never_pulls_or_creates():
    transport = FakeTransport(FakeResponse(404), FakeResponse(404))
    with pytest.raises(OllamaPreparationError, match="source model is not installed"):
        _client(transport).prepare()
    assert [call[1].rsplit("/", 1)[-1] for call in transport.calls] == ["show", "show"]


def test_required_tools_capability_is_verified_after_recreation():
    transport = FakeTransport(FakeResponse(payload=_show(tools=False)))
    with pytest.raises(OllamaPreparationError, match="tools capability"):
        _client(
            transport,
            profile=_profile(recreate_if_mismatch=False, require_tools=True),
        ).prepare()


def test_preload_and_loaded_context_verification_use_exact_values():
    transport = FakeTransport(
        FakeResponse(payload=_show()),
        FakeResponse(payload={"done": True}),
        FakeResponse(payload={
            "models": [{"name": "target-model:latest", "context_length": 32768}],
        }),
    )
    _client(
        transport,
        profile=_profile(preload=True, verify_context=True, keep_alive="30m"),
    ).prepare()
    assert _body(transport.calls[1]) == {
        "model": "target-model",
        "prompt": "",
        "stream": False,
        "keep_alive": "30m",
        "options": {"num_ctx": 32768},
    }
    assert transport.calls[2][0] == "GET"
    assert transport.calls[2][1].endswith("/api/ps")


@pytest.mark.parametrize("models", [
    [],
    [{"name": "target-model-plus", "context_length": 32768}],
    [{"name": "target-model", "context_length": 4096}],
])
def test_loaded_context_requires_exact_model_and_context(models):
    transport = FakeTransport(
        FakeResponse(payload=_show()),
        FakeResponse(payload={}),
        FakeResponse(payload={"models": models}),
    )
    with pytest.raises(OllamaPreparationError, match="not loaded|context_length"):
        _client(
            transport, profile=_profile(preload=True, verify_context=True)).prepare()


def test_architecture_context_maximum_is_enforced_before_create():
    transport = FakeTransport(FakeResponse(404), FakeResponse(payload=_show(context_max=8192)))
    with pytest.raises(OllamaPreparationError, match="architecture context maximum"):
        _client(transport).prepare()
    assert all(not call[1].endswith("/api/create") for call in transport.calls)


def test_auth_header_is_forwarded_but_never_appears_in_events_or_errors():
    secret = "ollama-preparation-secret"
    openai = _openai(openai_api_key_env="SITE_KEY")
    transport = FakeTransport(FakeResponse(payload=_show()))
    events: list[tuple[str, dict[str, object]]] = []
    _client(
        transport, openai=openai, environ={"SITE_KEY": secret}, events=events).prepare()
    assert transport.calls[0][2]["headers"]["Authorization"] == f"Bearer {secret}"
    assert secret not in repr(events)
    assert secret not in repr(_client(FakeTransport(), openai=openai))


@pytest.mark.parametrize(("response", "match"), [
    (FakeResponse(302), "redirects"),
    (FakeResponse(body=b"not-json"), "valid bounded JSON"),
    (FakeResponse(chunks=[b"x" * (MAX_OLLAMA_RESPONSE_BYTES + 1)]), "byte limit"),
    (FakeResponse(418), "status 418"),
])
def test_redirect_malformed_oversized_and_status_fail_safely(response, match):
    with pytest.raises(OllamaPreparationError, match=match):
        _client(FakeTransport(response)).prepare()


@pytest.mark.parametrize("error", [
    requests.ConnectionError("provider secret response"),
    requests.Timeout("provider secret timeout"),
])
def test_connection_and_timeout_errors_are_bounded_and_provider_text_free(error):
    with pytest.raises(OllamaPreparationError, match="connection failed or timed out") as exc:
        _client(FakeTransport(error, error)).prepare()
    assert "provider secret" not in str(exc.value)


def test_overall_deadline_exhaustion_stops_response_processing():
    clock = FakeClock()

    def expire() -> None:
        clock.now = 31

    response = FakeResponse(payload=_show(), before_chunk=expire)
    with pytest.raises(OllamaPreparationError, match="overall session deadline"):
        _client(FakeTransport(response), clock=clock).prepare()


@pytest.mark.parametrize(("decision", "approved"), [
    (ApprovalDecision.APPROVE_ONCE, True),
    (ApprovalDecision.DENY, False),
])
def test_interactive_create_requires_one_explicit_approval(decision, approved):
    provider = FakeApprovalProvider(decision)
    gate = ApprovalGate(True, SessionDeadline.from_timeout(30), provider)
    actions: list[object] = [FakeResponse(404), FakeResponse(payload=_show())]
    if approved:
        actions.extend([FakeResponse(payload={}), FakeResponse(payload=_show())])
    transport = FakeTransport(*actions)
    if approved:
        _client(transport, approvals=gate).prepare()
        assert any(call[1].endswith("/api/create") for call in transport.calls)
    else:
        with pytest.raises(OllamaPreparationError, match="operator denied"):
            _client(transport, approvals=gate).prepare()
        assert all(not call[1].endswith("/api/create") for call in transport.calls)
    assert len(provider.requests) == 1


def test_noninteractive_profile_selection_authorizes_creation_without_prompt():
    provider = FakeApprovalProvider(ApprovalDecision.DENY)
    gate = ApprovalGate(False, SessionDeadline.from_timeout(30), provider)
    transport = FakeTransport(
        FakeResponse(404), FakeResponse(payload=_show()),
        FakeResponse(payload={}), FakeResponse(payload=_show()),
    )
    _client(transport, approvals=gate).prepare()
    assert provider.requests == []


@pytest.mark.parametrize(("profile", "openai", "match"), [
    (_profile(api_base_url="http://other.example:11434"), _openai(), "same origin"),
    (_profile(api_base_url="http://localhost:11435"), _openai(), "same origin"),
    (_profile(api_base_url="http://localhost:11434/v1"), _openai(), "native API root"),
    (_profile(target_model="other-model"), _openai(), "target_model"),
])
def test_cross_origin_path_confusion_and_model_mismatch_are_rejected(profile, openai, match):
    with pytest.raises(OllamaConfigurationError, match=match):
        OllamaConfig.from_profile(profile, openai)


def test_native_root_derives_only_from_unambiguous_terminal_v1():
    openai = _openai()
    config = OllamaConfig.from_profile(_profile(api_base_url=None), openai)
    assert config.api_base_url == "http://localhost:11434"
    custom = _openai(openai_base_url="http://localhost:11434/custom/v1")
    with pytest.raises(OllamaConfigurationError, match="api_base_url is required"):
        OllamaConfig.from_profile(_profile(api_base_url=None), custom)


def test_source_and_target_must_differ_when_creation_enabled():
    with pytest.raises(OpenAIProfileError, match="must differ"):
        # Exercise the normalized comparison through the strict profile parser's
        # public behavior in the companion profile tests; direct construction is
        # intentionally followed by the same invariant here.
        from cve_agent.openai_profile import _parse_ollama_values

        _parse_ollama_values({
            "source_model": "same",
            "target_model": "same:latest",
            "num_ctx": "4096",
            "create_if_missing": "true",
        })
