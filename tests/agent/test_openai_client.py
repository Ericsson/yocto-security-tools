# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the bounded native Chat Completions protocol client."""
import json
import os
import subprocess
import sys
from collections.abc import Callable, Iterable
from pathlib import Path

import pytest
import requests

import cve_agent
from cve_agent.openai_backend import OpenAIConfig, OpenAIConfigurationError
from cve_agent.openai_client import (
    DEFAULT_MAX_JSON_DEPTH,
    AssistantResponse,
    OpenAIAuthenticationError,
    OpenAIChatCompletionsClient,
    OpenAIClientEvent,
    OpenAIClientLimits,
    OpenAIConnectionError,
    OpenAIDeadlineExceededError,
    OpenAILocalRequestError,
    OpenAIMalformedJSONError,
    OpenAINonRetryableHTTPError,
    OpenAINotFoundError,
    OpenAIProtocolError,
    OpenAIRateLimitError,
    OpenAIRequestTimeoutError,
    OpenAIResponseSizeError,
    OpenAIRetryableServerError,
    OpenAIRetryPolicy,
    TokenUsage,
)
from cve_agent.openai_deadline import SessionDeadline


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeResponse:
    def __init__(
        self,
        status_code: int = 200,
        payload: object = None,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        chunks: Iterable[bytes] | None = None,
        stream_error: Exception | None = None,
        close_error: Exception | None = None,
    ) -> None:
        if payload is None:
            payload = _text_payload("ok")
        self.status_code = status_code
        self.headers = headers or {}
        self.body = (
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
            if body is None else body
        )
        self.chunks = list(chunks) if chunks is not None else [self.body]
        self.stream_error = stream_error
        self.close_error = close_error
        self.closed = 0
        self.iter_calls: list[tuple[int, bool]] = []

    def iter_content(self, chunk_size: int,
                     decode_unicode: bool = False) -> Iterable[bytes]:
        self.iter_calls.append((chunk_size, decode_unicode))
        if self.stream_error is not None:
            raise self.stream_error
        yield from self.chunks

    def close(self) -> None:
        self.closed += 1
        if self.close_error is not None:
            raise self.close_error


class FakeTransport:
    def __init__(self, *actions: object,
                 before_post: Callable[[], None] | None = None) -> None:
        self.actions = list(actions)
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.before_post = before_post

    def post(self, url: str, **kwargs: object) -> FakeResponse:
        self.calls.append((url, kwargs))
        if self.before_post is not None:
            self.before_post()
        action = self.actions.pop(0)
        if isinstance(action, Exception):
            raise action
        assert isinstance(action, FakeResponse)
        return action


def _config(**overrides: object) -> OpenAIConfig:
    options: dict[str, object] = {
        "model": "test-model",
        "openai_base_url": "http://localhost:11434/v1",
    }
    options.update(overrides)
    environ = {}
    key_name = options.get("openai_api_key_env")
    if isinstance(key_name, str):
        environ[key_name] = "configured-for-validation"
    return OpenAIConfig.from_sources(options, environ)


def _client(
    transport: FakeTransport,
    *,
    config: OpenAIConfig | None = None,
    clock: FakeClock | None = None,
    timeout: float = 30,
    limits: OpenAIClientLimits | None = None,
    retry: OpenAIRetryPolicy | None = None,
    environ: dict[str, str] | None = None,
    sleep: Callable[[float], None] | None = None,
    events: list[OpenAIClientEvent] | None = None,
) -> OpenAIChatCompletionsClient:
    clock = clock or FakeClock()
    return OpenAIChatCompletionsClient(
        config or _config(),
        SessionDeadline.from_timeout(timeout, clock),
        limits=limits,
        retry_policy=retry,
        transport=transport,
        environ={} if environ is None else environ,
        sleep=(lambda _delay: None) if sleep is None else sleep,
        event_sink=None if events is None else events.append,
    )


def _text_payload(
    content: object,
    *,
    finish_reason: object = "stop",
    usage: object = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": finish_reason,
        }],
    }
    if usage is not None:
        result["usage"] = usage
    return result


def _tool_call(identifier: str, name: str = "read_file",
               arguments: object = '{"path":"a.c"}') -> dict[str, object]:
    return {
        "id": identifier,
        "type": "function",
        "function": {"name": name, "arguments": arguments},
    }


def _tool_payload(content: object, calls: list[dict[str, object]],
                  finish_reason: object = "tool_calls") -> dict[str, object]:
    return {
        "choices": [{
            "message": {
                "role": "assistant",
                "content": content,
                "tool_calls": calls,
            },
            "finish_reason": finish_reason,
        }],
    }


@pytest.mark.parametrize(
    ("base_url", "endpoint"),
    [
        ("http://localhost:11434", "http://localhost:11434/chat/completions"),
        ("http://localhost:11434/", "http://localhost:11434/chat/completions"),
        ("http://localhost:11434/v1", "http://localhost:11434/v1/chat/completions"),
        ("http://localhost:11434/v1/", "http://localhost:11434/v1/chat/completions"),
    ],
)
def test_endpoint_derivation_from_api_root(base_url, endpoint):
    response = FakeResponse()
    transport = FakeTransport(response)
    client = _client(transport, config=_config(openai_base_url=base_url))
    assert client.complete([{"role": "user", "content": "hello"}], []).content == "ok"
    assert transport.calls[0][0] == endpoint


def test_complete_endpoint_is_rejected_in_configuration():
    with pytest.raises(OpenAIConfigurationError, match="API root"):
        _config(openai_base_url="http://localhost:11434/v1/chat/completions/")


def test_minimal_portable_request_without_tools():
    transport = FakeTransport(FakeResponse())
    client = _client(transport)
    messages = [{"role": "user", "content": "hello"}]
    client.complete(messages, [])
    _, kwargs = transport.calls[0]
    body = json.loads(kwargs["data"])
    assert body == {
        "model": "test-model",
        "messages": messages,
        "stream": False,
        "max_tokens": 8192,
    }
    assert kwargs["headers"] == {"Content-Type": "application/json"}
    assert kwargs["stream"] is True
    assert kwargs["allow_redirects"] is False
    assert kwargs["proxies"] == {"http": None, "https": None, "all": None}
    assert not ({"temperature", "strict", "seed", "response_format",
                 "parallel_tool_calls", "reasoning_effort"} & set(body))


def test_opted_in_remote_endpoint_keeps_normal_proxy_configuration():
    config = _config(
        openai_base_url="https://remote.example/v1",
        openai_allow_remote_endpoint=True,
    )
    transport = FakeTransport(FakeResponse())
    _client(transport, config=config).complete(
        [{"role": "user", "content": "hello"}], [])
    assert "proxies" not in transport.calls[0][1]


def test_tools_add_only_portable_tools_and_auto_choice():
    transport = FakeTransport(FakeResponse())
    client = _client(transport)
    tool = {
        "type": "function",
        "function": {"name": "read_file", "parameters": {"type": "object"}},
    }
    client.complete([{"role": "user", "content": "hello"}], [tool])
    body = json.loads(transport.calls[0][1]["data"])
    assert body["tools"] == [tool]
    assert body["tool_choice"] == "auto"


def test_authorization_header_absent_for_missing_or_empty_key():
    config = _config(openai_api_key_env="MODEL_KEY")
    for environ in ({}, {"MODEL_KEY": ""}, {"MODEL_KEY": "   "}):
        transport = FakeTransport(FakeResponse())
        _client(transport, config=config, environ=environ).complete(
            [{"role": "user", "content": "hello"}], [])
        assert "Authorization" not in transport.calls[0][1]["headers"]


def test_authorization_header_uses_named_environment_secret():
    config = _config(openai_api_key_env="MODEL_KEY")
    transport = FakeTransport(FakeResponse())
    _client(transport, config=config, environ={"MODEL_KEY": "secret-value"}).complete(
        [{"role": "user", "content": "hello"}], [])
    assert transport.calls[0][1]["headers"]["Authorization"] == "Bearer secret-value"


def test_secret_is_redacted_from_diagnostics(caplog):
    secret = "sk-super-secret"
    config = _config(openai_api_key_env="MODEL_KEY")
    response = FakeResponse(
        401, body=(
            f"server echoed Bearer {secret} and {secret}\x1b[31m"
        ).encode())
    transport = FakeTransport(response)
    events: list[OpenAIClientEvent] = []
    client = _client(
        transport, config=config, environ={"MODEL_KEY": secret}, events=events,
        retry=OpenAIRetryPolicy(max_attempts=1))
    with pytest.raises(OpenAIAuthenticationError) as exc_info:
        client.complete([{"role": "user", "content": "hello"}], [])
    diagnostic = " ".join((repr(client), repr(exc_info.value), caplog.text,
                           repr(events)))
    assert secret not in diagnostic
    assert "[REDACTED]" in str(exc_info.value)
    assert "\x1b" not in str(exc_info.value)


def test_text_only_assistant_response():
    result = _client(FakeTransport(FakeResponse(payload=_text_payload("hello 🌍")))).complete(
        [{"role": "user", "content": "hello"}], [])
    assert result == AssistantResponse("hello 🌍", (), "stop", None)


def test_null_content_with_string_arguments_tool_call():
    response = FakeResponse(payload=_tool_payload(None, [_tool_call("call_1")]))
    result = _client(FakeTransport(response)).complete(
        [{"role": "user", "content": "inspect"}], [])
    assert result.content is None
    assert result.tool_calls[0].id == "call_1"
    assert result.tool_calls[0].arguments == '{"path":"a.c"}'
    assert result.tool_calls[0].arguments_were_object is False


def test_text_and_multiple_tool_calls_are_preserved():
    calls = [
        _tool_call("call_1", "read_file", '{"path":"a.c"}'),
        _tool_call("call_2", "git_status", "{}"),
    ]
    result = _client(FakeTransport(
        FakeResponse(payload=_tool_payload("I will inspect.", calls)))).complete(
            [{"role": "user", "content": "inspect"}], [])
    assert result.content == "I will inspect."
    assert [(call.id, call.name) for call in result.tool_calls] == [
        ("call_1", "read_file"), ("call_2", "git_status")]


def test_duplicate_tool_call_ids_are_rejected():
    response = FakeResponse(payload=_tool_payload(
        None, [_tool_call("same"), _tool_call("same", "git_status", "{}")] ))
    with pytest.raises(OpenAIProtocolError, match="duplicate"):
        _client(FakeTransport(response)).complete(
            [{"role": "user", "content": "inspect"}], [])


def test_object_arguments_are_canonicalized_for_ollama_compatibility():
    response = FakeResponse(payload=_tool_payload(
        None, [_tool_call("call_1", arguments={"path": "é.c", "offset": 0})]))
    call = _client(FakeTransport(response)).complete(
        [{"role": "user", "content": "inspect"}], []).tool_calls[0]
    assert call.arguments == '{"path":"é.c","offset":0}'
    assert call.arguments_were_object is True


def test_argument_string_is_not_semantically_decoded_by_http_client():
    response = FakeResponse(payload=_tool_payload(
        None, [_tool_call("call_1", arguments="{not-json")]))
    call = _client(FakeTransport(response)).complete(
        [{"role": "user", "content": "inspect"}], []).tool_calls[0]
    assert call.arguments == "{not-json"


@pytest.mark.parametrize(
    ("payload", "match"),
    [
        ({}, "choices"),
        ({"choices": []}, "choices"),
        ({"choices": {}}, "choices"),
        ({"choices": [None]}, "choice"),
        ({"choices": [{"message": None}]}, "message"),
        ({"choices": [{"message": {"content": "x"}}]}, "role"),
        ({"choices": [{"message": {"role": "user", "content": "x"}}]}, "role"),
        (_text_payload([{"type": "text", "text": "x"}]), "content"),
        (_text_payload(None), "content or tool calls"),
        (_text_payload("x", finish_reason=7), "finish_reason"),
    ],
)
def test_protocol_shape_violations(payload, match):
    with pytest.raises(OpenAIProtocolError, match=match):
        _client(FakeTransport(FakeResponse(payload=payload))).complete(
            [{"role": "user", "content": "hello"}], [])


@pytest.mark.parametrize("body", [b"not-json", b'{"choices":', b'{"x":NaN}'])
def test_malformed_or_nonstandard_json(body):
    with pytest.raises(OpenAIMalformedJSONError):
        _client(FakeTransport(FakeResponse(body=body))).complete(
            [{"role": "user", "content": "hello"}], [])


def test_excessive_json_nesting_is_rejected_before_decode():
    nesting = DEFAULT_MAX_JSON_DEPTH + 1
    body = ("[" * nesting + "0" + "]" * nesting).encode()
    with pytest.raises(OpenAIProtocolError, match="nesting"):
        _client(FakeTransport(FakeResponse(body=body))).complete(
            [{"role": "user", "content": "hello"}], [])


def test_finish_reason_and_optional_usage_are_preserved():
    usage = {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}
    response = FakeResponse(payload=_text_payload(
        "done", finish_reason="length", usage=usage))
    result = _client(FakeTransport(response)).complete(
        [{"role": "user", "content": "hello"}], [])
    assert result.finish_reason == "length"
    assert result.usage == TokenUsage(3, 4, 7)


@pytest.mark.parametrize("usage", [[], {"total_tokens": -1}, {"prompt_tokens": True}])
def test_invalid_optional_usage_is_rejected(usage):
    response = FakeResponse(payload=_text_payload("done", usage=usage))
    with pytest.raises(OpenAIProtocolError, match="usage"):
        _client(FakeTransport(response)).complete(
            [{"role": "user", "content": "hello"}], [])


@pytest.mark.parametrize(
    ("status", "error_type"),
    [
        (400, OpenAINonRetryableHTTPError),
        (401, OpenAIAuthenticationError),
        (403, OpenAIAuthenticationError),
        (404, OpenAINotFoundError),
        (429, OpenAIRateLimitError),
        (500, OpenAINonRetryableHTTPError),
        (502, OpenAIRetryableServerError),
        (503, OpenAIRetryableServerError),
        (504, OpenAIRetryableServerError),
    ],
)
def test_http_status_mapping(status, error_type):
    response = FakeResponse(status, body=b'{"error":"safe"}')
    client = _client(
        FakeTransport(response), retry=OpenAIRetryPolicy(max_attempts=1))
    with pytest.raises(error_type):
        client.complete([{"role": "user", "content": "hello"}], [])
    assert response.closed == 1


def test_connection_failure_and_timeout_are_distinct():
    connection = _client(
        FakeTransport(requests.ConnectionError("secret transport detail")),
        retry=OpenAIRetryPolicy(max_attempts=1))
    with pytest.raises(OpenAIConnectionError) as connection_exc:
        connection.complete([{"role": "user", "content": "hello"}], [])
    assert "secret transport detail" not in str(connection_exc.value)

    timeout = _client(
        FakeTransport(requests.Timeout("secret timeout detail")),
        retry=OpenAIRetryPolicy(max_attempts=3))
    with pytest.raises(OpenAIRequestTimeoutError) as timeout_exc:
        timeout.complete([{"role": "user", "content": "hello"}], [])
    assert "secret timeout detail" not in str(timeout_exc.value)


def test_streamed_read_timeout_wrapper_is_not_retried():
    read_timeout_type = type("ReadTimeoutError", (Exception,), {})
    wrapped = requests.ConnectionError(read_timeout_type("secret detail"))
    response = FakeResponse(stream_error=wrapped)
    transport = FakeTransport(response, FakeResponse())
    with pytest.raises(OpenAIRequestTimeoutError) as exc_info:
        _client(transport).complete(
            [{"role": "user", "content": "hello"}], [])
    assert "secret detail" not in str(exc_info.value)
    assert response.closed == 1
    assert len(transport.calls) == 1


@pytest.mark.parametrize("status", [429, 502, 503, 504])
def test_selected_transient_statuses_retry(status):
    transport = FakeTransport(FakeResponse(status), FakeResponse())
    result = _client(transport).complete(
        [{"role": "user", "content": "hello"}], [])
    assert result.content == "ok"
    assert len(transport.calls) == 2


def test_connection_retries_but_500_and_bad_protocol_do_not():
    connected = FakeTransport(requests.ConnectionError("down"), FakeResponse())
    assert _client(connected).complete(
        [{"role": "user", "content": "hello"}], []).content == "ok"
    assert len(connected.calls) == 2

    server = FakeTransport(FakeResponse(500), FakeResponse())
    with pytest.raises(OpenAINonRetryableHTTPError):
        _client(server).complete([{"role": "user", "content": "hello"}], [])
    assert len(server.calls) == 1

    malformed = FakeTransport(FakeResponse(body=b"bad"), FakeResponse())
    with pytest.raises(OpenAIMalformedJSONError):
        _client(malformed).complete([{"role": "user", "content": "hello"}], [])
    assert len(malformed.calls) == 1


def test_response_stream_connection_failure_retries_after_closing():
    broken = FakeResponse(stream_error=OSError("raw stream failed"))
    transport = FakeTransport(broken, FakeResponse())
    result = _client(transport).complete(
        [{"role": "user", "content": "hello"}], [])
    assert result.content == "ok"
    assert broken.closed == 1
    assert len(transport.calls) == 2


def test_retry_after_and_backoff_are_capped_and_audited():
    clock = FakeClock()
    sleeps: list[float] = []
    events: list[OpenAIClientEvent] = []

    def sleep(delay: float) -> None:
        sleeps.append(delay)
        clock.advance(delay)

    transport = FakeTransport(
        FakeResponse(429, headers={"retry-after": "999"}),
        FakeResponse(503, headers={"Retry-After": "invalid"}),
        FakeResponse(),
    )
    retry = OpenAIRetryPolicy(
        max_attempts=3, initial_backoff=0.75,
        backoff_multiplier=2, max_delay=2)
    result = _client(
        transport, clock=clock, retry=retry, sleep=sleep,
        events=events).complete([{"role": "user", "content": "hello"}], [])
    assert result.content == "ok"
    assert sleeps == [2, 1.5]
    assert [event.delay for event in events if event.kind == "retry"] == [2, 1.5]
    assert len(transport.calls) == 3


def test_retry_does_not_sleep_past_shared_deadline():
    clock = FakeClock()
    sleeps: list[float] = []
    response = FakeResponse(429, headers={"Retry-After": "2"})
    client = _client(
        FakeTransport(response), clock=clock, timeout=1,
        sleep=sleeps.append)
    with pytest.raises(OpenAIDeadlineExceededError):
        client.complete([{"role": "user", "content": "hello"}], [])
    assert sleeps == []
    assert response.closed == 1


def test_transport_timeouts_use_decreasing_shared_deadline():
    clock = FakeClock()
    response = FakeResponse()

    def advance() -> None:
        clock.advance(2)

    transport = FakeTransport(response, before_post=advance)
    client = _client(
        transport, clock=clock, timeout=5,
        config=_config(openai_connect_timeout=10, openai_request_timeout=20))
    client.complete([{"role": "user", "content": "hello"}], [])
    assert transport.calls[0][1]["timeout"] == (5, 5)
    assert clock.now == 2


def test_expired_deadline_prevents_network_attempt():
    clock = FakeClock()
    transport = FakeTransport(FakeResponse())
    client = _client(transport, clock=clock, timeout=2)
    clock.advance(3)
    with pytest.raises(OpenAIDeadlineExceededError):
        client.complete([{"role": "user", "content": "hello"}], [])
    assert transport.calls == []


def test_request_message_tool_and_total_size_limits():
    base_message = {"role": "user", "content": "x"}
    with pytest.raises(OpenAILocalRequestError, match="message count"):
        _client(
            FakeTransport(FakeResponse()),
            limits=OpenAIClientLimits(max_messages=1)).complete(
                [base_message, base_message], [])
    with pytest.raises(OpenAILocalRequestError, match="tool count"):
        _client(
            FakeTransport(FakeResponse()),
            limits=OpenAIClientLimits(max_tools=1)).complete(
                [base_message], [{}, {}])
    with pytest.raises(OpenAILocalRequestError, match="message.*byte"):
        _client(
            FakeTransport(FakeResponse()),
            limits=OpenAIClientLimits(max_message_bytes=32)).complete(
                [{"role": "user", "content": "x" * 64}], [])
    with pytest.raises(OpenAILocalRequestError, match="request.*byte"):
        _client(
            FakeTransport(FakeResponse()),
            limits=OpenAIClientLimits(
                max_request_bytes=128, max_message_bytes=128)).complete(
                    [{"role": "user", "content": "x" * 70}], [])


def test_tool_schema_size_and_depth_limits():
    message = [{"role": "user", "content": "hello"}]
    with pytest.raises(OpenAILocalRequestError, match="tool schema.*byte"):
        _client(
            FakeTransport(FakeResponse()),
            limits=OpenAIClientLimits(max_tool_schema_bytes=32)).complete(
                message, [{"description": "x" * 64}])
    nested: object = "leaf"
    for _ in range(5):
        nested = {"nested": nested}
    with pytest.raises(OpenAILocalRequestError, match="nesting"):
        _client(
            FakeTransport(FakeResponse()),
            limits=OpenAIClientLimits(max_json_depth=3)).complete(
                message, [{"schema": nested}])


def test_decoded_response_size_limit_and_content_length_preflight():
    limits = OpenAIClientLimits(max_response_bytes=64)
    decoded = FakeResponse(
        body=b"", headers={"Content-Encoding": "gzip"}, chunks=[b"x" * 40, b"y" * 40])
    with pytest.raises(OpenAIResponseSizeError):
        _client(FakeTransport(decoded), limits=limits).complete(
            [{"role": "user", "content": "hello"}], [])
    assert decoded.closed == 1

    declared = FakeResponse(body=b"{}", headers={"Content-Length": "100"})
    with pytest.raises(OpenAIResponseSizeError):
        _client(FakeTransport(declared), limits=limits).complete(
            [{"role": "user", "content": "hello"}], [])
    assert declared.closed == 1


def test_response_header_count_and_bytes_are_bounded():
    too_many = FakeResponse(headers={"x-a": "1", "x-b": "2"})
    with pytest.raises(OpenAIProtocolError, match="header count"):
        _client(
            FakeTransport(too_many),
            limits=OpenAIClientLimits(max_response_headers=1),
        ).complete([{"role": "user", "content": "hello"}], [])
    assert too_many.closed == 1

    oversized = FakeResponse(headers={"x-large": "v" * 64})
    with pytest.raises(OpenAIProtocolError, match="headers exceed"):
        _client(
            FakeTransport(oversized),
            limits=OpenAIClientLimits(max_response_header_bytes=16),
        ).complete([{"role": "user", "content": "hello"}], [])
    assert oversized.closed == 1


def test_response_tool_call_and_identifier_limits():
    message = [{"role": "user", "content": "hello"}]
    too_many = FakeResponse(payload=_tool_payload(
        None, [_tool_call("one"), _tool_call("two")]))
    with pytest.raises(OpenAIProtocolError, match="tool-call count"):
        _client(
            FakeTransport(too_many),
            limits=OpenAIClientLimits(max_tool_calls=1)).complete(message, [])

    long_id = FakeResponse(payload=_tool_payload(None, [_tool_call("x" * 20)]))
    with pytest.raises(OpenAIProtocolError, match="ID"):
        _client(
            FakeTransport(long_id),
            limits=OpenAIClientLimits(max_identifier_bytes=10)).complete(message, [])


def test_session_tool_budget_does_not_limit_client_schemas_or_response_batch():
    """The multi-turn loop, not the single-exchange client, owns total budget."""
    response = FakeResponse(payload=_tool_payload(
        None, [_tool_call("one"), _tool_call("two")]))
    result = _client(
        FakeTransport(response),
        config=_config(openai_max_tool_calls=1),
    ).complete(
        [{"role": "user", "content": "hello"}],
        [{"type": "function"}, {"type": "function"}],
    )
    assert [call.id for call in result.tool_calls] == ["one", "two"]


def test_response_is_closed_on_success_http_size_protocol_and_stream_failure():
    success = FakeResponse()
    _client(FakeTransport(success)).complete(
        [{"role": "user", "content": "hello"}], [])

    http = FakeResponse(400)
    with pytest.raises(OpenAINonRetryableHTTPError):
        _client(FakeTransport(http)).complete(
            [{"role": "user", "content": "hello"}], [])

    protocol = FakeResponse(payload={})
    with pytest.raises(OpenAIProtocolError):
        _client(FakeTransport(protocol)).complete(
            [{"role": "user", "content": "hello"}], [])

    stream = FakeResponse(stream_error=requests.ConnectionError("broken"))
    with pytest.raises(OpenAIConnectionError):
        _client(
            FakeTransport(stream),
            retry=OpenAIRetryPolicy(max_attempts=1)).complete(
                [{"role": "user", "content": "hello"}], [])
    assert [item.closed for item in (success, http, protocol, stream)] == [1, 1, 1, 1]


def test_response_cleanup_exception_is_redacted_and_fails_safely():
    secret = "distinctive-close-secret"
    response = FakeResponse(close_error=RuntimeError(secret))
    with pytest.raises(OpenAIConnectionError) as exc_info:
        _client(FakeTransport(response)).complete(
            [{"role": "user", "content": "hello"}], [])
    assert secret not in str(exc_info.value)
    assert response.closed == 1


def test_unicode_response_and_invalid_utf8():
    unicode_response = FakeResponse(payload=_text_payload("Zażółć 🛡️"))
    assert _client(FakeTransport(unicode_response)).complete(
        [{"role": "user", "content": "hello"}], []).content == "Zażółć 🛡️"

    invalid = FakeResponse(body=b'{"choices": ["\xff"]}')
    with pytest.raises(OpenAIMalformedJSONError, match="UTF-8"):
        _client(FakeTransport(invalid)).complete(
            [{"role": "user", "content": "hello"}], [])
    assert invalid.closed == 1


def test_import_has_no_network_activity():
    project_root = Path(cve_agent.__file__).resolve().parent.parent
    code = (
        "import socket, requests; "
        "socket.create_connection=lambda *a,**k: "
        "(_ for _ in ()).throw(AssertionError('network')); "
        "requests.sessions.Session.request=lambda *a,**k: "
        "(_ for _ in ()).throw(AssertionError('network')); "
        "import cve_agent.openai_client"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=project_root,
        capture_output=True, text=True, check=False,
        env={**os.environ, "PYTHONPATH": str(project_root)})
    assert result.returncode == 0, result.stderr
