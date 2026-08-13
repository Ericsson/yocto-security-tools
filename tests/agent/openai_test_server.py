# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Reusable loopback-only scripted Chat Completions test server."""

from __future__ import annotations

import contextlib
import json
import socket
import threading
import time
from collections import deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RequestCheck = Callable[[dict[str, object]], None]


@dataclass(frozen=True)
class RecordedRequest:
    """One request with deliberately credential-free header diagnostics."""

    method: str
    path: str
    content_type: str | None
    authorization_present: bool
    body: dict[str, object]
    body_bytes: int


@dataclass(frozen=True, repr=False)
class ScriptedHTTPResponse:
    """One queued transport action.

    The representation intentionally omits response bodies because error fixtures
    sometimes contain sentinel credentials used to verify redaction.
    """

    status: int = 200
    json_body: object | None = None
    raw_body: bytes | None = None
    headers: Mapping[str, str] | None = None
    delay: float = 0.0
    close_connection: bool = False
    partial_bytes: int | None = None
    check: RequestCheck | None = None

    def __repr__(self) -> str:
        return (
            "ScriptedHTTPResponse("
            f"status={self.status}, delay={self.delay}, "
            f"close_connection={self.close_connection}, "
            f"partial_bytes={self.partial_bytes})"
        )


class _LoopbackHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = False
    block_on_close = True


class ScriptedOpenAIServer:
    """Queue-driven local server for production-client integration tests."""

    def __init__(self, responses: Iterable[ScriptedHTTPResponse] = ()) -> None:
        self._responses = deque(responses)
        self._lock = threading.Lock()
        self._errors: list[str] = []
        self.requests: list[RecordedRequest] = []
        self._httpd: _LoopbackHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def base_url(self) -> str:
        if self._httpd is None:
            raise RuntimeError("scripted server is not running")
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}/v1"

    @property
    def request_count(self) -> int:
        with self._lock:
            return len(self.requests)

    def enqueue(self, *responses: ScriptedHTTPResponse) -> None:
        with self._lock:
            self._responses.extend(responses)

    def __enter__(self) -> ScriptedOpenAIServer:
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802 - stdlib callback name
                owner._handle(self)

            def log_message(self, format: str, *args: object) -> None:
                return

        self._httpd = _LoopbackHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="scripted-openai-server",
        )
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            if self._thread.is_alive():
                self._errors.append("server thread did not terminate")
        if exc_type is None:
            self.assert_complete()

    def assert_complete(self) -> None:
        with self._lock:
            errors = list(self._errors)
            remaining = len(self._responses)
        if remaining:
            errors.append(f"{remaining} scripted response(s) were not consumed")
        if errors:
            raise AssertionError("; ".join(errors))

    def _handle(self, handler: BaseHTTPRequestHandler) -> None:
        try:
            length = int(handler.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > 2 * 1024 * 1024:
            self._record_error("request Content-Length is invalid or excessive")
            self._send(handler, 413, b"request rejected", {})
            return
        raw = handler.rfile.read(length)
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            decoded = None
        if not isinstance(decoded, dict):
            self._record_error("request body is not a JSON object")
            decoded = {}
        request = RecordedRequest(
            method=handler.command,
            path=handler.path,
            content_type=handler.headers.get("Content-Type"),
            authorization_present="Authorization" in handler.headers,
            body=decoded,
            body_bytes=len(raw),
        )
        with self._lock:
            self.requests.append(request)
            action = self._responses.popleft() if self._responses else None
        if action is None:
            self._record_error("received a request with no scripted response")
            self._send(handler, 500, b"script exhausted", {})
            return
        if action.check is not None:
            try:
                action.check(decoded)
            except Exception as error:  # assertions are reported on fixture exit
                self._record_error(f"request check failed: {type(error).__name__}: {error}")
        if action.delay:
            time.sleep(action.delay)
        if action.close_connection:
            with contextlib.suppress(OSError):
                handler.connection.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                handler.connection.close()
            return
        if action.raw_body is not None:
            body = action.raw_body
        else:
            value = {} if action.json_body is None else action.json_body
            body = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        headers = dict(action.headers or {})
        if action.partial_bytes is not None:
            sent = body[: action.partial_bytes]
            headers["Content-Length"] = str(len(body))
            self._send(handler, action.status, sent, headers, force_close=True)
            return
        self._send(handler, action.status, body, headers)

    def _send(
        self,
        handler: BaseHTTPRequestHandler,
        status: int,
        body: bytes,
        headers: Mapping[str, str],
        *,
        force_close: bool = False,
    ) -> None:
        try:
            handler.send_response(status)
            if not any(name.lower() == "content-type" for name in headers):
                handler.send_header("Content-Type", "application/json")
            if not any(name.lower() == "content-length" for name in headers):
                handler.send_header("Content-Length", str(len(body)))
            for name, value in headers.items():
                handler.send_header(name, value)
            handler.send_header("Connection", "close")
            handler.end_headers()
            handler.wfile.write(body)
            handler.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            handler.close_connection = True

    def _record_error(self, message: str) -> None:
        with self._lock:
            self._errors.append(message)


def tool_call(identifier: str, name: str, arguments: object) -> dict[str, object]:
    """Build one portable function tool call."""
    encoded = (
        arguments
        if isinstance(arguments, str)
        else json.dumps(arguments, ensure_ascii=False, separators=(",", ":"))
    )
    return {
        "id": identifier,
        "type": "function",
        "function": {"name": name, "arguments": encoded},
    }


def assistant_response(
    *calls: dict[str, object],
    content: str | None = None,
    finish_reason: str | None = None,
) -> dict[str, object]:
    """Build a minimal valid Chat Completions response."""
    message: dict[str, object] = {"role": "assistant", "content": content}
    if calls:
        message["tool_calls"] = list(calls)
    return {
        "id": "chatcmpl-scripted",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": message,
                "finish_reason": finish_reason or ("tool_calls" if calls else "stop"),
            }
        ],
    }
