# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Cosmetic, best-effort console mirror of a subset of transcript events.

This module formats a small, terse subset of :class:`~cve_agent.openai_loop.
JSONLTranscript` events into one-line human-readable strings for live
terminal feedback during a non-interactive native OpenAI-compatible session.

It is never authoritative. The JSONL transcript file remains the single
source of truth for audit and debugging; this module only decides whether a
already-sanitized/redacted transcript event dict is *also* worth echoing to
the terminal, and how to render it tersely. Every formatter is total (never
raises) and defensive (`.get()` only, no direct indexing, no assumptions
about field types), because a formatting bug here must never be allowed to
interrupt the mandatory audit path in :class:`JSONLTranscript`.
"""
from collections.abc import Callable, Mapping

_Formatter = Callable[[Mapping[str, object]], str | None]


def _tool_request(data: Mapping[str, object]) -> str:
    tool = data.get("tool", "?")
    summary = data.get("argument_summary")
    if isinstance(summary, str) and summary:
        return f"tool_request: {tool} ({summary})"
    return f"tool_request: {tool}"


def _assistant_response(data: Mapping[str, object]) -> str | None:
    content = data.get("content")
    if not isinstance(content, str) or not content.strip():
        # Tool-call-only turns carry no visible commentary; skip the line
        # entirely rather than printing an empty one.
        return None
    return f"model: {content.strip()}"


def _tool_result(data: Mapping[str, object]) -> str:
    tool = data.get("tool", "?")
    if data.get("success") is True:
        return f"tool_result: {tool} \u2192 ok"
    error_kind = data.get("error_kind", "error")
    return f"tool_result: {tool} \u2192 failed ({error_kind})"


def _terminal_result(data: Mapping[str, object]) -> str:
    status = data.get("status", "?")
    return f"terminal_result: status={status}"


def _session_end(data: Mapping[str, object]) -> str:
    resolved = data.get("resolved", "?")
    reason = data.get("reason", "")
    return f"session_end: resolved={resolved} ({reason})"


def _session_error(data: Mapping[str, object]) -> str:
    error_type = data.get("error_type", "?")
    message = data.get("message", "")
    return f"session_error: {error_type}: {message}"


def _progress_warning(data: Mapping[str, object]) -> str:
    consecutive = data.get("consecutive", "?")
    threshold = data.get("threshold", "?")
    return f"progress_warning: consecutive={consecutive}/{threshold}"


def _progress_event(data: Mapping[str, object]) -> str | None:
    # Only surface the non-progressed classification: a plain "progressed"
    # event carries no diagnostic value on its own (the turn already reset
    # the counter), while "no_new_evidence"/"inspection_saturated" are
    # exactly what a bare progress_warning cannot show — which tool call,
    # in which turn, was judged not to have advanced the session.
    if data.get("progressed") is True:
        return None
    tool = data.get("tool", "?")
    kind = data.get("progress_kind", "?")
    return f"progress_event: {tool} \u2192 {kind}"


def _retry(data: Mapping[str, object]) -> str:
    attempt = data.get("attempt", "?")
    delay = data.get("delay", "?")
    return f"retry: attempt={attempt} delay={delay}"


def _http_failure(data: Mapping[str, object]) -> str:
    failure = data.get("failure")
    if isinstance(failure, Mapping):
        code = failure.get("code", "?")
        status_code = failure.get("status_code")
        if status_code is not None:
            return f"http_failure: {code} (status={status_code})"
        return f"http_failure: {code}"
    return "http_failure"


_FORMATTERS: dict[str, _Formatter] = {
    "tool_request": _tool_request,
    "assistant_response": _assistant_response,
    "tool_result": _tool_result,
    "progress_event": _progress_event,
    "terminal_result": _terminal_result,
    "session_end": _session_end,
    "session_error": _session_error,
    "progress_warning": _progress_warning,
    "retry": _retry,
    "http_failure": _http_failure,
}


def format_console_line(kind: str, data: Mapping[str, object]) -> str | None:
    """Return one terse console line for a streamed event kind, or None.

    Returns ``None`` for any kind not in the streamed subset, when a
    formatter intentionally has nothing to show (e.g. a tool-call-only
    assistant turn with no visible commentary), and for any input
    (including the transcript's compact ``{"truncated": True}`` fallback)
    that a formatter cannot render. Never raises.
    """
    formatter = _FORMATTERS.get(kind)
    if formatter is None:
        return None
    try:
        body = formatter(data)
    except Exception:
        return None
    if not isinstance(body, str):
        return None
    sequence = data.get("sequence", "?")
    return f"[#{sequence}] {body}"
