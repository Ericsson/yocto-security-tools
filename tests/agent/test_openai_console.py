# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the cosmetic console mirror of streamed transcript events."""
import pytest

from cve_agent.openai_console import format_console_line

_CASES: list[tuple[str, dict[str, object], str]] = [
    (
        "tool_request",
        {"sequence": 5, "tool": "read_file", "tool_call_id": "x"},
        "[#5] tool_request: read_file",
    ),
    (
        "assistant_response",
        {"sequence": 5, "turn": 2, "content": "Inspecting the build failure."},
        "[#5] model: Inspecting the build failure.",
    ),
    (
        "tool_result",
        {"sequence": 6, "tool": "read_file", "success": True},
        "[#6] tool_result: read_file \u2192 ok",
    ),
    (
        "tool_result",
        {"sequence": 7, "tool": "build_recipe", "success": False,
         "error_kind": "operation"},
        "[#7] tool_result: build_recipe \u2192 failed (operation)",
    ),
    (
        "terminal_result",
        {"sequence": 8, "status": "resolved"},
        "[#8] terminal_result: status=resolved",
    ),
    (
        "session_end",
        {"sequence": 9, "resolved": True, "reason": "host-verified terminal outcome"},
        "[#9] session_end: resolved=True (host-verified terminal outcome)",
    ),
    (
        "session_error",
        {"sequence": 10, "error_type": "ValueError", "message": "bad input"},
        "[#10] session_error: ValueError: bad input",
    ),
    (
        "progress_warning",
        {"sequence": 11, "consecutive": 2, "threshold": 3},
        "[#11] progress_warning: consecutive=2/3",
    ),
    (
        "retry",
        {"sequence": 12, "attempt": 2, "delay": 0.5},
        "[#12] retry: attempt=2 delay=0.5",
    ),
    (
        "http_failure",
        {"sequence": 13, "failure": {"code": "rate_limit", "status_code": 429}},
        "[#13] http_failure: rate_limit (status=429)",
    ),
    (
        "http_failure",
        {"sequence": 14, "failure": {"code": "connection_lost"}},
        "[#14] http_failure: connection_lost",
    ),
]


@pytest.mark.parametrize(("kind", "data", "expected"), _CASES)
def test_format_console_line_exact_output(kind, data, expected):
    assert format_console_line(kind, data) == expected


def test_unrecognized_kind_returns_none():
    assert format_console_line("model_request", {"sequence": 1}) is None
    assert format_console_line("profile_loaded", {"sequence": 3}) is None
    assert format_console_line("http_attempt", {"sequence": 4}) is None
    assert format_console_line("nonexistent_kind", {"sequence": 5}) is None


def test_assistant_response_skips_tool_call_only_turns():
    # A turn where the model only issued tool calls with no commentary
    # (content is None or empty) must not print an empty line.
    assert format_console_line("assistant_response", {"sequence": 1, "content": None}) is None
    assert format_console_line("assistant_response", {"sequence": 1, "content": ""}) is None
    assert format_console_line("assistant_response", {"sequence": 1, "content": "   "}) is None
    assert format_console_line("assistant_response", {"sequence": 1}) is None


def test_assistant_response_strips_surrounding_whitespace():
    assert format_console_line(
        "assistant_response", {"sequence": 3, "content": "  hello world  \n"},
    ) == "[#3] model: hello world"


def test_assistant_response_prints_full_multiline_text():
    text = "Line one.\nLine two.\nLine three."
    assert format_console_line(
        "assistant_response", {"sequence": 4, "content": text},
    ) == f"[#4] model: {text}"


def test_truncated_event_is_handled_without_raising():
    # write()'s oversize fallback replaces the event with a compact dict
    # that has no meaningful fields for any streamed kind.
    assert format_console_line("tool_request", {"truncated": True}) == (
        "[#?] tool_request: ?"
    )
    assert format_console_line("unknown", {"truncated": True}) is None


def test_missing_fields_do_not_raise():
    assert format_console_line("tool_request", {}) == "[#?] tool_request: ?"
    assert format_console_line("tool_result", {}) == "[#?] tool_result: ? \u2192 failed (error)"
    assert format_console_line("http_failure", {}) == "[#?] http_failure"
    assert format_console_line("retry", {}) == "[#?] retry: attempt=? delay=?"


def test_wildly_typed_values_do_not_raise():
    assert format_console_line(
        "tool_request", {"sequence": "not-an-int", "tool": 12345},
    ) == "[#not-an-int] tool_request: 12345"
    assert format_console_line(
        "http_failure", {"sequence": 1, "failure": "not-a-mapping"},
    ) == "[#1] http_failure"
    assert format_console_line(
        "http_failure", {"sequence": 1, "failure": ["a", "list"]},
    ) == "[#1] http_failure"
    # Non-mapping data would raise on .get() -- format_console_line itself
    # must still not propagate an exception past its boundary.
    assert format_console_line("tool_request", None) is None  # type: ignore[arg-type]
