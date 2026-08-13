# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.metrics — kiro session credit/time parsing."""
from cve_agent.metrics import parse_kiro_credits, strip_ansi


def test_parses_plain_line():
    assert parse_kiro_credits("Credits: 5.86 • Time: 1m 23s") == 5.86


def test_parses_line_embedded_in_output():
    text = (
        "Resolving conflict in foo.c...\n"
        "Done.\n"
        "Credits: 5.86 • Time: 1m 23s\n"
    )
    assert parse_kiro_credits(text) == 5.86


def test_parses_ansi_colored_line():
    # kiro-cli colours the summary when writing to a TTY / script transcript.
    text = "\x1b[1m\x1b[32mCredits:\x1b[0m 12.50 \x1b[2m•\x1b[0m Time: 45s\n"
    assert parse_kiro_credits(text) == 12.5


def test_parses_thousands_separator():
    assert parse_kiro_credits("Credits: 1,234.5 • Time: 1h 2m 3s") == 1234.5


def test_parses_seconds_only_time():
    assert parse_kiro_credits("Credits: 0.10 • Time: 9s") == 0.10


def test_parses_middot_bullet():
    # U+00B7 middle dot as an alternative separator.
    assert parse_kiro_credits("Credits: 3.00 \u00b7 Time: 2m 1s") == 3.0


def test_takes_last_match_when_multiple():
    text = (
        "Credits: 1.00 • Time: 10s\n"
        "...more work...\n"
        "Credits: 7.25 • Time: 2m 5s\n"
    )
    assert parse_kiro_credits(text) == 7.25


def test_missing_line_returns_none():
    assert parse_kiro_credits("no summary here\njust logs\n") is None


def test_empty_text_returns_none():
    assert parse_kiro_credits("") is None


def test_garbled_line_returns_none():
    # Non-numeric credit value must not raise, just skip.
    assert parse_kiro_credits("Credits: N/A • Time: ?") is None


def test_strip_ansi_removes_escapes():
    assert strip_ansi("\x1b[1mbold\x1b[0m text") == "bold text"
