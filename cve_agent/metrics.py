# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Parse per-session cost/time metrics from AI backend output.

kiro-cli prints a summary line at the end of each session, e.g.::

    Credits: 5.86 • Time: 1m 23s

This module extracts that figure so the agent can record how many credits a
session consumed and surface it in its result reports. The parser is a pure
function (no I/O) so it can be unit-tested against captured stdout or a
transcript file regardless of how the text was obtained.
"""
import re
from typing import Optional

# Strip ANSI escape sequences (colours, cursor moves) that kiro-cli emits when
# writing to a TTY — the interactive transcript captured via ``script`` is full
# of them, and even non-interactive output can carry colour codes.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")

# Match the end-of-session summary line. Tolerates:
#   - a leading label in any case ("Credits:")
#   - thousands separators and a decimal point in the amount (e.g. "1,234.5")
#   - either bullet glyph (U+2022 '•' or U+00B7 '·') or a plain separator
#   - a free-form time string ("45s", "1m 23s", "1h 2m 3s")
_CREDITS_RE = re.compile(
    r"Credits:\s*(?P<credits>[0-9][0-9,]*(?:\.[0-9]+)?)\s*"
    r"[\u2022\u00b7|]\s*"
    r"Time:\s*(?P<time>[0-9hms][0-9hms \t]*)",
    re.IGNORECASE,
)


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from *text*."""
    return _ANSI_RE.sub("", text)


def parse_kiro_credits(text: str) -> Optional[float]:
    """Extract the credits figure from kiro-cli output.

    Scans *text* for the ``Credits: <num> • Time: <str>`` summary line and
    returns the amount from the last match (a session may print progress lines
    that look similar; the final line is the authoritative session total). The
    ``Time:`` half anchors the match to the real summary line; it is not
    returned (wall-clock time is measured by the agent). ANSI colour codes are
    stripped first.

    Args:
        text: Captured kiro-cli stdout or transcript contents.

    Returns:
        The credits float, or ``None`` when no valid summary line is present.
    """
    if not text:
        return None
    clean = strip_ansi(text)
    last: Optional[float] = None
    for match in _CREDITS_RE.finditer(clean):
        raw_credits = match.group("credits").replace(",", "")
        try:
            last = float(raw_credits)
        except ValueError:
            continue
    return last
