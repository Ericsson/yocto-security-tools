# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Shared credential redaction for native endpoint diagnostics and artifacts."""

import re
from collections.abc import Iterable
from urllib.parse import urlsplit, urlunsplit

_BEARER_RE = re.compile(r"(?i)\bBearer\s+[^\s\"']+")
_KEY_RE = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{12,})\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def _redact_url_userinfo(match: re.Match[str]) -> str:
    value = match.group(0)
    try:
        parsed = urlsplit(value)
    except ValueError:
        return "[REDACTED URL]"
    if parsed.username is None:
        return value
    hostname = parsed.hostname or ""
    try:
        if parsed.port is not None:
            hostname += f":{parsed.port}"
    except ValueError:
        return "[REDACTED URL]"
    return urlunsplit((parsed.scheme, f"[REDACTED]@{hostname}", parsed.path,
                       parsed.query, parsed.fragment))


def redact_openai_text(value: str, secrets: Iterable[str] = ()) -> str:
    """Redact bearer forms and exact configured secrets from one text value."""
    redacted = _BEARER_RE.sub("Bearer [REDACTED]", value)
    redacted = _URL_RE.sub(_redact_url_userinfo, redacted)
    redacted = _KEY_RE.sub("[REDACTED]", redacted)
    for secret in sorted({secret for secret in secrets if secret}, key=len, reverse=True):
        redacted = redacted.replace(secret, "[REDACTED]")
    return redacted
