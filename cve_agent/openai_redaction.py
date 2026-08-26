# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Shared credential redaction for native endpoint diagnostics and artifacts."""

import re
from collections.abc import Iterable

_BEARER_RE = re.compile(r"(?i)\bBearer\s+[^\s\"']+")


def redact_openai_text(value: str, secrets: Iterable[str] = ()) -> str:
    """Redact bearer forms and exact configured secrets from one text value."""
    redacted = _BEARER_RE.sub("Bearer [REDACTED]", value)
    for secret in sorted({secret for secret in secrets if secret}, key=len, reverse=True):
        redacted = redacted.replace(secret, "[REDACTED]")
    return redacted
