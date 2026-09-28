# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""XDG Base Directory compliant paths for yocto-security-tools.

Follows https://specifications.freedesktop.org/basedir-spec/latest/
Override with CVE_TOOLS_DATA_DIR / CVE_TOOLS_CACHE_DIR for CI environments.
"""
import os
from pathlib import Path

_APP = "yocto-security-tools"


def data_dir() -> Path:
    """Persistent data: repos, knowledge base, results.

    Honors ``CVE_TOOLS_DATA_DIR`` (e.g. to isolate one CI/benchmark run's
    artifacts) ahead of the standard ``XDG_DATA_HOME``. Callers that need a
    location shared across all runs/processes on the host regardless of
    that per-run override — e.g. anything referenced from a machine-global
    config outside this tool's control — should use
    :func:`user_data_dir` instead.
    """
    base = os.environ.get("CVE_TOOLS_DATA_DIR") or os.environ.get(
        "XDG_DATA_HOME", str(Path.home() / ".local" / "share")
    )
    return Path(base) / _APP


def user_data_dir() -> Path:
    """Persistent, host-wide data directory — ignores ``CVE_TOOLS_DATA_DIR``.

    Same location :func:`data_dir` resolves to when no per-run override is
    set (``XDG_DATA_HOME``, defaulting to ``~/.local/share``). Use this for
    anything that must stay stable across runs that set ``CVE_TOOLS_DATA_DIR``
    to a temporary/isolated path — e.g. a file referenced from a
    machine-global config like a ``~/.kiro/agents/*.json`` prompt, where a
    dangling path left by one run's temporary override would break every
    other invocation on the host. See ``cve_agent/setup.py``'s
    ``STABLE_AGENT_INSTRUCTIONS``.
    """
    base = os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))
    return Path(base) / _APP


def cache_dir() -> Path:
    """Expendable cache: API responses, downloaded CVE JSON."""
    base = os.environ.get("CVE_TOOLS_CACHE_DIR") or os.environ.get(
        "XDG_CACHE_HOME", str(Path.home() / ".cache")
    )
    return Path(base) / _APP
