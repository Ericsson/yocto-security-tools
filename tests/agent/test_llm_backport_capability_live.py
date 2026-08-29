# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Opt-in real-model qualification for isolated security backports.

This suite intentionally does not source a Yocto environment, run BitBake,
fetch metadata, or invoke cve-corrector.  It measures the configured native
OpenAI-compatible model against fresh local Git fixtures and host-owned
validators.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cve_agent.backport_capability import (
    QualificationPolicy,
    qualify_capability_model,
)

from .backport_capability_support import builtin_live_cases, run_live_attempt

pytestmark = [
    pytest.mark.live,
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("CVE_AGENT_LLM_BACKPORT_TESTS") != "1",
        reason="set CVE_AGENT_LLM_BACKPORT_TESTS=1 to spend real model inference",
    ),
]


def test_live_llm_backport_qualification(tmp_path: Path) -> None:
    """Require repeatable secure repairs and a safe refusal control."""
    selector = os.environ.get(
        "CVE_AGENT_LLM_BACKPORT_BACKEND", "openai-qwen3.8-l40s")
    trials = _bounded_environment_integer(
        "CVE_AGENT_LLM_BACKPORT_TRIALS", default=5, minimum=5, maximum=20)
    timeout = _bounded_environment_integer(
        "CVE_AGENT_LLM_BACKPORT_TIMEOUT", default=600, minimum=30, maximum=3600)
    configured_root = os.environ.get("CVE_AGENT_LLM_BACKPORT_RESULTS", "").strip()
    output_root = (
        Path(configured_root).expanduser().resolve()
        if configured_root else tmp_path / "llm-backport-capability"
    )
    output_root.mkdir(parents=True, exist_ok=True)

    specs = builtin_live_cases()
    decisions = []
    rows = []
    for spec in specs:
        for trial in range(1, trials + 1):
            attempt_root = (
                output_root / spec.capability.case_id / f"trial-{trial:02d}")
            attempt_root.mkdir(parents=True, exist_ok=False)
            attempt = run_live_attempt(
                spec, selector, trial, attempt_root, timeout)
            decisions.append(attempt.decision)
            rows.append({
                "case": spec.capability.case_id,
                "stratum": spec.capability.stratum,
                "trial": trial,
                "accepted": attempt.decision.accepted,
                "failures": list(attempt.decision.failures),
                "security_status": attempt.evidence.security_status.value,
                "artifact_dir": str(attempt.artifact_dir),
            })

    policy = QualificationPolicy(trials_per_case=trials)
    qualification = qualify_capability_model(
        [spec.capability for spec in specs], decisions, policy)
    report = {
        "schema_version": 1,
        "backend_selector": selector,
        "policy": {
            "trials_per_case": policy.trials_per_case,
            "minimum_case_successes": policy.minimum_case_successes,
            "minimum_total_rate": policy.minimum_total_rate,
            "minimum_stratum_rate": policy.minimum_stratum_rate,
        },
        "qualification": qualification.to_dict(),
        "attempts": rows,
    }
    report_path = output_root / "qualification.json"
    report_path.write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )

    assert qualification.accepted, (
        f"model did not meet the backport capability gate; see {report_path}: "
        + "; ".join(qualification.failures)
    )


def _bounded_environment_integer(
    name: str, *, default: int, minimum: int, maximum: int,
) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise AssertionError(f"{name} must be an integer") from error
    if not minimum <= value <= maximum:
        raise AssertionError(f"{name} must be between {minimum} and {maximum}")
    return value
