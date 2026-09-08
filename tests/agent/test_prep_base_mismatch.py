# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Agent classification of the branch-preparation mismatch exit code.

A CVE branch whose base is missing a recipe patch the fix depends on cannot
produce a transferable resolution, so no provider call may be spent on it.
"""
from __future__ import annotations

import json
import time
from unittest.mock import patch

from cve_agent import (
    EXIT_PREP_BASE_MISMATCH,
    RECOVERABLE_EXITS,
    UNRECOVERABLE_EXITS,
    AgentConfig,
    FailureClass,
)
from cve_agent.knowledge import KnowledgeBase
from cve_agent.orchestrator import _run_cve_pipeline


def test_prep_base_mismatch_is_unrecoverable():
    assert EXIT_PREP_BASE_MISMATCH == 17
    assert EXIT_PREP_BASE_MISMATCH in UNRECOVERABLE_EXITS
    assert EXIT_PREP_BASE_MISMATCH not in RECOVERABLE_EXITS


def test_prep_base_mismatch_makes_zero_provider_calls(tmp_path):
    metadata = tmp_path / "cves.json"
    metadata.write_text(json.dumps({
        "CVE-2026-4711": {"name": "recipe", "hashes": ["a" * 40]},
    }), encoding="utf-8")
    config = AgentConfig(cve_id="CVE-2026-4711", cve_info_path=metadata)
    output = ("PREP_BASE_MISMATCH: recipe patch '7fabf6b4a96c Merge pull "
              "request #4332' could not be replayed in setuptools/package_index.py")
    with patch("cve_agent.orchestrator.run_corrector",
               return_value=(EXIT_PREP_BASE_MISMATCH, output)), \
            patch("cve_agent.orchestrator.guarded_session") as provider:
        result = _run_cve_pipeline(
            config, KnowledgeBase(tmp_path / "knowledge.json"), time.monotonic())

    assert result.failure_class is FailureClass.HOST_INITIALIZATION
    assert result.failure_code == "PREP_BASE_MISMATCH"
    provider.assert_not_called()
