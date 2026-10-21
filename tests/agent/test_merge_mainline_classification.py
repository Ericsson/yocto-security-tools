# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Agent classification of a merge fix commit that has no mainline parent.

The corrector exits 5 (patch error) and prints ``MERGE_MAINLINE_REQUIRED``. That
used to reach the result as a blank failure code under class ``unknown``. No
provider call can supply the missing parent, so none may be spent.
"""
from __future__ import annotations

import json
import time
from unittest.mock import patch

from cve_agent import EXIT_GIT_ERROR, EXIT_PATCH_ERROR, AgentConfig, FailureClass
from cve_agent.knowledge import KnowledgeBase
from cve_agent.orchestrator import _run_cve_pipeline

_MERGE_OUTPUT = (
    "All fix commits are ambiguous merge commits with no --mainline-parent "
    "supplied; nothing to resolve\n"
    "MERGE_MAINLINE_REQUIRED: 0d313b243194 is a merge commit; choose its "
    "mainline with --mainline-parent N\n"
    "  --mainline-parent 1: parent 3f2a1b9c0d4e, 4 file(s)\n")


def _run(tmp_path, exit_code, output):
    metadata = tmp_path / "cves.json"
    metadata.write_text(json.dumps({
        "CVE-2026-4712": {"name": "recipe", "hashes": ["a" * 40]},
    }), encoding="utf-8")
    config = AgentConfig(cve_id="CVE-2026-4712", cve_info_path=metadata)
    with patch("cve_agent.orchestrator.run_corrector",
               return_value=(exit_code, output)), \
            patch("cve_agent.orchestrator.guarded_session") as provider:
        result = _run_cve_pipeline(
            config, KnowledgeBase(tmp_path / "knowledge.json"), time.monotonic())
    return result, provider


def test_merge_refusal_is_classified_with_its_code_and_spends_no_provider_call(
        tmp_path):
    result, provider = _run(tmp_path, EXIT_PATCH_ERROR, _MERGE_OUTPUT)

    assert result.failure_class is FailureClass.HOST_INITIALIZATION
    assert result.failure_code == "MERGE_MAINLINE_REQUIRED"
    assert "--mainline-parent" in result.resolution_summary
    provider.assert_not_called()


def test_other_patch_errors_are_not_called_merge_refusals(tmp_path):
    result, _ = _run(tmp_path, EXIT_PATCH_ERROR,
                     "Cherry-pick of abc produced neither a commit nor a conflict")

    assert result.failure_code != "MERGE_MAINLINE_REQUIRED"


def test_the_code_only_counts_for_a_patch_error_exit(tmp_path):
    """The same text under another unrecoverable exit must not be reclassified."""
    result, _ = _run(tmp_path, EXIT_GIT_ERROR, _MERGE_OUTPUT)

    assert result.failure_code != "MERGE_MAINLINE_REQUIRED"
