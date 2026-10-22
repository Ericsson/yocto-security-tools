# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Failure codes printed by the ``--continue`` corrector run reach the result.

After the AI resolves a conflict the agent runs ``cve-corrector --continue``.
That run can fail with a typed ``TRANSFER_*`` or ``HANDOFF_*`` code (vim
CVE-2026-28421: ``TRANSFER_APPLY_FAILED``). The output used to be discarded,
so the result had class ``unknown`` and a blank code even though the log
named the cause.
"""
from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cve_agent import (
    EXIT_GIT_ERROR,
    EXIT_PATCH_ERROR,
    AgentConfig,
    FailureClass,
    ResultStatus,
)
from cve_agent.orchestrator import _finalize_resolution, _handle_clean_apply

_TRANSFER_OUTPUT = (
    "Transferring CVE commits to devtool branch\n"
    "Planning 1 CVE commit(s) for devtool\n"
    "TRANSFER_APPLY_FAILED: fixed staging failed\n"
    "  Unrecoverable error (exit 5)\n")
_HANDOFF_OUTPUT = (
    "Validating the repository handoff\n"
    "HANDOFF_RETRY_SCOPE_DRIFT: tracked paths changed outside the scope\n")


def _config() -> AgentConfig:
    return AgentConfig(cve_id="CVE-2026-28421", cve_info_path=Path("unused.json"))


def _finalize(exit_code, output):
    with patch("cve_agent.orchestrator.run_corrector",
               return_value=(exit_code, output)), \
            patch("cve_agent.orchestrator.build_change_summary"), \
            patch("cve_agent.orchestrator.gather_pattern_details"), \
            patch("cve_agent.orchestrator._capture_semantic_candidate"), \
            patch("cve_agent.orchestrator._record_semantic_validation"), \
            patch("cve_agent.orchestrator.current_run_artifacts",
                  return_value=None):
        outcome = _finalize_resolution(
            _config(), None, Path("/ws/vim"), "a" * 40, 2, time.monotonic())
    return outcome.result


def _clean_apply(exit_code, output):
    """Reach the --continue run of the analysis path with approval given."""
    session = MagicMock(resolved=True, outcome=None, failure_reason="")
    with patch("cve_agent.orchestrator.run_corrector",
               return_value=(exit_code, output)), \
            patch("cve_agent.orchestrator.build_change_summary"), \
            patch("cve_agent.orchestrator.gather_pattern_details"), \
            patch("cve_agent.orchestrator._capture_semantic_candidate"), \
            patch("cve_agent.orchestrator._record_semantic_validation"), \
            patch("cve_agent.orchestrator.current_run_artifacts",
                  return_value=None), \
            patch("cve_agent.orchestrator.guarded_session", return_value=session), \
            patch("cve_agent.orchestrator.get_upstream_sha", return_value="a" * 40), \
            patch("cve_agent.orchestrator._prepare_semantic_reference"), \
            patch("cve_agent.orchestrator._read_conclusion", return_value=None), \
            patch("cve_agent.orchestrator._read_escalation", return_value=None), \
            patch("cve_agent.orchestrator.request_approval",
                  return_value=("approved", "")), \
            patch("cve_agent.orchestrator.build_context",
                  return_value=Path("ctx.md")):
        return _handle_clean_apply(
            _config(), Path("/ws/vim"), {}, None, time.monotonic())


PATHS = pytest.mark.parametrize("path", [_finalize, _clean_apply],
                                ids=["after-resolution", "clean-apply"])


@PATHS
def test_transfer_code_from_continue_reaches_the_result(path):
    result = path(EXIT_PATCH_ERROR, _TRANSFER_OUTPUT)

    assert result.status is ResultStatus.FAILED
    assert result.failure_class is FailureClass.PATCH_TRANSFER
    assert result.failure_code == "TRANSFER_APPLY_FAILED"
    assert "TRANSFER_APPLY_FAILED" in result.resolution_summary


@PATHS
def test_handoff_code_from_continue_reaches_the_result(path):
    result = path(EXIT_PATCH_ERROR, _HANDOFF_OUTPUT)

    assert result.failure_class is FailureClass.CORRECTOR_HANDOFF
    assert result.failure_code == "HANDOFF_RETRY_SCOPE_DRIFT"


@PATHS
def test_transfer_code_wins_over_a_handoff_code_like_the_first_run(path):
    result = path(EXIT_PATCH_ERROR, _HANDOFF_OUTPUT + _TRANSFER_OUTPUT)

    assert result.failure_code == "TRANSFER_APPLY_FAILED"


@PATHS
def test_an_unrecoverable_exit_without_a_code_keeps_the_generic_failure(path):
    result = path(EXIT_GIT_ERROR, "git exploded\n")

    assert result.status is ResultStatus.FAILED
    assert result.failure_code != "TRANSFER_APPLY_FAILED"
    assert "exit" in result.resolution_summary
