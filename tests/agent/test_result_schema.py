# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the versioned host-owned result schema."""
import csv
import subprocess
import sys
from pathlib import Path

import pytest

from cve_agent import CveResult, ResultStatus
from cve_agent.backend import SessionResult
from cve_agent.result import (
    BuildStatus,
    FailureClass,
    ResultOutcome,
    ResultSchemaError,
    SecurityStatus,
    WorkflowStatus,
    migrate_legacy_status,
    outcome_for_finish,
    outcome_for_host_skip,
    security_gate_satisfied,
)


def test_done_is_completed_built_but_not_security_verified():
    outcome = outcome_for_finish("done")

    assert outcome.workflow_status is WorkflowStatus.COMPLETED
    assert outcome.build_status is BuildStatus.PASSED
    assert outcome.security_status is SecurityStatus.NOT_EVALUATED
    assert outcome.summary_state == "WORKFLOW_COMPLETED_UNVERIFIED"


def test_stale_build_cannot_be_workflow_completion():
    with pytest.raises(ResultSchemaError, match="current successful build"):
        ResultOutcome(
            WorkflowStatus.COMPLETED,
            BuildStatus.STALE,
            SecurityStatus.NOT_EVALUATED,
        )


def test_model_prose_cannot_assign_equivalence():
    result = CveResult(
        "CVE-2026-0001",
        ResultStatus.CONFLICT_RESOLVED,
        resolution_summary="The model claims this is equivalent and verified.",
    )

    assert result.outcome is not None
    assert result.outcome.security_status is SecurityStatus.NOT_EVALUATED


@pytest.mark.parametrize("status", ["needs_human", "not_applicable"])
def test_non_code_finish_statuses_remain_review_required(status):
    outcome = outcome_for_finish(status)

    assert outcome.workflow_status is WorkflowStatus.ESCALATED
    assert outcome.build_status is BuildStatus.NOT_RUN
    assert outcome.security_status is SecurityStatus.PLAUSIBLE_NEEDS_REVIEW


def test_trusted_host_skip_is_distinct_from_model_claims_and_legacy_data():
    outcome = outcome_for_host_skip()

    assert outcome.workflow_status is WorkflowStatus.SKIPPED
    assert outcome.build_status is BuildStatus.NOT_RUN
    assert outcome.security_status is SecurityStatus.NOT_EVALUATED
    assert outcome.summary_state == "SKIPPED"
    assert migrate_legacy_status("skipped").workflow_status is WorkflowStatus.ESCALATED


@pytest.mark.parametrize(
    ("build", "security", "failure"),
    [
        (BuildStatus.PASSED, SecurityStatus.NOT_EVALUATED, None),
        (BuildStatus.NOT_RUN, SecurityStatus.VERIFIED, None),
        (BuildStatus.NOT_RUN, SecurityStatus.NOT_EVALUATED, FailureClass.UNKNOWN),
    ],
)
def test_trusted_host_skip_rejects_unrelated_evidence(build, security, failure):
    with pytest.raises(ResultSchemaError, match="trusted host skip"):
        ResultOutcome(
            WorkflowStatus.SKIPPED,
            build,
            security,
            failure_class=failure,
        )


@pytest.mark.parametrize("failure_class", list(FailureClass))
def test_each_failure_class_and_detail_code_round_trips(failure_class):
    outcome = ResultOutcome(
        WorkflowStatus.FAILED,
        BuildStatus.NOT_RUN,
        SecurityStatus.NOT_EVALUATED,
        failure_class=failure_class,
        failure_code="bounded_detail",
    )

    assert ResultOutcome.from_dict(outcome.to_dict()) == outcome


def test_legacy_agent_resolved_requires_build_evidence_and_is_never_verified():
    without_evidence = migrate_legacy_status("AGENT_RESOLVED")
    with_evidence = migrate_legacy_status(
        "AGENT_RESOLVED", build_evidence=True)

    assert without_evidence.workflow_status is WorkflowStatus.ESCALATED
    assert with_evidence.workflow_status is WorkflowStatus.COMPLETED
    assert with_evidence.build_status is BuildStatus.PASSED
    assert with_evidence.security_status is SecurityStatus.NOT_EVALUATED


@pytest.mark.parametrize(
    "bad_value",
    [
        {
            "schema_version": 3,
            "workflow_status": "completed",
            "build_status": "passed",
            "security_status": "not_evaluated",
        },
        {
            "schema_version": 2,
            "workflow_status": "future_success",
            "build_status": "passed",
            "security_status": "verified",
        },
        {
            "schema_version": 2,
            "workflow_status": "completed",
            "build_status": "passed",
            "security_status": "future_verified",
        },
    ],
)
def test_unknown_schema_or_enum_fails_closed(bad_value):
    with pytest.raises(ResultSchemaError):
        ResultOutcome.from_dict(bad_value)


def test_verified_resume_gate_does_not_accept_legacy_unverified_result():
    outcome = migrate_legacy_status("AGENT_RESOLVED", build_evidence=True)

    assert not security_gate_satisfied(outcome, SecurityStatus.VERIFIED)


def test_summary_distinguishes_workflow_completion_from_security_acceptance():
    completed = outcome_for_finish("done")
    verified = ResultOutcome(
        WorkflowStatus.COMPLETED,
        BuildStatus.PASSED,
        SecurityStatus.VERIFIED,
    )

    assert completed.summary_state == "WORKFLOW_COMPLETED_UNVERIFIED"
    assert verified.summary_state == "SECURITY_VERIFIED"


def test_legacy_backend_session_result_remains_compatible():
    result = SessionResult(resolved=True, duration=1.0)

    assert result.resolved is True
    assert result.outcome is None


def test_legacy_integration_csv_migration_and_verified_resume_gate(tmp_path):
    csv_path = tmp_path / "results_full.csv"
    csv_path.write_text(
        "cve_id,recipe,status,exit_code,diff_changes,diff_patches,diff_files,duration_s\n"
        "CVE-2026-0001,zlib,AGENT_RESOLVED,SUCCESS,agent,1,1,10\n",
        encoding="utf-8",
    )
    tool = Path(__file__).parents[1] / "integration" / "result_schema.py"

    subprocess.run(
        [sys.executable, str(tool), "migrate", str(csv_path), "full"],
        check=True,
    )
    with csv_path.open(newline="", encoding="utf-8") as source:
        row = next(csv.DictReader(source))
    gated = subprocess.run(
        [
            sys.executable, str(tool), "resumable", str(csv_path), "full",
            "--required", "verified",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert row["workflow_status"] == "completed"
    assert row["build_status"] == "passed"
    assert row["security_status"] == "not_evaluated"
    assert gated.stdout == ""
