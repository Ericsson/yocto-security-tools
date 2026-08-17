# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Versioned, host-owned CVE agent outcome reporting.

The legacy result status is retained only as a compatibility label.  Release
acceptance must use the independent workflow, build, and security dimensions.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

RESULT_SCHEMA_VERSION = 2


class ResultSchemaError(ValueError):
    """A serialized result cannot be interpreted safely."""


class WorkflowStatus(str, Enum):
    COMPLETED = "completed"
    SKIPPED = "skipped"
    ESCALATED = "escalated"
    FAILED = "failed"


class BuildStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_RUN = "not_run"
    STALE = "stale"


class SecurityStatus(str, Enum):
    VERIFIED = "verified"
    EQUIVALENT = "equivalent"
    PLAUSIBLE_NEEDS_REVIEW = "plausible_needs_review"
    DIVERGENT = "divergent"
    REJECTED = "rejected"
    NOT_EVALUATED = "not_evaluated"


class FailureClass(str, Enum):
    HOST_INITIALIZATION = "host_initialization"
    CORRECTOR_HANDOFF = "corrector_handoff"
    PATCH_TRANSFER = "patch_transfer"
    PROVIDER_PROTOCOL = "provider_protocol"
    PROVIDER_TIMEOUT = "provider_timeout"
    MODEL_NO_PROGRESS = "model_no_progress"
    MODEL_BUDGET = "model_budget"
    BUILD = "build"
    SEMANTIC_VALIDATION = "semantic_validation"
    POLICY_REJECTION = "policy_rejection"
    OPERATOR_DENIAL = "operator_denial"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ResultOutcome:
    """The schema-v2 outcome fields assigned by trusted host code."""

    workflow_status: WorkflowStatus
    build_status: BuildStatus
    security_status: SecurityStatus
    failure_class: FailureClass | None = None
    failure_code: str | None = None
    legacy_status: str | None = None
    schema_version: int = RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != RESULT_SCHEMA_VERSION:
            raise ResultSchemaError(
                f"unsupported result schema version: {self.schema_version}")
        if (self.workflow_status is WorkflowStatus.COMPLETED
                and self.build_status is not BuildStatus.PASSED):
            raise ResultSchemaError(
                "workflow completion requires a current successful build")
        if (self.workflow_status is WorkflowStatus.SKIPPED
                and (self.build_status is not BuildStatus.NOT_RUN
                     or self.security_status is not SecurityStatus.NOT_EVALUATED
                     or self.failure_class is not None
                     or self.failure_code is not None)):
            raise ResultSchemaError(
                "trusted host skip cannot carry build, security, or failure evidence")
        if self.failure_code is not None:
            if (not self.failure_code or len(self.failure_code) > 128
                    or any(ord(char) < 0x20 or ord(char) == 0x7f
                           for char in self.failure_code)):
                raise ResultSchemaError(
                    "failure_code must be 1-128 printable characters")
            if self.failure_class is None:
                raise ResultSchemaError(
                    "failure_code requires a failure_class")

    @property
    def summary_state(self) -> str:
        """Return the single centrally-derived human/machine summary label."""
        if self.failure_class is FailureClass.HOST_INITIALIZATION:
            return "HOST_INITIALIZATION_ERROR"
        if self.failure_class is FailureClass.PROVIDER_TIMEOUT:
            return "PROVIDER_TIMEOUT"
        if self.failure_class is FailureClass.MODEL_NO_PROGRESS:
            return "AGENT_NO_PROGRESS"
        if self.security_status in {
                SecurityStatus.DIVERGENT, SecurityStatus.REJECTED}:
            return "SECURITY_REJECTED"
        if self.security_status in {
                SecurityStatus.VERIFIED, SecurityStatus.EQUIVALENT}:
            return "SECURITY_VERIFIED"
        if self.security_status is SecurityStatus.PLAUSIBLE_NEEDS_REVIEW:
            return "SECURITY_REVIEW_REQUIRED"
        if self.workflow_status is WorkflowStatus.COMPLETED:
            return "WORKFLOW_COMPLETED_UNVERIFIED"
        if self.workflow_status is WorkflowStatus.SKIPPED:
            return "SKIPPED"
        if self.workflow_status is WorkflowStatus.ESCALATED:
            return "SECURITY_REVIEW_REQUIRED"
        return "WORKFLOW_FAILED"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "workflow_status": self.workflow_status.value,
            "build_status": self.build_status.value,
            "security_status": self.security_status.value,
            "failure_class": (
                self.failure_class.value if self.failure_class is not None else None),
            "failure_code": self.failure_code,
            "legacy_status": self.legacy_status,
            "summary_state": self.summary_state,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> ResultOutcome:
        version = value.get("schema_version")
        if version != RESULT_SCHEMA_VERSION:
            raise ResultSchemaError(f"unsupported result schema version: {version!r}")
        try:
            failure_value = value.get("failure_class")
            failure = (
                FailureClass(failure_value) if isinstance(failure_value, str) else None)
            if failure_value is not None and failure is None:
                raise ValueError
            failure_code = value.get("failure_code")
            legacy_status = value.get("legacy_status")
            if failure_code is not None and not isinstance(failure_code, str):
                raise ResultSchemaError("failure_code must be a string or null")
            if legacy_status is not None and not isinstance(legacy_status, str):
                raise ResultSchemaError("legacy_status must be a string or null")
            return cls(
                workflow_status=WorkflowStatus(value["workflow_status"]),
                build_status=BuildStatus(value["build_status"]),
                security_status=SecurityStatus(value["security_status"]),
                failure_class=failure,
                failure_code=failure_code,
                legacy_status=legacy_status,
            )
        except (KeyError, TypeError, ValueError) as error:
            if isinstance(error, ResultSchemaError):
                raise
            raise ResultSchemaError("invalid result schema-v2 enum or field") from error


_LEGACY_COMPLETED = {
    "success", "conflict_resolved", "SUCCESS", "IDENTICAL",
    "ALREADY_APPLIED", "AGENT_RESOLVED",
}


def migrate_legacy_status(
    status: str,
    *,
    build_evidence: bool = False,
    failure_code: str | None = None,
) -> ResultOutcome:
    """Map one legacy JSON/CSV status without inventing security evidence.

    ``build_evidence`` must be supplied by the reader from durable evidence.
    In particular, integration rows named ``AGENT_RESOLVED`` may set it when
    the old trusted finish/build evidence is present.  Without that evidence,
    a purported success is review-required rather than silently accepted.
    """
    if not isinstance(status, str) or not status:
        raise ResultSchemaError("legacy status must be a non-empty string")
    if status in _LEGACY_COMPLETED:
        if build_evidence:
            return ResultOutcome(
                WorkflowStatus.COMPLETED,
                BuildStatus.PASSED,
                SecurityStatus.NOT_EVALUATED,
                legacy_status=status,
            )
        return ResultOutcome(
            WorkflowStatus.ESCALATED,
            BuildStatus.NOT_RUN,
            SecurityStatus.PLAUSIBLE_NEEDS_REVIEW,
            failure_class=FailureClass.UNKNOWN,
            failure_code="legacy_build_evidence_missing",
            legacy_status=status,
        )
    if status in {"escalated", "skipped", "NOT_APPLICABLE"} or status.startswith("SKIP"):
        return ResultOutcome(
            WorkflowStatus.ESCALATED,
            BuildStatus.NOT_RUN,
            SecurityStatus.PLAUSIBLE_NEEDS_REVIEW,
            legacy_status=status,
        )
    if status == "failed" or status.startswith("FAIL"):
        return ResultOutcome(
            WorkflowStatus.FAILED,
            BuildStatus.FAILED if "BUILD" in status else BuildStatus.NOT_RUN,
            SecurityStatus.NOT_EVALUATED,
            failure_class=(FailureClass.BUILD if "BUILD" in status
                           else FailureClass.UNKNOWN),
            failure_code=failure_code,
            legacy_status=status,
        )
    raise ResultSchemaError(f"unknown legacy result status: {status}")


def outcome_for_finish(status: str) -> ResultOutcome:
    """Map a host-accepted finish tool status to schema-v2 dimensions."""
    if status == "done":
        return ResultOutcome(
            WorkflowStatus.COMPLETED,
            BuildStatus.PASSED,
            SecurityStatus.NOT_EVALUATED,
        )
    if status in {"needs_human", "not_applicable"}:
        return ResultOutcome(
            WorkflowStatus.ESCALATED,
            BuildStatus.NOT_RUN,
            SecurityStatus.PLAUSIBLE_NEEDS_REVIEW,
        )
    raise ResultSchemaError(f"unknown trusted finish status: {status}")


def outcome_for_host_skip() -> ResultOutcome:
    """Represent a trusted host decision that requires no backport."""
    return ResultOutcome(
        WorkflowStatus.SKIPPED,
        BuildStatus.NOT_RUN,
        SecurityStatus.NOT_EVALUATED,
        legacy_status="skipped",
    )


def security_gate_satisfied(outcome: ResultOutcome, required: SecurityStatus) -> bool:
    """Return whether an outcome meets an explicit security resume gate."""
    if required is SecurityStatus.VERIFIED:
        return outcome.security_status is SecurityStatus.VERIFIED
    if required is SecurityStatus.EQUIVALENT:
        return outcome.security_status in {
            SecurityStatus.VERIFIED, SecurityStatus.EQUIVALENT}
    return outcome.security_status is required
