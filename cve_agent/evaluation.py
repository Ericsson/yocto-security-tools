# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Reproducible, backend-neutral CVE agent evaluation campaigns.

The expensive integration environment is injected through small callbacks so
the campaign and reporting invariants can be exercised entirely offline.
"""
from __future__ import annotations

import csv
import hashlib
import json
import math
import os
import platform
import selectors
import signal
import stat
import statistics
import subprocess
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import IO

from .result import (
    BuildStatus,
    FailureClass,
    ResultOutcome,
    SecurityStatus,
    WorkflowStatus,
    migrate_legacy_status,
)

EVALUATION_SCHEMA_VERSION = 1
MAX_REPOSITORY_OUTPUT_BYTES = 1024 * 1024
MAX_REPOSITORY_DIAGNOSTIC_BYTES = 64 * 1024
MAX_UNTRACKED_CONTENT_BYTES = 64 * 1024 * 1024
MAX_UNTRACKED_PATHS = 10_000
REPOSITORY_COMMAND_TIMEOUT = 30.0
REQUIRED_STABILITY_STRATA = frozenset({
    "clean_backport",
    "branch_conflict",
    "prerequisite_commit",
    "large_file_hunk",
    "merge_commit",
    "deterministic_host_failure",
    "expected_escalation",
})
MANDATORY_ARTIFACTS = frozenset({"manifest", "transcript", "result"})
DURATION_FIELDS = (
    "baseline_build", "corrector", "workspace_setup", "provider_wait",
    "tool_execution", "build", "ptest", "semantic_validation",
    "patch_transfer", "cleanup", "total",
)
CSV_COLUMNS = (
    "campaign_id", "mode", "cve_id", "recipe", "stratum", "backend",
    "profile", "model", "trial", "baseline_status", "workflow_status",
    "build_status", "security_status", "failure_class", "failure_code",
    "security_accepted", "legacy_unverified", *DURATION_FIELDS,
    "model_turns", "tool_calls", "duplicate_calls", "build_attempts",
    "sessions_attempts", "provider_retries", "input_tokens", "output_tokens",
    "human_review_disposition", "snapshot_digest", "worktree_identity",
)


class EvaluationError(RuntimeError):
    """An evaluation campaign or comparison violated a trusted invariant."""


class RunMode(str, Enum):
    BASELINE_HEALTH_ONLY = "baseline-health-only"
    SINGLE_BACKEND_FULL = "single-backend-full"
    CROSSOVER = "crossover"
    FALLBACK_POLICY = "fallback-policy"
    STABILITY_SUBSET = "stability-subset"
    RESUME_COMPATIBLE_LEGACY = "resume-compatible-legacy"


class BaselineStatus(str, Enum):
    HEALTHY = "BASELINE_HEALTHY"
    BUILD_BROKEN = "BASELINE_BUILD_BROKEN"
    PTEST_BROKEN = "BASELINE_PTEST_BROKEN"
    SETUP_BROKEN = "BASELINE_SETUP_BROKEN"
    BACKEND_NOT_EVALUATED = "BACKEND_NOT_EVALUATED"

    @property
    def testable(self) -> bool:
        return self is BaselineStatus.HEALTHY


class PrimaryMetric(str, Enum):
    SECURITY_ACCEPTED = "security-accepted"
    WORKFLOW_COMPLETED = "workflow-completed"
    BUILD_PASSED = "build-passed"


@dataclass(frozen=True)
class EvaluationCase:
    cve_id: str
    recipe: str
    stratum: str
    source_identity: str
    snapshot_digest: str
    download_identity: str = "unknown"
    cache_identity: str = "unknown"

    def __post_init__(self) -> None:
        for name in (
            "cve_id", "recipe", "stratum", "source_identity",
            "snapshot_digest", "download_identity", "cache_identity",
        ):
            _bounded_text(getattr(self, name), name)


@dataclass(frozen=True)
class BackendVariant:
    selector: str
    profile: str | None
    resolved_config_digest: str
    model: str
    model_digest: str | None = None
    fallback_policy: bool = False
    temperature: float | None = None

    def __post_init__(self) -> None:
        for name in ("selector", "resolved_config_digest", "model"):
            _bounded_text(getattr(self, name), name)
        if self.profile is not None:
            _bounded_text(self.profile, "profile")
        if self.model_digest is not None:
            _bounded_text(self.model_digest, "model_digest")
        if self.temperature is not None and (
            isinstance(self.temperature, bool)
            or not isinstance(self.temperature, (int, float))
            or not math.isfinite(self.temperature)
        ):
            raise ValueError("temperature must be finite when configured")


@dataclass(frozen=True)
class CleanSnapshot:
    snapshot_digest: str
    worktree_identity: str
    workspace: Path

    def __post_init__(self) -> None:
        _bounded_text(self.snapshot_digest, "snapshot_digest")
        _bounded_text(self.worktree_identity, "worktree_identity")
        if not self.workspace.is_absolute():
            raise ValueError("snapshot workspace must be absolute")


@dataclass(frozen=True)
class CampaignManifest:
    mode: RunMode
    repository_commit: str
    dirty_state_digest: str
    implementation_version: str
    metadata_sha256: str
    corrector_version: str
    validator_version: str
    limits: Mapping[str, int | float | str | bool]
    host_platform: Mapping[str, str]
    case_ids: tuple[str, ...]
    backend_selectors: tuple[str, ...]
    backend_digests: tuple[str, ...]
    trials: int
    attempt_seed: int | None
    campaign_id: str
    schema_version: int = EVALUATION_SCHEMA_VERSION

    @classmethod
    def create(
        cls,
        *,
        mode: RunMode,
        repository_commit: str,
        dirty_state_digest: str,
        implementation_version: str,
        metadata_sha256: str,
        corrector_version: str,
        validator_version: str,
        limits: Mapping[str, int | float | str | bool],
        cases: Sequence[EvaluationCase],
        backends: Sequence[BackendVariant],
        trials: int = 1,
        attempt_seed: int | None = None,
        host_platform: Mapping[str, str] | None = None,
    ) -> CampaignManifest:
        if isinstance(trials, bool) or not isinstance(trials, int) or not 1 <= trials <= 20:
            raise ValueError("trials must be between 1 and 20")
        if attempt_seed is not None and (
            isinstance(attempt_seed, bool) or not isinstance(attempt_seed, int)
        ):
            raise ValueError("attempt_seed must be an integer or null")
        case_ids = tuple(sorted(case.cve_id for case in cases))
        backend_selectors = tuple(sorted(backend.selector for backend in backends))
        backend_digests = tuple(sorted(
            f"{backend.selector}:{backend.resolved_config_digest}" for backend in backends))
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("campaign case IDs must be unique")
        if len(backend_selectors) != len(set(backend_selectors)):
            raise ValueError("campaign backend selectors must be unique")
        host = dict(host_platform or safe_host_platform())
        identity = {
            "schema_version": EVALUATION_SCHEMA_VERSION,
            "mode": mode.value,
            "repository_commit": repository_commit,
            "dirty_state_digest": dirty_state_digest,
            "implementation_version": implementation_version,
            "metadata_sha256": metadata_sha256,
            "corrector_version": corrector_version,
            "validator_version": validator_version,
            "limits": dict(sorted(limits.items())),
            "host_platform": dict(sorted(host.items())),
            "case_ids": list(case_ids),
            "backend_selectors": list(backend_selectors),
            "backend_digests": list(backend_digests),
            "trials": trials,
            "attempt_seed": attempt_seed,
        }
        campaign_id = hashlib.sha256(_canonical_json(identity)).hexdigest()
        return cls(
            mode, repository_commit, dirty_state_digest, implementation_version,
            metadata_sha256, corrector_version, validator_version,
            dict(sorted(limits.items())), dict(sorted(host.items())), case_ids,
            backend_selectors, backend_digests, trials, attempt_seed, campaign_id)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "campaign_id": self.campaign_id,
            "mode": self.mode.value,
            "repository_commit": self.repository_commit,
            "dirty_state_digest": self.dirty_state_digest,
            "implementation_version": self.implementation_version,
            "metadata_sha256": self.metadata_sha256,
            "corrector_version": self.corrector_version,
            "validator_version": self.validator_version,
            "limits": dict(self.limits),
            "host_platform": dict(self.host_platform),
            "case_ids": list(self.case_ids),
            "backend_selectors": list(self.backend_selectors),
            "backend_digests": list(self.backend_digests),
            "trials": self.trials,
            "attempt_seed": self.attempt_seed,
        }


@dataclass(frozen=True)
class ExecutionManifest:
    campaign_id: str
    mode: RunMode
    case: EvaluationCase
    backend: BackendVariant | None
    trial: int
    attempt_order: int
    snapshot: CleanSnapshot
    repository_commit: str
    dirty_state_digest: str
    implementation_version: str
    metadata_sha256: str
    corrector_version: str
    validator_version: str
    limits: Mapping[str, int | float | str | bool]
    host_platform: Mapping[str, str]

    def to_dict(self) -> dict[str, object]:
        backend = self.backend
        return {
            "schema_version": EVALUATION_SCHEMA_VERSION,
            "campaign_id": self.campaign_id,
            "mode": self.mode.value,
            "cve_id": self.case.cve_id,
            "recipe": self.case.recipe,
            "stratum": self.case.stratum,
            "repository_commit": self.repository_commit,
            "dirty_state_digest": self.dirty_state_digest,
            "implementation_version": self.implementation_version,
            "metadata_sha256": self.metadata_sha256,
            "profile": None if backend is None else backend.profile,
            "resolved_config_digest": (
                None if backend is None else backend.resolved_config_digest),
            "model": None if backend is None else backend.model,
            "model_digest": None if backend is None else backend.model_digest,
            "temperature": None if backend is None else backend.temperature,
            "source_identity": self.case.source_identity,
            "download_identity": self.case.download_identity,
            "cache_identity": self.case.cache_identity,
            "corrector_version": self.corrector_version,
            "validator_version": self.validator_version,
            "limits": dict(self.limits),
            "host_platform": dict(self.host_platform),
            "snapshot_digest": self.snapshot.snapshot_digest,
            "worktree_identity": self.snapshot.worktree_identity,
            "trial": self.trial,
            "attempt_order": self.attempt_order,
        }


@dataclass(frozen=True)
class EvaluationMetrics:
    durations: Mapping[str, float | None] = field(default_factory=dict)
    model_turns: int = 0
    tool_calls_by_class: Mapping[str, int] = field(default_factory=dict)
    duplicate_calls: int = 0
    build_attempts: int = 0
    sessions_attempts: int = 0
    provider_retries: int = 0
    input_tokens: int | None = None
    output_tokens: int | None = None

    def __post_init__(self) -> None:
        unknown = set(self.durations) - set(DURATION_FIELDS)
        if unknown:
            raise ValueError(f"unknown duration field: {sorted(unknown)[0]}")
        for name, value in self.durations.items():
            if value is None:
                continue
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or not math.isfinite(value) or value < 0):
                raise ValueError(f"duration {name} must be finite and nonnegative")
        counters = {
            "model_turns": self.model_turns,
            "duplicate_calls": self.duplicate_calls,
            "build_attempts": self.build_attempts,
            "sessions_attempts": self.sessions_attempts,
            "provider_retries": self.provider_retries,
            **{f"tool:{name}": value for name, value in self.tool_calls_by_class.items()},
        }
        for name, value in counters.items():
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"counter {name} must be a nonnegative integer")
        for name in ("input_tokens", "output_tokens"):
            value = getattr(self, name)
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                raise ValueError(f"{name} must be a nonnegative integer or null")

    @classmethod
    def from_artifact(cls, path: Path) -> EvaluationMetrics:
        """Load the bounded trusted telemetry artifact without deriving latency."""
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise EvaluationError("telemetry artifact could not be read") from error
        if len(raw) > 1024 * 1024:
            raise EvaluationError("telemetry artifact exceeds 1 MiB")
        try:
            value = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
            raise EvaluationError("telemetry artifact is malformed") from error
        if not isinstance(value, dict):
            raise EvaluationError("telemetry artifact must be an object")
        durations_value = value.get("durations_seconds")
        counters_value = value.get("counters")
        if not isinstance(durations_value, dict) or not isinstance(counters_value, dict):
            raise EvaluationError("telemetry artifact lacks duration or counter maps")
        durations = {
            name: durations_value.get(name) for name in DURATION_FIELDS}
        tool_map = {
            "read": counters_value.get("read_calls", 0),
            "mutation": counters_value.get("mutation_calls", 0),
            "git_inspection": counters_value.get("git_inspection_calls", 0),
            "build": counters_value.get("build_calls", 0),
            "finish": counters_value.get("finish_calls", 0),
            "other": counters_value.get("other_tool_calls", 0),
        }
        return cls(
            durations=durations,
            model_turns=counters_value.get("model_turns", 0),
            tool_calls_by_class={
                name: count for name, count in tool_map.items() if count},
            duplicate_calls=counters_value.get("duplicate_call_count", 0),
            build_attempts=counters_value.get("build_calls", 0),
            sessions_attempts=counters_value.get("sessions_attempts", 0),
            provider_retries=counters_value.get("provider_retries", 0),
            input_tokens=value.get("input_tokens"),
            output_tokens=value.get("output_tokens"),
        )

    @property
    def tool_calls(self) -> int:
        return sum(self.tool_calls_by_class.values())

    def to_dict(self) -> dict[str, object]:
        return {
            "durations_seconds": {
                name: self.durations.get(name, 0.0) for name in DURATION_FIELDS},
            "model_turns": self.model_turns,
            "tool_calls_by_class": dict(sorted(self.tool_calls_by_class.items())),
            "tool_calls": self.tool_calls,
            "duplicate_calls": self.duplicate_calls,
            "build_attempts": self.build_attempts,
            "sessions_attempts": self.sessions_attempts,
            "provider_retries": self.provider_retries,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
        }


@dataclass(frozen=True)
class BaselineAssessment:
    status: BaselineStatus
    metrics: EvaluationMetrics = field(default_factory=EvaluationMetrics)
    artifacts: Mapping[str, str] = field(default_factory=dict)
    reason: str = ""


@dataclass(frozen=True)
class BackendObservation:
    outcome: ResultOutcome
    metrics: EvaluationMetrics
    artifacts: Mapping[str, str]
    human_review_disposition: str | None = None


@dataclass(frozen=True)
class EvaluationRow:
    manifest: ExecutionManifest
    baseline_status: BaselineStatus
    outcome: ResultOutcome | None
    metrics: EvaluationMetrics
    artifacts: Mapping[str, str]
    human_review_disposition: str | None = None
    legacy_unverified: bool = False

    @property
    def key(self) -> tuple[str, str, int]:
        backend = "baseline" if self.manifest.backend is None else self.manifest.backend.selector
        return self.manifest.case.cve_id, backend, self.manifest.trial

    @property
    def security_accepted(self) -> bool:
        return bool(self.outcome and self.outcome.security_status in {
            SecurityStatus.VERIFIED, SecurityStatus.EQUIVALENT})

    def to_dict(self) -> dict[str, object]:
        return {
            "manifest": self.manifest.to_dict(),
            "baseline_status": self.baseline_status.value,
            "outcome": None if self.outcome is None else self.outcome.to_dict(),
            "metrics": self.metrics.to_dict(),
            "artifacts": dict(sorted(self.artifacts.items())),
            "human_review_disposition": self.human_review_disposition,
            "legacy_unverified": self.legacy_unverified,
            "security_accepted": self.security_accepted,
        }


SnapshotFactory = Callable[[EvaluationCase, str, int, Path], CleanSnapshot]
BaselineRunner = Callable[[EvaluationCase, CleanSnapshot, Path], BaselineAssessment]
BackendRunner = Callable[
    [EvaluationCase, BackendVariant, CleanSnapshot, ExecutionManifest, Path],
    BackendObservation,
]


@dataclass(frozen=True)
class CampaignResults:
    campaign: CampaignManifest
    rows: tuple[EvaluationRow, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": EVALUATION_SCHEMA_VERSION,
            "campaign": self.campaign.to_dict(),
            "rows": [row.to_dict() for row in sorted(self.rows, key=lambda item: item.key)],
        }


class CampaignRunner:
    """Execute one campaign using fresh injected snapshots and runners."""

    def __init__(
        self,
        campaign: CampaignManifest,
        cases: Sequence[EvaluationCase],
        backends: Sequence[BackendVariant],
        output_root: Path,
        snapshot_factory: SnapshotFactory,
        baseline_runner: BaselineRunner,
        backend_runner: BackendRunner,
    ) -> None:
        self.campaign = campaign
        self.cases = tuple(sorted(cases, key=lambda item: (item.cve_id, item.recipe)))
        self.backends = tuple(sorted(backends, key=lambda item: item.selector))
        self.output_root = output_root
        self.snapshot_factory = snapshot_factory
        self.baseline_runner = baseline_runner
        self.backend_runner = backend_runner
        self._validate_mode()

    def run(self, resume: CampaignResults | None = None) -> CampaignResults:
        existing = self._resume_rows(resume)
        rows = dict(existing)
        used_worktrees = {
            row.manifest.snapshot.worktree_identity for row in rows.values()}
        order = len(rows)
        self.output_root.mkdir(parents=True, exist_ok=True)
        _atomic_json(self.output_root / "campaign-manifest.json", self.campaign.to_dict())

        for case in self.cases:
            baseline_dir = self.output_root / case.cve_id / "baseline"
            baseline_dir.mkdir(parents=True, exist_ok=True)
            baseline_snapshot = self.snapshot_factory(case, "baseline", 0, baseline_dir)
            self._verify_snapshot(case, baseline_snapshot, used_worktrees)
            baseline = self.baseline_runner(case, baseline_snapshot, baseline_dir)
            if self.campaign.mode is RunMode.BASELINE_HEALTH_ONLY:
                order += 1
                manifest = self._execution_manifest(
                    case, None, 0, order, baseline_snapshot)
                manifest_path = baseline_dir / "manifest.json"
                _atomic_json(manifest_path, manifest.to_dict())
                artifacts = {**baseline.artifacts, "manifest": str(manifest_path)}
                rows[(case.cve_id, "baseline", 0)] = EvaluationRow(
                    manifest, baseline.status, None, baseline.metrics, artifacts)
                continue

            if not baseline.status.testable:
                for backend in self.backends:
                    for trial in range(1, self._trial_count + 1):
                        key = (case.cve_id, backend.selector, trial)
                        if key in rows:
                            continue
                        order += 1
                        manifest = self._execution_manifest(
                            case, backend, trial, order, baseline_snapshot)
                        artifact_dir = (
                            self.output_root / case.cve_id / backend.selector
                            / f"trial-{trial:02d}")
                        artifact_dir.mkdir(parents=True, exist_ok=False)
                        manifest_path = artifact_dir / "manifest.json"
                        _atomic_json(manifest_path, manifest.to_dict())
                        rows[key] = EvaluationRow(
                            manifest, baseline.status, None, baseline.metrics,
                            {**baseline.artifacts, "manifest": str(manifest_path)})
                continue

            for backend in self.backends:
                for trial in range(1, self._trial_count + 1):
                    key = (case.cve_id, backend.selector, trial)
                    if key in rows:
                        continue
                    artifact_dir = (
                        self.output_root / case.cve_id / backend.selector
                        / f"trial-{trial:02d}")
                    artifact_dir.mkdir(parents=True, exist_ok=False)
                    snapshot = self.snapshot_factory(
                        case, backend.selector, trial, artifact_dir)
                    self._verify_snapshot(case, snapshot, used_worktrees)
                    order += 1
                    manifest = self._execution_manifest(
                        case, backend, trial, order, snapshot)
                    manifest_path = artifact_dir / "manifest.json"
                    _atomic_json(manifest_path, manifest.to_dict())
                    observation = self.backend_runner(
                        case, backend, snapshot, manifest, artifact_dir)
                    artifacts = {
                        **observation.artifacts, "manifest": str(manifest_path)}
                    rows[key] = EvaluationRow(
                        manifest, BaselineStatus.HEALTHY, observation.outcome,
                        _merge_metrics(baseline.metrics, observation.metrics),
                        artifacts, observation.human_review_disposition)
        return CampaignResults(
            self.campaign,
            tuple(sorted(rows.values(), key=lambda item: item.key)))

    @property
    def _trial_count(self) -> int:
        return self.campaign.trials if (
            self.campaign.mode is RunMode.STABILITY_SUBSET) else 1

    def _validate_mode(self) -> None:
        mode = self.campaign.mode
        actual_cases = tuple(sorted(case.cve_id for case in self.cases))
        actual_backends = tuple(sorted(backend.selector for backend in self.backends))
        actual_digests = tuple(sorted(
            f"{backend.selector}:{backend.resolved_config_digest}"
            for backend in self.backends))
        if actual_cases != self.campaign.case_ids:
            raise EvaluationError("runner cases differ from immutable campaign manifest")
        if (actual_backends != self.campaign.backend_selectors
                or actual_digests != self.campaign.backend_digests):
            raise EvaluationError(
                "runner backends differ from immutable campaign manifest")
        if mode is RunMode.BASELINE_HEALTH_ONLY and self.backends:
            raise EvaluationError("baseline-health-only does not accept backends")
        if mode is RunMode.SINGLE_BACKEND_FULL and len(self.backends) != 1:
            raise EvaluationError("single-backend-full requires exactly one backend")
        if mode is RunMode.CROSSOVER and len(self.backends) < 2:
            raise EvaluationError("crossover requires at least two backends")
        if mode is RunMode.FALLBACK_POLICY and (
            len(self.backends) != 1 or not self.backends[0].fallback_policy
        ):
            raise EvaluationError("fallback-policy requires one cascade variant")
        if mode is RunMode.STABILITY_SUBSET and self.campaign.trials < 2:
            raise EvaluationError("stability-subset requires repeated trials")
        if mode is RunMode.RESUME_COMPATIBLE_LEGACY:
            raise EvaluationError("legacy mode imports rows; it cannot run fresh backends")

    def _resume_rows(
        self, resume: CampaignResults | None,
    ) -> dict[tuple[str, str, int], EvaluationRow]:
        if resume is None:
            return {}
        if resume.campaign.campaign_id != self.campaign.campaign_id:
            raise EvaluationError("resume campaign ID does not match immutable manifest")
        rows: dict[tuple[str, str, int], EvaluationRow] = {}
        for row in resume.rows:
            if row.manifest.campaign_id != self.campaign.campaign_id:
                raise EvaluationError("resume rows mix campaign IDs")
            if row.key in rows:
                raise EvaluationError("resume contains a duplicate execution key")
            rows[row.key] = row
        return rows

    def _verify_snapshot(
        self, case: EvaluationCase, snapshot: CleanSnapshot, used: set[str],
    ) -> None:
        if snapshot.snapshot_digest != case.snapshot_digest:
            raise EvaluationError(
                f"snapshot mismatch for {case.cve_id}: crossover is not comparable")
        if snapshot.worktree_identity in used:
            raise EvaluationError("campaign attempted to reuse a worktree identity")
        used.add(snapshot.worktree_identity)

    def _execution_manifest(
        self, case: EvaluationCase, backend: BackendVariant | None, trial: int,
        order: int, snapshot: CleanSnapshot,
    ) -> ExecutionManifest:
        return ExecutionManifest(
            self.campaign.campaign_id, self.campaign.mode, case, backend,
            trial, order, snapshot, self.campaign.repository_commit,
            self.campaign.dirty_state_digest,
            self.campaign.implementation_version,
            self.campaign.metadata_sha256, self.campaign.corrector_version,
            self.campaign.validator_version, self.campaign.limits,
            self.campaign.host_platform)


@dataclass(frozen=True)
class ComparisonReport:
    campaign: CampaignManifest
    rows: tuple[EvaluationRow, ...]
    valid: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    summary: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": EVALUATION_SCHEMA_VERSION,
            "campaign": self.campaign.to_dict(),
            "comparison_valid": self.valid,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "summary": dict(self.summary),
            "rows": [row.to_dict() for row in self.rows],
        }


def build_comparison_report(
    results: CampaignResults,
    *,
    strict: bool = False,
    input_price_per_million: float | None = None,
    output_price_per_million: float | None = None,
    primary_metric: PrimaryMetric = PrimaryMetric.SECURITY_ACCEPTED,
) -> ComparisonReport:
    """Validate cohort integrity and aggregate security-first metrics."""
    rows = tuple(sorted(results.rows, key=lambda item: item.key))
    errors, warnings = _comparison_issues(results.campaign, rows)
    if strict and errors:
        raise EvaluationError("invalid comparison: " + "; ".join(errors))
    summary = _aggregate(
        results.campaign, rows, input_price_per_million,
        output_price_per_million, primary_metric)
    return ComparisonReport(
        results.campaign, rows, not errors, tuple(errors), tuple(warnings), summary)


def write_reports(report: ComparisonReport, output_dir: Path) -> None:
    """Write deterministic machine-readable and concise human reports."""
    output_dir.mkdir(parents=True, exist_ok=True)
    _atomic_json(output_dir / "evaluation.json", report.to_dict())
    temporary = output_dir / ".evaluation.csv.tmp"
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="", closefd=False) \
                as output:
            writer = csv.DictWriter(output, CSV_COLUMNS)
            writer.writeheader()
            for row in report.rows:
                writer.writerow(_csv_row(row))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, output_dir / "evaluation.csv")
    finally:
        os.close(descriptor)
        if temporary.exists():
            temporary.unlink()
    markdown = _markdown_report(report)
    _atomic_bytes(output_dir / "evaluation.md", markdown.encode("utf-8"))


def import_legacy_csv(
    source: IO[str], campaign: CampaignManifest, backend: BackendVariant,
) -> CampaignResults:
    """Import old cumulative rows as explicitly unverified, non-comparable data."""
    rows: list[EvaluationRow] = []
    for order, raw in enumerate(csv.DictReader(source), 1):
        cve_id = raw.get("cve_id", "")
        recipe = raw.get("recipe", "unknown")
        status = raw.get("status", "failed")
        outcome = migrate_legacy_status(
            status,
            build_evidence=False,
            failure_code=raw.get("exit_code") or None)
        case = EvaluationCase(
            cve_id, recipe, "legacy_unclassified", "legacy_unknown",
            "legacy_unknown")
        snapshot = CleanSnapshot(
            "legacy_unknown", f"legacy-row-{order}", Path("/legacy/unverified"))
        manifest = ExecutionManifest(
            campaign.campaign_id, RunMode.RESUME_COMPATIBLE_LEGACY,
            case, backend, 1, order, snapshot, campaign.repository_commit,
            campaign.dirty_state_digest, campaign.implementation_version,
            campaign.metadata_sha256, campaign.corrector_version,
            campaign.validator_version, campaign.limits, campaign.host_platform)
        rows.append(EvaluationRow(
            manifest, BaselineStatus.BACKEND_NOT_EVALUATED, outcome,
            EvaluationMetrics(durations={
                "total": _safe_legacy_duration(raw.get("duration_s"))}),
            {}, legacy_unverified=True))
    return CampaignResults(campaign, tuple(rows))


def metadata_sha256(path: Path) -> str:
    """Hash one bounded metadata file without interpreting it."""
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        while chunk := source.read(64 * 1024):
            total += len(chunk)
            if total > 64 * 1024 * 1024:
                raise EvaluationError("evaluation metadata exceeds 64 MiB")
            digest.update(chunk)
    return digest.hexdigest()


def repository_state(root: Path) -> tuple[str, str]:
    """Return HEAD and a content-free digest of bounded repository state."""
    repository = root.resolve(strict=True)
    head = _bounded_git_output(repository, ["rev-parse", "--verify", "HEAD"])
    status = _bounded_git_output(
        repository,
        ["status", "--porcelain=v2", "-z", "--untracked-files=all"],
        text=False,
    )
    diff = _bounded_git_output(
        repository, ["diff", "--binary", "HEAD", "--"], text=False)
    untracked = _untracked_content_digest(repository)
    assert isinstance(head, str) and isinstance(status, bytes) and isinstance(diff, bytes)
    commit = head.strip()
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise EvaluationError("evaluation repository HEAD is malformed")
    label = "clean" if not status else "dirty"
    dirty_digest = hashlib.sha256(
        status + bytes(1) + diff + bytes(1) + untracked).hexdigest()
    return commit, f"{label}:{dirty_digest}"


def safe_host_platform() -> dict[str, str]:
    """Return a small secret-free host description for provenance."""
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    }


def _bounded_git_output(
    root: Path, arguments: Sequence[str], *, text: bool = True,
) -> str | bytes:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    try:
        process = subprocess.Popen(
            ["git", "--no-pager", *arguments], cwd=root, env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False, start_new_session=True)
    except OSError as error:
        raise EvaluationError("evaluation repository inspection failed") from error
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    output = bytearray()
    diagnostic = bytearray()
    started = time.monotonic()
    try:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            if time.monotonic() - started > REPOSITORY_COMMAND_TIMEOUT:
                raise EvaluationError("evaluation repository inspection timed out")
            for key, _ in selector.select(0.1):
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = output if key.fd == process.stdout.fileno() else diagnostic
                target.extend(chunk)
                if (len(output) > MAX_REPOSITORY_OUTPUT_BYTES
                        or len(diagnostic) > MAX_REPOSITORY_DIAGNOSTIC_BYTES):
                    raise EvaluationError(
                        "evaluation repository inspection exceeded its output limit")
        returncode = process.wait(timeout=REPOSITORY_COMMAND_TIMEOUT)
    except subprocess.TimeoutExpired as error:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        raise EvaluationError("evaluation repository inspection timed out") from error
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    if returncode != 0:
        raise EvaluationError("evaluation repository inspection was rejected")
    if text:
        try:
            return bytes(output).decode("ascii", errors="strict")
        except UnicodeDecodeError as error:
            raise EvaluationError("evaluation repository output is malformed") from error
    return bytes(output)


def _untracked_content_digest(root: Path) -> bytes:
    """Hash untracked content without following links or retaining source bytes."""
    raw = _bounded_git_output(
        root, ["ls-files", "--others", "--exclude-standard", "-z"], text=False)
    assert isinstance(raw, bytes)
    paths = [item for item in raw.split(bytes(1)) if item]
    if len(paths) > MAX_UNTRACKED_PATHS:
        raise EvaluationError("evaluation repository has too many untracked paths")
    digest = hashlib.sha256()
    total = 0
    try:
        root_descriptor = os.open(
            root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0))
    except OSError as error:
        raise EvaluationError(
            "evaluation repository could not be inspected safely") from error
    try:
        for encoded in paths:
            if encoded.startswith(b"/") or b"\x00" in encoded:
                raise EvaluationError(
                    "evaluation repository has a malformed untracked path")
            parts = encoded.split(b"/")
            if any(part in {b"", b".", b".."} for part in parts):
                raise EvaluationError("evaluation repository has an unsafe untracked path")
            opened_directories: list[int] = []
            parent = root_descriptor
            try:
                directory_flags = (
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
                for component in parts[:-1]:
                    parent = os.open(component, directory_flags, dir_fd=parent)
                    opened_directories.append(parent)
                metadata = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)
                digest.update(len(encoded).to_bytes(4, "big"))
                digest.update(encoded)
                if stat.S_ISLNK(metadata.st_mode):
                    target = os.readlink(parts[-1], dir_fd=parent)
                    assert isinstance(target, bytes)
                    digest.update(b"link\x00")
                    digest.update(target)
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    raise EvaluationError(
                        "evaluation untracked path is not a regular file")
                flags = (
                    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0))
                descriptor = os.open(parts[-1], flags, dir_fd=parent)
                with os.fdopen(descriptor, "rb") as source:
                    opened = os.fstat(source.fileno())
                    if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise EvaluationError(
                            "evaluation untracked state changed during inspection")
                    digest.update(b"file\x00")
                    while chunk := source.read(64 * 1024):
                        total += len(chunk)
                        if total > MAX_UNTRACKED_CONTENT_BYTES:
                            raise EvaluationError(
                                "evaluation untracked content exceeds 64 MiB")
                        digest.update(chunk)
            except OSError as error:
                raise EvaluationError(
                    "evaluation untracked content could not be inspected safely") from error
            finally:
                for descriptor in reversed(opened_directories):
                    os.close(descriptor)
    finally:
        os.close(root_descriptor)
    return digest.digest()


def _comparison_issues(
    campaign: CampaignManifest, rows: Sequence[EvaluationRow],
) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if any(row.manifest.campaign_id != campaign.campaign_id for row in rows):
        errors.append("rows mix immutable campaign IDs")
    if any(row.legacy_unverified for row in rows):
        errors.append("legacy CSV rows are unverified and cannot support comparison")
    testable = {
        row.manifest.case.cve_id for row in rows
        if row.baseline_status is BaselineStatus.HEALTHY}
    if campaign.mode is RunMode.CROSSOVER:
        for backend in campaign.backend_selectors:
            observed = {
                row.manifest.case.cve_id for row in rows
                if row.manifest.backend is not None
                and row.manifest.backend.selector == backend
                and row.baseline_status is BaselineStatus.HEALTHY}
            if observed != testable:
                errors.append(f"backend {backend} did not run the full testable cohort")
    by_case: dict[str, set[str]] = defaultdict(set)
    worktrees: list[str] = []
    configs: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        by_case[row.manifest.case.cve_id].add(row.manifest.snapshot.snapshot_digest)
        if row.baseline_status.testable and row.outcome is not None:
            worktrees.append(row.manifest.snapshot.worktree_identity)
        if row.manifest.backend is not None:
            configs[row.manifest.backend.selector].add(
                row.manifest.backend.resolved_config_digest)
        if row.baseline_status.testable and row.outcome is not None:
            backend_name = (
                "baseline" if row.manifest.backend is None
                else row.manifest.backend.selector)
            if row.outcome.security_status is SecurityStatus.NOT_EVALUATED:
                errors.append(
                    f"semantic validation unavailable for {row.manifest.case.cve_id}/"
                    f"{backend_name}")
            missing_artifacts = MANDATORY_ARTIFACTS - set(row.artifacts)
            if missing_artifacts:
                errors.append(
                    f"mandatory artifacts missing for {row.manifest.case.cve_id}/"
                    f"{backend_name}: {','.join(sorted(missing_artifacts))}")
            missing_paths = sorted(
                name for name in MANDATORY_ARTIFACTS
                if name in row.artifacts and not Path(row.artifacts[name]).is_file())
            if missing_paths:
                errors.append(
                    f"mandatory artifact paths unavailable for "
                    f"{row.manifest.case.cve_id}/{backend_name}: "
                    f"{','.join(missing_paths)}")
    if any(len(digests) != 1 for digests in by_case.values()):
        errors.append("selected backends did not use identical case snapshots")
    if len(worktrees) != len(set(worktrees)):
        errors.append("executions reused a worktree identity")
    for backend, digests in sorted(configs.items()):
        if len(digests) != 1:
            errors.append(f"backend {backend} mixed resolved configuration versions")
    if campaign.mode is RunMode.STABILITY_SUBSET:
        represented = {row.manifest.case.stratum for row in rows}
        missing_strata = sorted(REQUIRED_STABILITY_STRATA - represented)
        if missing_strata:
            warnings.append(
                "stability subset lacks strata: " + ", ".join(missing_strata))
    return sorted(set(errors)), sorted(set(warnings))


def _aggregate(
    campaign: CampaignManifest,
    rows: Sequence[EvaluationRow],
    input_price: float | None,
    output_price: float | None,
    primary_metric: PrimaryMetric,
) -> dict[str, object]:
    metadata_cases = set(campaign.case_ids)
    baseline_by_case: dict[str, BaselineStatus] = {}
    for row in rows:
        baseline_by_case.setdefault(row.manifest.case.cve_id, row.baseline_status)
    excluded = {
        case: status for case, status in baseline_by_case.items() if not status.testable}
    testable_cases = set(baseline_by_case) - set(excluded)
    backend_rows = [
        row for row in rows
        if row.manifest.backend is not None and row.baseline_status.testable
        and row.outcome is not None]
    accepted = sum(row.security_accepted for row in backend_rows)
    workflow = sum(
        row.outcome is not None
        and row.outcome.workflow_status is WorkflowStatus.COMPLETED
        for row in backend_rows)
    builds = sum(
        row.outcome is not None and row.outcome.build_status is BuildStatus.PASSED
        for row in backend_rows)
    security_counts = Counter(
        row.outcome.security_status.value for row in backend_rows if row.outcome)
    deterministic = sum(
        row.outcome is not None and row.outcome.failure_class in {
            FailureClass.HOST_INITIALIZATION, FailureClass.CORRECTOR_HANDOFF,
            FailureClass.PATCH_TRANSFER, FailureClass.POLICY_REJECTION,
            FailureClass.OPERATOR_DENIAL,
        }
        for row in backend_rows)
    known_false_positives = sum(
        row.human_review_disposition == "false_positive" for row in backend_rows)
    addressable = [
        row for row in backend_rows
        if row.outcome is not None and row.outcome.failure_class not in {
            FailureClass.HOST_INITIALIZATION, FailureClass.CORRECTOR_HANDOFF,
            FailureClass.PATCH_TRANSFER, FailureClass.POLICY_REJECTION,
            FailureClass.OPERATOR_DENIAL,
        }]
    primary_values = {
        PrimaryMetric.SECURITY_ACCEPTED: accepted,
        PrimaryMetric.WORKFLOW_COMPLETED: workflow,
        PrimaryMetric.BUILD_PASSED: builds,
    }
    case_recipes = {
        row.manifest.case.cve_id: row.manifest.case.recipe for row in rows}
    baseline_clusters: dict[str, Counter[str]] = defaultdict(Counter)
    for case_id, status in baseline_by_case.items():
        if not status.testable:
            baseline_clusters[status.value][case_recipes[case_id]] += 1
    summary: dict[str, object] = {
        "primary_metric": primary_metric.value,
        "primary_numerator": primary_values[primary_metric],
        "primary_rate": _rate(primary_values[primary_metric], len(backend_rows)),
        "primary_denominator_kind": "testable_backend_executions",
        "primary_by_backend": _primary_by_backend(backend_rows, primary_metric),
        "metadata_denominator": len(metadata_cases),
        "testable_case_denominator": len(testable_cases),
        "backend_execution_denominator": len(backend_rows),
        "security_accepted": accepted,
        "security_accepted_rate": _rate(accepted, len(backend_rows)),
        "workflow_completed": workflow,
        "workflow_completion_rate": _rate(workflow, len(backend_rows)),
        "build_passed": builds,
        "build_passed_rate": _rate(builds, len(backend_rows)),
        "security_status_counts": dict(sorted(security_counts.items())),
        "known_false_positive_count": known_false_positives,
        "known_false_positive_rate": _rate(
            known_false_positives, len(backend_rows)),
        "deterministic_host_corrector_failure_rate": _rate(
            deterministic, len(backend_rows)),
        "model_addressable_success_rate": _rate(
            sum(row.security_accepted for row in addressable), len(addressable)),
        "review_required_workload": security_counts[
            SecurityStatus.PLAUSIBLE_NEEDS_REVIEW.value],
        "baseline_excluded_count": len(excluded),
        "baseline_status_counts": dict(sorted(Counter(
            status.value for status in excluded.values()).items())),
        "baseline_recipe_clusters": {
            status: dict(sorted(recipes.items()))
            for status, recipes in sorted(baseline_clusters.items())},
        "coverage_gap": len(metadata_cases) - len(testable_cases),
        "provider_wait_seconds": _distribution([
            value for row in backend_rows
            if (value := row.metrics.durations.get("provider_wait", 0.0)) is not None]),
        "total_seconds": _distribution([
            value for row in backend_rows
            if (value := row.metrics.durations.get("total", 0.0)) is not None]),
        "metric_totals": _metric_totals(backend_rows),
        "fallback_policy_run": campaign.mode is RunMode.FALLBACK_POLICY,
        "human_review_dispositions": dict(sorted(Counter(
            row.human_review_disposition for row in backend_rows
            if row.human_review_disposition).items())),
        "per_backend": _per_backend_summary(backend_rows),
    }
    if campaign.mode is RunMode.STABILITY_SUBSET:
        summary["stability"] = _stability_summary(backend_rows)
    if input_price is not None or output_price is not None:
        if input_price is None or output_price is None:
            raise ValueError("both input and output token prices are required")
        if any(value < 0 or not math.isfinite(value)
               for value in (input_price, output_price)):
            raise ValueError("token prices must be finite and nonnegative")
        if any(row.metrics.input_tokens is None or row.metrics.output_tokens is None
               for row in backend_rows):
            summary["cost_per_security_accepted_fix"] = None
            summary["cost_limitation"] = "token usage unavailable for one or more runs"
        else:
            cost = sum(
                (row.metrics.input_tokens or 0) * input_price / 1_000_000
                + (row.metrics.output_tokens or 0) * output_price / 1_000_000
                for row in backend_rows)
            summary["cost_per_security_accepted_fix"] = (
                cost / accepted if accepted else None)
    else:
        summary["cost_per_security_accepted_fix"] = None
        summary["cost_limitation"] = "token pricing was not configured"
    return summary


def _metric_totals(rows: Sequence[EvaluationRow]) -> dict[str, object]:
    durations = {
        name: _optional_float_sum(
            row.metrics.durations.get(name, 0.0) for row in rows)
        for name in DURATION_FIELDS}
    tools: Counter[str] = Counter()
    for row in rows:
        tools.update(row.metrics.tool_calls_by_class)
    return {
        "durations_seconds": durations,
        "model_turns": sum(row.metrics.model_turns for row in rows),
        "tool_calls_by_class": dict(sorted(tools.items())),
        "duplicate_calls": sum(row.metrics.duplicate_calls for row in rows),
        "build_attempts": sum(row.metrics.build_attempts for row in rows),
        "sessions_attempts": sum(row.metrics.sessions_attempts for row in rows),
        "provider_retries": sum(row.metrics.provider_retries for row in rows),
        "input_tokens": _optional_sum(row.metrics.input_tokens for row in rows),
        "output_tokens": _optional_sum(row.metrics.output_tokens for row in rows),
    }


def _per_backend_summary(rows: Sequence[EvaluationRow]) -> dict[str, object]:
    grouped: dict[str, list[EvaluationRow]] = defaultdict(list)
    for row in rows:
        if row.manifest.backend is not None:
            grouped[row.manifest.backend.selector].append(row)
    result: dict[str, object] = {}
    for backend, backend_rows in sorted(grouped.items()):
        accepted = sum(row.security_accepted for row in backend_rows)
        result[backend] = {
            "testable_case_denominator": len({
                row.manifest.case.cve_id for row in backend_rows}),
            "executions": len(backend_rows),
            "security_accepted": accepted,
            "security_accepted_rate": _rate(accepted, len(backend_rows)),
            "workflow_completion_rate": _rate(sum(
                row.outcome is not None
                and row.outcome.workflow_status is WorkflowStatus.COMPLETED
                for row in backend_rows), len(backend_rows)),
            "build_passed_rate": _rate(sum(
                row.outcome is not None
                and row.outcome.build_status is BuildStatus.PASSED
                for row in backend_rows), len(backend_rows)),
            "provider_wait_seconds": _distribution([
                value for row in backend_rows
                if (value := row.metrics.durations.get(
                    "provider_wait", 0.0)) is not None]),
            "total_seconds": _distribution([
                value for row in backend_rows
                if (value := row.metrics.durations.get("total", 0.0)) is not None]),
        }
    return result


def _primary_by_backend(
    rows: Sequence[EvaluationRow], primary_metric: PrimaryMetric,
) -> dict[str, object]:
    grouped: dict[str, list[EvaluationRow]] = defaultdict(list)
    for row in rows:
        if row.manifest.backend is not None:
            grouped[row.manifest.backend.selector].append(row)
    result: dict[str, object] = {}
    for backend, backend_rows in sorted(grouped.items()):
        if primary_metric is PrimaryMetric.SECURITY_ACCEPTED:
            numerator = sum(row.security_accepted for row in backend_rows)
        elif primary_metric is PrimaryMetric.WORKFLOW_COMPLETED:
            numerator = sum(
                row.outcome is not None
                and row.outcome.workflow_status is WorkflowStatus.COMPLETED
                for row in backend_rows)
        else:
            numerator = sum(
                row.outcome is not None
                and row.outcome.build_status is BuildStatus.PASSED
                for row in backend_rows)
        denominator = len(backend_rows)
        result[backend] = {
            "numerator": numerator,
            "testable_case_denominator": len({
                row.manifest.case.cve_id for row in backend_rows}),
            "execution_denominator": denominator,
            "rate": _rate(numerator, denominator),
        }
    return result


def _stability_summary(rows: Sequence[EvaluationRow]) -> dict[str, object]:
    grouped: dict[tuple[str, str], list[EvaluationRow]] = defaultdict(list)
    for row in rows:
        if row.manifest.backend is not None:
            grouped[(row.manifest.case.cve_id,
                     row.manifest.backend.selector)].append(row)
    result: dict[str, object] = {}
    for (cve_id, backend), trials in sorted(grouped.items()):
        waits = [
            value for row in trials
            if (value := row.metrics.durations.get("provider_wait", 0.0)) is not None]
        totals = [
            value for row in trials
            if (value := row.metrics.durations.get("total", 0.0)) is not None]
        key = f"{cve_id}/{backend}"
        result[key] = {
            "trials": len(trials),
            "accepted_trials": sum(row.security_accepted for row in trials),
            "acceptance_stability": _rate(
                sum(row.security_accepted for row in trials), len(trials)),
            "provider_wait_variance": (
                statistics.pvariance(waits) if len(waits) > 1
                else 0.0 if waits else None),
            "total_duration_variance": (
                statistics.pvariance(totals) if len(totals) > 1
                else 0.0 if totals else None),
        }
    return result


def _merge_metrics(
    baseline: EvaluationMetrics, observed: EvaluationMetrics,
) -> EvaluationMetrics:
    durations = {
        name: _optional_float_pair_sum(
            baseline.durations.get(name, 0.0),
            observed.durations.get(name, 0.0))
        for name in DURATION_FIELDS}
    tools = Counter(baseline.tool_calls_by_class)
    tools.update(observed.tool_calls_by_class)
    return EvaluationMetrics(
        durations, baseline.model_turns + observed.model_turns, dict(tools),
        baseline.duplicate_calls + observed.duplicate_calls,
        baseline.build_attempts + observed.build_attempts,
        baseline.sessions_attempts + observed.sessions_attempts,
        baseline.provider_retries + observed.provider_retries,
        _optional_pair_sum(baseline.input_tokens, observed.input_tokens),
        _optional_pair_sum(baseline.output_tokens, observed.output_tokens),
    )


def _csv_row(row: EvaluationRow) -> dict[str, object]:
    outcome = row.outcome
    backend = row.manifest.backend
    value: dict[str, object] = {
        "campaign_id": row.manifest.campaign_id,
        "mode": row.manifest.mode.value,
        "cve_id": row.manifest.case.cve_id,
        "recipe": row.manifest.case.recipe,
        "stratum": row.manifest.case.stratum,
        "backend": "" if backend is None else backend.selector,
        "profile": "" if backend is None or backend.profile is None else backend.profile,
        "model": "" if backend is None else backend.model,
        "trial": row.manifest.trial,
        "baseline_status": row.baseline_status.value,
        "workflow_status": "" if outcome is None else outcome.workflow_status.value,
        "build_status": "" if outcome is None else outcome.build_status.value,
        "security_status": "" if outcome is None else outcome.security_status.value,
        "failure_class": (
            "" if outcome is None or outcome.failure_class is None
            else outcome.failure_class.value),
        "failure_code": "" if outcome is None else outcome.failure_code or "",
        "security_accepted": str(row.security_accepted).lower(),
        "legacy_unverified": str(row.legacy_unverified).lower(),
        "model_turns": row.metrics.model_turns,
        "tool_calls": row.metrics.tool_calls,
        "duplicate_calls": row.metrics.duplicate_calls,
        "build_attempts": row.metrics.build_attempts,
        "sessions_attempts": row.metrics.sessions_attempts,
        "provider_retries": row.metrics.provider_retries,
        "input_tokens": "" if row.metrics.input_tokens is None else row.metrics.input_tokens,
        "output_tokens": "" if row.metrics.output_tokens is None else row.metrics.output_tokens,
        "human_review_disposition": row.human_review_disposition or "",
        "snapshot_digest": row.manifest.snapshot.snapshot_digest,
        "worktree_identity": row.manifest.snapshot.worktree_identity,
    }
    value.update({
        name: "" if row.metrics.durations.get(name, 0.0) is None
        else row.metrics.durations.get(name, 0.0)
        for name in DURATION_FIELDS})
    return value


def _markdown_report(report: ComparisonReport) -> str:
    summary = report.summary
    validity = "valid" if report.valid else "INVALID"
    lines = [
        "# CVE agent evaluation",
        "",
        f"- Campaign: `{report.campaign.campaign_id}`",
        f"- Mode: `{report.campaign.mode.value}`",
        f"- Comparison: **{validity}**",
        f"- Metadata cases: {summary['metadata_denominator']}",
        f"- Testable cases: {summary['testable_case_denominator']}",
        f"- Backend executions: {summary['backend_execution_denominator']}",
        f"- Security accepted: {summary['security_accepted']} "
        f"({summary['security_accepted_rate']:.1%})",
        f"- Baseline exclusions: {summary['baseline_excluded_count']}",
        f"- Review required: {summary['review_required_workload']}",
    ]
    if report.errors:
        lines.extend(["", "## Invalid comparison guards", ""])
        lines.extend(f"- {error}" for error in report.errors)
    if report.warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in report.warnings)
    lines.extend([
        "",
        f"The configured primary metric is `{summary['primary_metric']}` over "
        "testable backend executions. Baseline failures are a coverage gap, not "
        "backend outcomes. "
        "Total duration is not inference latency; provider wait is reported separately.",
        "",
    ])
    return "\n".join(lines)


def _distribution(values: Sequence[float]) -> dict[str, float | None]:
    if not values:
        return {"median": None, "p90": None, "p95": None}
    ordered = sorted(values)
    return {
        "median": statistics.median(ordered),
        "p90": _nearest_rank(ordered, 0.90),
        "p95": _nearest_rank(ordered, 0.95),
    }


def _nearest_rank(ordered: Sequence[float], percentile: float) -> float:
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _optional_sum(values) -> int | None:
    items = list(values)
    return None if any(value is None for value in items) else sum(items)


def _optional_pair_sum(first: int | None, second: int | None) -> int | None:
    return None if first is None or second is None else first + second


def _optional_float_sum(values) -> float | None:
    items = list(values)
    return None if any(value is None for value in items) else float(sum(items))


def _optional_float_pair_sum(
    first: float | None, second: float | None,
) -> float | None:
    return None if first is None or second is None else first + second


def _safe_legacy_duration(value: str | None) -> float:
    try:
        result = float(value or "0")
    except ValueError:
        return 0.0
    return result if math.isfinite(result) and result >= 0 else 0.0


def _bounded_text(value: object, label: str) -> str:
    if (not isinstance(value, str) or not value
            or len(value.encode("utf-8")) > 512
            or any(not character.isprintable() for character in value)):
        raise ValueError(f"{label} must be bounded printable text")
    return value


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")


def _atomic_json(path: Path, value: object) -> None:
    _atomic_bytes(path, _canonical_json(value) + b"\n")


def _atomic_bytes(path: Path, value: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        os.close(descriptor)
        if temporary.exists():
            temporary.unlink()
