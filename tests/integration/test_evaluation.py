# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Offline tests for reproducible backend evaluation campaigns."""
from __future__ import annotations

import io
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from cve_agent.evaluation import (
    REQUIRED_STABILITY_STRATA,
    BackendObservation,
    BackendVariant,
    BaselineAssessment,
    BaselineStatus,
    CampaignManifest,
    CampaignResults,
    CampaignRunner,
    CleanSnapshot,
    EvaluationCase,
    EvaluationError,
    EvaluationMetrics,
    PrimaryMetric,
    RunMode,
    build_comparison_report,
    import_legacy_csv,
    repository_state,
    write_reports,
)
from cve_agent.result import (
    BuildStatus,
    ResultOutcome,
    SecurityStatus,
    WorkflowStatus,
)


def _cases() -> list[EvaluationCase]:
    return [
        EvaluationCase(
            "CVE-1", "alpha", "clean_backport", "source-a", "snapshot-a",
            "downloads-a", "cache-a"),
        EvaluationCase(
            "CVE-2", "beta", "branch_conflict", "source-b", "snapshot-b",
            "downloads-b", "cache-b"),
        EvaluationCase(
            "CVE-3", "broken", "deterministic_host_failure", "source-c",
            "snapshot-c", "downloads-c", "cache-c"),
    ]


def _backends() -> list[BackendVariant]:
    return [
        BackendVariant("openai-a", "a", "config-a", "model-a", "model-digest-a", False, 0),
        BackendVariant("openai-b", "b", "config-b", "model-b", None, False, None),
    ]


def _campaign(
    mode=RunMode.CROSSOVER, *, cases=None, backends=None, trials=1, seed=None,
):
    cases = _cases() if cases is None else cases
    backends = _backends() if backends is None else backends
    return CampaignManifest.create(
        mode=mode,
        repository_commit="a" * 40,
        dirty_state_digest="clean:" + "0" * 64,
        implementation_version="yocto-security-tools:test",
        metadata_sha256="b" * 64,
        corrector_version="corrector-v1",
        validator_version="semantic-v1",
        limits={"case_timeout": 120, "max_steps": 20},
        cases=cases,
        backends=backends,
        trials=trials,
        attempt_seed=seed,
        host_platform={"system": "test", "machine": "test", "python": "3.10"},
    )


class FakeEnvironment:
    def __init__(self) -> None:
        self.snapshot_calls = []
        self.baseline_calls = []
        self.backend_calls = []
        self.counter = 0

    def snapshot(self, case, phase, trial, artifact_dir):
        self.counter += 1
        workspace = artifact_dir / f"workspace-{self.counter}"
        workspace.mkdir()
        identity = f"{case.cve_id}:{phase}:{trial}:{self.counter}"
        self.snapshot_calls.append((case.cve_id, phase, trial, identity))
        return CleanSnapshot(case.snapshot_digest, identity, workspace.resolve())

    def baseline(self, case, snapshot, artifact_dir):
        self.baseline_calls.append((case.cve_id, snapshot.worktree_identity))
        log = artifact_dir / "baseline.log"
        log.write_text("bounded baseline log\n", encoding="utf-8")
        if case.cve_id == "CVE-3":
            return BaselineAssessment(
                BaselineStatus.BUILD_BROKEN,
                EvaluationMetrics(durations={"baseline_build": 7, "total": 7}),
                {"baseline_log": str(log)},
                "pre-existing build failure",
            )
        return BaselineAssessment(
            BaselineStatus.HEALTHY,
            EvaluationMetrics(durations={
                "baseline_build": 2, "workspace_setup": 1, "total": 3}),
            {"baseline_log": str(log)},
        )

    def backend(self, case, backend, snapshot, manifest, artifact_dir):
        self.backend_calls.append((
            case.cve_id, backend.selector, snapshot.worktree_identity,
            manifest.campaign_id))
        transcript = artifact_dir / "agent-transcript.jsonl"
        result = artifact_dir / "result.json"
        transcript.write_text('{"event":"done"}\n', encoding="utf-8")
        result.write_text('{"schema_version":2}\n', encoding="utf-8")
        security = (
            SecurityStatus.VERIFIED if backend.selector == "openai-a"
            else SecurityStatus.EQUIVALENT)
        return BackendObservation(
            ResultOutcome(
                WorkflowStatus.COMPLETED, BuildStatus.PASSED, security),
            EvaluationMetrics(
                durations={
                    "corrector": 2,
                    "provider_wait": 3 if backend.selector == "openai-a" else 5,
                    "tool_execution": 1,
                    "build": 4,
                    "ptest": 2,
                    "semantic_validation": 1,
                    "patch_transfer": 0.5,
                    "cleanup": 0.5,
                    "total": 14 if backend.selector == "openai-a" else 16,
                },
                model_turns=4,
                tool_calls_by_class={"read": 2, "mutation": 1, "build": 1},
                duplicate_calls=1,
                build_attempts=1,
                sessions_attempts=1,
                provider_retries=0,
                input_tokens=None if backend.selector == "openai-b" else 100,
                output_tokens=None if backend.selector == "openai-b" else 20,
            ),
            {"transcript": str(transcript), "result": str(result)},
            "accepted",
        )


def _run(tmp_path, *, mode=RunMode.CROSSOVER, cases=None, backends=None, trials=1):
    cases = _cases() if cases is None else cases
    backends = _backends() if backends is None else backends
    campaign = _campaign(mode, cases=cases, backends=backends, trials=trials)
    environment = FakeEnvironment()
    runner = CampaignRunner(
        campaign, cases, backends, tmp_path / "campaign",
        environment.snapshot, environment.baseline, environment.backend)
    return runner.run(), environment, runner


def test_clean_full_crossover_runs_every_backend_on_fresh_identical_snapshots(tmp_path):
    results, environment, _ = _run(tmp_path)

    assert len(environment.backend_calls) == 4
    assert {(case, backend) for case, backend, _, _ in environment.backend_calls} == {
        ("CVE-1", "openai-a"), ("CVE-1", "openai-b"),
        ("CVE-2", "openai-a"), ("CVE-2", "openai-b"),
    }
    worktrees = [call[2] for call in environment.backend_calls]
    assert len(worktrees) == len(set(worktrees))
    by_case = {}
    for row in results.rows:
        by_case.setdefault(row.manifest.case.cve_id, set()).add(
            row.manifest.snapshot.snapshot_digest)
    assert all(len(digests) == 1 for digests in by_case.values())
    report = build_comparison_report(results, strict=True)
    assert report.valid
    assert report.summary["metadata_denominator"] == 3
    assert report.summary["testable_case_denominator"] == 2
    assert report.summary["backend_execution_denominator"] == 4
    assert report.summary["security_accepted"] == 4


def test_baseline_health_only_never_invokes_a_backend(tmp_path):
    results, environment, _ = _run(
        tmp_path, mode=RunMode.BASELINE_HEALTH_ONLY, backends=[])

    assert environment.backend_calls == []
    assert len(results.rows) == 3
    assert {row.baseline_status for row in results.rows} == {
        BaselineStatus.HEALTHY, BaselineStatus.BUILD_BROKEN}
    assert all(row.manifest.backend is None for row in results.rows)
    assert {status.value for status in BaselineStatus} == {
        "BASELINE_HEALTHY",
        "BASELINE_BUILD_BROKEN",
        "BASELINE_PTEST_BROKEN",
        "BASELINE_SETUP_BROKEN",
        "BACKEND_NOT_EVALUATED",
    }


def test_crossover_never_copies_success_rows_between_backends(tmp_path):
    results, environment, _ = _run(tmp_path)

    healthy = [row for row in results.rows if row.baseline_status.testable]
    assert len(healthy) == len(environment.backend_calls) == 4
    assert all(row.manifest.attempt_order > 0 for row in healthy)
    assert len({row.manifest.snapshot.worktree_identity for row in healthy}) == 4


def test_single_backend_full_runs_complete_testable_cohort(tmp_path):
    results, environment, _ = _run(
        tmp_path, mode=RunMode.SINGLE_BACKEND_FULL,
        backends=_backends()[:1])

    assert [(case, backend) for case, backend, _, _ in environment.backend_calls] == [
        ("CVE-1", "openai-a"), ("CVE-2", "openai-a")]
    report = build_comparison_report(results, strict=True)
    primary = report.summary["primary_by_backend"]["openai-a"]
    assert primary["testable_case_denominator"] == 2
    assert primary["numerator"] == 2


def test_resume_requires_immutable_campaign_and_does_not_rerun_completed_backends(tmp_path):
    results, environment, runner = _run(tmp_path)
    calls = len(environment.backend_calls)

    resumed = runner.run(results)

    assert resumed.rows == results.rows
    assert len(environment.backend_calls) == calls
    changed = replace(runner.campaign, campaign_id="different")
    changed_runner = CampaignRunner(
        changed, runner.cases, runner.backends, tmp_path / "changed",
        environment.snapshot, environment.baseline, environment.backend)
    with pytest.raises(EvaluationError, match="campaign ID"):
        changed_runner.run(results)
    with pytest.raises(EvaluationError, match="runner cases"):
        CampaignRunner(
            runner.campaign, runner.cases[:1], runner.backends,
            tmp_path / "wrong-cohort", environment.snapshot,
            environment.baseline, environment.backend)


def test_snapshot_mismatch_is_rejected_before_backend_execution(tmp_path):
    cases = _cases()[:1]
    backends = _backends()
    campaign = _campaign(cases=cases, backends=backends)
    environment = FakeEnvironment()

    def mismatched(case, phase, trial, artifact_dir):
        snapshot = environment.snapshot(case, phase, trial, artifact_dir)
        return replace(snapshot, snapshot_digest="wrong")

    runner = CampaignRunner(
        campaign, cases, backends, tmp_path / "mismatch", mismatched,
        environment.baseline, environment.backend)
    with pytest.raises(EvaluationError, match="snapshot mismatch"):
        runner.run()
    assert environment.backend_calls == []


def test_baseline_failure_is_coverage_gap_not_backend_denominator(tmp_path):
    results, _, _ = _run(tmp_path)
    broken = [row for row in results.rows if row.manifest.case.cve_id == "CVE-3"]
    assert len(broken) == 2
    assert all(row.baseline_status is BaselineStatus.BUILD_BROKEN for row in broken)
    assert all(row.outcome is None for row in broken)

    summary = build_comparison_report(results).summary
    assert summary["baseline_excluded_count"] == 1
    assert summary["coverage_gap"] == 1
    assert summary["baseline_status_counts"] == {"BASELINE_BUILD_BROKEN": 1}
    assert summary["baseline_recipe_clusters"] == {
        "BASELINE_BUILD_BROKEN": {"broken": 1}}
    assert summary["backend_execution_denominator"] == 4


def test_decomposed_metrics_counters_and_null_tokens_aggregate(tmp_path):
    results, _, _ = _run(tmp_path)
    summary = build_comparison_report(
        results, input_price_per_million=1, output_price_per_million=2).summary
    totals = summary["metric_totals"]

    assert totals["durations_seconds"]["baseline_build"] == 8
    assert totals["durations_seconds"]["provider_wait"] == 16
    assert totals["model_turns"] == 16
    assert totals["tool_calls_by_class"] == {"build": 4, "mutation": 4, "read": 8}
    assert totals["duplicate_calls"] == 4
    assert totals["build_attempts"] == 4
    assert totals["sessions_attempts"] == 4
    assert totals["input_tokens"] is None
    assert summary["cost_per_security_accepted_fix"] is None
    assert "token usage unavailable" in summary["cost_limitation"]
    assert summary["provider_wait_seconds"] == {"median": 4.0, "p90": 5, "p95": 5}


def test_trusted_telemetry_adapter_preserves_unknowns_and_tool_classes(tmp_path):
    path = tmp_path / "telemetry.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "durations_seconds": {
            "provider_wait": 4.5,
            "tool_execution": 2,
            "semantic_validation": None,
            "total": 9,
        },
        "counters": {
            "model_turns": 3,
            "tool_calls": 6,
            "read_calls": 2,
            "mutation_calls": 1,
            "git_inspection_calls": 1,
            "build_calls": 1,
            "finish_calls": 1,
            "other_tool_calls": 0,
            "duplicate_call_count": 1,
            "sessions_attempts": 2,
            "provider_retries": 1,
        },
        "input_tokens": None,
        "output_tokens": None,
    }), encoding="utf-8")

    metrics = EvaluationMetrics.from_artifact(path)

    assert metrics.durations["provider_wait"] == 4.5
    assert metrics.durations["semantic_validation"] is None
    assert metrics.tool_calls_by_class == {
        "read": 2, "mutation": 1, "git_inspection": 1,
        "build": 1, "finish": 1,
    }
    assert metrics.tool_calls == 6
    assert metrics.sessions_attempts == 2
    assert metrics.input_tokens is None


def test_security_status_drives_configurable_primary_metric(tmp_path):
    results, _, _ = _run(tmp_path)
    first = next(row for row in results.rows if row.outcome is not None)
    unverified_outcome = ResultOutcome(
        WorkflowStatus.COMPLETED, BuildStatus.PASSED,
        SecurityStatus.NOT_EVALUATED, legacy_status="AGENT_RESOLVED")
    rows = tuple(
        replace(row, outcome=unverified_outcome) if row.key == first.key else row
        for row in results.rows)
    modified = CampaignResults(results.campaign, rows)

    security = build_comparison_report(modified)
    workflow = build_comparison_report(
        modified, primary_metric=PrimaryMetric.WORKFLOW_COMPLETED)
    assert security.summary["security_accepted"] == 3
    assert security.summary["primary_numerator"] == 3
    assert workflow.summary["primary_numerator"] == 4
    assert not security.valid
    assert any("semantic validation unavailable" in item for item in security.errors)


def test_fallback_policy_campaign_is_distinct_from_standalone_model(tmp_path):
    variant = replace(_backends()[0], fallback_policy=True)
    results, environment, _ = _run(
        tmp_path, mode=RunMode.FALLBACK_POLICY,
        cases=_cases()[:1], backends=[variant])
    report = build_comparison_report(results)

    assert len(environment.backend_calls) == 1
    assert report.campaign.mode is RunMode.FALLBACK_POLICY
    assert report.summary["fallback_policy_run"] is True
    with pytest.raises(EvaluationError, match="cascade"):
        CampaignRunner(
            _campaign(
                RunMode.FALLBACK_POLICY, cases=_cases()[:1],
                backends=[_backends()[0]]),
            _cases()[:1], [_backends()[0],], tmp_path / "invalid",
            environment.snapshot, environment.baseline, environment.backend)


def test_stability_subset_records_repeated_trials_and_variance(tmp_path):
    case = _cases()[:1]
    backend = _backends()[:1]
    results, environment, _ = _run(
        tmp_path, mode=RunMode.STABILITY_SUBSET,
        cases=case, backends=backend, trials=3)
    report = build_comparison_report(results)

    assert len(environment.backend_calls) == 3
    stability = report.summary["stability"]["CVE-1/openai-a"]
    assert stability["trials"] == 3
    assert stability["accepted_trials"] == 3
    assert stability["acceptance_stability"] == 1
    assert any("lacks strata" in warning for warning in report.warnings)
    assert set(REQUIRED_STABILITY_STRATA) - {"clean_backport"}


def test_invalid_comparison_guards_incomplete_cohort_artifacts_and_config(tmp_path):
    results, _, _ = _run(tmp_path)
    rows = list(results.rows)
    rows.pop(next(
        index for index, row in enumerate(rows)
        if row.manifest.case.cve_id == "CVE-2"
        and row.manifest.backend is not None
        and row.manifest.backend.selector == "openai-b"))
    first = next(row for row in rows if row.outcome is not None)
    bad_backend = replace(first.manifest.backend, resolved_config_digest="changed")
    bad_manifest = replace(first.manifest, backend=bad_backend)
    rows[rows.index(first)] = replace(
        first, manifest=bad_manifest,
        artifacts={"manifest": "/missing", "transcript": "/missing", "result": "/missing"})
    report = build_comparison_report(
        CampaignResults(results.campaign, tuple(rows)))

    assert not report.valid
    assert any("full testable cohort" in error for error in report.errors)
    assert any("configuration versions" in error for error in report.errors)
    assert any("artifact paths unavailable" in error for error in report.errors)
    with pytest.raises(EvaluationError, match="invalid comparison"):
        build_comparison_report(
            CampaignResults(results.campaign, tuple(rows)), strict=True)


def test_artifacts_manifests_and_reports_are_retained_and_deterministic(tmp_path):
    results, _, _ = _run(tmp_path)
    report = build_comparison_report(results)
    first = tmp_path / "reports-a"
    second = tmp_path / "reports-b"

    write_reports(report, first)
    write_reports(report, second)

    for name in ("evaluation.json", "evaluation.csv", "evaluation.md"):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    payload = json.loads((first / "evaluation.json").read_text())
    keys = [(row["manifest"]["cve_id"], row["manifest"]["profile"])
            for row in payload["rows"]]
    assert keys == sorted(keys, key=lambda item: (item[0], item[1] or ""))
    for row in results.rows:
        if row.outcome is not None:
            assert set(row.artifacts) >= {"manifest", "transcript", "result"}
            assert all(Path(row.artifacts[name]).is_file()
                       for name in ("manifest", "transcript", "result"))


def test_legacy_csv_import_is_explicitly_unverified_and_never_model_success():
    backend = _backends()[0]
    campaign = _campaign(
        RunMode.RESUME_COMPATIBLE_LEGACY, cases=[], backends=[backend])
    source = io.StringIO(
        "cve_id,recipe,status,exit_code,duration_s\n"
        "CVE-OLD,old,AGENT_RESOLVED,0,12\n")

    results = import_legacy_csv(source, campaign, backend)
    report = build_comparison_report(results)

    assert results.rows[0].legacy_unverified is True
    assert results.rows[0].security_accepted is False
    assert results.rows[0].outcome.security_status is SecurityStatus.PLAUSIBLE_NEEDS_REVIEW
    assert not report.valid
    assert any("legacy CSV" in error for error in report.errors)


def test_repository_state_records_head_and_content_free_dirty_digest(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.name", "Evaluation Test"],
        cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "evaluation@example.com"],
        cwd=repository, check=True)
    tracked = repository / "tracked"
    tracked.write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked"], cwd=repository, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "baseline"],
                   cwd=repository, check=True)

    head, clean = repository_state(repository)
    tracked.write_text("secret source content\n", encoding="utf-8")
    dirty_head, dirty = repository_state(repository)

    assert dirty_head == head
    assert clean.startswith("clean:")
    assert dirty.startswith("dirty:")
    assert clean != dirty
    assert "secret source content" not in dirty

    untracked = repository / "untracked"
    untracked.write_text("first secret value\n", encoding="utf-8")
    _, first_untracked = repository_state(repository)
    untracked.write_text("second secret value\n", encoding="utf-8")
    _, second_untracked = repository_state(repository)
    assert first_untracked != second_untracked
    assert "second secret value" not in second_untracked


def test_repository_state_rejects_oversized_git_output_before_accumulating_it(
    tmp_path,
):
    repository = tmp_path / "oversized"
    repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.name", "Evaluation Test"],
        cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "evaluation@example.com"],
        cwd=repository, check=True)
    target = repository / "large"
    target.write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "large"], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "baseline"], cwd=repository, check=True)
    target.write_bytes(b"x" * (2 * 1024 * 1024))

    with pytest.raises(EvaluationError, match="output limit"):
        repository_state(repository)


def test_repository_state_hashes_untracked_symlink_without_following_it(tmp_path):
    repository = tmp_path / "special"
    repository.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.name", "Evaluation Test"],
        cwd=repository, check=True)
    subprocess.run(
        ["git", "config", "user.email", "evaluation@example.com"],
        cwd=repository, check=True)
    target = repository / "tracked"
    target.write_text("baseline\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked"], cwd=repository, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "baseline"], cwd=repository, check=True)
    link = repository / "untracked-link"
    os.symlink("first-target", link)
    _, first = repository_state(repository)
    link.unlink()
    os.symlink("second-target", link)
    _, second = repository_state(repository)

    assert first != second
    assert "second-target" not in second
