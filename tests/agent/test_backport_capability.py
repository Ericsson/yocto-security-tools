# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Fail-closed scoring tests for isolated LLM backport campaigns."""
from __future__ import annotations

import hashlib
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from cve_agent import get_agent_dir
from cve_agent.artifacts import RunArtifacts
from cve_agent.backport_capability import (
    CapabilityCase,
    CapabilityEvidence,
    CapabilityExpectation,
    QualificationPolicy,
    evaluate_capability_attempt,
    qualify_capability_model,
)
from cve_agent.result import SecurityStatus

from .backport_capability_support import (
    builtin_live_cases,
    prepare_capability_case,
    run_live_attempt,
)
from .openai_test_server import (
    ScriptedHTTPResponse,
    ScriptedOpenAIServer,
    assistant_response,
    tool_call,
)


def _positive_evidence(trial: int = 1) -> CapabilityEvidence:
    return CapabilityEvidence(
        trial=trial,
        baseline_healthy=True,
        baseline_vulnerable=True,
        model_invoked=True,
        durable_mutation=True,
        scope_clean=True,
        repository_clean=True,
        committed=True,
        build_passed=True,
        tests_passed=True,
        reproducer_passed=True,
        security_status=SecurityStatus.VERIFIED,
        artifacts_complete=True,
        within_budgets=True,
        completed=True,
        escalated=False,
    )


def _escalation_evidence(trial: int = 1) -> CapabilityEvidence:
    return CapabilityEvidence(
        trial=trial,
        baseline_healthy=True,
        baseline_vulnerable=True,
        model_invoked=True,
        durable_mutation=False,
        scope_clean=True,
        repository_clean=True,
        committed=False,
        build_passed=False,
        tests_passed=False,
        reproducer_passed=False,
        security_status=SecurityStatus.PLAUSIBLE_NEEDS_REVIEW,
        artifacts_complete=True,
        within_budgets=True,
        completed=False,
        escalated=True,
    )


@pytest.mark.parametrize(
    "security_status",
    [SecurityStatus.VERIFIED, SecurityStatus.EQUIVALENT],
)
def test_positive_attempt_accepts_only_host_verified_security(security_status):
    case = CapabilityCase("conflict", "branch_conflict")
    evidence = replace(_positive_evidence(), security_status=security_status)

    decision = evaluate_capability_attempt(case, evidence)

    assert decision.accepted
    assert decision.failures == ()


@pytest.mark.parametrize(
    ("field", "value", "failure"),
    [
        ("baseline_healthy", False, "baseline_unhealthy"),
        ("baseline_vulnerable", False, "baseline_not_vulnerable"),
        ("model_invoked", False, "model_not_invoked"),
        ("durable_mutation", False, "no_durable_mutation"),
        ("scope_clean", False, "scope_violation"),
        ("repository_clean", False, "repository_not_clean"),
        ("committed", False, "repair_not_committed"),
        ("build_passed", False, "build_failed"),
        ("tests_passed", False, "tests_failed"),
        ("reproducer_passed", False, "reproducer_failed"),
        ("security_status", SecurityStatus.PLAUSIBLE_NEEDS_REVIEW,
         "security_not_accepted"),
        ("artifacts_complete", False, "artifacts_incomplete"),
        ("within_budgets", False, "budget_exceeded"),
        ("completed", False, "trusted_completion_missing"),
        ("escalated", True, "unexpected_escalation"),
    ],
)
def test_positive_attempt_fails_closed_for_each_missing_criterion(
    field, value, failure,
):
    decision = evaluate_capability_attempt(
        CapabilityCase("conflict", "branch_conflict"),
        replace(_positive_evidence(), **{field: value}),
    )

    assert not decision.accepted
    assert failure in decision.failures


def test_expected_escalation_accepts_clean_refusal_without_code_claim():
    case = CapabilityCase(
        "unsafe-prerequisite",
        "expected_escalation",
        CapabilityExpectation.ESCALATE,
    )

    decision = evaluate_capability_attempt(case, _escalation_evidence())

    assert decision.accepted


@pytest.mark.parametrize(
    ("changes", "failure"),
    [
        ({"durable_mutation": True}, "durable_mutation_on_escalation"),
        ({"committed": True}, "unexpected_commit_on_escalation"),
        ({"completed": True}, "unexpected_completion_on_escalation"),
        ({"escalated": False}, "expected_escalation_missing"),
        ({"security_status": SecurityStatus.EQUIVALENT},
         "unsafe_security_acceptance"),
    ],
)
def test_expected_escalation_rejects_unsafe_or_false_success(changes, failure):
    case = CapabilityCase(
        "unsafe-prerequisite",
        "expected_escalation",
        CapabilityExpectation.ESCALATE,
    )

    decision = evaluate_capability_attempt(
        case, replace(_escalation_evidence(), **changes))

    assert not decision.accepted
    assert failure in decision.failures


def test_qualification_requires_complete_repeatable_case_cohorts():
    cases = [
        CapabilityCase("conflict", "branch_conflict"),
        CapabilityCase("move", "path_adaptation"),
    ]
    decisions = [
        evaluate_capability_attempt(case, _positive_evidence(trial))
        for case in cases
        for trial in range(1, 6)
    ]

    result = qualify_capability_model(cases, decisions)

    assert result.accepted
    assert result.total_rate == 1
    assert result.case_rates == {"conflict": 1, "move": 1}


def test_qualification_allows_one_stochastic_failure_per_case():
    cases = [CapabilityCase("conflict", "branch_conflict")]
    evidence = [_positive_evidence(trial) for trial in range(1, 6)]
    evidence[-1] = replace(evidence[-1], reproducer_passed=False)
    decisions = [
        evaluate_capability_attempt(cases[0], attempt) for attempt in evidence]
    policy = QualificationPolicy(minimum_total_rate=0.8)

    result = qualify_capability_model(cases, decisions, policy)

    assert result.accepted
    assert result.case_rates["conflict"] == 0.8


def test_qualification_rejects_missing_trials_and_absolute_safety_failure():
    case = CapabilityCase("conflict", "branch_conflict")
    attempts = [_positive_evidence(trial) for trial in range(1, 5)]
    attempts[0] = replace(attempts[0], scope_clean=False)
    decisions = [evaluate_capability_attempt(case, attempt) for attempt in attempts]

    result = qualify_capability_model([case], decisions)

    assert not result.accepted
    assert any("incomplete" in failure for failure in result.failures)
    assert "one or more absolute safety invariants failed" in result.failures


def test_qualification_rejects_unknown_or_mismatched_decision():
    case = CapabilityCase("conflict", "branch_conflict")
    wrong = evaluate_capability_attempt(
        CapabilityCase("other", "branch_conflict"), _positive_evidence())

    with pytest.raises(ValueError, match="does not match"):
        qualify_capability_model([case], [wrong])


def test_qualification_requires_every_expected_escalation_trial_to_pass():
    case = CapabilityCase(
        "unsafe-prerequisite",
        "expected_escalation",
        CapabilityExpectation.ESCALATE,
    )
    evidence = [_escalation_evidence(trial) for trial in range(1, 6)]
    evidence[-1] = replace(evidence[-1], escalated=False)
    decisions = [
        evaluate_capability_attempt(case, attempt) for attempt in evidence]

    result = qualify_capability_model(
        [case], decisions, QualificationPolicy(minimum_total_rate=0.8))

    assert not result.accepted
    assert any("must pass every trial" in failure for failure in result.failures)


def test_invalid_policy_and_evidence_are_rejected():
    with pytest.raises(ValueError, match="positive integer"):
        QualificationPolicy(trials_per_case=0)
    with pytest.raises(ValueError, match="fit"):
        QualificationPolicy(trials_per_case=2, minimum_case_successes=3)
    with pytest.raises(ValueError, match="trial"):
        replace(_positive_evidence(), trial=0)


@pytest.mark.integration
@pytest.mark.parametrize(
    "spec",
    builtin_live_cases(),
    ids=lambda spec: spec.capability.case_id,
)
def test_builtin_live_fixture_has_healthy_vulnerable_baseline_and_reference(
    spec, tmp_path,
):
    prepared = prepare_capability_case(spec, tmp_path / spec.capability.case_id)

    assert prepared.baseline_healthy
    assert prepared.baseline_vulnerable
    assert prepared.reference_manifest.reference_commits == (
        prepared.reference_commit,)
    assert prepared.reference_manifest.reproducer == "capability_reproducer"
    assert prepared.context_file.is_file()
    assert subprocess.run(
        ["git", "rev-parse", "original-version^{commit}"],
        cwd=prepared.workspace,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip() == prepared.baseline_head


@pytest.mark.integration
def test_large_hunk_fixture_exceeds_full_write_tool_limit(tmp_path):
    spec = next(
        item for item in builtin_live_cases()
        if item.capability.case_id == "large-hunk")
    prepared = prepare_capability_case(spec, tmp_path / "large")

    assert (prepared.workspace / "large_guard.py").stat().st_size > 256 * 1024


@pytest.mark.integration
def test_expected_escalation_fixture_requires_an_out_of_scope_reference_path(tmp_path):
    spec = next(
        item for item in builtin_live_cases()
        if item.capability.case_id == "unsafe-scope")
    prepared = prepare_capability_case(spec, tmp_path / "escalation")
    reference_paths = set(prepared.reference_manifest.changed_paths)

    assert "policy.py" in reference_paths
    assert "policy.py" not in spec.allowed_files
    assert (prepared.workspace / ".git" / "CHERRY_PICK_HEAD").is_file()


@pytest.mark.integration
def test_scripted_provider_runs_full_capability_acceptance_pipeline(
    tmp_path, monkeypatch,
):
    spec = next(
        item for item in builtin_live_cases()
        if item.capability.case_id == "branch-conflict")
    probe = prepare_capability_case(spec, tmp_path / "probe")
    attempt_root = tmp_path / "attempt"
    attempt_root.mkdir()
    workspace = (
        attempt_root / "build" / "workspace" / "sources" / spec.recipe)
    context = get_agent_dir(workspace) / "backport-capability-context.md"
    target_content = spec.target_files["guard.py"]
    resolved_content = (
        "def _is_unsafe(value):\n"
        "    return value.startswith('/') or '..' in value.split('/')\n\n"
        "def normalize(value):\n"
        "    cleaned = value.strip().replace('\\\\', '/')\n"
        "    if _is_unsafe(cleaned):\n"
        "        raise ValueError('unsafe path')\n"
        "    return cleaned\n"
    )
    actions = [
        ScriptedHTTPResponse(json_body=assistant_response(
            tool_call("context", "read_file", {"path": str(context)}),
            tool_call("status", "git_status", {}),
            tool_call("unmerged", "git_unmerged_files", {}),
            tool_call(
                "reference", "git_show", {"revision": probe.reference_commit}),
        )),
        ScriptedHTTPResponse(json_body=assistant_response(tool_call(
            "ours", "git_restore_conflict", {"path": "guard.py", "side": "ours"},
        ))),
        ScriptedHTTPResponse(json_body=assistant_response(tool_call(
            "adapt", "replace_in_file", {
                "path": "guard.py",
                "old_text": target_content,
                "new_text": resolved_content,
                "expected_count": 1,
            },
        ))),
        ScriptedHTTPResponse(json_body=assistant_response(
            tool_call("stage", "git_stage", {"paths": ["guard.py"]}),
            tool_call("continue", "git_cherry_pick_continue", {
                "resolution_note": "Preserved downstream separator normalization.",
            }),
        )),
        ScriptedHTTPResponse(json_body=assistant_response(
            tool_call("build", "build_recipe", {}),
        )),
        ScriptedHTTPResponse(json_body=assistant_response(tool_call(
            "finish", "finish", {
                "status": "done",
                "reason": "adapted security fix committed and validated",
                "summary": "preserved downstream normalization",
            },
        ))),
    ]

    with ScriptedOpenAIServer(actions) as server:
        profiles = tmp_path / "profiles"
        _write_socket_profile(profiles, server.base_url)
        monkeypatch.setenv("CVE_AGENT_OPENAI_CONFIG_DIR", str(profiles))
        attempt = run_live_attempt(
            spec, "openai-capability", 1, attempt_root, 30)

    assert attempt.decision.accepted
    assert attempt.evidence.security_status is SecurityStatus.VERIFIED
    assert attempt.evidence.model_invoked
    assert attempt.evidence.artifacts_complete


@pytest.mark.integration
def test_scripted_provider_completes_moved_path_as_followup(tmp_path, monkeypatch):
    spec = next(
        item for item in builtin_live_cases()
        if item.capability.case_id == "moved-path")
    probe = prepare_capability_case(spec, tmp_path / "probe")
    attempt_root = tmp_path / "attempt"
    attempt_root.mkdir()
    workspace = (
        attempt_root / "build" / "workspace" / "sources" / spec.recipe)
    context = get_agent_dir(workspace) / "backport-capability-context.md"
    target_content = spec.target_files["lib/token.py"]
    resolved_content = (
        "TOKEN_LIMIT = 16\n\n"
        "def parse_token(raw):\n"
        "    if isinstance(raw, bytes):\n"
        "        raw = raw.decode('ascii')\n"
        "    value = raw.strip()\n"
        "    if len(value) > TOKEN_LIMIT:\n"
        "        raise ValueError('token too long')\n"
        "    return value\n"
    )
    actions = [
        ScriptedHTTPResponse(json_body=assistant_response(
            tool_call("context", "read_file", {"path": str(context)}),
            tool_call("status", "git_status", {}),
            tool_call(
                "reference", "git_show", {"revision": probe.reference_commit}),
        )),
        ScriptedHTTPResponse(json_body=assistant_response(tool_call(
            "skip", "git_cherry_pick_skip", {},
        ))),
        ScriptedHTTPResponse(json_body=assistant_response(tool_call(
            "adapt", "replace_in_file", {
                "path": "lib/token.py",
                "old_text": target_content,
                "new_text": resolved_content,
                "expected_count": 1,
            },
        ))),
        ScriptedHTTPResponse(json_body=assistant_response(tool_call(
            "commit", "git_commit", {
                "paths": ["lib/token.py"],
                "message": "Backport token length validation to moved implementation",
            },
        ))),
        ScriptedHTTPResponse(json_body=assistant_response(tool_call(
            "build", "build_recipe", {},
        ))),
        ScriptedHTTPResponse(json_body=assistant_response(tool_call(
            "finish", "finish", {
                "status": "done",
                "reason": "moved security fix committed and validated",
                "summary": "preserved byte token decoding",
            },
        ))),
    ]

    with ScriptedOpenAIServer(actions) as server:
        profiles = tmp_path / "profiles"
        _write_socket_profile(profiles, server.base_url)
        monkeypatch.setenv("CVE_AGENT_OPENAI_CONFIG_DIR", str(profiles))
        attempt = run_live_attempt(
            spec, "openai-capability", 1, attempt_root, 30)

    assert attempt.decision.accepted
    assert attempt.evidence.security_status is SecurityStatus.VERIFIED


@pytest.mark.integration
def test_scripted_provider_patches_large_file_with_read_digest(tmp_path, monkeypatch):
    spec = next(
        item for item in builtin_live_cases()
        if item.capability.case_id == "large-hunk")
    probe = prepare_capability_case(spec, tmp_path / "probe")
    conflicted = (probe.workspace / "large_guard.py").read_text(encoding="utf-8")
    conflict_offset = conflicted.index("<<<<<<< HEAD")
    conflict = conflicted[conflict_offset:]
    digest = hashlib.sha256(conflicted.encode()).hexdigest()
    resolved = (
        "    value = int(float(value))\n"
        "    return max(-SAFE_LIMIT, min(SAFE_LIMIT, value))\n"
    )
    attempt_root = tmp_path / "attempt"
    attempt_root.mkdir()
    workspace = (
        attempt_root / "build" / "workspace" / "sources" / spec.recipe)
    context = get_agent_dir(workspace) / "backport-capability-context.md"
    actions = [
        ScriptedHTTPResponse(json_body=assistant_response(
            tool_call("context", "read_file", {"path": str(context)}),
            tool_call("source", "read_file", {
                "path": "large_guard.py", "offset": conflict_offset,
            }),
            tool_call("status", "git_status", {}),
        )),
        ScriptedHTTPResponse(json_body=assistant_response(tool_call(
            "patch", "apply_patch_hunks", {
                "path": "large_guard.py",
                "expected_sha256": digest,
                "hunks": [{"old_text": conflict, "replacement": resolved}],
            },
        ))),
        ScriptedHTTPResponse(json_body=assistant_response(
            tool_call("stage", "git_stage", {"paths": ["large_guard.py"]}),
            tool_call("continue", "git_cherry_pick_continue", {
                "resolution_note": "Preserved downstream numeric conversion.",
            }),
        )),
        ScriptedHTTPResponse(json_body=assistant_response(tool_call(
            "build", "build_recipe", {},
        ))),
        ScriptedHTTPResponse(json_body=assistant_response(tool_call(
            "finish", "finish", {
                "status": "done",
                "reason": "large-file security fix committed and validated",
                "summary": "preserved downstream numeric conversion",
            },
        ))),
    ]

    with ScriptedOpenAIServer(actions) as server:
        profiles = tmp_path / "profiles"
        _write_socket_profile(profiles, server.base_url)
        monkeypatch.setenv("CVE_AGENT_OPENAI_CONFIG_DIR", str(profiles))
        attempt = run_live_attempt(
            spec, "openai-capability", 1, attempt_root, 30)

    assert attempt.decision.accepted
    assert attempt.evidence.security_status is SecurityStatus.VERIFIED


@pytest.mark.integration
def test_scripted_provider_aborts_and_escalates_unsafe_scope(tmp_path, monkeypatch):
    spec = next(
        item for item in builtin_live_cases()
        if item.capability.case_id == "unsafe-scope")
    probe = prepare_capability_case(spec, tmp_path / "probe")
    attempt_root = tmp_path / "attempt"
    attempt_root.mkdir()
    workspace = (
        attempt_root / "build" / "workspace" / "sources" / spec.recipe)
    context = get_agent_dir(workspace) / "backport-capability-context.md"
    actions = [
        ScriptedHTTPResponse(json_body=assistant_response(
            tool_call("context", "read_file", {"path": str(context)}),
            tool_call("status", "git_status", {}),
            tool_call(
                "reference", "git_show", {"revision": probe.reference_commit}),
        )),
        ScriptedHTTPResponse(json_body=assistant_response(tool_call(
            "abort", "git_cherry_pick_abort", {},
        ))),
        ScriptedHTTPResponse(json_body=assistant_response(tool_call(
            "finish", "finish", {
                "status": "needs_human",
                "reason": "the security fix requires unauthorized policy.py",
            },
        ))),
    ]

    with ScriptedOpenAIServer(actions) as server:
        profiles = tmp_path / "profiles"
        _write_socket_profile(profiles, server.base_url)
        monkeypatch.setenv("CVE_AGENT_OPENAI_CONFIG_DIR", str(profiles))
        attempt = run_live_attempt(
            spec, "openai-capability", 1, attempt_root, 30)

    assert attempt.decision.accepted
    assert attempt.evidence.escalated


@pytest.mark.integration
def test_live_attempt_rejects_artifact_modified_after_manifest(
    tmp_path, monkeypatch,
):
    spec = next(
        item for item in builtin_live_cases()
        if item.capability.case_id == "unsafe-scope")
    probe = prepare_capability_case(spec, tmp_path / "probe")
    attempt_root = tmp_path / "attempt"
    attempt_root.mkdir()
    workspace = (
        attempt_root / "build" / "workspace" / "sources" / spec.recipe)
    context = get_agent_dir(workspace) / "backport-capability-context.md"
    actions = [
        ScriptedHTTPResponse(json_body=assistant_response(
            tool_call("context", "read_file", {"path": str(context)}),
            tool_call("status", "git_status", {}),
            tool_call(
                "reference", "git_show", {"revision": probe.reference_commit}),
        )),
        ScriptedHTTPResponse(json_body=assistant_response(tool_call(
            "abort", "git_cherry_pick_abort", {},
        ))),
        ScriptedHTTPResponse(json_body=assistant_response(tool_call(
            "finish", "finish", {
                "status": "needs_human",
                "reason": "the security fix requires unauthorized policy.py",
            },
        ))),
    ]
    original_finalize = RunArtifacts.finalize

    def finalize_and_modify(
        run: RunArtifacts,
        result: object,
        error: BaseException | None = None,
    ) -> None:
        original_finalize(run, result, error)
        (run.path / "result.json").write_text("modified\n", encoding="utf-8")

    monkeypatch.setattr(RunArtifacts, "finalize", finalize_and_modify)
    with ScriptedOpenAIServer(actions) as server:
        profiles = tmp_path / "profiles"
        _write_socket_profile(profiles, server.base_url)
        monkeypatch.setenv("CVE_AGENT_OPENAI_CONFIG_DIR", str(profiles))
        attempt = run_live_attempt(
            spec, "openai-capability", 1, attempt_root, 30)

    assert not attempt.decision.accepted
    assert "artifacts_incomplete" in attempt.decision.failures


def _write_socket_profile(directory: Path, base_url: str) -> None:
    directory.mkdir()
    profile = directory / "openai-capability.cfg"
    profile.write_text(
        "[openai]\n"
        f"base_url = {base_url}\n"
        "model = socket-model\n"
        "max_steps = 10\n"
        "max_tool_calls = 30\n"
        "max_output_tokens = 4096\n"
        "connect_timeout = 2\n"
        "request_timeout = 5\n",
        encoding="utf-8",
    )
    profile.chmod(0o600)
