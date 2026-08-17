# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Durability, redaction, and lifecycle tests for per-attempt artifacts."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_agent import AgentConfig, CveResult, ResultStatus
from cve_agent.artifacts import (
    ArtifactError,
    RunArtifacts,
    recover_jsonl,
    verify_artifact_manifest,
)
from cve_agent.knowledge import KnowledgeBase
from cve_agent.openai_deadline import SessionDeadline
from cve_agent.openai_loop import JSONLTranscript
from cve_agent.orchestrator import process_single_cve


def _events(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _result() -> CveResult:
    return CveResult("CVE-2026-0001", ResultStatus.SUCCESS)


def test_immediate_preflight_exception_retains_started_transcript_and_result(
        tmp_path, monkeypatch):
    monkeypatch.setenv("CVE_TOOLS_DATA_DIR", str(tmp_path))
    config = AgentConfig(cve_id="CVE-2026-0001")

    with patch(
        "cve_agent.orchestrator._process_single_cve",
        side_effect=RuntimeError("preflight failed"),
    ), pytest.raises(RuntimeError, match="preflight failed"):
        process_single_cve(config, KnowledgeBase())

    attempts = list(
        (tmp_path / "yocto-security-tools" / "results" / "cases"
         / config.cve_id).iterdir())
    assert len(attempts) == 1
    events = _events(attempts[0] / "agent-transcript.jsonl")
    assert [event["event"] for event in events][:2] == [
        "run_started", "configuration_resolved"]
    assert "preflight_failed" in [event["event"] for event in events]
    assert json.loads((attempts[0] / "result.json").read_text())["workflow_status"] == "failed"


def test_artifact_path_is_announced_before_pipeline_runs(
        tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CVE_TOOLS_DATA_DIR", str(tmp_path))
    print("Continue in trust mode? [y/N]: ", end="")

    def finish(*args, **kwargs):
        output = capsys.readouterr().out
        assert any(line.startswith("Artifacts: ") for line in output.splitlines())
        return _result()

    with patch("cve_agent.orchestrator._process_single_cve", side_effect=finish):
        process_single_cve(
            AgentConfig(cve_id="CVE-2026-0001"), KnowledgeBase())


def test_successful_result_survives_workspace_cleanup(tmp_path, monkeypatch):
    monkeypatch.setenv("CVE_TOOLS_DATA_DIR", str(tmp_path))
    workspace = tmp_path / "temporary-workspace"
    workspace.mkdir()

    def finish(*args, **kwargs):
        workspace.rmdir()
        return _result()

    with patch("cve_agent.orchestrator._process_single_cve", side_effect=finish):
        result = process_single_cve(
            AgentConfig(cve_id="CVE-2026-0001"), KnowledgeBase())

    assert not workspace.exists()
    assert result.artifact_dir is not None
    assert (result.artifact_dir / "agent-transcript.jsonl").is_file()
    assert (result.artifact_dir / "result.json").is_file()


def test_unique_attempts_do_not_overwrite(tmp_path):
    first = RunArtifacts.create("CVE-1", "openai", None, "model", root=tmp_path)
    second = RunArtifacts.create("CVE-1", "openai", None, "model", root=tmp_path)
    first.finalize({"status": "first"})
    second.finalize({"status": "second"})

    assert first.path != second.path
    assert json.loads((first.path / "result.json").read_text())["status"] == "first"
    assert json.loads((second.path / "result.json").read_text())["status"] == "second"


def test_directory_and_sensitive_file_permissions(tmp_path):
    run = RunArtifacts.create("CVE-1", "openai", None, "model", root=tmp_path)
    run.finalize({"status": "done"})

    assert stat.S_IMODE(run.path.stat().st_mode) == 0o700
    for child in run.path.iterdir():
        assert stat.S_IMODE(child.stat().st_mode) == 0o600


def test_partial_jsonl_tail_is_recovered_but_interior_corruption_is_rejected(tmp_path):
    tail = tmp_path / "tail.jsonl"
    tail.write_bytes(b'{"sequence":1}\n{"partial"')
    assert recover_jsonl(tail) == 1
    assert tail.read_bytes() == b'{"sequence":1}\n'

    interior = tmp_path / "interior.jsonl"
    interior.write_bytes(b'{broken}\n{"sequence":2}\n')
    with pytest.raises(ArtifactError, match="interior corruption"):
        recover_jsonl(interior)


def test_transcript_failure_is_fatal_before_and_after_mutation(tmp_path):
    before = RunArtifacts.create("CVE-1", "openai", None, "model", root=tmp_path)
    before._transcript.close()
    with pytest.raises(ArtifactError, match="transcript write failed"):
        before.event("preflight_started")

    after = RunArtifacts.create("CVE-2", "openai", None, "model", root=tmp_path)
    after.event("mutation_committed", tool="write_file")
    after._transcript.close()
    with pytest.raises(ArtifactError, match="transcript write failed"):
        after.event("build_started")


def test_seeded_secrets_are_absent_from_all_retained_artifacts(tmp_path):
    secret = "sk-test-secret-value-123456"
    run = RunArtifacts.create(
        "CVE-1", "openai", None, "model", root=tmp_path, secrets=(secret,))
    run.event("provider_response_received", body=f"Bearer {secret}")
    run.event("tool_call_completed", output=f"failed with {secret}")
    run.atomic_json("provider-summary.json", {
        "error": f"https://user:{secret}@example.invalid/fail",
    })
    run.atomic_text("semantic-validation.txt", f"evidence {secret}\n")
    run.finalize({"message": f"exception: {secret}"})

    for child in run.path.iterdir():
        if child.is_file():
            assert secret.encode() not in child.read_bytes()


def test_finalize_always_retains_semantic_status_and_human_report(tmp_path):
    run = RunArtifacts.create("CVE-1", "openai", None, "model", root=tmp_path)
    run.finalize({"status": "failed"})
    semantic = json.loads((run.path / "semantic-validation.json").read_text())
    assert semantic["status"] == "not_evaluated"
    assert semantic["reason_code"] == "workflow_did_not_reach_semantic_validation"
    assert "not_evaluated" in (
        run.path / "semantic-validation.txt").read_text(encoding="utf-8")


def test_progress_warnings_increment_duplicate_telemetry(tmp_path):
    run = RunArtifacts.create("CVE-1", "openai", None, "model", root=tmp_path)
    run.event("progress_warning", consecutive=1)
    run.event("progress_warning", consecutive=2)
    run.finalize({"status": "failed"})
    telemetry = json.loads((run.path / "telemetry.json").read_text())
    assert telemetry["counters"]["duplicate_call_count"] == 2


def test_large_values_are_bounded_with_hash(tmp_path):
    run = RunArtifacts.create("CVE-1", "openai", None, "model", root=tmp_path)
    large = "x" * 100_000
    run.event("tool_call_completed", output=large)
    run.finalize({"status": "done"})

    event = next(
        item for item in _events(run.transcript_path)
        if item["event"] == "tool_call_completed")
    output = event["output"]
    assert isinstance(output, dict)
    assert output["bytes"] == 100_000
    assert output["sha256"] == hashlib.sha256(large.encode()).hexdigest()
    assert run.transcript_path.stat().st_size < 20_000


def test_artifact_manifest_verifies_and_detects_modification(tmp_path):
    run = RunArtifacts.create("CVE-1", "openai", None, "model", root=tmp_path)
    run.finalize({"status": "done"})

    assert verify_artifact_manifest(run.path, ("result.json", "telemetry.json"))
    lines = (run.path / "artifact-manifest.sha256").read_text().splitlines()
    for line in lines:
        expected, name = line.split("  ", 1)
        assert hashlib.sha256((run.path / name).read_bytes()).hexdigest() == expected
    (run.path / "result.json").write_text("modified", encoding="utf-8")
    result_line = next(line for line in lines if line.endswith("  result.json"))
    expected, name = result_line.split("  ", 1)
    assert hashlib.sha256((run.path / name).read_bytes()).hexdigest() != expected
    assert not verify_artifact_manifest(run.path, ("result.json", "telemetry.json"))


def test_native_tool_loop_events_are_mirrored_in_exact_order(tmp_path):
    run = RunArtifacts.create("CVE-1", "openai", None, "model", root=tmp_path)
    native_root = tmp_path / "native"
    native_root.mkdir()
    token = run.activate()
    try:
        transcript = JSONLTranscript.create(
            native_root, "model", SessionDeadline.from_timeout(10))
        transcript.write("model_request", turn=1)
        transcript.write("assistant_response", turn=1)
        transcript.write("tool_request", tool_call_id="1", tool="read_file")
        transcript.write(
            "tool_result", tool_call_id="1", tool="read_file",
            success=True, mutated=False)
        transcript.close()
    finally:
        RunArtifacts.deactivate(token)
    run.finalize({"status": "done"})

    kinds = [event["event"] for event in _events(run.transcript_path)]
    assert kinds[2:6] == [
        "provider_request_started",
        "provider_response_received",
        "tool_call_requested",
        "tool_call_completed",
    ]


def test_final_secret_scan_fails_without_echoing_secret(tmp_path):
    secret = "test-secret-that-must-not-be-echoed"
    run = RunArtifacts.create(
        "CVE-1", "openai", None, "model", root=tmp_path, secrets=(secret,))
    leaked = run.path / "hostile-provider.bin"
    descriptor = os.open(leaked, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(secret.encode())

    with pytest.raises(ArtifactError) as caught:
        run.finalize({"status": "done"})
    assert secret not in str(caught.value)
    events = _events(run.transcript_path)
    assert any(
        event.get("error_code") == "artifact_secret_detected" for event in events)
