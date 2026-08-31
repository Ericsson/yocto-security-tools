# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for backend selection in the legacy bulk integration runner."""
from __future__ import annotations

import csv
import json
import os
import subprocess
from pathlib import Path

import pytest

_BULK_RUNNER = Path(__file__).resolve().parent / "test_cve_corrector.sh"


def _runner_environment(tmp_path: Path) -> dict[str, str]:
    oe_dir = tmp_path / "openembedded-core"
    build_dir = tmp_path / "build"
    mirror_dir = tmp_path / "git-mirrors"
    oe_dir.mkdir(exist_ok=True)
    build_dir.mkdir(exist_ok=True)
    mirror_dir.mkdir(exist_ok=True)
    return {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "OE_DIR": str(oe_dir),
        "BUILD_DIR": str(build_dir),
        "MIRROR_DIR": str(mirror_dir),
    }


def _agent_flags(
    tmp_path: Path,
    *,
    backend: str | None = None,
    model: str | None = None,
    extra_flags: str = "",
) -> list[str]:
    environment = _runner_environment(tmp_path)
    if backend is not None:
        environment["AGENT_BACKEND"] = backend
    if model is not None:
        environment["AGENT_MODEL"] = model
    script = (
        f'. "{_BULK_RUNNER}"; '
        'flags=(); build_agent_flags flags "$1"; '
        'printf "%s\\0" "${flags[@]}"'
    )
    result = subprocess.run(
        ["bash", "-c", script, "bulk-runner-test", extra_flags],
        env=environment,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return [item.decode() for item in result.stdout.split(b"\0") if item]


def test_bulk_runner_defaults_to_kiro_backend(tmp_path):
    assert _agent_flags(tmp_path) == ["--backend", "kiro"]


@pytest.mark.parametrize("backend", ["claude", "openai-qwen3.8-l40s"])
def test_bulk_runner_forwards_named_backend(tmp_path, backend):
    assert _agent_flags(tmp_path, backend=backend) == ["--backend", backend]


def test_bulk_runner_forwards_model_and_corrector_flags(tmp_path):
    assert _agent_flags(
        tmp_path,
        backend="openai-local",
        model="local-model",
        extra_flags="--skip-build --skip-ptest",
    ) == [
        "--backend",
        "openai-local",
        "--model",
        "local-model",
        "--skip-build",
        "--skip-ptest",
    ]


def test_bulk_runner_classifies_durable_security_review_without_agent_success(
    tmp_path,
):
    result_json = tmp_path / "result.json"
    result_json.write_text(
        json.dumps({
            "schema_version": 2,
            "workflow_status": "completed",
            "build_status": "passed",
            "security_status": "plausible_needs_review",
            "failure_class": "semantic_validation",
            "failure_code": "structural_adaptation_requires_review",
            "legacy_status": "conflict_resolved",
        }),
        encoding="utf-8",
    )
    log_dir = tmp_path / "results"
    script = f'''
        . "{_BULK_RUNNER}"
        RESULT_JSON="$1"
        LOG_DIR="$2"
        mkdir -p "$LOG_DIR"
        test_single_cve() {{
            CVE_CORRECTOR_RESULT="1:agent:1:2:$RESULT_JSON"
        }}
        reset_oe_tree() {{ :; }}
        run_loop full "" "CVE-2024-39689:python3-certifi" ""
    '''

    completed = subprocess.run(
        ["bash", "-c", script, "bulk-runner-test", str(result_json), str(log_dir)],
        env=_runner_environment(tmp_path),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    with (log_dir / "results_full.csv").open(newline="", encoding="utf-8") as source:
        row = next(csv.DictReader(source))
    assert row["status"] == "SECURITY_REVIEW_REQUIRED"
    assert row["exit_code"] == "SECURITY_REVIEW_REQUIRED"
    assert row["workflow_status"] == "completed"
    assert row["build_status"] == "passed"
    assert row["security_status"] == "plausible_needs_review"
    summary = (log_dir / "summary_full.txt").read_text(encoding="utf-8")
    assert "Success:        0" in summary
    assert "Review needed:  1" in summary
    assert "Failed:         0" in summary


def test_bulk_runner_replaces_agent_reference_copy_with_actual_candidate(tmp_path):
    log_dir = tmp_path / "results"
    artifacts = tmp_path / "artifacts"
    log_dir.mkdir()
    artifacts.mkdir()
    reference = log_dir / "full_agent_CVE-2024-39689_reference.patch"
    reference.write_text("reference patch\n", encoding="utf-8")
    (artifacts / "final.patch").write_text("model candidate\n", encoding="utf-8")
    script = f'''
        . "{_BULK_RUNNER}"
        LOG_DIR="$1"
        remove_agent_reference_copies CVE-2024-39689 full
        copy_agent_candidate "$2" CVE-2024-39689 full
    '''

    completed = subprocess.run(
        ["bash", "-c", script, "bulk-runner-test", str(log_dir), str(artifacts)],
        env=_runner_environment(tmp_path),
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not reference.exists()
    candidate = log_dir / "full_agent_CVE-2024-39689_candidate.patch"
    assert candidate.read_text(encoding="utf-8") == "model candidate\n"
