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
_CAMPAIGN_WRAPPER = Path(__file__).resolve().parent / "run_qwen_campaign.sh"


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
    agent_extra_flags: str | None = None,
) -> list[str]:
    environment = _runner_environment(tmp_path)
    if backend is not None:
        environment["AGENT_BACKEND"] = backend
    if model is not None:
        environment["AGENT_MODEL"] = model
    if agent_extra_flags is not None:
        environment["AGENT_EXTRA_FLAGS"] = agent_extra_flags
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


def test_bulk_runner_forwards_agent_extra_flags_before_corrector_flags(tmp_path):
    """AGENT_EXTRA_FLAGS reaches cve_agent, e.g. a longer per-attempt timeout."""
    assert _agent_flags(
        tmp_path,
        backend="openai-local",
        extra_flags="--skip-build",
        agent_extra_flags="--session-timeout 1800 --max-retries 4",
    ) == [
        "--backend",
        "openai-local",
        "--session-timeout",
        "1800",
        "--max-retries",
        "4",
        "--skip-build",
    ]


def test_bulk_runner_ignores_blank_agent_extra_flags(tmp_path):
    assert _agent_flags(tmp_path, agent_extra_flags="  ") == ["--backend", "kiro"]


@pytest.mark.parametrize(("override", "expected"), [(None, "3600"), ("7200", "7200")])
def test_bulk_runner_test_timeout_is_overridable(tmp_path, override, expected):
    environment = _runner_environment(tmp_path)
    if override is not None:
        environment["TEST_TIMEOUT"] = override
    result = subprocess.run(
        ["bash", "-c", f'. "{_BULK_RUNNER}"; printf "%s" "$TEST_TIMEOUT"'],
        env=environment, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.stdout.decode() == expected


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


def _run_campaign_wrapper(tmp_path: Path, overrides: dict[str, str], *args: str) -> dict:
    """Run the wrapper beside a stub runner that reports what it received."""
    stub_dir = tmp_path / "campaign"
    stub_dir.mkdir()
    wrapper = stub_dir / _CAMPAIGN_WRAPPER.name
    wrapper.write_bytes(_CAMPAIGN_WRAPPER.read_bytes())
    wrapper.chmod(0o755)
    stub = stub_dir / _BULK_RUNNER.name
    stub.write_text(
        "#!/bin/bash\n"
        'printf \'{"backend":"%s","flags":"%s","timeout":"%s","args":"%s"}\' '
        '"$AGENT_BACKEND" "$AGENT_EXTRA_FLAGS" "$TEST_TIMEOUT" "$*"\n',
        encoding="utf-8")
    stub.chmod(0o755)
    environment = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), **overrides}
    result = subprocess.run(
        [str(wrapper), *args], env=environment, capture_output=True, check=False)
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    return json.loads(result.stdout)


def test_campaign_wrapper_supplies_the_qwen_settings_and_forwards_arguments(tmp_path):
    seen = _run_campaign_wrapper(tmp_path, {}, "--full-only", "--resume", "dir")
    assert seen == {
        "backend": "openai-qwen3.8-plain-32k-medium",
        "flags": "--session-timeout 1800",
        "timeout": "7200",
        "args": "--full-only --resume dir",
    }


def test_campaign_wrapper_values_can_be_overridden_or_opted_out(tmp_path):
    seen = _run_campaign_wrapper(
        tmp_path,
        {"AGENT_BACKEND": "kiro", "AGENT_EXTRA_FLAGS": "", "TEST_TIMEOUT": "3600"},
    )
    assert (seen["backend"], seen["flags"], seen["timeout"]) == ("kiro", "", "3600")


def test_campaign_wrapper_run_timeout_exceeds_its_session_timeout(tmp_path):
    seen = _run_campaign_wrapper(tmp_path, {})
    flags = seen["flags"].split()
    assert int(seen["timeout"]) > int(flags[flags.index("--session-timeout") + 1])
