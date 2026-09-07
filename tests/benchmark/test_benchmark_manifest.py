# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Resume-safety tests for immutable benchmark configuration identity."""
import os
import subprocess
from pathlib import Path

RUNNER = Path(__file__).with_name("run_benchmark.sh")


def _environment(tmp_path, **updates):
    environment = {
        **os.environ,
        "OE_DIR": str(tmp_path),
        "BUILD_DIR": str(tmp_path),
        "MIRROR_DIR": str(tmp_path),
        "BBPATH": "benchmark-test",
        "CVE_AGENT_OPENAI_BASE_URL": "http://localhost:11434/v1",
    }
    environment.update(updates)
    return environment


def _dry_resume(results_dir, environment, *arguments):
    results_dir.mkdir(exist_ok=True)
    return subprocess.run(
        [
            str(RUNNER),
            "--resume", str(results_dir),
            "--dry-run",
            "--skip-judge",
            *arguments,
        ],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )


def _assert_mismatch(result, section):
    assert result.returncode != 0
    assert f"configuration mismatch ({section})" in result.stderr


def test_plain_openai_model_change_rejects_resume(tmp_path):
    results = tmp_path / "results"
    first = _dry_resume(
        results,
        _environment(tmp_path, CVE_AGENT_OPENAI_MODEL="agent-model-a"),
        "--backend", "openai",
    )
    assert first.returncode == 0, first.stderr

    second = _dry_resume(
        results,
        _environment(tmp_path, CVE_AGENT_OPENAI_MODEL="agent-model-b"),
        "--backend", "openai",
    )
    _assert_mismatch(second, "agent")


def test_named_profile_change_rejects_resume(tmp_path):
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    profile = profiles / "openai-agent.cfg"
    profile.write_text(
        "[openai]\nmodel = profile-model-a\n", encoding="utf-8")
    profile.chmod(0o600)
    environment = _environment(
        tmp_path, CVE_AGENT_OPENAI_CONFIG_DIR=str(profiles))
    results = tmp_path / "results"

    first = _dry_resume(
        results, environment, "--backend", "openai-agent")
    assert first.returncode == 0, first.stderr

    profile.write_text(
        "[openai]\nmodel = profile-model-b\n", encoding="utf-8")
    second = _dry_resume(
        results, environment, "--backend", "openai-agent")
    _assert_mismatch(second, "agent")


def test_judge_backend_change_rejects_resume(tmp_path):
    environment = _environment(tmp_path)
    results = tmp_path / "results"
    first = _dry_resume(results, environment)
    assert first.returncode == 0, first.stderr

    second = _dry_resume(
        results,
        environment,
        "--judge-backend", "openai",
        "--judge-model", "judge-model",
    )
    _assert_mismatch(second, "judge")


def test_judge_model_change_rejects_resume(tmp_path):
    environment = _environment(tmp_path)
    results = tmp_path / "results"
    first = _dry_resume(
        results, environment, "--judge-model", "judge-model-a")
    assert first.returncode == 0, first.stderr

    second = _dry_resume(
        results, environment, "--judge-model", "judge-model-b")
    _assert_mismatch(second, "judge")


def test_run_timeout_too_small_for_slow_model_is_rejected(tmp_path):
    """A RUN_TIMEOUT far below the model's own retry budget must be rejected.

    Reproduces the observed failure mode from bench_20260906_074657: an
    OpenAI-backed model configured with a large request_timeout (e.g. 900s,
    matching a slow local/self-hosted endpoint) combined with the default
    RUN_TIMEOUT=3600 leaves no room for cve-agent's own retry/session-timeout
    logic to end an attempt cleanly, so the outer `timeout` kills the run
    mid-attempt instead. build_run_manifest() must refuse to build a manifest
    in that configuration rather than silently accepting a run_timeout too
    small to ever fail safely.
    """
    results = tmp_path / "results"
    result = _dry_resume(
        results,
        _environment(
            tmp_path,
            CVE_AGENT_OPENAI_MODEL="slow-model",
            CVE_AGENT_OPENAI_REQUEST_TIMEOUT="900",
            RUN_TIMEOUT="120",
        ),
        "--backend", "openai",
    )
    assert result.returncode != 0
    assert "agent_run_timeout" in result.stderr
    assert "too small" in result.stderr


def test_run_timeout_large_enough_for_slow_model_is_accepted(tmp_path):
    """The same slow-model configuration succeeds once RUN_TIMEOUT is raised."""
    results = tmp_path / "results"
    result = _dry_resume(
        results,
        _environment(
            tmp_path,
            CVE_AGENT_OPENAI_MODEL="slow-model",
            CVE_AGENT_OPENAI_REQUEST_TIMEOUT="900",
            RUN_TIMEOUT="10800",
        ),
        "--backend", "openai",
    )
    assert result.returncode == 0, result.stderr
