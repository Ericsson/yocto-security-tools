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


def _agent_models(results_dir):
    import json
    manifest = json.loads((results_dir / "run-manifest.json").read_text(encoding="utf-8"))
    return [entry["model"] for entry in manifest["agent"]], manifest


def _assert_rejected(result, *sections):
    assert result.returncode != 0
    assert "configuration mismatch" in result.stderr
    for section in sections:
        assert section in result.stderr


def test_a_new_model_is_refused_on_resume_without_add_models(tmp_path):
    environment = _environment(tmp_path)
    results = tmp_path / "results"
    assert _dry_resume(results, environment, "--models", "claude-sonnet-5").returncode == 0
    second = _dry_resume(
        results, environment, "--models", "claude-sonnet-5,claude-opus-5.5")
    _assert_rejected(second, "agent")
    assert _agent_models(results)[0] == ["claude-sonnet-5"]


def test_add_models_appends_the_new_model_and_keeps_the_recorded_ones(tmp_path):
    environment = _environment(tmp_path)
    results = tmp_path / "results"
    assert _dry_resume(results, environment, "--models", "claude-sonnet-5").returncode == 0
    before_models, before = _agent_models(results)

    second = _dry_resume(
        results, environment, "--models", "claude-sonnet-5,claude-opus-5.5", "--add-models")
    assert second.returncode == 0, second.stderr
    models, after = _agent_models(results)
    assert models == ["claude-sonnet-5", "claude-opus-5.5"]
    assert before_models == ["claude-sonnet-5"]
    assert after["agent"][0] == before["agent"][0]  # same config_id as recorded
    assert {k: v for k, v in after.items() if k != "agent"} == {
        k: v for k, v in before.items() if k != "agent"}


def test_add_models_with_the_same_models_changes_nothing(tmp_path):
    environment = _environment(tmp_path)
    results = tmp_path / "results"
    assert _dry_resume(results, environment, "--models", "claude-sonnet-5").returncode == 0
    recorded = (results / "run-manifest.json").read_bytes()
    again = _dry_resume(results, environment, "--models", "claude-sonnet-5", "--add-models")
    assert again.returncode == 0, again.stderr
    assert (results / "run-manifest.json").read_bytes() == recorded


def test_add_models_does_not_excuse_a_changed_judge(tmp_path):
    environment = _environment(tmp_path)
    results = tmp_path / "results"
    assert _dry_resume(results, environment, "--models", "claude-sonnet-5").returncode == 0
    recorded = (results / "run-manifest.json").read_bytes()
    second = _dry_resume(
        results, environment, "--models", "claude-sonnet-5,claude-opus-5.5",
        "--add-models", "--judge-model", "judge-model-b")
    _assert_rejected(second, "judge")
    assert (results / "run-manifest.json").read_bytes() == recorded


def test_add_models_does_not_excuse_a_changed_session_timeout(tmp_path):
    environment = _environment(tmp_path)
    results = tmp_path / "results"
    first = _dry_resume(
        results, environment, "--models", "claude-sonnet-5", "--session-timeout", "600")
    assert first.returncode == 0, first.stderr
    second = _dry_resume(
        results, environment, "--models", "claude-sonnet-5,claude-opus-5.5",
        "--add-models", "--session-timeout", "900")
    _assert_rejected(second, "agent_session_timeout")


def test_add_models_does_not_reorder_or_drop_recorded_models(tmp_path):
    environment = _environment(tmp_path)
    results = tmp_path / "results"
    first = _dry_resume(
        results, environment, "--models", "claude-sonnet-5,claude-sonnet-4.6")
    assert first.returncode == 0, first.stderr
    recorded = (results / "run-manifest.json").read_bytes()
    for selector in ("claude-sonnet-4.6,claude-sonnet-5,claude-opus-5.5",
                     "claude-sonnet-5,claude-opus-5.5",
                     "claude-sonnet-5"):
        result = _dry_resume(results, environment, "--models", selector, "--add-models")
        _assert_rejected(result, "agent")
        assert (results / "run-manifest.json").read_bytes() == recorded


def test_add_models_requires_resume(tmp_path):
    result = subprocess.run(
        [str(RUNNER), "--add-models", "--dry-run", "--skip-judge"],
        capture_output=True, text=True, check=False, env=_environment(tmp_path))
    assert result.returncode != 0
    assert "--add-models only applies to --resume" in result.stdout + result.stderr
