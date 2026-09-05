# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Offline contract tests for the native OpenAI benchmark entry point."""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

SCRIPT = Path(__file__).with_name("run_openai_benchmark.sh")
RUNNER = Path(__file__).with_name("run_benchmark.sh")
CVE_METADATA = SCRIPT.parents[1] / "integration" / "test-cve-metadata-agent.json"


def _benchmark_env(tmp_path):
    return {
        **os.environ,
        "OE_DIR": str(tmp_path),
        "BUILD_DIR": str(tmp_path),
        "MIRROR_DIR": str(tmp_path),
    }


def test_benchmark_scripts_have_valid_bash_syntax():
    for script in (SCRIPT, RUNNER):
        result = subprocess.run(
            ["bash", "-n", str(script)], capture_output=True, text=True,
            check=False)
        assert result.returncode == 0, result.stderr


def test_runner_preserves_candidate_before_durable_classification():
    runner = RUNNER.read_text(encoding="utf-8")
    save_call = runner.index(
        '                    save_generated_patches "$cve_id" "$model"')
    classify = runner.index(
        '                    local durable_summary="" candidate_ready=false')
    csv_write = runner.index(
        '                echo "${cve_id},${tier},${model},${exit_status},')

    assert save_call < classify < csv_write


def test_openai_entry_point_is_executable():
    assert os.access(SCRIPT, os.X_OK)


def test_cve_2026_0990_uses_only_its_security_fix_commit():
    metadata = json.loads(CVE_METADATA.read_text(encoding="utf-8"))

    assert metadata["CVE-2026-0990"]["series"] == [{
        "pull_url": "https://gitlab.gnome.org/GNOME/libxml2/-/issues/1018",
        "commits": ["1961208e958ca22f80a0b4e4c9d71cfa050aa982"],
    }]


def test_cve_2024_6345_selects_security_merge_mainline():
    metadata = json.loads(CVE_METADATA.read_text(encoding="utf-8"))

    assert metadata["CVE-2024-6345"]["hashes"] == [
        "88807c7062788254f654ea8c03427adc859321f0",
    ]
    assert metadata["CVE-2024-6345"]["mainline_parent"] == 1


def test_help_documents_openai_agent_and_configurable_judge():
    result = subprocess.run(
        [str(SCRIPT), "--help"], capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "--backend <selector>" in result.stdout
    assert "--session-timeout <sec>" in result.stdout
    assert "--judge-backend <backend>" in result.stdout
    assert "kiro (default)" in result.stdout


def test_wrapper_defaults_to_openai_agent_and_kiro_judge(tmp_path):
    wrapper = tmp_path / SCRIPT.name
    shutil.copy2(SCRIPT, wrapper)
    runner = tmp_path / RUNNER.name
    runner.write_text(
        "#!/bin/bash\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
    runner.chmod(0o755)

    result = subprocess.run(
        [str(wrapper), "--run-case", "2", "--skip-judge"],
        capture_output=True, text=True, check=False,
        env={**os.environ, "OPENAI_BENCHMARK_BACKEND": "openai-test"},
    )

    assert result.returncode == 0
    assert result.stdout.splitlines() == [
        "--backend", "openai-test",
        "--judge-backend", "kiro",
        "--session-timeout", "1800",
        "--run-case", "2", "--skip-judge",
    ]


def test_wrapper_forwards_judge_override_after_default(tmp_path):
    wrapper = tmp_path / SCRIPT.name
    shutil.copy2(SCRIPT, wrapper)
    runner = tmp_path / RUNNER.name
    runner.write_text(
        "#!/bin/bash\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
    runner.chmod(0o755)

    result = subprocess.run(
        [str(wrapper), "--judge-backend", "openai-judge",
         "--judge-model", "judge-model"],
        capture_output=True, text=True, check=False,
    )

    assert result.returncode == 0
    assert result.stdout.splitlines()[-4:] == [
        "--judge-backend", "openai-judge",
        "--judge-model", "judge-model",
    ]


def test_wrapper_session_timeout_is_configurable(tmp_path):
    wrapper = tmp_path / SCRIPT.name
    shutil.copy2(SCRIPT, wrapper)
    runner = tmp_path / RUNNER.name
    runner.write_text(
        "#!/bin/bash\nprintf '%s\\n' \"$@\"\n", encoding="utf-8")
    runner.chmod(0o755)

    result = subprocess.run(
        [str(wrapper), "--session-timeout", "2400"],
        capture_output=True, text=True, check=False,
        env={**os.environ, "OPENAI_BENCHMARK_SESSION_TIMEOUT": "1200"},
    )

    assert result.returncode == 0
    assert result.stdout.splitlines()[-2:] == ["--session-timeout", "2400"]


def test_wrapper_exports_checkout_identity_for_native_commits(tmp_path):
    wrapper = tmp_path / SCRIPT.name
    shutil.copy2(SCRIPT, wrapper)
    runner = tmp_path / RUNNER.name
    runner.write_text(
        "#!/bin/bash\nprintf '%s <%s>\\n' \"$GIT_COMMITTER_NAME\" "
        "\"$GIT_COMMITTER_EMAIL\"\n",
        encoding="utf-8",
    )
    runner.chmod(0o755)
    checkout = tmp_path / "oe"
    checkout.mkdir()
    subprocess.run(["git", "init", "-q", str(checkout)], check=True)
    subprocess.run(
        ["git", "-C", str(checkout), "config", "user.name", "Test Operator"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(checkout), "config", "user.email",
         "operator@example.com"],
        check=True,
    )
    environment = {
        key: value for key, value in os.environ.items()
        if key not in {"GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL"}
    }
    environment["OE_DIR"] = str(checkout)

    result = subprocess.run(
        [str(wrapper), "--skip-judge"],
        capture_output=True, text=True, check=False, env=environment,
    )

    assert result.returncode == 0
    assert result.stdout == "Test Operator <operator@example.com>\n"


def test_runner_rejects_invalid_session_timeout(tmp_path):
    result = subprocess.run(
        [str(RUNNER), "--session-timeout", "0", "--list-cases"],
        capture_output=True, text=True, check=False,
        env=_benchmark_env(tmp_path),
    )
    assert result.returncode != 0
    assert "--session-timeout must be a positive integer" in result.stdout


def test_openai_backend_accepts_profile_model_for_case_listing(tmp_path):
    result = subprocess.run(
        [str(RUNNER), "--backend", "openai-test", "--list-cases"],
        capture_output=True, text=True, check=False,
        env=_benchmark_env(tmp_path),
    )
    assert result.returncode == 0, result.stderr
    assert "CVE-" in result.stdout


def test_openai_backend_rejects_kiro_model_roster(tmp_path):
    result = subprocess.run(
        [str(RUNNER), "--backend", "openai-test",
         "--models", "default", "--list-cases"],
        capture_output=True, text=True, check=False,
        env=_benchmark_env(tmp_path),
    )
    assert result.returncode != 0
    assert "--models is the Kiro roster" in result.stdout


def test_unknown_judge_backend_is_rejected_before_run(tmp_path):
    result = subprocess.run(
        [str(RUNNER), "--judge-backend", "claude", "--list-cases"],
        capture_output=True, text=True, check=False,
        env=_benchmark_env(tmp_path),
    )
    assert result.returncode != 0
    assert "--judge-backend must be" in result.stdout


def _artifact_selection_source() -> str:
    """Extract the runner's own artifact-directory selection program.

    The snippet is executed rather than reimplemented, so this test fails if
    the runner's real path logic drifts from cve_agent's artifact layout.
    """
    runner = RUNNER.read_text(encoding="utf-8")
    start = runner.index(
        'artifact_dir=$(python3 - "$artifact_data_root" "$cve_id"')
    body_start = runner.index("<<'PY'\n", start) + len("<<'PY'\n")
    return runner[body_start:runner.index("\nPY\n", body_start)]


def test_artifact_selection_finds_the_run_directory_cve_agent_creates(
        tmp_path, monkeypatch):
    """The runner must resolve the directory cve_agent actually writes.

    shared.paths.data_dir() appends the application component to
    CVE_TOOLS_DATA_DIR, so an open-coded '<root>/results/cases/<cve>' join
    finds nothing at all. That regression made every selection fail in
    bench_20260904_165741: artifact_dir came back empty for all 100 rows,
    which silently disabled both the durable-result exit-status override and
    the generated-vs-reference patch comparison, leaving 93 rows stuck at
    diff_bucket='-' and exactly one judgeable row for the judge phase.
    """
    from cve_agent import CveResult, ResultStatus
    from cve_agent.artifacts import RunArtifacts

    cve_id = "CVE-2026-0001"
    monkeypatch.setenv("CVE_TOOLS_DATA_DIR", str(tmp_path))
    environment = {**os.environ, "CVE_TOOLS_DATA_DIR": str(tmp_path)}
    artifacts = RunArtifacts.create(cve_id, "kiro", None, "claude-opus-5")
    try:
        expected = artifacts.path.resolve(strict=True)
    finally:
        artifacts.finalize(CveResult(cve_id, ResultStatus.SUCCESS))

    result = subprocess.run(
        [sys.executable, "-", str(tmp_path), cve_id],
        input=_artifact_selection_source(),
        capture_output=True, text=True, check=False, env=environment,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str(expected)


def test_artifact_selection_failure_reports_where_the_path_diverges(tmp_path):
    """A selection miss must be attributable from the run log alone.

    The original failure recorded nothing: artifact_dir was silently empty and
    every downstream column just read '-'. Diagnostics must name the case root,
    walk the ancestor chain, and list the deepest directory that does exist --
    on stderr only, since stdout is the sole channel for the resolved path.
    """
    environment = {**os.environ, "CVE_TOOLS_DATA_DIR": str(tmp_path)}
    (tmp_path / "wrong-layout").mkdir()

    result = subprocess.run(
        [sys.executable, "-", str(tmp_path), "CVE-2026-0002"],
        input=_artifact_selection_source(),
        capture_output=True, text=True, check=False, env=environment,
    )

    assert result.returncode != 0
    assert result.stdout.strip() == ""
    assert "ARTIFACT_SELECT_FAILED" in result.stderr
    assert "found 0" in result.stderr
    assert f"exists({tmp_path})=True" in result.stderr
    assert "deepest existing=" in result.stderr
    assert "wrong-layout" in result.stderr

