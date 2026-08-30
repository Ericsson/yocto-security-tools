# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for backend selection in the legacy bulk integration runner."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

_BULK_RUNNER = Path(__file__).resolve().parent / "test_cve_corrector.sh"


def _agent_flags(
    tmp_path: Path,
    *,
    backend: str | None = None,
    model: str | None = None,
    extra_flags: str = "",
) -> list[str]:
    oe_dir = tmp_path / "openembedded-core"
    build_dir = tmp_path / "build"
    mirror_dir = tmp_path / "git-mirrors"
    oe_dir.mkdir()
    build_dir.mkdir()
    mirror_dir.mkdir()
    environment = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "OE_DIR": str(oe_dir),
        "BUILD_DIR": str(build_dir),
        "MIRROR_DIR": str(mirror_dir),
    }
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
