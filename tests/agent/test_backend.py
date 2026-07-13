# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for pluggable AI backend interface."""
import subprocess
import sys
from pathlib import Path

import pytest

import cve_agent
from cve_agent.backend import (
    AIBackend,
    SessionResult,
    available_backends,
    get_backend,
    register_backend,
)
from cve_agent.kiro_backend import KiroBackend


def _completed(cmd, stdout=""):
    return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")


class MockBackend(AIBackend):
    name = "mock"

    def is_available(self):
        return True

    def run_session(self, prompt, workspace_path, allowed_files,
                   model, timeout, interactive):
        return SessionResult(resolved=True, duration=0.1)


def test_register_and_get_backend():
    register_backend(MockBackend())
    assert 'mock' in available_backends()
    backend = get_backend('mock')
    assert backend.name == 'mock'


def test_mock_backend_session():
    register_backend(MockBackend())
    backend = get_backend('mock')
    result = backend.run_session(
        'test prompt', Path('/tmp'), set(), 'model', 60, False)
    assert result.resolved is True
    assert result.duration > 0


def test_default_backend_is_kiro():
    assert 'kiro' in available_backends()
    backend = get_backend('kiro')
    assert backend.name == 'kiro'


def test_kiro_backend_module_imports_standalone():
    """Importing cve_agent.kiro_backend before cve_agent.backend must work —
    same import-order guarantee test_claude_backend.py asserts for the claude
    module. A fresh interpreter is the only reliable way to test import order.
    """
    project_root = Path(cve_agent.__file__).resolve().parent.parent
    result = subprocess.run(
        [sys.executable, "-c", "import cve_agent.kiro_backend"],
        capture_output=True, text=True, check=False, cwd=project_root)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("marker", ["CHERRY_PICK_HEAD", "MERGE_HEAD"])
def test_kiro_check_resolution_mid_operation_is_unresolved(tmp_path, monkeypatch, marker):
    """Same false-positive this backend shares with ClaudeBackend: staging a
    conflicted file clears its U marker, but the cherry-pick/merge itself
    isn't finalized until --continue commits it.
    """
    workspace = tmp_path / "workspace" / "sources" / "openssl"
    workspace.mkdir(parents=True)
    git_dir = workspace / ".git"
    git_dir.mkdir()
    (git_dir / marker).write_text("deadbeef\n", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        return _completed(cmd, stdout="")  # staged: no U markers left

    monkeypatch.setattr("cve_agent.kiro_backend.subprocess.run", fake_run)
    assert KiroBackend()._check_resolution(workspace) is False
