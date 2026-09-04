# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for pluggable AI backend interface."""
import subprocess
import sys
from pathlib import Path

import pytest

import cve_agent
from cve_agent.backend import (
    VERIFY_MARKER,
    AIBackend,
    SessionResult,
    VerifyResult,
    _verify_cli_marker,
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


# --- AIBackend.verify() / _verify_cli_marker() --------------------------

class _UnavailableBackend(AIBackend):
    name = "unavailable-mock"

    def is_available(self):
        return False

    def run_session(self, prompt, workspace_path, allowed_files,
                   model, timeout, interactive):
        raise NotImplementedError


def test_default_verify_ok_when_available():
    result = MockBackend().verify()
    assert isinstance(result, VerifyResult)
    assert result.ok is True


def test_default_verify_fails_when_unavailable():
    result = _UnavailableBackend().verify()
    assert result.ok is False
    assert "prerequisites not met" in result.detail


def test_verify_cli_marker_success(monkeypatch):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=f"{VERIFY_MARKER}\n")

    monkeypatch.setattr("cve_agent.backend.subprocess.run", fake_run)
    result = _verify_cli_marker(["some-cli", "chat"])
    assert result.ok is True
    assert result.detail == ""


def test_verify_cli_marker_not_found(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise FileNotFoundError()

    monkeypatch.setattr("cve_agent.backend.subprocess.run", fake_run)
    result = _verify_cli_marker(["missing-cli"])
    assert result.ok is False
    assert "not found on PATH" in result.detail


def test_verify_cli_marker_nonzero_exit(monkeypatch):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="boom")

    monkeypatch.setattr("cve_agent.backend.subprocess.run", fake_run)
    result = _verify_cli_marker(["some-cli"])
    assert result.ok is False
    assert "exited 1" in result.detail


def test_verify_cli_marker_missing_marker(monkeypatch):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="unrelated output")

    monkeypatch.setattr("cve_agent.backend.subprocess.run", fake_run)
    result = _verify_cli_marker(["some-cli"])
    assert result.ok is False
    assert "without the expected marker" in result.detail


def test_verify_cli_marker_timeout(monkeypatch):
    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 30))

    monkeypatch.setattr("cve_agent.backend.subprocess.run", fake_run)
    result = _verify_cli_marker(["some-cli"], timeout=5)
    assert result.ok is False
    assert "timed out after 5s" in result.detail


def test_verify_cli_marker_real_subprocess():
    """End-to-end with a real subprocess (no mocking) using `echo`."""
    result = _verify_cli_marker(["echo", VERIFY_MARKER])
    assert result.ok is True


# --- KiroBackend.verify() -----------------------------------------------

def test_kiro_verify_builds_bare_command(monkeypatch):
    """No --agent flag: verify() bypasses the agent JSON / tool allow-lists
    that run_session() applies, per the design intent of a bare check.
    """
    captured = {}

    def fake_verify_cli_marker(cmd, timeout=30, extra_env=None):
        captured["cmd"] = cmd
        return VerifyResult(True, "")

    monkeypatch.setattr(
        "cve_agent.backend._verify_cli_marker", fake_verify_cli_marker)
    result = KiroBackend().verify()
    assert result.ok is True
    cmd = captured["cmd"]
    assert cmd[0] == "kiro-cli"
    assert "--no-interactive" in cmd
    assert "--model" in cmd
    assert "--agent" not in cmd


def test_kiro_verify_passes_through_failure(monkeypatch):
    def fake_verify_cli_marker(cmd, timeout=30, extra_env=None):
        return VerifyResult(False, "not found on PATH")

    monkeypatch.setattr(
        "cve_agent.backend._verify_cli_marker", fake_verify_cli_marker)
    result = KiroBackend().verify()
    assert result.ok is False
    assert result.detail == "not found on PATH"


def test_kiro_verify_end_to_end(monkeypatch):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout=f"{VERIFY_MARKER}\n")

    monkeypatch.setattr("cve_agent.backend.subprocess.run", fake_run)
    result = KiroBackend().verify()
    assert result.ok is True
