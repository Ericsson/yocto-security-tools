# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for KiroBackend credit/time capture."""

from cve_agent.kiro_backend import KiroBackend


class _FakeProc:
    """Minimal subprocess.Popen stand-in yielding preset stdout lines."""

    def __init__(self, lines):
        self.stdout = iter(lines)
        self.killed = False

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.killed = True


def _patch_popen(monkeypatch, lines):
    def fake_popen(cmd, **kwargs):
        return _FakeProc(lines)
    monkeypatch.setattr("cve_agent.kiro_backend.subprocess.Popen", fake_popen)


def test_noninteractive_captures_credits(monkeypatch, tmp_path, capsys):
    _patch_popen(monkeypatch, [
        "Resolving conflict...\n",
        "Done.\n",
        "Credits: 5.86 • Time: 1m 23s\n",
    ])
    monkeypatch.setattr(KiroBackend, "_check_resolution", lambda self, ws: True)
    monkeypatch.setattr("cve_agent.kiro_backend.build_git_env", lambda: {})

    backend = KiroBackend()
    result = backend.run_session(
        "prompt", tmp_path, set(), "model", 60, interactive=False)

    assert result.resolved is True
    assert result.credits == 5.86
    assert result.credits_unit == "credits"
    # Output is streamed live to stdout while being captured.
    assert "Resolving conflict..." in capsys.readouterr().out


def test_noninteractive_no_summary_leaves_credits_none(monkeypatch, tmp_path):
    _patch_popen(monkeypatch, ["working...\n", "still working...\n"])
    monkeypatch.setattr(KiroBackend, "_check_resolution", lambda self, ws: True)
    monkeypatch.setattr("cve_agent.kiro_backend.build_git_env", lambda: {})

    backend = KiroBackend()
    result = backend.run_session(
        "prompt", tmp_path, set(), "model", 60, interactive=False)

    assert result.resolved is True
    assert result.credits is None
    assert result.credits_unit is None


def test_interactive_parses_transcript(monkeypatch, tmp_path):
    transcript = tmp_path / "kiro-session.log"
    transcript.write_text(
        "\x1b[1mCredits:\x1b[0m 2.14 • Time: 45s\n", encoding="utf-8")

    monkeypatch.setattr(
        KiroBackend, "_transcript_path", staticmethod(lambda ws: transcript))
    monkeypatch.setattr(
        KiroBackend, "_wrap_with_script",
        staticmethod(lambda cmd, path: ["true"]))
    monkeypatch.setattr(
        "cve_agent.kiro_backend.subprocess.run",
        lambda *a, **k: None)
    monkeypatch.setattr(KiroBackend, "_check_resolution", lambda self, ws: True)
    monkeypatch.setattr("cve_agent.kiro_backend.build_git_env", lambda: {})

    backend = KiroBackend()
    result = backend.run_session(
        "prompt", tmp_path, set(), "model", 60, interactive=True)

    assert result.credits == 2.14
    assert result.credits_unit == "credits"


def test_interactive_missing_transcript_leaves_credits_none(monkeypatch, tmp_path):
    missing = tmp_path / "does-not-exist.log"
    monkeypatch.setattr(
        KiroBackend, "_transcript_path", staticmethod(lambda ws: missing))
    monkeypatch.setattr(
        KiroBackend, "_wrap_with_script",
        staticmethod(lambda cmd, path: ["true"]))
    monkeypatch.setattr(
        "cve_agent.kiro_backend.subprocess.run", lambda *a, **k: None)
    monkeypatch.setattr(KiroBackend, "_check_resolution", lambda self, ws: True)
    monkeypatch.setattr("cve_agent.kiro_backend.build_git_env", lambda: {})

    backend = KiroBackend()
    result = backend.run_session(
        "prompt", tmp_path, set(), "model", 60, interactive=True)

    assert result.credits is None
