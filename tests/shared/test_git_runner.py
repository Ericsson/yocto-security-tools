# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Regression tests for shared.git_runner text decoding.

Reproduces the crash from a git repo containing a commit whose diff
contains a byte that is invalid UTF-8 (0xA4, as hit by cve-agent on
CVE-2026-39956): subprocess with text=True decodes using errors='strict'
and raises UnicodeDecodeError, aborting the whole run. run_capture() and
run_git_stdout() must use shared.TEXT_ERRORS ('replace') instead.
"""
from pathlib import Path

from shared.git_runner import run_capture, run_git_stdout


def _make_repo_with_invalid_utf8_content(tmp_path: Path) -> Path:
    """Create a git repo with a tracked file containing an invalid UTF-8 byte."""
    import subprocess

    repo = tmp_path / "repo"
    repo.mkdir()
    env = {
        "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@test.com",
        "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@test.com",
        "GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin",
    }
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=env)

    # 0xa4 is not a valid UTF-8 start byte — the exact byte from the traceback.
    bad_file = repo / "notes.txt"
    bad_file.write_bytes(b"line one\n\xa4 not valid utf-8\nline three\n")

    subprocess.run(["git", "add", "notes.txt"], cwd=repo, check=True, env=env)
    subprocess.run(["git", "commit", "-q", "-m", "Add notes"], cwd=repo,
                   check=True, env=env)
    return repo


def test_run_git_stdout_does_not_raise_on_invalid_utf8(tmp_path):
    repo = _make_repo_with_invalid_utf8_content(tmp_path)

    # Previously: UnicodeDecodeError from subprocess.communicate() (text=True
    # defaults to errors='strict'), matching the traceback in the bug report.
    output = run_git_stdout(["show", "HEAD"], cwd=repo)

    assert "Add notes" in output
    assert "\ufffd" in output  # invalid byte replaced, not raised


def test_run_capture_does_not_raise_on_invalid_utf8(tmp_path):
    repo = _make_repo_with_invalid_utf8_content(tmp_path)

    result = run_capture(["git", "show", "HEAD"], cwd=repo)

    assert result.returncode == 0
    assert "\ufffd" in result.stdout
