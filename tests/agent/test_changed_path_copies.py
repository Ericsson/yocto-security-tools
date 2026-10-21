# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""A copy's unchanged source is not a changed path.

gnutls CVE-2025-6395 adds ``tests/tls13/hello_retry_request_psk.c``, a near
copy of the existing ``hello_retry_request.c``. The host lists changed paths
with ``diff-tree -M -C --find-copies-harder``, which reports that as a copy
record naming both files, and the parser kept both. The untouched source was
then rejected as outside the allowed files ("trusted commit lineage reaches
unauthorized paths"), which blocked a fix whose real diff is exactly the
authorised set. binutils CVE-2025-1179 failed the same way on
``ld/testsuite/ld-i386/tlsgd2.s`` and ``ld-x86-64/tlsie2.s``.

A rename is different: its source really is removed, so both paths count.
"""
import os
import subprocess
from pathlib import Path

import pytest

from cve_agent.openai_git_tools import GitToolRuntime

_BODY = "".join(f"line {number} of a reasonably long test source file\n"
                for number in range(40))


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, encoding="utf-8",
        errors="replace", check=False,
        env={**os.environ, "GIT_EDITOR": "true", "GIT_TERMINAL_PROMPT": "0"})
    assert result.returncode == 0, f"git {' '.join(args)}: {result.stderr}"
    return result.stdout.strip()


@pytest.fixture
def repository(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.name", "CVE Test")
    _git(repo, "config", "user.email", "cve@example.com")
    (repo / "tests").mkdir()
    (repo / "tests" / "retry.c").write_text(_BODY, encoding="utf-8")
    (repo / "lib.c").write_text("base\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "base")
    return repo, _git(repo, "branch", "--show-current")


def _runtime(repo: Path, allowed: set[str]) -> GitToolRuntime:
    return GitToolRuntime(repo, allowed, model="gpt-test", timeout_seconds=30)


def _source_commit(repo: Path, branch: str, *, rename: bool) -> str:
    """Upstream commit: fix lib.c and add a near-copy of tests/retry.c."""
    _git(repo, "checkout", "-q", "-b", "source")
    (repo / "lib.c").write_text("fixed\n", encoding="utf-8")
    copy = repo / "tests" / "retry_psk.c"
    copy.write_text(_BODY.replace("line 7 ", "line seven "), encoding="utf-8")
    if rename:
        _git(repo, "rm", "-q", "tests/retry.c")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "fix and add a test")
    commit = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", branch)
    return commit


def test_host_diff_flags_do_report_a_copy_record(repository) -> None:
    """Guard the premise: these flags emit a copy that names the source."""
    repo, branch = repository
    commit = _source_commit(repo, branch, rename=False)
    raw = _git(repo, "diff-tree", "--no-commit-id", "--raw", "-r", "-M", "-C",
               "--find-copies-harder", f"{commit}^", commit)
    assert any(line.split()[4].startswith("C") for line in raw.splitlines())


def test_cherry_pick_start_does_not_count_a_copy_source(repository) -> None:
    repo, branch = repository
    commit = _source_commit(repo, branch, rename=False)
    runtime = _runtime(repo, {"lib.c", "tests/retry_psk.c"})

    result = runtime.dispatch("git_cherry_pick_start", {"revision": commit})

    assert result.success, result.payload
    assert (repo / "tests" / "retry_psk.c").exists()


def test_the_changed_set_is_exactly_the_paths_the_commit_touches(
        repository) -> None:
    repo, branch = repository
    commit = _source_commit(repo, branch, rename=False)
    runtime = _runtime(repo, {"lib.c", "tests/retry_psk.c"})

    changed = runtime._changed_paths(commit)

    assert sorted(item.path for item in changed) == ["lib.c", "tests/retry_psk.c"]


def test_range_diff_does_not_count_a_copy_source(repository) -> None:
    """``_changed_paths_between`` is what the durable-lineage check uses."""
    repo, branch = repository
    base = _git(repo, "rev-parse", "HEAD")
    commit = _source_commit(repo, branch, rename=False)
    runtime = _runtime(repo, {"lib.c", "tests/retry_psk.c"})

    changed = runtime._changed_paths_between(base, commit)

    assert sorted(item.path for item in changed) == ["lib.c", "tests/retry_psk.c"]


def test_a_rename_still_reports_both_paths(repository) -> None:
    repo, branch = repository
    commit = _source_commit(repo, branch, rename=True)
    runtime = _runtime(repo, {"lib.c", "tests/retry_psk.c"})

    changed = runtime._changed_paths(commit)

    assert "tests/retry.c" in {item.path for item in changed}
    assert "tests/retry_psk.c" in {item.path for item in changed}
