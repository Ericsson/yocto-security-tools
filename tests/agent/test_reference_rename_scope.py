# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Reference-scope mapping across an upstream directory rename.

Models the CVE-2026-24049 / python3-wheel failure with real git: upstream moved
``src/wheel/cli`` to ``src/wheel/_commands`` after the recipe's 0.42.0 release,
so the fix commit's paths do not exist in the recipe's source tree. Git's own
rename detection still applies the change to the older path, which the handoff
then reported as an unauthorized tracked path
(``HANDOFF_UNKNOWN_OUT_OF_SCOPE``) before any model call.

The mapping now accepts the older path on the same evidence the corrector's
patch transfer requires: a unique tracked candidate whose blob is byte-identical
to the reference pre-image.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from cve_agent.handoff import validate_repository_handoff
from cve_corrector.handoff import emit_handoff
from cve_corrector.state import WorkflowState
from shared.handoff import HandoffError

CVE_ID = "CVE-2026-24049"
OLD_PATH = "src/wheel/cli/unpack.py"
NEW_PATH = "src/wheel/_commands/unpack.py"
UNPACK = "def unpack(path, dest):\n    namever = parse(path)\n    return dest\n"
UNPACK_FIXED = ("def unpack(path, dest):\n    namever = parse(path)\n"
                "    if not resolved(dest):\n        raise ValueError(dest)\n"
                "    return dest\n")


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, check=True,
                            capture_output=True, text=True)
    return result.stdout.strip()


def _write(repo: Path, path: str, content: str) -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def renamed(tmp_path: Path) -> tuple[Path, str]:
    """A workspace whose source tree predates an upstream directory rename."""
    repo = tmp_path / "build" / "workspace" / "sources" / "python3-wheel"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "upstream-history")
    _git(repo, "config", "user.name", "Test")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "commit.gpgsign", "false")

    _write(repo, OLD_PATH, UNPACK)
    _write(repo, "docs/news.rst", "0.42.0\n")
    release = _commit(repo, "release 0.42.0")

    # Upstream renames the package directory, then lands the fix on the new path.
    (repo / NEW_PATH).parent.mkdir(parents=True, exist_ok=True)
    _git(repo, "mv", OLD_PATH, NEW_PATH)
    _commit(repo, "rename cli to _commands")
    _write(repo, NEW_PATH, UNPACK_FIXED)
    _write(repo, "docs/news.rst", "0.42.0\nfix\n")
    fix = _commit(repo, "Fixed security issue around wheel unpack")

    # The corrector's CVE branch is the release, where only the old path exists.
    _git(repo, "checkout", "-q", "-b", CVE_ID, release)
    _git(repo, "tag", "-f", "original-version")
    return repo, fix


def _state(repo: Path, fix: str) -> WorkflowState:
    return WorkflowState(
        workspace_path=repo, cve_id=CVE_ID, recipe="python3-wheel",
        commit_hash=fix, hash_details=[], meta_layer=None,
        skip_build=True, skip_ptest=True)


def test_reference_scope_follows_the_rename(renamed) -> None:
    """The pre-rename path the cherry-pick will modify is authorized."""
    repo, fix = renamed
    # Git's rename detection applies the fix to the old path, cleanly.
    subprocess.run(["git", "cherry-pick", fix], cwd=repo, capture_output=True)
    assert "raise ValueError" in (repo / OLD_PATH).read_text(encoding="utf-8")
    _git(repo, "reset", "--hard", "original-version")

    manifest = emit_handoff(_state(repo, fix), repo.parent.parent / "cve_corrector")

    assert OLD_PATH in manifest.allowed_paths
    assert NEW_PATH not in manifest.allowed_paths
    assert "docs/news.rst" in manifest.allowed_paths
    assert manifest.tracked_out_of_scope_paths == ()
    assert validate_repository_handoff(repo, CVE_ID, required=True) == manifest


def test_modified_candidate_is_not_anchored(renamed) -> None:
    """Without byte-identical content there is no evidence, so no mapping."""
    repo, fix = renamed
    _write(repo, OLD_PATH, UNPACK + "# local change\n")
    _commit(repo, "recipe patch: local change")
    _git(repo, "tag", "-f", "original-version")

    manifest = emit_handoff(_state(repo, fix), repo.parent.parent / "cve_corrector")

    assert NEW_PATH in manifest.allowed_paths
    assert OLD_PATH not in manifest.allowed_paths


def test_ambiguous_candidates_are_not_anchored(renamed) -> None:
    """Two identical candidates are ambiguous, so the upstream path stands."""
    repo, fix = renamed
    _write(repo, "src/wheel/legacy/unpack.py", UNPACK)
    _commit(repo, "recipe patch: vendor a second copy")
    _git(repo, "tag", "-f", "original-version")

    manifest = emit_handoff(_state(repo, fix), repo.parent.parent / "cve_corrector")

    assert NEW_PATH in manifest.allowed_paths
    assert OLD_PATH not in manifest.allowed_paths


def test_unmapped_reference_path_still_fails_handoff(renamed) -> None:
    """A tracked change outside the declared scope is still refused."""
    repo, fix = renamed
    _write(repo, OLD_PATH, UNPACK + "# local change\n")
    _commit(repo, "recipe patch: local change")
    _git(repo, "tag", "-f", "original-version")
    # The cherry-pick's rename-detected write is now unauthorized.
    subprocess.run(["git", "cherry-pick", "--no-commit", fix],
                   cwd=repo, capture_output=True)

    with pytest.raises(HandoffError) as excinfo:
        emit_handoff(_state(repo, fix), repo.parent.parent / "cve_corrector")

    assert excinfo.value.code == "HANDOFF_UNKNOWN_OUT_OF_SCOPE"
