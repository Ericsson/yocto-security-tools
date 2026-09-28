# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Synthetic semantic-security fixtures for trusted host validation."""
import os
import subprocess
from pathlib import Path

import pytest

from cve_agent.result import BuildStatus, SecurityStatus
from cve_agent.semantic_validation import (
    ReproducerResult,
    SemanticValidationError,
    build_reference_manifest,
    capture_generated_snapshot,
    validate_semantic_result,
)

_UNSET = object()


def _git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], cwd=repo, check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    return result.stdout.strip()


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _fixture(
    tmp_path: Path,
    *,
    base_files: dict[str, str] | None = None,
    reference_files: dict[str, str] | None = None,
    generated_files: dict[str, str] | None | object = _UNSET,
    metadata: dict[str, object] | None = None,
):
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Semantic Test")
    _git(repo, "config", "user.email", "semantic@example.com")
    for path, content in (base_files or {"src.c": "int old_value;\n"}).items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    base = _commit(repo, "base")
    _git(repo, "tag", "original-version", base)
    _git(repo, "switch", "-q", "-c", "reference")
    for path, content in (reference_files or {"src.c": "int secure_value;\n"}).items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    reference = _commit(repo, "security fix")
    _git(repo, "switch", "-q", "main")
    selected_generated = (
        {"src.c": "int secure_value;\n"}
        if generated_files is _UNSET else generated_files)
    if isinstance(selected_generated, dict):
        for path, content in selected_generated.items():
            target = repo / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        _commit(repo, "generated backport")
    info: dict[str, object] = {"hashes": [reference]}
    if metadata is not None:
        info["semantic_validation"] = metadata
    manifest = build_reference_manifest(repo, "CVE-2099-0001", info)
    snapshot = capture_generated_snapshot(repo, manifest)
    return repo, manifest, snapshot


def _validate(fixture, **kwargs):
    repo, manifest, snapshot = fixture
    return validate_semantic_result(
        manifest, snapshot, BuildStatus.PASSED,
        tests_executed=kwargs.pop("tests_executed", True),
        workspace=repo, **kwargs)


def test_exact_equivalent_patch_is_verified(tmp_path):
    result = _validate(_fixture(tmp_path))
    assert result.status is SecurityStatus.VERIFIED
    assert result.reason_code == "exact_patch_and_tests"
    assert result.exact_match and result.normalized_match


def test_indentation_only_difference_is_equivalent(tmp_path):
    fixture = _fixture(
        tmp_path,
        base_files={"src.c": "void f(void) {\nreturn;\n}\n"},
        reference_files={"src.c": "void f(void) {\n    secure();\n}\n"},
        generated_files={"src.c": "void f(void) {\n\tsecure();\n}\n"},
    )
    result = _validate(fixture)
    assert result.status is SecurityStatus.EQUIVALENT
    assert not result.exact_match and result.normalized_match
    assert result.reason_code == "normalized_patch_equivalent"


def test_valid_older_branch_adaptation_requires_review_without_reproducer(tmp_path):
    fixture = _fixture(
        tmp_path,
        reference_files={"src.c": "int secure_anchor = validate(new_api);\n"},
        generated_files={"src.c": "int secure_anchor = validate_legacy(old_api);\n"},
        metadata={"expected_symbols": ["secure_anchor"]},
    )
    result = _validate(fixture)
    assert result.status is SecurityStatus.PLAUSIBLE_NEEDS_REVIEW
    assert result.reason_code == "structural_adaptation_requires_review"


def test_adaptation_with_registered_reproducer_is_verified(tmp_path):
    fixture = _fixture(
        tmp_path,
        reference_files={"src.c": "int secure_anchor = validate(new_api);\n"},
        generated_files={"src.c": "int secure_anchor = validate_legacy(old_api);\n"},
        metadata={"expected_symbols": ["secure_anchor"], "reproducer": "bounds"},
    )
    result = _validate(
        fixture,
        reproducers={"bounds": lambda _workspace: ReproducerResult(
            True, "fixed deterministic reproducer passed")})
    assert result.status is SecurityStatus.VERIFIED
    assert result.reason_code == "structural_adaptation_reproducer_passed"


def test_omitted_upstream_security_test_requires_review(tmp_path):
    fixture = _fixture(
        tmp_path,
        base_files={"src.c": "old\n", "tests/security.test": "old test\n"},
        reference_files={
            "src.c": "secure\n", "tests/security.test": "regression test\n"},
        generated_files={"src.c": "secure\n"},
    )
    result = _validate(fixture)
    assert result.status is SecurityStatus.PLAUSIBLE_NEEDS_REVIEW
    assert result.reason_code == "required_test_omitted"
    assert result.missing_test_paths == ("tests/security.test",)


def test_missing_prerequisite_initialization_is_rejected(tmp_path):
    fixture = _fixture(
        tmp_path,
        reference_files={"src.c": "state = initialized();\nconsume(state);\n"},
        generated_files={"src.c": "consume(state);\n"},
        metadata={
            "prerequisite_commits": [],
            "initialization_checks": [{
                "symbol": "state",
                "initialize_anchor": "state = initialized()",
                "use_anchor": "consume(state)",
            }],
        },
    )
    result = _validate(fixture)
    assert result.status is SecurityStatus.REJECTED
    assert result.reason_code == "prerequisite_behavior_absent"
    assert "use appears before" in result.prerequisite_issues[0]


def test_changelog_only_generated_output_is_rejected(tmp_path):
    fixture = _fixture(
        tmp_path,
        base_files={"src.c": "old\n", "NEWS": "old news\n"},
        reference_files={"src.c": "secure\n", "NEWS": "old news\n"},
        generated_files={"NEWS": "claims security fixed\n"},
    )
    result = _validate(fixture)
    assert result.status is SecurityStatus.REJECTED
    assert result.reason_code == "runtime_change_missing"


def test_fix_already_in_baseline_requires_retained_host_proof(tmp_path):
    fixture = _fixture(
        tmp_path,
        base_files={"src.c": "int secure_anchor = 1;\n"},
        reference_files={"src.c": "int secure_anchor = 1;\nint defense = 1;\n"},
        generated_files=None,
        metadata={"preexisting_fix_symbols": ["secure_anchor"]},
    )
    result = _validate(fixture)
    assert result.status is SecurityStatus.EQUIVALENT
    assert result.reason_code == "preexisting_fix_proven"


def test_path_mapping_from_transfer_can_be_equivalent(tmp_path):
    fixture = _fixture(
        tmp_path,
        base_files={"upstream/api.c": "old\n", "downstream/api.c": "old\n"},
        reference_files={
            "upstream/api.c": "secure\n", "downstream/api.c": "old\n"},
        generated_files={"downstream/api.c": "secure\n"},
        metadata={"path_map": {"upstream/api.c": "downstream/api.c"}},
    )
    result = _validate(fixture)
    assert result.status in {SecurityStatus.VERIFIED, SecurityStatus.EQUIVALENT}
    assert result.normalized_match


_OLD_PATH = "src/wheel/cli/unpack.py"
_NEW_PATH = "src/wheel/_commands/unpack.py"
_VULNERABLE = ("def unpack(path, dest):\n"
               "    extract(path, dest)\n"
               "    chmod(dest / name)\n")
_FIXED = ("def unpack(path, dest):\n"
          "    target = extract(path, dest)\n"
          "    chmod(target)\n")


def _renamed_repo(tmp_path, *, drift=False):
    """A recipe tree predating an upstream directory rename.

    Models CVE-2026-24049 / python3-wheel: upstream moved ``src/wheel/cli`` to
    ``src/wheel/_commands`` after the recipe's release, then landed the fix on
    the new path, so the reference commit names a path the recipe tree lacks.

    With ``drift`` the upstream file also gains unrelated edits before the fix,
    so the pre-image is no longer byte-identical to the recipe's copy and only
    Git's similarity detection can relate the two.
    """
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Semantic Test")
    _git(repo, "config", "user.email", "semantic@example.com")
    (repo / "src/wheel/cli").mkdir(parents=True)
    (repo / "docs").mkdir(parents=True)
    (repo / _OLD_PATH).write_text(_VULNERABLE, encoding="utf-8")
    (repo / "docs/news.rst").write_text("0.42.0\n", encoding="utf-8")
    base = _commit(repo, "release 0.42.0")

    # Upstream renames the package directory, then fixes the new path.
    _git(repo, "switch", "-q", "-c", "upstream-history")
    (repo / _NEW_PATH).parent.mkdir(parents=True, exist_ok=True)
    _git(repo, "mv", _OLD_PATH, _NEW_PATH)
    if drift:
        (repo / _NEW_PATH).write_text(
            _VULNERABLE + "\n\ndef helper():\n    return 1\n", encoding="utf-8")
    _commit(repo, "refactor: rename cli to _commands")
    (repo / _NEW_PATH).write_text(
        _FIXED + ("\n\ndef helper():\n    return 1\n" if drift else ""),
        encoding="utf-8")
    (repo / "docs/news.rst").write_text("0.42.0\nfix\n", encoding="utf-8")
    reference = _commit(repo, "Fixed security issue around wheel unpack")

    _git(repo, "switch", "-q", "main")
    _git(repo, "tag", "-f", "original-version", base)
    return repo, reference


def _apply_generated_fix(repo):
    """Resolve the backport the way Git's rename detection lands it."""
    (repo / _OLD_PATH).write_text(_FIXED, encoding="utf-8")
    (repo / "docs/news.rst").write_text("0.42.0\nfix\n", encoding="utf-8")
    _commit(repo, "generated backport")


def test_upstream_rename_is_anchored_not_rejected(tmp_path):
    """A correct backport onto the pre-rename path is not runtime_change_missing.

    Regression: with no rename mapping the comparison looked for the reference's
    ``src/wheel/_commands/unpack.py`` among the resolved paths, never found it,
    and rejected a correct fix as ``runtime_change_missing``.
    """
    repo, reference = _renamed_repo(tmp_path)
    _apply_generated_fix(repo)

    manifest = build_reference_manifest(repo, "CVE-2026-24049", {"hashes": [reference]})
    snapshot = capture_generated_snapshot(repo, manifest)
    result = validate_semantic_result(
        manifest, snapshot, BuildStatus.PASSED, tests_executed=True, workspace=repo)

    assert result.reason_code != "runtime_change_missing"
    assert result.missing_runtime_paths == ()
    assert manifest.path_map == {_NEW_PATH: _OLD_PATH}
    assert result.status in {SecurityStatus.VERIFIED, SecurityStatus.EQUIVALENT}


def test_rename_anchor_maps_relocation_despite_content_drift(tmp_path):
    """A relocation Git detects maps even when the pre-image is not identical.

    Regression for the dropbear/libsoup shape: upstream moved sources into a
    subdirectory long after the recipe's release, so the content has drifted and
    the byte-identical anchor cannot fire. Git's similarity detection is the
    same mechanism that decides where the cherry-pick applies, so it maps here.
    """
    repo, reference = _renamed_repo(tmp_path, drift=True)
    _apply_generated_fix(repo)

    manifest = build_reference_manifest(repo, "CVE-2026-24049", {"hashes": [reference]})
    snapshot = capture_generated_snapshot(repo, manifest)
    result = validate_semantic_result(
        manifest, snapshot, BuildStatus.PASSED, tests_executed=True, workspace=repo)

    assert manifest.path_map == {_NEW_PATH: _OLD_PATH}
    assert result.reason_code != "runtime_change_missing"
    assert result.missing_runtime_paths == ()


def test_unrelated_baseline_file_is_not_mapped(tmp_path):
    """No content and no name relation means no mapping, so the gate holds."""
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Semantic Test")
    _git(repo, "config", "user.email", "semantic@example.com")
    (repo / "other.c").write_text("unrelated implementation\n", encoding="utf-8")
    base = _commit(repo, "recipe release")
    _git(repo, "tag", "-f", "original-version", base)

    _git(repo, "switch", "-q", "-c", "upstream-history")
    (repo / "src").mkdir()
    (repo / "src/secret.c").write_text("alpha\nbeta\n", encoding="utf-8")
    _commit(repo, "upstream layout")
    (repo / "src/secret.c").write_text("alpha\nbeta\nsecure();\n", encoding="utf-8")
    reference = _commit(repo, "security fix")

    _git(repo, "switch", "-q", "main")
    (repo / "other.c").write_text("unrelated implementation\nlocal\n", encoding="utf-8")
    _commit(repo, "generated backport")

    manifest = build_reference_manifest(repo, "CVE-2099-0002", {"hashes": [reference]})
    snapshot = capture_generated_snapshot(repo, manifest)
    result = validate_semantic_result(
        manifest, snapshot, BuildStatus.PASSED, tests_executed=True, workspace=repo)

    assert manifest.path_map == {}
    assert result.status is SecurityStatus.REJECTED
    assert result.reason_code == "runtime_change_missing"


def test_unclassified_data_fix_is_review_not_rejection(tmp_path):
    """A fix carried by a data file is not "no runtime change".

    Regression for python3-certifi / CVE-2024-39689: the security fix removes a
    root from ``cacert.pem`` (classified uncertain), while the only
    runtime-classified file the reference touches carries nothing but a version
    bump. Rejecting that as a missing fix is a false positive.
    """
    fixture = _fixture(
        tmp_path,
        base_files={"pkg/__init__.py": '__version__ = "1.0"\n',
                    "pkg/cacert.pem": "OLD ROOT\n"},
        reference_files={"pkg/__init__.py": '__version__ = "1.1"\n',
                         "pkg/cacert.pem": "NEW ROOT\n"},
        generated_files={"pkg/cacert.pem": "NEW ROOT\n"},
    )
    _repo, manifest, _snapshot = fixture
    result = _validate(fixture)

    assert manifest.runtime_paths == ("pkg/__init__.py",)
    assert manifest.uncertain_paths == ("pkg/cacert.pem",)
    assert result.status is SecurityStatus.PLAUSIBLE_NEEDS_REVIEW
    assert result.reason_code == "unclassified_change_requires_review"


def test_declared_path_map_is_not_overridden_by_anchor(tmp_path):
    """Trusted metadata outranks derived Git evidence."""
    repo, reference = _renamed_repo(tmp_path)
    _apply_generated_fix(repo)

    manifest = build_reference_manifest(
        repo, "CVE-2026-24049",
        {"hashes": [reference],
         "semantic_validation": {"path_map": {_NEW_PATH: "docs/news.rst"}}})

    assert manifest.path_map == {_NEW_PATH: "docs/news.rst"}


def test_large_valid_adaptation_is_review_not_line_count_rejection(tmp_path):
    generated = "\n".join(f"secure_anchor_{index}();" for index in range(700)) + "\n"
    reference = "\n".join(f"secure_reference_{index}();" for index in range(700)) + "\n"
    fixture = _fixture(
        tmp_path,
        reference_files={"src.c": reference},
        generated_files={"src.c": generated},
        metadata={"expected_symbols": ["secure_anchor_699"]},
    )
    result = _validate(fixture)
    assert result.status is SecurityStatus.PLAUSIBLE_NEEDS_REVIEW
    assert result.generated_diff.lines_added >= 700


def test_model_equivalence_claim_has_no_input_to_validator(tmp_path):
    fixture = _fixture(
        tmp_path,
        generated_files={"README": "I certify this is equivalent\n"},
    )
    result = _validate(fixture)
    assert result.status is SecurityStatus.REJECTED


@pytest.mark.parametrize(
    "build", [BuildStatus.FAILED, BuildStatus.STALE, BuildStatus.NOT_RUN])
def test_failed_stale_or_missing_build_cannot_be_verified(tmp_path, build):
    repo, manifest, snapshot = _fixture(tmp_path)
    result = validate_semantic_result(
        manifest, snapshot, build, tests_executed=True, workspace=repo)
    assert result.status is SecurityStatus.NOT_EVALUATED
    assert result.reason_code == "build_evidence_not_current"


def test_missing_comparison_artifact_is_never_verified():
    result = validate_semantic_result(
        None, None, BuildStatus.PASSED, tests_executed=True)
    assert result.status is SecurityStatus.NOT_EVALUATED
    assert result.reason_code == "comparison_artifact_missing"


def test_metadata_unknown_keys_and_unsafe_paths_fail_closed(tmp_path):
    with pytest.raises(SemanticValidationError, match="unknown"):
        _fixture(tmp_path / "unknown", metadata={"model_claim": "equivalent"})
    with pytest.raises(SemanticValidationError, match="unsafe path"):
        _fixture(tmp_path / "path", metadata={"runtime_paths": ["../src.c"]})


def test_merge_reference_requires_and_records_explicit_mainline(tmp_path):
    repo = tmp_path / "merge"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.name", "Semantic Test")
    _git(repo, "config", "user.email", "semantic@example.com")
    (repo / "src.c").write_text("old\n", encoding="utf-8")
    (repo / "branch.txt").write_text("base\n", encoding="utf-8")
    base = _commit(repo, "base")
    _git(repo, "tag", "original-version", base)
    _git(repo, "switch", "-q", "-c", "security-side")
    (repo / "src.c").write_text("secure\n", encoding="utf-8")
    _commit(repo, "security side")
    _git(repo, "switch", "-q", "main")
    (repo / "branch.txt").write_text("mainline\n", encoding="utf-8")
    _commit(repo, "mainline work")
    _git(repo, "merge", "--no-ff", "-m", "merge security", "security-side")
    merge = _git(repo, "rev-parse", "HEAD")

    with pytest.raises(SemanticValidationError, match="mainline_parent"):
        build_reference_manifest(repo, "CVE-2099-0002", {"hashes": [merge]})

    manifest = build_reference_manifest(
        repo, "CVE-2099-0002", {"hashes": [merge], "mainline_parent": 1})
    assert manifest.parent_basis == _git(repo, "rev-parse", f"{merge}^1")
    assert manifest.changed_paths == ("src.c",)
