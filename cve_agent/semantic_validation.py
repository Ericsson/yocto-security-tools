# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Offline host-owned semantic evidence and conservative security decisions."""
from __future__ import annotations

import hashlib
import os
import re
import selectors
import signal
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import TypedDict

from shared import build_git_env

from .result import BuildStatus, SecurityStatus

SEMANTIC_SCHEMA_VERSION = 1
MAX_SEMANTIC_GIT_BYTES = 8 * 1024 * 1024
MAX_SEMANTIC_PATHS = 128
MAX_SEMANTIC_SYMBOLS = 64
MAX_SEMANTIC_TEXT_BYTES = 2 * 1024 * 1024
MAX_SEMANTIC_REPORT_ITEMS = 64
MAX_SEMANTIC_COMMAND_SECONDS = 30

_SYMBOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
_TEST_PARTS = frozenset({"test", "tests", "testing", "testsuite", "ptest"})
_DOC_PARTS = frozenset({"doc", "docs", "documentation"})
_DOC_NAMES = ("readme", "changelog", "changes", "news", "authors")
_BUILD_NAMES = (
    "configure", "makefile", "cmakelists.txt", "meson.build", "meson_options.txt",
    "configure.ac", "configure.in", "aclocal.m4",
)
_ALLOWED_METADATA = frozenset({
    "reference_commits", "prerequisite_commits", "path_map", "runtime_paths",
    "test_paths", "docs_paths", "build_paths", "expected_symbols",
    "required_tests", "equivalent_tests", "preexisting_fix_symbols",
    "prerequisite_symbols", "initialization_checks", "reproducer",
})


class SemanticValidationError(RuntimeError):
    """Trusted semantic evidence could not be constructed safely."""


@dataclass(frozen=True)
class DiffEvidence:
    exact_fingerprint: str
    normalized_fingerprint: str
    lines_added: int
    lines_removed: int
    bytes_examined: int

    def to_dict(self) -> dict[str, object]:
        return {
            "exact_fingerprint": self.exact_fingerprint,
            "normalized_fingerprint": self.normalized_fingerprint,
            "lines_added": self.lines_added,
            "lines_removed": self.lines_removed,
            "bytes_examined": self.bytes_examined,
        }


@dataclass(frozen=True)
class InitializationCheck:
    symbol: str
    initialize_anchor: str
    use_anchor: str

    def to_dict(self) -> dict[str, str]:
        return {
            "symbol": self.symbol,
            "initialize_anchor": self.initialize_anchor,
            "use_anchor": self.use_anchor,
        }


@dataclass(frozen=True)
class ReferenceManifest:
    schema_version: int
    cve: str
    reference_commits: tuple[str, ...]
    prerequisite_commits: tuple[str, ...]
    parent_basis: str
    changed_paths: tuple[str, ...]
    runtime_paths: tuple[str, ...]
    test_paths: tuple[str, ...]
    docs_paths: tuple[str, ...]
    build_paths: tuple[str, ...]
    uncertain_paths: tuple[str, ...]
    file_statuses: Mapping[str, str]
    path_map: Mapping[str, str]
    expected_symbols: tuple[str, ...]
    required_tests: tuple[str, ...]
    equivalent_tests: tuple[str, ...]
    prerequisite_symbols: tuple[str, ...]
    initialization_checks: tuple[InitializationCheck, ...]
    preexisting_fix_proven: bool
    preexisting_fix_evidence: tuple[str, ...]
    reproducer: str | None
    diff: DiffEvidence

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "cve": self.cve,
            "reference_commits": list(self.reference_commits),
            "prerequisite_commits": list(self.prerequisite_commits),
            "parent_basis": self.parent_basis,
            "changed_paths": list(self.changed_paths),
            "runtime_paths": list(self.runtime_paths),
            "test_paths": list(self.test_paths),
            "docs_paths": list(self.docs_paths),
            "build_paths": list(self.build_paths),
            "uncertain_paths": list(self.uncertain_paths),
            "file_statuses": dict(self.file_statuses),
            "path_map": dict(self.path_map),
            "expected_symbols": list(self.expected_symbols),
            "required_tests": list(self.required_tests),
            "equivalent_tests": list(self.equivalent_tests),
            "prerequisite_symbols": list(self.prerequisite_symbols),
            "initialization_checks": [
                check.to_dict() for check in self.initialization_checks],
            "preexisting_fix_proven": self.preexisting_fix_proven,
            "preexisting_fix_evidence": list(self.preexisting_fix_evidence),
            "reproducer": self.reproducer,
            "diff": self.diff.to_dict(),
        }


@dataclass(frozen=True)
class GeneratedSnapshot:
    baseline: str
    head: str
    changed_paths: tuple[str, ...]
    file_statuses: Mapping[str, str]
    diff: DiffEvidence
    searchable_text: str

    def to_dict(self) -> dict[str, object]:
        return {
            "baseline": self.baseline,
            "head": self.head,
            "changed_paths": list(self.changed_paths),
            "file_statuses": dict(self.file_statuses),
            "diff": self.diff.to_dict(),
            "searchable_text_bytes": len(self.searchable_text.encode("utf-8")),
        }


@dataclass(frozen=True)
class ReproducerResult:
    passed: bool
    reason: str
    output_excerpt: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "passed": self.passed,
            "reason": self.reason[:512],
            "output_excerpt": self.output_excerpt[:2048],
        }


@dataclass(frozen=True)
class SemanticValidation:
    schema_version: int
    status: SecurityStatus
    reason_code: str
    reason: str
    build_status: BuildStatus
    reference_paths: tuple[str, ...]
    generated_paths: tuple[str, ...]
    missing_runtime_paths: tuple[str, ...]
    missing_test_paths: tuple[str, ...]
    missing_symbols: tuple[str, ...]
    prerequisite_issues: tuple[str, ...]
    exact_match: bool
    normalized_match: bool
    reproducer: ReproducerResult | None
    review_items: tuple[str, ...]
    limitations: tuple[str, ...]
    reference_diff: DiffEvidence
    generated_diff: DiffEvidence

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "build_status": self.build_status.value,
            "reference_paths": list(self.reference_paths),
            "generated_paths": list(self.generated_paths),
            "missing_runtime_paths": list(self.missing_runtime_paths),
            "missing_test_paths": list(self.missing_test_paths),
            "missing_symbols": list(self.missing_symbols),
            "prerequisite_issues": list(self.prerequisite_issues),
            "exact_match": self.exact_match,
            "normalized_match": self.normalized_match,
            "reproducer": None if self.reproducer is None else self.reproducer.to_dict(),
            "review_items": list(self.review_items),
            "limitations": list(self.limitations),
            "diff_metrics": {
                "reference": self.reference_diff.to_dict(),
                "generated": self.generated_diff.to_dict(),
            },
        }

    def human_report(self) -> str:
        lines = [
            f"Semantic security status: {self.status.value}",
            f"Reason: {self.reason_code} — {self.reason}",
            f"Build evidence: {self.build_status.value}",
            ("Comparison: exact=" + str(self.exact_match).lower()
             + ", normalized=" + str(self.normalized_match).lower()),
            f"Reference paths: {_bounded_join(self.reference_paths)}",
            f"Generated paths: {_bounded_join(self.generated_paths)}",
        ]
        if self.review_items:
            lines.append("Human review items:")
            lines.extend(f"- {item}" for item in self.review_items)
        if self.limitations:
            lines.append("Evidence limitations:")
            lines.extend(f"- {item}" for item in self.limitations)
        return "\n".join(lines) + "\n"


Reproducer = Callable[[Path], ReproducerResult]

# CVE-specific reproducers are deliberately code-owned. Adding a runner
# requires a reviewed source change; neither metadata nor the model can choose
# an executable or argument vector.
TRUSTED_REPRODUCERS: Mapping[str, Reproducer] = MappingProxyType({})


class _ValidationEvidence(TypedDict):
    schema_version: int
    build_status: BuildStatus
    reference_paths: tuple[str, ...]
    generated_paths: tuple[str, ...]
    missing_runtime_paths: tuple[str, ...]
    missing_test_paths: tuple[str, ...]
    missing_symbols: tuple[str, ...]
    prerequisite_issues: tuple[str, ...]
    exact_match: bool
    normalized_match: bool
    reproducer: ReproducerResult | None
    review_items: tuple[str, ...]
    limitations: tuple[str, ...]
    reference_diff: DiffEvidence
    generated_diff: DiffEvidence


def build_reference_manifest(
    workspace: Path,
    cve: str,
    cve_info: Mapping[str, object],
) -> ReferenceManifest:
    """Build immutable comparison evidence from trusted metadata and Git objects."""
    metadata = _semantic_metadata(cve_info)
    commits = _string_tuple(
        metadata.get("reference_commits"), "reference_commits", hashes=True)
    if not commits:
        commits = _default_reference_commits(cve_info)
    if not commits:
        raise SemanticValidationError("semantic reference has no commits")
    resolved = tuple(_resolve_commit(workspace, commit) for commit in commits)
    prerequisites = _string_tuple(
        metadata.get("prerequisite_commits"), "prerequisite_commits", hashes=True)
    prerequisites = tuple(
        _resolve_commit(workspace, commit) for commit in prerequisites)
    parent = _reference_parent(workspace, resolved[0], cve_info)
    statuses = _changed_statuses(workspace, parent, resolved[-1])
    if not statuses:
        raise SemanticValidationError("semantic reference contains no changed paths")
    path_map = _path_map(metadata, cve_info)
    changed_paths = tuple(sorted(statuses))
    explicit_runtime = set(_string_tuple(
        metadata.get("runtime_paths"), "runtime_paths", paths=True))
    explicit_tests = set(_string_tuple(
        metadata.get("test_paths"), "test_paths", paths=True))
    explicit_docs = set(_string_tuple(
        metadata.get("docs_paths"), "docs_paths", paths=True))
    explicit_build = set(_string_tuple(
        metadata.get("build_paths"), "build_paths", paths=True))
    explicitly_classified = (
        explicit_runtime | explicit_tests | explicit_docs | explicit_build)
    unknown_explicit = explicitly_classified - set(changed_paths)
    if unknown_explicit:
        raise SemanticValidationError(
            "explicit semantic path is absent from the reference change: "
            f"{sorted(unknown_explicit)[0]}")
    categories: dict[str, list[str]] = {
        "runtime": [], "test": [], "docs": [], "build": [], "uncertain": []}
    for path in changed_paths:
        explicit = [
            name for name, values in (
                ("runtime", explicit_runtime), ("test", explicit_tests),
                ("docs", explicit_docs), ("build", explicit_build))
            if path in values
        ]
        if len(explicit) > 1:
            raise SemanticValidationError(
                f"semantic path has contradictory categories: {path}")
        category = explicit[0] if explicit else _classify_path(path)
        categories[category].append(path)
    expected_symbols = _string_tuple(
        metadata.get("expected_symbols"), "expected_symbols", symbols=True)
    required_tests = _string_tuple(
        metadata.get("required_tests"), "required_tests", paths=True)
    if not required_tests:
        required_tests = tuple(categories["test"])
    equivalent_tests = _string_tuple(
        metadata.get("equivalent_tests"), "equivalent_tests", paths=True)
    prerequisite_symbols = _string_tuple(
        metadata.get("prerequisite_symbols"), "prerequisite_symbols", symbols=True)
    checks = _initialization_checks(metadata.get("initialization_checks"))
    baseline_symbols = _string_tuple(
        metadata.get("preexisting_fix_symbols"),
        "preexisting_fix_symbols", symbols=True)
    baseline_text = _tree_text(
        workspace, parent, tuple(path_map.get(path, path)
                                 for path in categories["runtime"]))
    proof_evidence = tuple(
        symbol for symbol in baseline_symbols if symbol in baseline_text)
    preexisting = bool(baseline_symbols) and len(proof_evidence) == len(baseline_symbols)
    diff = _diff_evidence(workspace, parent, resolved[-1], path_map)
    reproducer_value = metadata.get("reproducer")
    if reproducer_value is not None and (
            not isinstance(reproducer_value, str)
            or not _SYMBOL_RE.fullmatch(reproducer_value)):
        raise SemanticValidationError("reproducer must be a bounded registered name")
    return ReferenceManifest(
        schema_version=SEMANTIC_SCHEMA_VERSION,
        cve=cve,
        reference_commits=resolved,
        prerequisite_commits=prerequisites,
        parent_basis=parent,
        changed_paths=changed_paths,
        runtime_paths=tuple(categories["runtime"]),
        test_paths=tuple(categories["test"]),
        docs_paths=tuple(categories["docs"]),
        build_paths=tuple(categories["build"]),
        uncertain_paths=tuple(categories["uncertain"]),
        file_statuses=statuses,
        path_map=path_map,
        expected_symbols=expected_symbols,
        required_tests=required_tests,
        equivalent_tests=equivalent_tests,
        prerequisite_symbols=prerequisite_symbols,
        initialization_checks=checks,
        preexisting_fix_proven=preexisting,
        preexisting_fix_evidence=proof_evidence,
        reproducer=reproducer_value,
        diff=diff,
    )


def capture_generated_snapshot(
    workspace: Path,
    manifest: ReferenceManifest,
    baseline: str = "original-version",
) -> GeneratedSnapshot:
    """Capture final candidate evidence before devtool removes the workspace."""
    baseline_commit = _resolve_commit(workspace, baseline)
    head = _resolve_commit(workspace, "HEAD")
    statuses = _changed_statuses(workspace, baseline_commit, head)
    diff = _diff_evidence(workspace, baseline_commit, head, {})
    relevant = set(statuses)
    relevant.update(manifest.path_map.get(path, path) for path in manifest.runtime_paths)
    relevant.update(manifest.equivalent_tests)
    text = _workspace_text(workspace, tuple(sorted(relevant)))
    return GeneratedSnapshot(
        baseline=baseline_commit,
        head=head,
        changed_paths=tuple(sorted(statuses)),
        file_statuses=statuses,
        diff=diff,
        searchable_text=text,
    )


def validate_semantic_result(
    manifest: ReferenceManifest | None,
    generated: GeneratedSnapshot | None,
    build_status: BuildStatus,
    *,
    tests_executed: bool,
    workspace: Path | None = None,
    reproducers: Mapping[str, Reproducer] | None = None,
) -> SemanticValidation:
    """Apply the conservative evidence ladder without accepting model claims."""
    if manifest is None or generated is None:
        empty = DiffEvidence("", "", 0, 0, 0)
        return SemanticValidation(
            SEMANTIC_SCHEMA_VERSION, SecurityStatus.NOT_EVALUATED,
            "comparison_artifact_missing",
            "trusted reference or generated comparison evidence is unavailable",
            build_status, (), (), (), (), (), (), False, False, None,
            ("reconstruct the missing trusted comparison artifact",),
            ("no semantic equivalence decision was attempted",), empty, empty)

    mapped_statuses = {
        manifest.path_map.get(path, path): status
        for path, status in manifest.file_statuses.items()
    }
    expected_runtime = {
        manifest.path_map.get(path, path) for path in manifest.runtime_paths}
    generated_paths = set(generated.changed_paths)
    generated_runtime = expected_runtime & generated_paths
    missing_runtime = tuple(sorted(expected_runtime - generated_paths))
    expected_tests = {
        manifest.path_map.get(path, path) for path in manifest.required_tests}
    equivalent_tests = set(manifest.equivalent_tests)
    missing_tests = tuple(sorted(
        path for path in expected_tests
        if path not in generated_paths and not (equivalent_tests & generated_paths)))
    missing_symbols = tuple(sorted(
        symbol for symbol in manifest.expected_symbols
        if symbol not in generated.searchable_text))
    prerequisite_issues = [
        f"missing prerequisite symbol: {symbol}"
        for symbol in manifest.prerequisite_symbols
        if symbol not in generated.searchable_text
    ]
    for check in manifest.initialization_checks:
        initialize = generated.searchable_text.find(check.initialize_anchor)
        use = generated.searchable_text.find(check.use_anchor)
        if use >= 0 and (initialize < 0 or initialize > use):
            prerequisite_issues.append(
                f"{check.symbol}: use appears before required initialization")

    status_match = mapped_statuses == dict(generated.file_statuses)
    exact_match = (
        status_match
        and manifest.diff.exact_fingerprint == generated.diff.exact_fingerprint)
    normalized_match = (
        status_match
        and manifest.diff.normalized_fingerprint
        == generated.diff.normalized_fingerprint)
    reproducer_result: ReproducerResult | None = None
    limitations = list(manifest.uncertain_paths[:MAX_SEMANTIC_REPORT_ITEMS])
    if manifest.prerequisite_commits and not manifest.prerequisite_symbols:
        limitations.append("prerequisite commits declared without behavior anchors")
    if manifest.reproducer is not None:
        runner = (reproducers or {}).get(manifest.reproducer)
        if runner is None or workspace is None:
            limitations.append(
                f"registered reproducer unavailable: {manifest.reproducer}")
        else:
            try:
                reproducer_result = runner(workspace)
            except Exception:
                reproducer_result = ReproducerResult(
                    False, "registered reproducer failed safely")
            if not reproducer_result.passed:
                limitations.append(
                    f"deterministic reproducer did not pass: {manifest.reproducer}")

    review_items = []
    if missing_tests:
        review_items.append(
            "required reference tests omitted: " + _bounded_join(missing_tests))
    if missing_symbols:
        review_items.append(
            "expected security anchors absent: " + _bounded_join(missing_symbols))
    if not tests_executed and manifest.required_tests:
        review_items.append("required tests were retained but not executed")

    common: _ValidationEvidence = {
        "schema_version": SEMANTIC_SCHEMA_VERSION,
        "build_status": build_status,
        "reference_paths": manifest.changed_paths,
        "generated_paths": generated.changed_paths,
        "missing_runtime_paths": missing_runtime,
        "missing_test_paths": missing_tests,
        "missing_symbols": missing_symbols,
        "prerequisite_issues": tuple(prerequisite_issues),
        "exact_match": exact_match,
        "normalized_match": normalized_match,
        "reproducer": reproducer_result,
        "review_items": tuple(review_items[:MAX_SEMANTIC_REPORT_ITEMS]),
        "limitations": tuple(limitations[:MAX_SEMANTIC_REPORT_ITEMS]),
        "reference_diff": manifest.diff,
        "generated_diff": generated.diff,
    }
    if build_status is not BuildStatus.PASSED:
        return SemanticValidation(
            status=SecurityStatus.NOT_EVALUATED,
            reason_code="build_evidence_not_current",
            reason="failed, stale, or missing build evidence cannot verify security",
            **common)
    if prerequisite_issues:
        return SemanticValidation(
            status=SecurityStatus.REJECTED,
            reason_code="prerequisite_behavior_absent",
            reason="deterministic prerequisite initialization evidence failed",
            **common)
    if manifest.runtime_paths and not generated_runtime:
        if manifest.preexisting_fix_proven:
            return SemanticValidation(
                status=SecurityStatus.EQUIVALENT,
                reason_code="preexisting_fix_proven",
                reason="trusted baseline anchors prove the runtime fix was already present",
                **common)
        return SemanticValidation(
            status=SecurityStatus.REJECTED,
            reason_code="runtime_change_missing",
            reason="reference changes runtime code but the result changes no mapped runtime path",
            **common)
    if missing_tests:
        return SemanticValidation(
            status=SecurityStatus.PLAUSIBLE_NEEDS_REVIEW,
            reason_code="required_test_omitted",
            reason="a reference security test was neither retained nor declared equivalent",
            **common)
    if manifest.reproducer is not None and (
            reproducer_result is None or not reproducer_result.passed):
        return SemanticValidation(
            status=SecurityStatus.PLAUSIBLE_NEEDS_REVIEW,
            reason_code="required_reproducer_not_passed",
            reason="the configured deterministic reproducer did not provide passing evidence",
            **common)
    if exact_match:
        verified = tests_executed or not manifest.required_tests
        return SemanticValidation(
            status=(SecurityStatus.VERIFIED if verified
                    else SecurityStatus.EQUIVALENT),
            reason_code=("exact_patch_and_tests" if verified else "exact_patch"),
            reason="changed path/status set and exact patch fingerprint match",
            **common)
    if normalized_match:
        return SemanticValidation(
            status=(SecurityStatus.VERIFIED
                    if reproducer_result is not None and reproducer_result.passed
                    else SecurityStatus.EQUIVALENT),
            reason_code="normalized_patch_equivalent",
            reason="patches differ only by the documented whitespace normalization",
            **common)
    if reproducer_result is not None and reproducer_result.passed and not missing_symbols:
        return SemanticValidation(
            status=SecurityStatus.VERIFIED,
            reason_code="structural_adaptation_reproducer_passed",
            reason="mapped runtime adaptation retained anchors and passed its reproducer",
            **common)
    if generated_runtime and not missing_symbols:
        return SemanticValidation(
            status=SecurityStatus.PLAUSIBLE_NEEDS_REVIEW,
            reason_code="structural_adaptation_requires_review",
            reason="mapped runtime paths changed but normalized patch evidence differs",
            **common)
    return SemanticValidation(
        status=SecurityStatus.DIVERGENT,
        reason_code="security_structure_divergent",
        reason="generated result lacks required mapped paths or security anchors",
        **common)


def _semantic_metadata(cve_info: Mapping[str, object]) -> Mapping[str, object]:
    value = cve_info.get("semantic_validation", {})
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise SemanticValidationError("semantic_validation metadata must be an object")
    unknown = set(value) - _ALLOWED_METADATA
    if unknown:
        raise SemanticValidationError(
            f"unknown semantic_validation key: {sorted(unknown)[0]}")
    return value


def _bounded_join(values: Sequence[str]) -> str:
    if not values:
        return "(none)"
    selected = [value[:256] for value in values[:MAX_SEMANTIC_REPORT_ITEMS]]
    if len(values) > len(selected):
        selected.append(f"... {len(values) - len(selected)} more")
    return ", ".join(selected)


def _default_reference_commits(cve_info: Mapping[str, object]) -> tuple[str, ...]:
    series = cve_info.get("series")
    if isinstance(series, list) and series:
        first = series[0]
        if isinstance(first, Mapping):
            commits = first.get("commits")
            parsed = _string_tuple(commits, "series commits", hashes=True)
            if parsed:
                return parsed
    hashes = _string_tuple(cve_info.get("hashes"), "hashes", hashes=True)
    return hashes[:1]


def _string_tuple(
    value: object,
    field: str,
    *,
    hashes: bool = False,
    paths: bool = False,
    symbols: bool = False,
) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > MAX_SEMANTIC_PATHS:
        raise SemanticValidationError(f"{field} must be a bounded string list")
    if symbols and len(value) > MAX_SEMANTIC_SYMBOLS:
        raise SemanticValidationError(f"{field} exceeds the symbol limit")
    result = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > 4096:
            raise SemanticValidationError(f"{field} contains an invalid value")
        if hashes and not _HEX_RE.fullmatch(item):
            raise SemanticValidationError(f"{field} contains an invalid commit")
        if paths:
            item = _validate_path(item)
        if symbols and not _SYMBOL_RE.fullmatch(item):
            raise SemanticValidationError(f"{field} contains an invalid symbol")
        result.append(item)
    if len(set(result)) != len(result):
        raise SemanticValidationError(f"{field} contains duplicates")
    return tuple(result)


def _path_map(
    metadata: Mapping[str, object], cve_info: Mapping[str, object],
) -> dict[str, str]:
    value = metadata.get("path_map")
    if value is None:
        transfer = cve_info.get("transfer")
        value = transfer.get("path_map") if isinstance(transfer, Mapping) else None
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > MAX_SEMANTIC_PATHS:
        raise SemanticValidationError("path_map must be a bounded object")
    result = {}
    for source, target in value.items():
        if not isinstance(source, str) or not isinstance(target, str):
            raise SemanticValidationError("path_map entries must be strings")
        result[_validate_path(source)] = _validate_path(target)
    return dict(sorted(result.items()))


def _validate_path(path: str) -> str:
    if (not path or path.startswith("/") or "\\" in path or "\x00" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))):
        raise SemanticValidationError("semantic metadata contains an unsafe path")
    return PurePosixPath(path).as_posix()


def _initialization_checks(value: object) -> tuple[InitializationCheck, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > MAX_SEMANTIC_SYMBOLS:
        raise SemanticValidationError("initialization_checks must be a bounded list")
    checks = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {
                "symbol", "initialize_anchor", "use_anchor"}:
            raise SemanticValidationError("initialization check has invalid fields")
        symbol = item["symbol"]
        initialize = item["initialize_anchor"]
        use = item["use_anchor"]
        if (not isinstance(symbol, str) or not _SYMBOL_RE.fullmatch(symbol)
                or not isinstance(initialize, str) or not initialize
                or not isinstance(use, str) or not use
                or len(initialize.encode("utf-8")) > 1024
                or len(use.encode("utf-8")) > 1024):
            raise SemanticValidationError("initialization check is malformed")
        checks.append(InitializationCheck(symbol, initialize, use))
    return tuple(checks)


def _classify_path(path: str) -> str:
    parts = tuple(part.casefold() for part in PurePosixPath(path).parts)
    name = parts[-1]
    if any(part in _TEST_PARTS for part in parts) or "test" in name:
        return "test"
    if any(part in _DOC_PARTS for part in parts) or name.startswith(_DOC_NAMES):
        return "docs"
    if name in _BUILD_NAMES or name.endswith((".m4", ".mk", ".cmake")):
        return "build"
    if "." not in name or name.endswith((
            ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".py",
            ".rs", ".go", ".java", ".sh", ".pl", ".rb")):
        return "runtime"
    return "uncertain"


def _resolve_commit(workspace: Path, revision: str) -> str:
    if (not revision or revision.startswith("-") or "\x00" in revision
            or any(character.isspace() for character in revision)):
        raise SemanticValidationError("unsafe semantic Git revision")
    output = _git(workspace, [
        "rev-parse", "--verify", "--quiet", "--end-of-options",
        f"{revision}^{{commit}}"], 1024).decode("ascii").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40,64}", output):
        raise SemanticValidationError("semantic Git revision did not resolve")
    return output


def _reference_parent(
    workspace: Path, commit: str, cve_info: Mapping[str, object],
) -> str:
    parents = _git(
        workspace, ["show", "-s", "--format=%P", commit], 1024,
    ).decode("ascii").split()
    if len(parents) == 1:
        return parents[0]
    mainline = cve_info.get("mainline_parent")
    if (len(parents) < 2 or isinstance(mainline, bool)
            or not isinstance(mainline, int)
            or not 1 <= mainline <= len(parents)):
        raise SemanticValidationError(
            "merge semantic reference requires a valid mainline_parent")
    return parents[mainline - 1]


def _changed_statuses(workspace: Path, old: str, new: str) -> dict[str, str]:
    output = _git(workspace, [
        "diff", "--name-status", "-z", "--find-renames", old, new, "--"],
        MAX_SEMANTIC_GIT_BYTES)
    tokens = output.decode("utf-8", errors="strict").split("\x00")
    result: dict[str, str] = {}
    index = 0
    while index < len(tokens):
        status = tokens[index]
        index += 1
        if not status:
            continue
        code = status[0]
        if code in {"R", "C"}:
            if index + 1 >= len(tokens):
                raise SemanticValidationError("malformed rename status")
            old_path = _validate_path(tokens[index])
            new_path = _validate_path(tokens[index + 1])
            index += 2
            result[old_path] = "D"
            result[new_path] = "A"
        else:
            if index >= len(tokens) or code not in {"A", "D", "M", "T"}:
                raise SemanticValidationError("unsupported changed-path status")
            result[_validate_path(tokens[index])] = code
            index += 1
        if len(result) > MAX_SEMANTIC_PATHS:
            raise SemanticValidationError("semantic changed-path limit exceeded")
    return dict(sorted(result.items()))


def _diff_evidence(
    workspace: Path, old: str, new: str, path_map: Mapping[str, str],
) -> DiffEvidence:
    output = _git(workspace, [
        "diff", "--no-ext-diff", "--no-textconv", "--unified=0",
        "--no-color", old, new, "--"], MAX_SEMANTIC_GIT_BYTES)
    exact = hashlib.sha256()
    normalized = hashlib.sha256()
    added = 0
    removed = 0
    current_path = ""
    for raw in output.decode("utf-8", errors="replace").splitlines():
        if raw.startswith("+++ b/"):
            current_path = path_map.get(raw[6:], raw[6:])
            exact.update(f"path:{current_path}\n".encode())
            normalized.update(f"path:{current_path}\n".encode())
            continue
        if raw.startswith(("diff --git ", "index ", "--- ", "@@")):
            continue
        if not raw.startswith(("+", "-")):
            continue
        marker = raw[0]
        text = raw[1:]
        added += marker == "+"
        removed += marker == "-"
        exact.update(f"{marker}{text}\n".encode())
        normalized_text = "".join(text.split())
        normalized.update(f"{marker}{normalized_text}\n".encode())
    return DiffEvidence(
        exact.hexdigest(), normalized.hexdigest(), added, removed, len(output))


def _workspace_text(workspace: Path, paths: Sequence[str]) -> str:
    chunks = []
    used = 0
    for path in paths:
        target = workspace / path
        try:
            if target.is_symlink() or not target.is_file():
                continue
            data = target.read_bytes()
        except OSError:
            continue
        if b"\x00" in data or used + len(data) > MAX_SEMANTIC_TEXT_BYTES:
            continue
        chunks.append(data.decode("utf-8", errors="replace"))
        used += len(data)
    return "\n".join(chunks)


def _tree_text(workspace: Path, tree: str, paths: Sequence[str]) -> str:
    chunks = []
    used = 0
    for path in paths:
        try:
            data = _git(
                workspace, ["show", f"{tree}:{path}"],
                MAX_SEMANTIC_TEXT_BYTES - used)
        except SemanticValidationError:
            continue
        if b"\x00" in data:
            continue
        chunks.append(data.decode("utf-8", errors="replace"))
        used += len(data)
        if used >= MAX_SEMANTIC_TEXT_BYTES:
            break
    return "\n".join(chunks)


def _git(workspace: Path, arguments: Sequence[str], limit: int) -> bytes:
    if limit < 1 or limit > MAX_SEMANTIC_GIT_BYTES:
        raise SemanticValidationError("invalid semantic Git output limit")
    environment = build_git_env()
    environment.update({
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_EXTERNAL_DIFF": "",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "LC_ALL": "C",
    })
    try:
        process = subprocess.Popen(
            ["git", "--no-pager", *arguments], cwd=workspace, env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False, start_new_session=True)
    except OSError as exc:
        raise SemanticValidationError("unable to start semantic Git inspection") from exc
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    output = bytearray()
    diagnostic = bytearray()
    started = time.monotonic()
    try:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            if time.monotonic() - started > MAX_SEMANTIC_COMMAND_SECONDS:
                raise SemanticValidationError("semantic Git inspection timed out")
            events = selector.select(0.1)
            for key, _ in events:
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = output if key.fd == process.stdout.fileno() else diagnostic
                target.extend(chunk)
                if len(output) > limit or len(diagnostic) > 4096:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                    raise SemanticValidationError(
                        "semantic Git inspection exceeded its output limit")
            if process.poll() is None:
                continue
        returncode = process.wait(timeout=MAX_SEMANTIC_COMMAND_SECONDS)
    except subprocess.TimeoutExpired as exc:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise SemanticValidationError("semantic Git inspection timed out") from exc
    except BaseException:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    if returncode != 0:
        raise SemanticValidationError("semantic Git inspection failed")
    return bytes(output)
