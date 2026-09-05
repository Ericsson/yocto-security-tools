# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Offline tests for the post-hoc benchmark patch-comparison backfill."""

import csv
from pathlib import Path

from cve_agent import (
    BuildStatus,
    CveResult,
    ResultOutcome,
    ResultStatus,
    SecurityStatus,
    WorkflowStatus,
)
from cve_agent.artifacts import RunArtifacts
from tests.benchmark.backfill_diffs import (
    CSV_COLUMNS,
    backfill,
    candidate_patch,
    reference_patches,
    write_rows,
)

CVE = "CVE-2026-0001"
MODEL = "claude-opus-5"

REFERENCE = """\
Upstream-Status: Backport [https://example.invalid/commit/abc]

diff --git a/filename.c b/filename.c
--- a/filename.c
+++ b/filename.c
@@ -1,3 +1,3 @@
 static int must_quote(char c)
 {
-\treturn (c == 'x');
+\treturn (c == '\\n');
 }
"""

# Same change as the reference, so the comparison is 'identical'.
CANDIDATE = """\
From abc Mon Sep 17 00:00:00 2001
Subject: [PATCH] quote newlines

diff --git a/filename.c b/filename.c
--- a/filename.c
+++ b/filename.c
@@ -1,3 +1,3 @@
 static int must_quote(char c)
 {
-\treturn (c == 'x');
+\treturn (c == '\\n');
 }
"""


def _row(**overrides):
    row = {name: "" for name in CSV_COLUMNS}
    row.update({
        "cve_id": CVE, "tier": "easy", "model": MODEL, "exit_status": "14",
        "duration_s": "10", "commands": "3", "diff_bucket": "-",
        "diff_lines": "-",
    })
    row.update(overrides)
    return row


def _write_csv(results_dir: Path, rows):
    path = results_dir / "agent_results.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(CSV_COLUMNS))
        writer.writeheader()
        writer.writerows(rows)
    return path


def _make_results_dir(tmp_path, monkeypatch, outcome, *, candidate=CANDIDATE,
                      status=ResultStatus.SUCCESS):
    """Build a results directory with one real, validated artifact run."""
    results_dir = tmp_path / "bench"
    (results_dir / "agent-artifacts").mkdir(parents=True)
    (results_dir / f"bench_{CVE}_{CVE}.patch").write_text(
        REFERENCE, encoding="utf-8")

    root = results_dir / "agent-artifacts" / f"{CVE}_{MODEL}.abc123"
    root.mkdir()
    monkeypatch.setenv("CVE_TOOLS_DATA_DIR", str(root))
    artifacts = RunArtifacts.create(CVE, "kiro", None, MODEL)
    if candidate is not None:
        artifacts.atomic_repository_text("final-commits.patch", candidate)
    result = CveResult(CVE, status, outcome=outcome)
    result.artifact_dir = artifacts.path
    artifacts.finalize(result)
    return results_dir


def _completed_outcome():
    return ResultOutcome(
        WorkflowStatus.COMPLETED, BuildStatus.PASSED, SecurityStatus.EQUIVALENT)


def test_reference_patches_excludes_generated_and_comparison_outputs(tmp_path):
    """Only the run's saved reference copies may be the comparison baseline."""
    for name in (
        f"bench_{CVE}_{CVE}.patch",
        f"bench_{CVE}_{CVE}-002.patch",
        f"bench_{CVE}_{CVE}_differences_diff.patch",
        f"bench_{CVE}_agent_{CVE}.patch",
        f"generated_{CVE}_{MODEL}_{CVE}.patch",
    ):
        (tmp_path / name).write_text("x", encoding="utf-8")

    found = [path.name for path in reference_patches(tmp_path, CVE)]

    assert found == [f"bench_{CVE}_{CVE}-002.patch", f"bench_{CVE}_{CVE}.patch"]


def test_candidate_patch_prefers_commits_and_ignores_empty(tmp_path):
    """An empty artifact is not a candidate; commits outrank the worktree diff."""
    assert candidate_patch(tmp_path) is None

    (tmp_path / "final-commits.patch").write_text("", encoding="utf-8")
    (tmp_path / "final.patch").write_text("diff", encoding="utf-8")
    assert candidate_patch(tmp_path).name == "final.patch"

    (tmp_path / "final-commits.patch").write_text("diff", encoding="utf-8")
    assert candidate_patch(tmp_path).name == "final-commits.patch"


def test_backfill_recovers_bucket_and_exit_status(tmp_path, monkeypatch):
    """A completed, built attempt is compared straight from its artifact.

    This is the whole point of the tool: recover the comparison the run failed
    to record, without spending a single model call re-running the backport.
    """
    results_dir = _make_results_dir(tmp_path, monkeypatch, _completed_outcome())
    _write_csv(results_dir, [_row()])

    rows, log, buckets = backfill(
        results_dir, "kiro", force=False, dry_run=False)

    assert rows[0]["diff_bucket"] == "identical"
    assert rows[0]["exit_status"] == "0"
    assert buckets == {"identical": 1}
    assert "compared via final-commits.patch" in "\n".join(log)
    # The judge phase reads exactly these two names.
    assert (results_dir / f"{CVE}_{MODEL}_differences.txt").is_file()
    assert (results_dir / f"{CVE}_{MODEL}_differences_diff.patch").is_file()


def test_backfill_marks_durable_skip_as_skipped(tmp_path, monkeypatch):
    """A SKIPPED workflow has no candidate, matching the runner's own rule."""
    outcome = ResultOutcome(
        WorkflowStatus.SKIPPED, BuildStatus.NOT_RUN,
        SecurityStatus.NOT_EVALUATED)
    results_dir = _make_results_dir(tmp_path, monkeypatch, outcome)
    _write_csv(results_dir, [_row()])

    rows, _, _ = backfill(results_dir, "kiro", force=False, dry_run=False)

    assert rows[0]["diff_bucket"] == "skipped"


def test_backfill_leaves_non_comparable_rows_untouched(tmp_path, monkeypatch):
    """An escalated attempt built nothing, so it must not get a bucket."""
    outcome = ResultOutcome(
        WorkflowStatus.ESCALATED, BuildStatus.NOT_RUN,
        SecurityStatus.PLAUSIBLE_NEEDS_REVIEW)
    results_dir = _make_results_dir(tmp_path, monkeypatch, outcome)
    _write_csv(results_dir, [_row()])

    rows, log, _ = backfill(results_dir, "kiro", force=False, dry_run=False)

    assert rows[0]["diff_bucket"] == "-"
    assert "not comparable" in "\n".join(log)


def test_backfill_reports_empty_artifact_without_inventing_a_bucket(
        tmp_path, monkeypatch):
    """A clean apply finalized before cve-agent ran leaves no candidate."""
    results_dir = _make_results_dir(
        tmp_path, monkeypatch, _completed_outcome(), candidate=None)
    _write_csv(results_dir, [_row()])

    rows, log, _ = backfill(results_dir, "kiro", force=False, dry_run=False)

    assert rows[0]["diff_bucket"] == "-"
    assert "no generated commits" in "\n".join(log)


def test_dry_run_projects_the_result_without_writing(tmp_path, monkeypatch):
    """The preview must report what it would achieve, not the stale state."""
    results_dir = _make_results_dir(tmp_path, monkeypatch, _completed_outcome())
    csv_path = _write_csv(results_dir, [_row()])
    before = csv_path.read_text(encoding="utf-8")

    rows, log, buckets = backfill(
        results_dir, "kiro", force=False, dry_run=True)

    assert buckets == {"identical": 1}
    assert rows[0]["diff_bucket"] == "-"
    assert csv_path.read_text(encoding="utf-8") == before
    assert "WOULD UPDATE" in "\n".join(log)


def test_existing_buckets_are_preserved_unless_forced(tmp_path, monkeypatch):
    """A row the run already compared is authoritative; do not clobber it."""
    results_dir = _make_results_dir(tmp_path, monkeypatch, _completed_outcome())
    _write_csv(results_dir, [_row(diff_bucket="major", diff_lines="900")])

    rows, log, buckets = backfill(
        results_dir, "kiro", force=False, dry_run=False)
    assert rows[0]["diff_bucket"] == "major"
    assert buckets == {"major": 1}
    assert "kept existing comparison" in "\n".join(log)

    rows, _, _ = backfill(results_dir, "kiro", force=True, dry_run=False)
    assert rows[0]["diff_bucket"] == "identical"


def test_backfill_recovers_the_outcome_column_from_result_json(
        tmp_path, monkeypatch):
    """The outcome column comes from the durable result, not the log.

    It was empty for every row of bench_20260904_165741 because the log
    parser still expected the old '✓ <cve>: <status>' line while cve-agent
    prints '<cve>: <summary_state>'. summary_state cannot be reverse-mapped
    (it collapses escalation into SECURITY_REVIEW_REQUIRED), so the value is
    read from result.json's legacy_status instead.
    """
    outcome = ResultOutcome(
        WorkflowStatus.ESCALATED, BuildStatus.NOT_RUN,
        SecurityStatus.PLAUSIBLE_NEEDS_REVIEW)
    results_dir = _make_results_dir(
        tmp_path, monkeypatch, outcome, status=ResultStatus.ESCALATED)
    # The log carries only the current, lossy summary line.
    (results_dir / f"{CVE}_{MODEL}.log").write_text(
        f"{CVE}: SECURITY_REVIEW_REQUIRED\n", encoding="utf-8")
    _write_csv(results_dir, [_row()])

    rows, _, _ = backfill(results_dir, "kiro", force=False, dry_run=False)

    assert rows[0]["outcome"] == "escalated"


def test_existing_comparison_is_kept_while_outcome_is_recovered(
        tmp_path, monkeypatch):
    """A row the live run compared keeps its bucket but gains its outcome.

    The live comparison ran against the real OE tree, so it stays
    authoritative; the outcome column was never populated for any row and is
    recovered regardless.
    """
    results_dir = _make_results_dir(tmp_path, monkeypatch, _completed_outcome())
    _write_csv(results_dir, [_row(diff_bucket="major", diff_lines="900")])

    rows, log, _ = backfill(results_dir, "kiro", force=False, dry_run=False)

    assert rows[0]["diff_bucket"] == "major"
    assert rows[0]["diff_lines"] == "900"
    assert rows[0]["outcome"] == "success"
    assert "kept existing comparison" in "\n".join(log)


def test_write_rows_backs_up_the_original_once(tmp_path):
    """The first write preserves the untouched CSV for comparison."""
    csv_path = _write_csv(tmp_path, [_row()])
    original = csv_path.read_text(encoding="utf-8")

    write_rows(csv_path, [_row(diff_bucket="minor")])
    backup = csv_path.with_suffix(".csv.orig")
    assert backup.read_text(encoding="utf-8") == original
    assert "minor" in csv_path.read_text(encoding="utf-8")

    write_rows(csv_path, [_row(diff_bucket="major")])
    assert backup.read_text(encoding="utf-8") == original
