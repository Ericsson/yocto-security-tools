#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Recompute a finished benchmark's patch comparison from durable artifacts.

``run_benchmark.sh`` compares each generated backport against the human
reference patch at the end of every run, while the generated patch still sits
in the OE tree. When that comparison does not happen, the row keeps
``diff_bucket='-'``, and because ``bench_lib.filter_for_judging`` only judges
``minor``/``moderate``/``major``/``partial``, the judge phase silently skips
it — so the whole leaderboard collapses to a handful of judged rows.

Re-running the agent to recover those rows costs the full model spend again.
It is also unnecessary: every attempt writes its final candidate commits to a
durable, host-owned artifact directory (``final-commits.patch``, see
``docs/agent-artifacts.md``), which survives ``reset_oe_tree``. This tool
replays only the comparison step from those artifacts, updates
``agent_results.csv`` in place, and writes the per-model
``*_differences.txt`` / ``*_differences_diff.patch`` files that the judge
phase reads.

It needs no Yocto environment, no OE tree, and no model calls: the reference
side comes from the ``bench_<cve>_*.patch`` copies the run already saved, and
the generated side from the artifact directory. Afterwards, resume the same
results directory to run only the judge phase:

    python3 tests/benchmark/backfill_diffs.py <results-dir>
    tests/benchmark/run_benchmark.sh --resume <results-dir>

Every ``(cve_id, model)`` row already present in ``agent_results.csv`` is
skipped by the resumed agent phase, so that second command judges without
re-running a single backport.
"""

from __future__ import annotations

import argparse
import csv
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.benchmark.bench_lib import (  # noqa: E402
    JUDGEABLE_BUCKETS,
    BenchmarkArtifactExpectation,
    benchmark_artifact_outcome,
    classify_diff_bucket,
    count_diff_changed_lines,
    parse_agent_outcome,
    parse_skip_reason,
    scope_diff_to_common_files,
)
from tests.benchmark.benchmark_manifest import resolve_backend_identity  # noqa: E402
from tests.integration.test_utils import compare_patches_detailed  # noqa: E402

CSV_COLUMNS = (
    "cve_id", "tier", "model", "exit_status", "outcome", "skip_reason",
    "credits", "duration_s", "commands", "diff_bucket", "diff_lines",
)

# The candidate's final commits, preferred over final.patch: the comparison is
# between commit series, and final.patch is a worktree diff that can be empty
# for a run whose work was already committed.
CANDIDATE_ARTIFACTS = ("final-commits.patch", "final.patch")

MISSING = "-"


@dataclass
class Backfilled:
    """One row's recomputed comparison columns."""

    exit_status: str
    diff_bucket: str
    diff_lines: str
    note: str
    outcome: str = ""
    skip_reason: str = ""


def reference_patches(results_dir: Path, cve_id: str) -> list[Path]:
    """Return the reference patches ``remove_cve_patch`` saved for one CVE.

    Mirrors ``compare_patches_detailed``'s selection in
    ``tests/integration/test_common.sh``: the ``bench_<cve>_*`` copies of the
    recipe's original patches, excluding generated copies and the comparison
    outputs that live in the same directory.
    """
    candidates = []
    for path in sorted(results_dir.glob(f"bench_{cve_id}_*.patch")):
        name = path.name
        if name.endswith("_diff.patch") or "_agent_" in name:
            continue
        candidates.append(path)
    return candidates


def candidate_patch(artifact_dir: Path) -> Path | None:
    """Return the artifact holding this attempt's generated commits."""
    for name in CANDIDATE_ARTIFACTS:
        path = artifact_dir / name
        try:
            if path.is_file() and path.stat().st_size > 0:
                return path
        except OSError:
            continue
    return None


def expectation_for(cve_id: str, model: str,
                    backend: str) -> BenchmarkArtifactExpectation:
    """Build the identity an artifact's manifest must match."""
    identity = resolve_backend_identity(backend, model or None)
    profile = identity["profile"] if isinstance(identity["profile"], str) else None
    return BenchmarkArtifactExpectation(
        cve_id, str(identity["backend"]), profile, str(identity["model"]))


def recover_outcome(results_dir: Path, artifact_dir: Path, cve_id: str,
                    model: str, backend: str) -> tuple[str, str]:
    """Recover the run's own outcome and, if skipped, why.

    The outcome comes from the durable ``result.json`` rather than the log:
    ``summary_state`` maps both a completed-but-review-required run and an
    escalation to ``SECURITY_REVIEW_REQUIRED``, so the printed line cannot
    distinguish an honest escalation from a finished backport awaiting review.
    The skip reason is only derivable from the log, so it is still read there.
    """
    expected = expectation_for(cve_id, model, backend)
    log_path = results_dir / f"{cve_id}_{model}.log"
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    outcome = parse_agent_outcome(text, artifact_dir, expected)
    reason = parse_skip_reason(text) if outcome == "skipped" else ""
    return outcome, reason


def find_artifact_dir(
    results_dir: Path, cve_id: str, model: str, backend: str,
) -> Path | None:
    """Resolve one row's validated artifact directory.

    The host-owned root is ``agent-artifacts/<cve>_<model>.XXXXXX``, and the
    run itself lives under ``<root>/<app>/results/cases/<cve>/<run-id>``.
    Provenance is confirmed with the same manifest binding the live runner
    uses, so an unrelated or tampered directory is never consumed.
    """
    expected = expectation_for(cve_id, model, backend)
    roots = sorted((results_dir / "agent-artifacts").glob(f"{cve_id}_{model}.*"))
    for root in roots:
        for case_root in sorted(root.glob(f"*/results/cases/{cve_id}")):
            for run in sorted(case_root.iterdir()):
                if not run.is_dir() or run.is_symlink():
                    continue
                if benchmark_artifact_outcome(run.resolve(), expected) is not None:
                    return run.resolve()
    return None


def durable_outcome(artifact_dir: Path, cve_id: str, model: str,
                    backend: str) -> tuple[str, str, bool]:
    """Return the row's durable summary state, exit status, and comparability.

    Same contract the runner applies: a verified release reads as ``0``, any
    other valid durable outcome reports its own summary state, and a completed
    built attempt stays comparable even when the release gate rejected it.
    """
    outcome = benchmark_artifact_outcome(
        artifact_dir, expectation_for(cve_id, model, backend))
    if outcome is None:
        return "", "", False
    summary, comparable = outcome
    return summary, ("0" if summary == "SECURITY_VERIFIED" else summary), comparable


def compare_row(results_dir: Path, cve_id: str, model: str,
                references: list[Path], candidate: Path) -> tuple[str, str]:
    """Write one row's comparison reports and return its bucket and size."""
    report = results_dir / f"{cve_id}_{model}_differences.txt"
    compare_patches_detailed(
        [str(path) for path in references], [str(candidate)], str(report))
    try:
        text = report.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    bucket = classify_diff_bucket(text or None)
    scoped = results_dir / f"{cve_id}_{model}_differences_diff.patch"
    try:
        diff_text = scoped.read_text(encoding="utf-8", errors="replace")
    except OSError:
        diff_text = ""
    if bucket == "partial":
        # Report the divergence the judge actually sees: the shared files,
        # not the whole-patch delta dominated by the one-sided files.
        lines = count_diff_changed_lines(scope_diff_to_common_files(diff_text))
    else:
        lines = count_diff_changed_lines(diff_text)
    return bucket, str(lines)


def backfill_row(results_dir: Path, row: dict[str, str], backend: str,
                 *, compare: bool = True) -> Backfilled | None:
    """Recompute one row, or return ``None`` when nothing can be recovered.

    Reproduces the runner's own bucket rules rather than inventing new ones:
    a durable ``SKIPPED`` state has no candidate by definition, a completed
    built attempt is compared even when the release gate rejected it, and any
    other non-comparable outcome (escalated, failed) keeps ``'-'``.

    With ``compare=False`` the existing bucket is left exactly as the live run
    recorded it — that comparison ran against the real OE tree and is the more
    authoritative of the two — while the outcome and exit status are still
    recovered from the durable result.
    """
    cve_id, model = row["cve_id"], row["model"]
    artifact_dir = find_artifact_dir(results_dir, cve_id, model, backend)
    if artifact_dir is None:
        return Backfilled(row["exit_status"], row["diff_bucket"],
                          row["diff_lines"], "no validated artifact directory",
                          row.get("outcome", ""), row.get("skip_reason", ""))

    summary, exit_status, comparable = durable_outcome(
        artifact_dir, cve_id, model, backend)
    exit_status = exit_status or row["exit_status"]
    outcome, skip_reason = recover_outcome(
        results_dir, artifact_dir, cve_id, model, backend)
    outcome = outcome or row.get("outcome", "")
    skip_reason = skip_reason or row.get("skip_reason", "")

    if not compare:
        return Backfilled(exit_status, row["diff_bucket"], row["diff_lines"],
                          "kept existing comparison", outcome, skip_reason)
    if summary == "SKIPPED":
        return Backfilled(exit_status, "skipped", MISSING,
                          "durable outcome is SKIPPED (no candidate)",
                          outcome, skip_reason)
    if not comparable and exit_status != "0":
        return Backfilled(exit_status, row["diff_bucket"], row["diff_lines"],
                          f"{summary or 'unknown'} is not comparable",
                          outcome, skip_reason)

    references = reference_patches(results_dir, cve_id)
    if not references:
        return Backfilled(exit_status, row["diff_bucket"], row["diff_lines"],
                          "no saved reference patch", outcome, skip_reason)
    candidate = candidate_patch(artifact_dir)
    if candidate is None:
        return Backfilled(exit_status, row["diff_bucket"], row["diff_lines"],
                          "artifact holds no generated commits",
                          outcome, skip_reason)

    bucket, lines = compare_row(
        results_dir, cve_id, model, references, candidate)
    return Backfilled(exit_status, bucket, lines,
                      f"compared via {candidate.name}", outcome, skip_reason)


def backfill(results_dir: Path, backend: str, *, force: bool,
             dry_run: bool) -> tuple[list[dict[str, str]], list[str], dict[str, int]]:
    """Recompute every eligible row.

    Returns the rows, a human-readable log, and the resulting bucket
    distribution. The distribution is the *projected* one even for a dry run,
    so the preview reports what the update would achieve rather than the
    unchanged state it leaves behind.
    """
    csv_path = results_dir / "agent_results.csv"
    with csv_path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    log: list[str] = []
    buckets: dict[str, int] = {}

    def record(bucket: str) -> None:
        buckets[bucket] = buckets.get(bucket, 0) + 1

    for row in rows:
        label = f"{row['cve_id']} / {row['model']}"
        # A row the live run already compared keeps that bucket: it was
        # measured against the real OE tree. The outcome column is still
        # recovered, since it was never populated for any row.
        compare = row.get("diff_bucket", MISSING) == MISSING or force
        result = backfill_row(results_dir, row, backend, compare=compare)
        if result is None:
            record(row.get("diff_bucket", MISSING))
            continue
        changed = (result.exit_status != row["exit_status"]
                   or result.diff_bucket != row["diff_bucket"]
                   or result.outcome != row.get("outcome", ""))
        log.append(
            f"{'WOULD ' if dry_run else ''}"
            f"{'UPDATE' if changed else 'KEEP'} {label}: "
            f"exit={result.exit_status} outcome={result.outcome or '?'} "
            f"bucket={result.diff_bucket} "
            f"lines={result.diff_lines} ({result.note})")
        record(result.diff_bucket)
        if not dry_run:
            row["exit_status"] = result.exit_status
            row["diff_bucket"] = result.diff_bucket
            row["diff_lines"] = result.diff_lines
            row["outcome"] = result.outcome
            row["skip_reason"] = result.skip_reason
    return rows, log, buckets


def write_rows(csv_path: Path, rows: list[dict[str, str]]) -> None:
    """Replace ``agent_results.csv`` after backing up the original once."""
    backup = csv_path.with_suffix(".csv.orig")
    if not backup.exists():
        shutil.copy2(csv_path, backup)
    temporary = csv_path.with_suffix(".csv.tmp")
    with temporary.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(CSV_COLUMNS))
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in CSV_COLUMNS})
    temporary.replace(csv_path)


def main() -> None:
    """Entry point."""
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "results_dir", type=Path,
        help="Benchmark results directory containing agent_results.csv")
    parser.add_argument(
        "--backend", default="kiro",
        help="Agent backend selector the run used (default: kiro)")
    parser.add_argument(
        "--force", action="store_true",
        help="Recompute rows that already have a diff_bucket")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report what would change without writing anything")
    args = parser.parse_args()

    results_dir = args.results_dir.resolve()
    csv_path = results_dir / "agent_results.csv"
    if not csv_path.is_file():
        parser.error(f"no agent_results.csv in {results_dir}")

    rows, log, buckets = backfill(
        results_dir, args.backend, force=args.force, dry_run=args.dry_run)
    for line in log:
        print(line)

    judgeable = sum(count for name, count in buckets.items()
                    if name in JUDGEABLE_BUCKETS)
    print("\nBucket distribution: "
          + ", ".join(f"{name}={count}"
                      for name, count in sorted(buckets.items())))
    print(f"Judgeable rows (bucket in {'/'.join(JUDGEABLE_BUCKETS)}): {judgeable}")

    if args.dry_run:
        print("\nDry run: agent_results.csv left unchanged.")
        return
    write_rows(csv_path, rows)
    print(f"\nUpdated {csv_path} (original saved as {csv_path.name}.orig).")
    print("Run the judge phase without re-running backports:\n"
          f"  tests/benchmark/run_benchmark.sh --resume {results_dir}")


if __name__ == "__main__":
    main()
