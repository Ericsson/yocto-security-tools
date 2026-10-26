#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Judge the review-required results of a bulk integration run.

``test_cve_corrector.sh`` marks a CVE ``SECURITY_REVIEW_REQUIRED`` (or
``WORKFLOW_COMPLETED_UNVERIFIED``) when it produced a patch that the automatic
checks could not confirm.  This tool gives those rows a second opinion with the
benchmark's judge: it compares each generated patch with the human reference
patch the harness saved, buckets the difference the way the benchmark does, and
asks the judge whether a remaining difference is ``meaningful`` or
``stylistic``.

It works from durable files only -- ``results_full.csv``, the saved
``full_<cve>_*.patch`` reference copies and each CVE's
``<cve>_full_artifacts/final-commits.patch`` -- so it needs no Yocto
environment and can run while a campaign is still going.  The only external
call is the judge itself.

Rows that need no judge call get a verdict of their own: ``identical``,
``file-mismatch``, ``structural-only``, ``comment-only``, ``no-patch`` (the
agent escalated without committing anything) and ``no-reference``.  A judge
call that returns nothing usable is not recorded, so the next run retries it.
The output is resumable: CVEs already in ``judge_results.csv`` are skipped.

The verdict measures similarity to the reference only.  There is no build or
test behind it, and a reference written for a different version can make a
sound patch look ``meaningful``.

Usage:
    python3 tests/benchmark/judge_campaign.py <results-dir> [--dry-run]
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import glob
import io
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.benchmark.backfill_diffs import candidate_patch  # noqa: E402
from tests.benchmark.bench_lib import (  # noqa: E402
    JUDGEABLE_BUCKETS,
    classify_diff_bucket,
    count_diff_changed_lines,
    judge_diff,
    scope_diff_to_common_files,
)
from tests.integration.test_utils import compare_patches_detailed  # noqa: E402

REVIEW_STATUSES = ("SECURITY_REVIEW_REQUIRED", "WORKFLOW_COMPLETED_UNVERIFIED")
DEFAULT_JUDGE_MODEL = "claude-opus-5.5"
DEFAULT_JUDGE_BACKEND = "kiro"
OUTPUT_COLUMNS = (
    "cve_id", "recipe", "status", "bucket", "diff_lines", "judgment", "reason",
    "judge_model", "judge_credits", "scope",
)

Judge = Callable[..., tuple[str, str, str, float | None]]


def reference_patches(results_dir: Path, cve_id: str, mode: str = "full") -> list[Path]:
    """Return the saved reference copies of the recipe's original patches.

    Mirrors ``compare_patches_detailed`` in ``tests/integration/test_common.sh``:
    the ``<mode>_<cve>_*`` copies, minus comparison outputs and agent copies.
    """
    pattern = f"{mode}_{glob.escape(cve_id)}_*.patch"
    return [
        path for path in sorted(results_dir.glob(pattern))
        if not path.name.endswith("_diff.patch") and "_agent_" not in path.name
    ]


def read_review_rows(csv_path: Path) -> list[dict[str, str]]:
    """Return the review-required rows of a results CSV."""
    with csv_path.open(newline="", encoding="utf-8") as handle:
        return [row for row in csv.DictReader(handle) if row["status"] in REVIEW_STATUSES]


def read_judged(output_csv: Path) -> dict[str, str]:
    """Return ``{cve_id: judge_model}`` for rows already in the output CSV."""
    if not output_csv.is_file():
        return {}
    with output_csv.open(newline="", encoding="utf-8") as handle:
        return {row["cve_id"]: row.get("judge_model", "") for row in csv.DictReader(handle)}


def compare_row(out_dir: Path, cve_id: str, references: list[Path],
                candidate: Path) -> tuple[str, int, str]:
    """Compare one CVE's patches and return its bucket, size and judged diff text.

    For a ``partial`` overlap the diff is scoped to the files both sides touch,
    exactly as the benchmark does; its size is the scoped size.
    """
    report = out_dir / f"{cve_id}_differences.txt"
    with contextlib.redirect_stdout(io.StringIO()):  # it prints DIFF_* lines for the shell
        compare_patches_detailed([str(p) for p in references], [str(candidate)], str(report))
    text = report.read_text(encoding="utf-8", errors="replace") if report.is_file() else ""
    bucket = classify_diff_bucket(text or None)
    scoped = out_dir / f"{cve_id}_differences_diff.patch"
    diff_text = scoped.read_text(encoding="utf-8", errors="replace") if scoped.is_file() else ""
    if bucket == "partial":
        diff_text = scope_diff_to_common_files(diff_text)
    return bucket, count_diff_changed_lines(diff_text), diff_text


def judge_row(results_dir: Path, out_dir: Path, row: dict[str, str], *,
              judge_model: str, backend: str, dry_run: bool,
              judge: Judge) -> dict[str, str] | None:
    """Build one output row, or ``None`` when the judge gave nothing usable."""
    cve_id = row["cve_id"]
    base = {name: "" for name in OUTPUT_COLUMNS}
    base.update(cve_id=cve_id, recipe=row.get("recipe", ""), status=row["status"],
                bucket="-", diff_lines="-", scope="full")

    candidate = candidate_patch(results_dir / f"{cve_id}_full_artifacts")
    if candidate is None:
        base.update(judgment="no-patch",
                    reason="The agent finished without committing a patch.")
        return base
    references = reference_patches(results_dir, cve_id)
    if not references:
        base.update(judgment="no-reference",
                    reason="No saved reference patch to compare against.")
        return base

    bucket, lines, diff_text = compare_row(out_dir, cve_id, references, candidate)
    base.update(bucket=bucket, diff_lines=str(lines))
    if bucket not in JUDGEABLE_BUCKETS:  # identical, or file-mismatch (nothing shared)
        base["judgment"] = bucket
        return base
    if bucket == "partial":
        base["scope"] = "partial"
    if not diff_text.strip():
        base.update(judgment="structural-only",
                    reason="Shared files are identical; only the set of touched files differs.")
        return base
    if dry_run:
        base["judgment"] = "pending"
        return base

    judgment, reason, full_reason, credits = judge(
        diff_text, model=judge_model, backend=backend)
    if judgment == "meaningful" and not reason and credits is None:
        # judge_diff defaults to 'meaningful' when the reply had no verdict, so
        # an empty reason with no credits line means the call produced nothing.
        return None
    base.update(judgment=judgment, reason=reason, judge_model=judge_model,
                judge_credits="" if credits is None else str(credits))
    (out_dir / f"{cve_id}_judge-reason.txt").write_text(
        (full_reason or reason or "(no reason given)") + "\n", encoding="utf-8")
    return base


def run(results_dir: Path, *, csv_name: str = "results_full.csv",
        judge_model: str = DEFAULT_JUDGE_MODEL, backend: str = DEFAULT_JUDGE_BACKEND,
        limit: int | None = None, dry_run: bool = False,
        judge: Judge = judge_diff, log: Callable[[str], None] = print) -> Counter:
    """Judge the review-required rows and return a count per judgment."""
    csv_path = results_dir / csv_name
    out_dir = results_dir / "judge"
    output_csv = out_dir / "judge_results.csv"
    rows = read_review_rows(csv_path)
    judged = read_judged(output_csv)
    mixed = sorted({model for model in judged.values() if model and model != judge_model})
    if mixed:
        raise SystemExit(
            f"{output_csv} already holds verdicts from {', '.join(mixed)}; refusing to mix in "
            f"{judge_model}. Use another results copy or remove the file.")
    pending = [row for row in rows if row["cve_id"] not in judged]
    todo = pending if limit is None else pending[:limit]
    log(f"{len(rows)} review-required rows, {len(rows) - len(pending)} already judged, "
        f"{len(todo)} to do ({'dry run' if dry_run else judge_model})")

    out_dir.mkdir(exist_ok=True)
    counts: Counter = Counter()
    new_file = not output_csv.is_file()
    handle = None if dry_run else output_csv.open("a", newline="", encoding="utf-8")
    try:
        writer = csv.DictWriter(handle, fieldnames=list(OUTPUT_COLUMNS)) if handle else None
        if writer and new_file:
            writer.writeheader()
        for index, row in enumerate(todo, 1):
            try:
                result = judge_row(results_dir, out_dir, row, judge_model=judge_model,
                                   backend=backend, dry_run=dry_run, judge=judge)
            except (OSError, ValueError) as exc:
                log(f"[{index}/{len(todo)}] {row['cve_id']}: error, will retry later: {exc}")
                counts["error"] += 1
                continue
            if result is None:
                log(f"[{index}/{len(todo)}] {row['cve_id']}: the judge returned nothing, "
                    "will retry later")
                counts["error"] += 1
                continue
            counts[result["judgment"]] += 1
            log(f"[{index}/{len(todo)}] {row['cve_id']} ({row['recipe']}): "
                f"{result['bucket']}/{result['judgment']} {result['reason'][:90]}")
            if writer and handle:
                writer.writerow(result)
                handle.flush()
    finally:
        if handle:
            handle.close()
    return counts


def main() -> None:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("results_dir", type=Path,
                        help="Integration results directory containing results_full.csv")
    parser.add_argument("--csv", default="results_full.csv", help="Results CSV name")
    parser.add_argument("--judge-model", default=DEFAULT_JUDGE_MODEL,
                        help=f"Judge model (default: {DEFAULT_JUDGE_MODEL})")
    parser.add_argument("--judge-backend", default=DEFAULT_JUDGE_BACKEND,
                        help="kiro (default), openai, or openai-<profile>")
    parser.add_argument("--limit", type=int, help="Judge at most this many rows")
    parser.add_argument("--dry-run", action="store_true",
                        help="Compare and bucket only; make no judge calls, write no CSV")
    args = parser.parse_args()

    results_dir = args.results_dir.resolve()
    if not (results_dir / args.csv).is_file():
        parser.error(f"no {args.csv} in {results_dir}")
    counts = run(results_dir, csv_name=args.csv, judge_model=args.judge_model,
                 backend=args.judge_backend, limit=args.limit, dry_run=args.dry_run)
    print("\nVerdicts: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))


if __name__ == "__main__":
    main()
