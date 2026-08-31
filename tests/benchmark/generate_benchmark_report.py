#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Generate a model benchmark report from run_benchmark.sh results.

Reads agent_results.csv and judge_results.csv from a results directory,
joins them on (cve_id, model), and produces markdown with a per-model
summary, a per-tier bucket distribution, and a meaningful-vs-stylistic split
for the judged (moderate/major/partial) subset. Bucket names/thresholds mirror
tests/integration/generate_differences_report.py rather than restating them.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tests.benchmark.bench_lib import JUDGEABLE_BUCKETS  # noqa: E402

# Same bucket set generate_differences_report.py classifies diffs into, plus
# 'partial' (fileset overlap, judged on the shared files — see
# bench_lib.scope_diff_to_common_files).
DIFF_BUCKETS = ("identical", "minor", "moderate", "major", "partial", "file-mismatch")

# Judge model used by run_benchmark.sh's phase 2 — fixed, and deliberately
# not part of the model roster being benchmarked (see bench_lib.judge_diff).
JUDGE_MODEL_NOTE = "claude-opus-4.8"


def read_csv(path: Path) -> list[dict[str, str]]:
    """Read a CSV into a list of row dicts. Missing file -> empty list."""
    if not path.is_file():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _to_float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def generate_report(results_dir: Path) -> str:
    """Generate the full benchmark report as markdown text."""
    agent_csv = results_dir / "agent_results.csv"
    if not agent_csv.exists():
        sys.exit(f"ERROR: {agent_csv} not found")

    agent_rows = read_csv(agent_csv)
    judge_rows = read_csv(results_dir / "judge_results.csv")
    judge_by_key = {(row["cve_id"], row["model"]): row for row in judge_rows}

    lines: list[str] = []
    lines.append("# CVE Agent Model Benchmark Report")
    lines.append("")
    lines.append(f"**Results directory:** `{results_dir}`")
    lines.append("")
    lines.append(
        f"Judge model (fixed, non-roster): `{JUDGE_MODEL_NOTE}` — used only "
        "to classify moderate/major diffs as meaningful or stylistic; it "
        "is never one of the models being benchmarked."
    )
    lines.append("")

    # --- Per-model summary ---
    by_model: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in agent_rows:
        by_model[row["model"]].append(row)

    lines.append("## Per-Model Summary")
    lines.append("")
    lines.append("| Model | Runs | Total Credits | Avg Duration (s) | Avg Commands |")
    lines.append("|-------|------|---------------|-------------------|--------------|")
    for model in sorted(by_model):
        rows = by_model[model]
        credits = [c for c in (_to_float(r.get("credits", "")) for r in rows) if c is not None]
        durations = [c for c in (_to_float(r.get("duration_s", "")) for r in rows) if c is not None]
        commands = [c for c in (_to_float(r.get("commands", "")) for r in rows) if c is not None]
        total_credits = sum(credits) if credits else 0.0
        avg_duration = sum(durations) / len(durations) if durations else 0.0
        avg_commands = sum(commands) / len(commands) if commands else 0.0
        lines.append(
            f"| {model} | {len(rows)} | {total_credits:.2f} "
            f"| {avg_duration:.1f} | {avg_commands:.1f} |"
        )
    lines.append("")

    # --- Per-tier bucket distribution ---
    by_tier: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in agent_rows:
        by_tier[row["tier"]].append(row)

    lines.append("## Per-Tier Bucket Distribution")
    lines.append("")
    header = "| Tier | " + " | ".join(DIFF_BUCKETS) + " |"
    sep = "|------|" + "|".join("-" * (len(b) + 2) for b in DIFF_BUCKETS) + "|"
    lines.append(header)
    lines.append(sep)
    # Known resolution tiers first (score_tier's order), then any other
    # value actually present -- e.g. "clean_apply" from a run against
    # benchmark-roster-clean-apply.json, which has no tier/score_tier at
    # all. Iterating only the fixed three would silently drop those rows.
    known_tiers = ("easy", "medium", "hard")
    other_tiers = sorted(t for t in by_tier if t not in known_tiers)
    for tier in (*known_tiers, *other_tiers):
        rows = by_tier.get(tier, [])
        counts = {b: 0 for b in DIFF_BUCKETS}
        for row in rows:
            bucket = row.get("diff_bucket", "")
            if bucket in counts:
                counts[bucket] += 1
        lines.append(
            f"| {tier} | " + " | ".join(str(counts[b]) for b in DIFF_BUCKETS) + " |"
        )
    lines.append("")

    # --- Meaningful vs stylistic split (judged moderate/major/partial subset) ---
    judged_subset = [row for row in agent_rows if row.get("diff_bucket") in JUDGEABLE_BUCKETS]

    lines.append("## Meaningful vs Stylistic (Judged Moderate/Major/Partial Diffs)")
    lines.append("")
    lines.append(
        "_Structural-only: a `partial` fileset overlap whose shared files were "
        "identical, so only the set of touched files differed — not sent to "
        "the judge. Comment-only: every remaining changed line was a comment, "
        "so the code is equivalent — also not sent to the judge._"
    )
    lines.append("")
    lines.append("| Model | Meaningful | Stylistic | Comment-only | Structural-only "
                 "| Not Yet Judged |")
    lines.append("|-------|------------|-----------|--------------|-----------------"
                 "|-----------------|")
    for model in sorted(by_model):
        model_judged = [row for row in judged_subset if row["model"] == model]
        meaningful = stylistic = comment_only = structural_only = not_judged = 0
        for row in model_judged:
            key = (row["cve_id"], row["model"])
            judge_row = judge_by_key.get(key)
            if judge_row is None:
                not_judged += 1
            elif judge_row.get("judgment") == "meaningful":
                meaningful += 1
            elif judge_row.get("judgment") == "stylistic":
                stylistic += 1
            elif judge_row.get("judgment") == "comment-only":
                comment_only += 1
            elif judge_row.get("judgment") == "structural-only":
                structural_only += 1
            else:
                not_judged += 1
        if not model_judged:
            continue
        lines.append(
            f"| {model} | {meaningful} | {stylistic} | {comment_only} "
            f"| {structural_only} | {not_judged} |"
        )
    lines.append("")

    # --- Per-verdict reasoning ------------------------------------------------
    # The judge's own justification, so a verdict can be sanity-checked without
    # opening the diff. Older results dirs have no 'reason' column; skip the
    # section entirely rather than printing a table of blanks.
    reasoned = [row for row in judge_rows if (row.get("reason") or "").strip()]
    if reasoned:
        lines.append("## Judge Reasoning")
        lines.append("")
        lines.append("| CVE | Model | Verdict | Reason |")
        lines.append("|-----|-------|---------|--------|")
        for row in sorted(reasoned, key=lambda r: (r["cve_id"], r["model"])):
            # '|' would break the markdown table; the reason is free-form prose.
            reason = row["reason"].replace("|", "\\|")
            lines.append(
                f"| {row['cve_id']} | {row['model']} | {row.get('judgment', '')} "
                f"| {reason} |"
            )
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    """Entry point for the benchmark report generator."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "results_dir",
        type=Path,
        help="Path to the benchmark results directory (e.g., bench_20260814_120000)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=None,
        help="Output file path (default: <results_dir>/benchmark_report.md)",
    )
    args = parser.parse_args()

    if not args.results_dir.is_dir():
        sys.exit(f"ERROR: {args.results_dir} is not a directory")

    report = generate_report(args.results_dir)

    output_path = args.output or (args.results_dir / "benchmark_report.md")
    output_path.write_text(report)
    print(f"Report written to: {output_path}")


if __name__ == "__main__":
    main()
