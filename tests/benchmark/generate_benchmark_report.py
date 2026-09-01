#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Generate a model benchmark report from run_benchmark.sh results.

Reads agent_results.csv and judge_results.csv from a results directory,
joins them on (cve_id, model), and produces markdown with a per-model
summary, a per-tier bucket distribution, and a meaningful-vs-stylistic split
for the judged (minor/moderate/major/partial) subset. Bucket names/thresholds
mirror tests/integration/generate_differences_report.py rather than restating
them.
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

# cve_agent.ResultStatus values, ordered best-to-worst as a backport result
# rather than by exit code. See the Per-Model Outcomes note in the report for
# why exit status alone is misleading.
OUTCOMES = ("conflict_resolved", "success", "skipped", "escalated", "failed")

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

    # --- Per-model outcome distribution ---
    # The headline "did it work" signal, and deliberately separate from the
    # exit status: cve-agent exits 0 for both a real backport and a "not
    # applicable" verdict, and exits 14 for both an honest escalation and a
    # genuine failure. Ranking models on the exit code alone therefore rewards
    # a confident wrong dismissal over a correct refusal to guess.
    lines.append("## Per-Model Outcomes")
    lines.append("")
    lines.append(
        "_`conflict_resolved`/`success` produced a patch. `skipped` means the "
        "model judged the CVE **not applicable** — it exits 0 and looks like a "
        "pass, but no backport was produced, and if the verdict is wrong a live "
        "vulnerability was dismissed; check these before trusting them. "
        "`escalated` means the model declined to guess and asked for a human, "
        "which is the **intended** outcome when the fix cannot be made in "
        "scope, even though it exits non-zero. Only `failed` is an outright "
        "breakage._"
    )
    lines.append("")
    outcome_header = "| Model | " + " | ".join(OUTCOMES) + " | (no outcome) |"
    outcome_sep = ("|-------|" + "|".join("-" * (len(o) + 2) for o in OUTCOMES)
                   + "|--------------|")
    lines.append(outcome_header)
    lines.append(outcome_sep)
    for model in sorted(by_model):
        outcome_counts: dict[str, int] = {o: 0 for o in OUTCOMES}
        unknown = 0
        for row in by_model[model]:
            outcome = (row.get("outcome") or "").strip()
            if outcome in outcome_counts:
                outcome_counts[outcome] += 1
            else:
                unknown += 1
        cells = " | ".join(str(outcome_counts[o]) for o in OUTCOMES)
        lines.append(f"| {model} | {cells} | {unknown} |")
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

    # --- Meaningful vs stylistic split (judged minor/moderate/major/partial subset) ---
    judged_subset = [row for row in agent_rows if row.get("diff_bucket") in JUDGEABLE_BUCKETS]

    lines.append("## Meaningful vs Stylistic (Judged Minor/Moderate/Major/Partial Diffs)")
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

    # --- Not-applicable audit ------------------------------------------------
    # Every `skipped` row asserts a CVE does not affect this recipe version.
    # That claim exits 0 and is otherwise invisible in the report, so list them
    # explicitly: a wrong one silently leaves a live vulnerability unpatched,
    # and the models disagreeing with each other on the same CVE is the
    # cheapest signal that one of them is wrong.
    dismissed: dict[str, list[str]] = defaultdict(list)
    for row in agent_rows:
        if (row.get("outcome") or "").strip() == "skipped":
            dismissed[row["cve_id"]].append(row["model"])
    if dismissed:
        lines.append("## Not-Applicable Verdicts (verify these)")
        lines.append("")
        lines.append(
            "_Each row is a model asserting the CVE does not affect this "
            "recipe version, which exits 0 and counts as a pass. A wrong "
            "verdict here leaves a live vulnerability unpatched. Where the "
            "**Models** column does not list every model that ran the CVE, "
            "the others disagreed — at least one side is wrong._"
        )
        lines.append("")
        ran_per_cve: dict[str, int] = defaultdict(int)
        for row in agent_rows:
            ran_per_cve[row["cve_id"]] += 1
        lines.append("| CVE | Dismissed by | Of runs | Models |")
        lines.append("|-----|--------------|---------|--------|")
        for cve in sorted(dismissed):
            models = sorted(dismissed[cve])
            lines.append(
                f"| {cve} | {len(models)} | {ran_per_cve[cve]} "
                f"| {', '.join(models)} |"
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
