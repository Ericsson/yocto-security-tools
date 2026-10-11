#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Standalone plotting of a bulk cve-corrector/cve-agent integration test run.

Reads ``results_<mode>.csv`` from a bulk test-results directory (produced by
``tests/integration/test_cve_corrector.sh``, see also
``tests/integration/result_schema.py``) and generates PNG charts breaking
down the per-CVE ``status`` column.

Why not just "success/fail": the ``status`` column already distinguishes
*how* a CVE reached its outcome, and collapsing that distinction loses the
one thing this test run is meant to answer — how much of the result is
cve-corrector alone vs. cve-agent stepping in after a recoverable failure.
A CVE whose patch applied cleanly (``IDENTICAL``/``SUCCESS``/
``ALREADY_APPLIED``) never invoked the AI backend at all; ``AGENT_RESOLVED``
means cve-agent resolved a conflict/build/ptest failure and the result passed
the semantic security gate; ``SECURITY_REVIEW_REQUIRED`` and
``WORKFLOW_COMPLETED_UNVERIFIED`` mean a patch exists (the workflow and build
completed) but automatic verification could not confirm it is a correct fix,
so it is kept visually distinct from a verified success rather than folded
into it.

Colors come from the Okabe-Ito palette (distinguishable under the common
forms of color blindness) and every bar is annotated with its value, so no
chart depends on hue alone being read correctly.

This is a standalone, dev-only tool. It is NOT part of the installed
yocto-security-tools package and requires matplotlib, which is not a runtime
dependency of the project (see AGENTS.md "Minimize Dependencies").

Usage:
    pip install matplotlib
    python3 tools/plot_corrector_results.py \\
        tests/integration/test-results/bulk_20261001_153754 \\
        --mode full-enriched --output-dir plots/
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

# --- Outcome taxonomy -------------------------------------------------------
#
# One bucket per distinct status the shell runner can write to the CSV (see
# classify_agent_summary() and run_loop() in test_cve_corrector.sh). Grouped
# into five families so the chart legend stays readable regardless of how
# many distinct FAIL_*/SKIP_* codes a given run produced.

FAMILY_DIRECT_SUCCESS = 'direct success'
FAMILY_AGENT_VERIFIED = 'agent-resolved (verified)'
FAMILY_NEEDS_REVIEW = 'produced a patch, needs review'
FAMILY_SKIPPED = 'skipped'
FAMILY_FAILED = 'failed'

# Statuses cve-corrector reaches without any AI backend involvement at all.
DIRECT_SUCCESS_STATUSES = ('IDENTICAL', 'SUCCESS', 'ALREADY_APPLIED')

# cve-agent was invoked after a recoverable corrector failure and the result
# passed the semantic security-equivalence gate (SECURITY_VERIFIED).
AGENT_VERIFIED_STATUSES = ('AGENT_RESOLVED',)

# A patch exists and the workflow/build completed, but automatic
# verification could not confirm correctness — these are NOT the same as a
# verified success and must stay visually distinct from it, even though a
# patch was "produced".
NEEDS_REVIEW_STATUSES = ('SECURITY_REVIEW_REQUIRED', 'WORKFLOW_COMPLETED_UNVERIFIED')

# Family membership is resolved by prefix for the open-ended SKIP_*/FAIL_*
# codes, and by exact match for everything else.
FAMILY_ORDER = (
    FAMILY_DIRECT_SUCCESS,
    FAMILY_AGENT_VERIFIED,
    FAMILY_NEEDS_REVIEW,
    FAMILY_SKIPPED,
    FAMILY_FAILED,
)

FAMILY_COLORS = {
    FAMILY_DIRECT_SUCCESS: '#009E73',
    FAMILY_AGENT_VERIFIED: '#0072B2',
    FAMILY_NEEDS_REVIEW: '#CC79A7',
    FAMILY_SKIPPED: '#999999',
    FAMILY_FAILED: '#D55E00',
}


def classify_family(status: str) -> str:
    """Map a raw ``status`` CSV value to one of the five outcome families.

    Args:
        status: The ``status`` column value for one CVE row.

    Returns:
        One of the ``FAMILY_*`` constants.
    """
    if status in DIRECT_SUCCESS_STATUSES:
        return FAMILY_DIRECT_SUCCESS
    if status in AGENT_VERIFIED_STATUSES:
        return FAMILY_AGENT_VERIFIED
    if status in NEEDS_REVIEW_STATUSES:
        return FAMILY_NEEDS_REVIEW
    if status.startswith('SKIP'):
        return FAMILY_SKIPPED
    # Treat anything else (FAIL_*, and any future status not yet listed
    # above) as a failure rather than silently dropping it from the chart.
    return FAMILY_FAILED


# --- Data loading ------------------------------------------------------------


def read_results_csv(path: Path) -> list[dict[str, str]]:
    """Read a ``results_<mode>.csv`` file into a list of row dicts.

    Args:
        path: Path to the results CSV.

    Returns:
        Row dicts in file order.

    Raises:
        SystemExit: If the file does not exist or has no data rows.
    """
    if not path.is_file():
        raise SystemExit(f'error: {path} does not exist')
    with open(path, newline='', encoding='utf-8') as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        raise SystemExit(f'error: {path} has no data rows — nothing to plot')
    return rows


def find_results_csv(results_dir: Path, mode: str | None) -> Path:
    """Locate the ``results_<mode>.csv`` file to plot.

    Args:
        results_dir: Bulk test-results directory.
        mode: Explicit mode suffix (e.g. ``full-enriched``), or ``None`` to
            auto-detect when exactly one ``results_*.csv`` is present.

    Returns:
        Path to the resolved CSV file.

    Raises:
        SystemExit: If no file matches, or if ``mode`` is omitted and more
            than one candidate CSV exists (ambiguous auto-detection must fail
            loudly rather than silently pick one).
    """
    if mode:
        return results_dir / f'results_{mode}.csv'
    candidates = sorted(results_dir.glob('results_*.csv'))
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise SystemExit(f'error: no results_*.csv found in {results_dir}')
    names = ', '.join(c.name for c in candidates)
    raise SystemExit(
        f'error: multiple results CSVs found ({names}) — pass --mode to pick one'
    )


# --- Aggregation --------------------------------------------------------------


def status_counts(rows: list[dict[str, str]]) -> Counter[str]:
    """Count rows per raw ``status`` value, in CSV order of first appearance.

    Args:
        rows: Parsed CSV rows.

    Returns:
        A :class:`collections.Counter` keyed by raw status string.
    """
    return Counter(row['status'] for row in rows)


def family_counts(counts: Counter[str]) -> dict[str, Counter[str]]:
    """Group raw status counts into outcome families.

    Args:
        counts: Raw per-status counts, as returned by :func:`status_counts`.

    Returns:
        Mapping of family name to a ``Counter`` of the raw statuses within
        it, so a chart can both size each family and label its composition.
    """
    grouped: dict[str, Counter[str]] = {family: Counter() for family in FAMILY_ORDER}
    for status, count in counts.items():
        grouped[classify_family(status)][status] = count
    return grouped


def recipe_breakdown(rows: list[dict[str, str]]) -> dict[str, Counter[str]]:
    """Count outcome families per recipe.

    Args:
        rows: Parsed CSV rows.

    Returns:
        Mapping of recipe name to a ``Counter`` of outcome families, ordered
        by nothing in particular — callers sort as needed.
    """
    per_recipe: dict[str, Counter[str]] = {}
    for row in rows:
        recipe = row.get('recipe', '') or '(unknown)'
        per_recipe.setdefault(recipe, Counter())[classify_family(row['status'])] += 1
    return per_recipe


# --- Charts ------------------------------------------------------------------


def _caption(fig, text: str) -> None:
    """Attach a small explanatory caption under a figure."""
    fig.text(0.01, 0.01, text, fontsize=7.5, color='#555555', ha='left', va='bottom')


def plot_status_distribution(counts: Counter[str], out_path: Path) -> None:
    """Horizontal bar chart of every raw ``status`` value, colored by family.

    Args:
        counts: Raw per-status counts.
        out_path: PNG output path.
    """
    import matplotlib.pyplot as plt

    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    labels = [status for status, _ in ordered]
    values = [count for _, count in ordered]
    colors = [FAMILY_COLORS[classify_family(status)] for status in labels]
    ypos = list(range(len(labels)))

    fig, ax = plt.subplots(figsize=(9.5, 0.42 * len(labels) + 2.2))
    ax.barh(ypos, values, height=0.62, color=colors, edgecolor='white', linewidth=0.8)
    top = max(values) if values else 1
    for y, value in enumerate(values):
        ax.text(value + top * 0.015, y, str(value), va='center', fontsize=9)

    ax.set_yticks(ypos)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlabel('CVEs')
    ax.set_xlim(0, top * 1.12)
    ax.set_title('Result status distribution', fontsize=13, fontweight='bold')
    ax.grid(axis='x', alpha=0.25, linestyle=':')
    ax.set_axisbelow(True)

    from matplotlib.patches import Patch

    ax.legend(
        handles=[Patch(facecolor=FAMILY_COLORS[f], label=f) for f in FAMILY_ORDER],
        loc='lower right', fontsize=8.5, frameon=False,
    )
    _caption(fig, 'Every distinct status the test runner can emit, colored by outcome family. '
                  'See family_breakdown.png for the same data collapsed to five bars.')
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_family_breakdown(grouped: dict[str, Counter[str]], total: int, out_path: Path) -> None:
    """Single stacked horizontal bar of the five outcome families.

    Args:
        grouped: Per-family raw-status counters, as returned by
            :func:`family_counts`.
        total: Total CVE count, for the percentage labels.
        out_path: PNG output path.
    """
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(9.5, 2.6))
    left = 0.0
    for family in FAMILY_ORDER:
        count = sum(grouped[family].values())
        if not count:
            continue
        ax.barh([0], [count], left=[left], height=0.55, color=FAMILY_COLORS[family],
                edgecolor='white', linewidth=1.0, label=family)
        pct = 100 * count / total if total else 0.0
        ax.text(left + count / 2, 0, f'{count}\n({pct:.0f}%)', ha='center', va='center',
                color='white', fontsize=9.5, fontweight='bold')
        left += count

    ax.set_xlim(0, total)
    ax.set_yticks([])
    ax.set_title(f'Outcome family breakdown  (n={total})', fontsize=13, fontweight='bold')
    ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.25), ncol=5, fontsize=9, frameon=False)
    _caption(fig, '"agent-resolved" passed the semantic security gate after a recoverable '
                  'corrector failure. "needs review" produced a patch and a completed build '
                  'but could not be auto-verified — it is a result worth looking at, not a '
                  'confirmed fix.')
    fig.tight_layout(rect=(0, 0.12, 1, 1))
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_recipe_breakdown(per_recipe: dict[str, Counter[str]], out_path: Path,
                           top_n: int = 25) -> None:
    """Stacked horizontal bars of outcome family per recipe.

    Args:
        per_recipe: Mapping of recipe name to outcome-family counts.
        out_path: PNG output path.
        top_n: Maximum number of recipes to show, ranked by total CVE count,
            so a roster with many single-CVE recipes doesn't produce an
            unreadably tall chart.
    """
    import matplotlib.pyplot as plt

    ranked = sorted(per_recipe.items(), key=lambda kv: -sum(kv[1].values()))[:top_n]
    recipes = [name for name, _ in ranked]
    ypos = list(range(len(recipes)))

    fig, ax = plt.subplots(figsize=(9.5, 0.38 * len(recipes) + 2.2))
    left = [0.0] * len(recipes)
    for family in FAMILY_ORDER:
        widths = [float(per_recipe[r][family]) for r in recipes]
        if not any(widths):
            continue
        ax.barh(ypos, widths, left=left, height=0.62, color=FAMILY_COLORS[family],
                label=family, edgecolor='white', linewidth=0.8)
        for y, (width, start) in enumerate(zip(widths, left, strict=True)):
            if width >= 1:
                ax.text(start + width / 2, y, f'{int(width)}', ha='center', va='center',
                        color='white', fontsize=8)
        left = [a + b for a, b in zip(left, widths, strict=True)]

    ax.set_yticks(ypos)
    ax.set_yticklabels(recipes, fontsize=8.5)
    ax.invert_yaxis()
    ax.set_xlabel('CVEs')
    title = f'Outcome by recipe (top {len(recipes)} by CVE count)' if len(per_recipe) > top_n \
        else 'Outcome by recipe'
    ax.set_title(title, fontsize=13, fontweight='bold')
    ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.14), ncol=5, fontsize=8.5, frameon=False)
    ax.grid(axis='x', alpha=0.25, linestyle=':')
    ax.set_axisbelow(True)
    _caption(fig, 'A recipe where every CVE needed agent involvement or review is a harder '
                  'target for automatic backporting than one that resolves identically every time.')
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


# --- Text summary --------------------------------------------------------------


def print_summary(counts: Counter[str], grouped: dict[str, Counter[str]], total: int) -> None:
    """Print the same figures the charts show, for quoting into a report."""
    print(f'Total CVEs: {total}')
    print()
    print('By family:')
    for family in FAMILY_ORDER:
        count = sum(grouped[family].values())
        pct = 100 * count / total if total else 0.0
        print(f'  {family:<30} {count:>4}  ({pct:5.1f}%)')
    print()
    print('By raw status:')
    for status, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        pct = 100 * count / total if total else 0.0
        print(f'  {status:<32} {count:>4}  ({pct:5.1f}%)  [{classify_family(status)}]')


# --- Entry point ---------------------------------------------------------------


CHART_BUILDERS = (
    ('status_distribution.png', 'every raw status value, colored by outcome family'),
    ('family_breakdown.png', 'single stacked bar of the five outcome families'),
    ('recipe_breakdown.png', 'outcome family per recipe'),
)


def main() -> None:
    """Entry point for the corrector/agent bulk-run plotting tool."""
    parser = argparse.ArgumentParser(
        description='Plot a bulk cve-corrector/cve-agent integration test run.'
    )
    parser.add_argument(
        'results_dir', type=Path,
        help='Bulk test-results directory (e.g. tests/integration/test-results/bulk_*)',
    )
    parser.add_argument(
        '--mode', default=None,
        help='Mode suffix of the results CSV to read (e.g. full-enriched). '
             'Auto-detected if the directory has exactly one results_*.csv.',
    )
    parser.add_argument(
        '--output-dir', type=Path, default=None,
        help='Directory to write PNGs into (default: the results directory)',
    )
    args = parser.parse_args()

    try:
        import matplotlib  # noqa: F401
    except ImportError:
        print('error: matplotlib is required for this script but is not installed.\n'
              'This is a standalone dev tool; matplotlib is intentionally not a runtime\n'
              'dependency of yocto-security-tools. Install it with:\n\n'
              '    pip install matplotlib\n', file=sys.stderr)
        raise SystemExit(1) from None

    if not args.results_dir.is_dir():
        raise SystemExit(f'error: {args.results_dir} is not a directory')

    csv_path = find_results_csv(args.results_dir, args.mode)
    rows = read_results_csv(csv_path)

    counts = status_counts(rows)
    grouped = family_counts(counts)
    total = len(rows)
    print_summary(counts, grouped, total)

    out_dir = args.output_dir or args.results_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    plot_status_distribution(counts, out_dir / 'status_distribution.png')
    plot_family_breakdown(grouped, total, out_dir / 'family_breakdown.png')
    plot_recipe_breakdown(recipe_breakdown(rows), out_dir / 'recipe_breakdown.png')

    print()
    for name, description in CHART_BUILDERS:
        print(f'wrote {out_dir / name}  -- {description}')


if __name__ == '__main__':
    main()
