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

Failures are split in two so an AI shortfall is not conflated with a problem
the AI never had a chance to fix: ``failed (AI)`` is a failure after (or
during) cve-agent involvement, while ``failed (pre-existing)`` is an
environment/infrastructure failure of the corrector run itself (devtool or
git errors, a bad checkout, ...) that is independent of the AI backend.
``failed (tool)`` is a third kind: a FAIL_* row whose ``failure_code`` names a
limit of the corrector-to-agent handoff or the patch transfer (see
TOOL_FAILURE_CODES), so no model could have changed the outcome.

Colors come from the Okabe-Ito palette (distinguishable under the common
forms of color blindness) and every bar is annotated with its value, so no
chart depends on hue alone being read correctly.

This is a standalone, dev-only tool. It is NOT part of the installed
yocto-security-tools package and requires matplotlib, which is not a runtime
dependency of the project (see AGENTS.md "Minimize Dependencies").

``--judge-csv`` adds a second opinion on the "needs review" rows: it reads the
``judge_results.csv`` written by ``tests/benchmark/judge_campaign.py`` and splits
that family by the judge's verdict (equivalent to the human reference,
meaningfully different, or no comparable patch).  Rows without a verdict stay in
"needs review".

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
# into several families so the chart legend stays readable regardless of how
# many distinct FAIL_*/SKIP_* codes a given run produced.

FAMILY_DIRECT_SUCCESS = 'direct success'
FAMILY_AGENT_VERIFIED = 'agent-resolved (verified)'
FAMILY_NEEDS_REVIEW = 'produced a patch, needs review'
FAMILY_SKIPPED = 'skipped'
FAMILY_PREEXISTING_FAILED = 'failed (pre-existing)'
FAMILY_AI_FAILED = 'failed (AI)'

# Only drawn when a run has such a row; see apply_failure_codes().
FAMILY_TOOL_FAILED = 'failed (tool)'

# Families that only exist when a judge CSV splits the "needs review" rows.
FAMILY_REVIEW_EQUIVALENT = 'patch, judged equivalent to reference'
FAMILY_REVIEW_DIVERGENT = 'patch, judged meaningfully different'
FAMILY_REVIEW_NOT_COMPARABLE = 'review item without a comparable patch'

# Pseudo-statuses substituted for a review row that has a judge verdict.
STATUS_REVIEW_EQUIVALENT = 'REVIEW_JUDGED_EQUIVALENT'
STATUS_REVIEW_DIVERGENT = 'REVIEW_JUDGED_DIVERGENT'
STATUS_REVIEW_NOT_COMPARABLE = 'REVIEW_NOT_COMPARABLE'

# judge_results.csv ``judgment`` -> pseudo-status.  ``identical``,
# ``comment-only`` and ``structural-only`` need no model opinion.  A verdict not
# listed (e.g. ``pending`` from a dry run) leaves the row in "needs review".
JUDGMENT_STATUS = {
    'identical': STATUS_REVIEW_EQUIVALENT,
    'stylistic': STATUS_REVIEW_EQUIVALENT,
    'comment-only': STATUS_REVIEW_EQUIVALENT,
    'structural-only': STATUS_REVIEW_EQUIVALENT,
    'meaningful': STATUS_REVIEW_DIVERGENT,
    'no-patch': STATUS_REVIEW_NOT_COMPARABLE,
    'no-reference': STATUS_REVIEW_NOT_COMPARABLE,
    'file-mismatch': STATUS_REVIEW_NOT_COMPARABLE,
}

# ``failure_code`` values of a FAIL_* row that come from a limit of the
# corrector-to-agent handoff or of the verified patch transfer, not from the
# model: the reference changes under the repository (reference drift), no path
# in the target tree matches a changed file, or the change is a binary file.
# An explicit list on purpose: most other HANDOFF_*/TRANSFER_* codes can follow
# from what the model did, so they stay "failed (AI)" until shown otherwise.
TOOL_FAILURE_CODES = (
    'HANDOFF_REFERENCE_DRIFT',
    'TRANSFER_NO_TARGET_PATH',
    'TRANSFER_UNSUPPORTED_FILE_TYPE',
)

# Pseudo-status prefix substituted for a FAIL_* row with a tool failure code;
# the code follows, so the status chart still tells the causes apart.
STATUS_TOOL_PREFIX = 'FAIL_TOOL_'

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

# ``FAIL_<exit_name>`` suffixes that come from the corrector run or its
# environment rather than from the AI backend: cve-agent is only started for
# the recoverable exit codes (conflict, ptest, build, patch error), so these
# can never be an AI shortfall.  Any other ``FAIL_*`` status (agent summary
# states such as WORKFLOW_FAILED/SECURITY_REJECTED/PROVIDER_TIMEOUT, the
# recoverable corrector codes after a failed agent retry, TIMEOUT, and any
# future code) is counted as an AI failure.
PREEXISTING_FAIL_SUFFIXES = (
    'CHECKOUT_ERROR',
    'METADATA_ERROR',
    'GIT_ERROR',
    'DEVTOOL_ERROR',
    'PTEST_PREEXISTING',
    'BUILD_PREEXISTING',
    'IGNORED_BY_STATUS',
    'PREP_BASE_MISMATCH',
)

# Family membership is resolved by prefix for the open-ended SKIP_*/FAIL_*
# codes, and by exact match for everything else.
FAMILY_ORDER = (
    FAMILY_DIRECT_SUCCESS,
    FAMILY_AGENT_VERIFIED,
    FAMILY_NEEDS_REVIEW,
    FAMILY_SKIPPED,
    FAMILY_PREEXISTING_FAILED,
    FAMILY_AI_FAILED,
)

# Left-to-right order of every family a chart can show; the judged families sit
# beside the family they refine.  A chart shows only the families present.
DISPLAY_ORDER = (
    FAMILY_DIRECT_SUCCESS,
    FAMILY_AGENT_VERIFIED,
    FAMILY_REVIEW_EQUIVALENT,
    FAMILY_REVIEW_DIVERGENT,
    FAMILY_REVIEW_NOT_COMPARABLE,
    FAMILY_NEEDS_REVIEW,
    FAMILY_SKIPPED,
    FAMILY_PREEXISTING_FAILED,
    FAMILY_TOOL_FAILED,
    FAMILY_AI_FAILED,
)

FAMILY_COLORS = {
    FAMILY_DIRECT_SUCCESS: '#009E73',
    FAMILY_AGENT_VERIFIED: '#0072B2',
    FAMILY_NEEDS_REVIEW: '#CC79A7',
    FAMILY_SKIPPED: '#999999',
    FAMILY_PREEXISTING_FAILED: '#8C510A',
    FAMILY_TOOL_FAILED: '#6A3D9A',
    FAMILY_AI_FAILED: '#D55E00',
    FAMILY_REVIEW_EQUIVALENT: '#56B4E9',
    FAMILY_REVIEW_DIVERGENT: '#E69F00',
    FAMILY_REVIEW_NOT_COMPARABLE: '#4D4D4D',
}


def classify_family(status: str) -> str:
    """Map a ``status`` CSV value to an outcome family.

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
    if status == STATUS_REVIEW_EQUIVALENT:
        return FAMILY_REVIEW_EQUIVALENT
    if status == STATUS_REVIEW_DIVERGENT:
        return FAMILY_REVIEW_DIVERGENT
    if status == STATUS_REVIEW_NOT_COMPARABLE:
        return FAMILY_REVIEW_NOT_COMPARABLE
    if status.startswith('SKIP'):
        return FAMILY_SKIPPED
    if status.startswith(STATUS_TOOL_PREFIX):
        return FAMILY_TOOL_FAILED
    if status.startswith('FAIL_') and status.removeprefix('FAIL_') in PREEXISTING_FAIL_SUFFIXES:
        return FAMILY_PREEXISTING_FAILED
    # Treat anything else (FAIL_*, and any future status not yet listed
    # above) as an AI failure rather than silently dropping it from the chart.
    return FAMILY_AI_FAILED


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


def read_judge_csv(path: Path) -> dict[str, str]:
    """Read ``judge_results.csv`` into ``{cve_id: judgment}``.

    Args:
        path: Path to the judge results CSV.

    Returns:
        The judgment per CVE.

    Raises:
        SystemExit: If the file does not exist or lacks the expected columns.
    """
    if not path.is_file():
        raise SystemExit(f'error: {path} does not exist')
    with open(path, newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        if not {'cve_id', 'judgment'} <= set(reader.fieldnames or ()):
            raise SystemExit(f'error: {path} has no cve_id/judgment columns')
        return {row['cve_id']: row['judgment'] for row in reader}


def apply_judge(rows: list[dict[str, str]], verdicts: dict[str, str]) -> list[dict[str, str]]:
    """Refine the "needs review" rows with the judge's verdicts.

    Only a row whose status is a review status and whose CVE has a recognised
    verdict changes; its ``status`` becomes the matching pseudo-status.  Every
    other row, and the input list itself, is left untouched.

    Args:
        rows: Parsed results rows.
        verdicts: ``{cve_id: judgment}`` from :func:`read_judge_csv`.

    Returns:
        A new list of rows.
    """
    refined = []
    for row in rows:
        pseudo = JUDGMENT_STATUS.get(verdicts.get(row['cve_id'], ''))
        if pseudo and row['status'] in NEEDS_REVIEW_STATUSES:
            row = {**row, 'status': pseudo}
        refined.append(row)
    return refined


def apply_failure_codes(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Mark the FAIL_* rows whose failure is a tool limit, not a model outcome.

    Only a row whose status starts with ``FAIL_`` and whose ``failure_code`` is
    in :data:`TOOL_FAILURE_CODES` changes; its ``status`` becomes
    ``FAIL_TOOL_<code>``.  Every other row, and the input list itself, is left
    untouched, and a CSV without a ``failure_code`` column is left as it is.

    Args:
        rows: Parsed results rows.

    Returns:
        A new list of rows.
    """
    marked = []
    for row in rows:
        code = row.get('failure_code') or ''
        if row['status'].startswith('FAIL_') and code in TOOL_FAILURE_CODES:
            row = {**row, 'status': STATUS_TOOL_PREFIX + code}
        marked.append(row)
    return marked


def families_in_order(grouped: dict[str, Counter[str]]) -> list[str]:
    """Return the families a chart should draw, in display order."""
    return [family for family in DISPLAY_ORDER if family in grouped]


def families_for_recipes(per_recipe: dict[str, Counter[str]]) -> list[str]:
    """Return the families that occur in any recipe, in display order."""
    present = {family for counter in per_recipe.values() for family in counter}
    return [family for family in DISPLAY_ORDER if family in present]


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
        grouped.setdefault(classify_family(status), Counter())[status] = count
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
        handles=[Patch(facecolor=FAMILY_COLORS[f], label=f) for f in DISPLAY_ORDER
                 if f in {classify_family(status) for status in labels}],
        loc='lower right', fontsize=8.5, frameon=False,
    )
    _caption(fig, 'Every distinct status the test runner can emit, colored by outcome family. '
                  'See family_breakdown.png for the same data collapsed to outcome families.')
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


# A bar narrower than this share of the total cannot hold its own label.
NARROW_BAR_SHARE = 0.07


def label_levels(counts: list[int], total: int) -> list[int | None]:
    """Decide where each bar's label goes.

    Args:
        counts: Bar widths, left to right.
        total: Total CVE count.

    Returns:
        ``None`` for a bar wide enough to label inside; otherwise a staggered
        level (0, 1, 0, 1, ...) above the bar, so neighbouring narrow bars
        do not print their labels on top of each other.
    """
    levels: list[int | None] = []
    narrow = 0
    for count in counts:
        if total and count / total >= NARROW_BAR_SHARE:
            levels.append(None)
        else:
            levels.append(narrow % 2)
            narrow += 1
    return levels


def plot_family_breakdown(grouped: dict[str, Counter[str]], total: int, out_path: Path) -> None:
    """Single stacked horizontal bar of the outcome families.

    Args:
        grouped: Per-family raw-status counters, as returned by
            :func:`family_counts`.
        total: Total CVE count, for the percentage labels.
        out_path: PNG output path.
    """
    import textwrap

    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(9.5, 3.0))
    left = 0.0
    drawn = [f for f in families_in_order(grouped) if sum(grouped[f].values())]
    sizes = [sum(grouped[f].values()) for f in drawn]
    for family, count, level in zip(drawn, sizes, label_levels(sizes, total), strict=True):
        ax.barh([0], [count], left=[left], height=0.55, color=FAMILY_COLORS[family],
                edgecolor='white', linewidth=1.0, label=family)
        pct = 100 * count / total if total else 0.0
        centre = left + count / 2
        if level is None:
            ax.text(centre, 0, f'{count}\n({pct:.0f}%)', ha='center', va='center',
                    color='white', fontsize=9.5, fontweight='bold')
        else:
            height = 0.34 + 0.2 * level
            ax.plot([centre, centre], [0.275, height], color='#555555', linewidth=0.7)
            ax.text(centre, height + 0.02, f'{count} ({pct:.0f}%)', ha='center', va='bottom',
                    color='#222222', fontsize=9, fontweight='bold')
        left += count

    ax.set_xlim(0, total)
    ax.set_ylim(-0.4, 0.85)
    ax.set_yticks([])
    ax.set_title(f'Outcome family breakdown  (n={total})', fontsize=13, fontweight='bold')
    ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.2), ncol=min(len(drawn), 4),
              fontsize=9, frameon=False)
    caption = ('"agent-resolved" passed the semantic security gate after a recoverable '
               'corrector failure. "needs review" produced a patch and a completed build '
               'but could not be auto-verified — it is a result worth looking at, not a '
               'confirmed fix.')
    if any(family in drawn for family in (FAMILY_REVIEW_EQUIVALENT, FAMILY_REVIEW_DIVERGENT)):
        caption += (' The judged families split those rows by a model\'s comparison with the '
                    'human reference patch: it measures similarity only, with no build or '
                    'test behind it.')
    _caption(fig, textwrap.fill(caption, width=150))
    fig.tight_layout(rect=(0, 0.14, 1, 1))
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
    drawn = families_for_recipes(per_recipe)
    for family in drawn:
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
    ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.14), ncol=min(len(drawn), 3),
              fontsize=8.5, frameon=False)
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
    for family in families_in_order(grouped):
        count = sum(grouped[family].values())
        pct = 100 * count / total if total else 0.0
        print(f'  {family:<40} {count:>4}  ({pct:5.1f}%)')
    print()
    print('By raw status:')
    for status, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        pct = 100 * count / total if total else 0.0
        print(f'  {status:<32} {count:>4}  ({pct:5.1f}%)  [{classify_family(status)}]')


# --- Entry point ---------------------------------------------------------------


CHART_BUILDERS = (
    ('status_distribution.png', 'every raw status value, colored by outcome family'),
    ('family_breakdown.png', 'single stacked bar of the outcome families'),
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
    parser.add_argument(
        '--judge-csv', type=Path, default=None,
        help='judge_results.csv from tests/benchmark/judge_campaign.py; splits the '
             '"needs review" rows by the judge verdict',
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
    rows = apply_failure_codes(read_results_csv(csv_path))
    if args.judge_csv:
        rows = apply_judge(rows, read_judge_csv(args.judge_csv))

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
