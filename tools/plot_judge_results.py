#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Standalone plot of the judge verdicts for the AI-produced patches of a bulk run.

Reads the ``judge_results.csv`` written by ``tests/benchmark/judge_campaign.py``
and draws one bar chart: how many of the review-required patches the judge
found identical to, equivalent to, or meaningfully different from the human
reference patch.  Nothing else from the run is shown, so the chart stays
readable next to the much larger outcome charts of ``plot_corrector_results.py``.

The verdicts fall into three groups, shown by colour (Okabe-Ito palette) and
annotated with their counts, so no bar depends on hue alone:

  * equivalent to the reference: identical, stylistic, comment-only,
    structural-only (the shared files are identical; only the set of touched
    files differs);
  * meaningfully different;
  * no comparable patch: no patch committed, no reference, or no files in
    common with the reference.

A verdict measures similarity to the human reference only; no build or test is
behind it.  This is a standalone, dev-only tool.  It is NOT part of the
installed package and requires matplotlib, which is not a runtime dependency
(see AGENTS.md "Minimize Dependencies").

Usage:
    pip install matplotlib
    python3 tools/plot_judge_results.py \\
        tests/integration/test-results/resume-seed/judge/judge_results.csv \\
        --output judge_verdicts.png
"""
from __future__ import annotations

import argparse
import csv
import sys
import textwrap
from collections import Counter
from pathlib import Path

GROUP_EQUIVALENT = 'equivalent to the reference'
GROUP_DIVERGENT = 'meaningfully different'
GROUP_NOT_COMPARABLE = 'no comparable patch'
GROUP_OTHER = 'other / unrecognised verdict'

GROUP_COLORS = {
    GROUP_EQUIVALENT: '#56B4E9',
    GROUP_DIVERGENT: '#E69F00',
    GROUP_NOT_COMPARABLE: '#4D4D4D',
    GROUP_OTHER: '#999999',
}

# Judgment -> (group, label), in the order the bars are drawn.
VERDICTS = {
    'identical': (GROUP_EQUIVALENT, 'identical to the reference'),
    'stylistic': (GROUP_EQUIVALENT, 'stylistic difference only'),
    'comment-only': (GROUP_EQUIVALENT, 'comment-only difference'),
    'structural-only': (GROUP_EQUIVALENT, 'only the touched files differ'),
    'meaningful': (GROUP_DIVERGENT, 'meaningful difference'),
    'no-patch': (GROUP_NOT_COMPARABLE, 'no patch committed'),
    'no-reference': (GROUP_NOT_COMPARABLE, 'no reference patch'),
    'file-mismatch': (GROUP_NOT_COMPARABLE, 'no files in common'),
}


def read_verdicts(path: Path) -> list[str]:
    """Read the ``judgment`` column of a ``judge_results.csv``.

    Args:
        path: Path to the judge results CSV.

    Returns:
        One judgment string per row, in file order.

    Raises:
        SystemExit: If the file is missing, has no ``judgment`` column or no rows.
    """
    if not path.is_file():
        raise SystemExit(f'error: {path} does not exist')
    with open(path, newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        if 'judgment' not in (reader.fieldnames or ()):
            raise SystemExit(f'error: {path} has no judgment column')
        verdicts = [row['judgment'] for row in reader]
    if not verdicts:
        raise SystemExit(f'error: {path} has no data rows — nothing to plot')
    return verdicts


def ordered_bars(verdicts: list[str]) -> list[tuple[str, str, str, int]]:
    """Count the verdicts and order them for drawing.

    Args:
        verdicts: Judgments, as returned by :func:`read_verdicts`.

    Returns:
        ``(judgment, label, group, count)`` for every verdict that occurs, in
        the fixed display order; a verdict this tool does not know follows,
        in its own group, instead of being dropped.
    """
    counts = Counter(verdicts)
    bars = [(judgment, label, group, counts[judgment])
            for judgment, (group, label) in VERDICTS.items() if counts[judgment]]
    bars += [(judgment, judgment, GROUP_OTHER, count)
             for judgment, count in sorted(counts.items()) if judgment not in VERDICTS]
    return bars


def group_totals(bars: list[tuple[str, str, str, int]]) -> dict[str, int]:
    """Sum the bar counts per group, keeping only groups that occur."""
    totals: dict[str, int] = {}
    for _judgment, _label, group, count in bars:
        totals[group] = totals.get(group, 0) + count
    return totals


def plot_verdicts(bars: list[tuple[str, str, str, int]], title: str, out_path: Path) -> None:
    """Horizontal bar chart of the judge verdicts, coloured by group.

    Args:
        bars: As returned by :func:`ordered_bars`.
        title: Chart title.
        out_path: PNG output path.
    """
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    total = sum(count for *_rest, count in bars)
    ypos = list(range(len(bars)))
    fig, ax = plt.subplots(figsize=(9, 0.5 * len(bars) + 2.4))
    ax.barh(ypos, [count for *_rest, count in bars], height=0.62,
            color=[GROUP_COLORS[group] for _j, _l, group, _c in bars],
            edgecolor='white', linewidth=0.8)
    top = max(count for *_rest, count in bars)
    for y, (_judgment, _label, _group, count) in enumerate(bars):
        ax.text(count + top * 0.015, y, f'{count}  ({100 * count / total:.0f}%)',
                va='center', fontsize=9.5)
    ax.set_yticks(ypos)
    ax.set_yticklabels([label for _j, label, _g, _c in bars])
    ax.invert_yaxis()
    ax.set_xlim(0, top * 1.18)
    ax.set_xlabel('patches')
    ax.set_title(f'{title}  (n={total})', fontsize=13, fontweight='bold')
    ax.grid(axis='x', alpha=0.25, linestyle=':')
    ax.set_axisbelow(True)
    totals = group_totals(bars)
    ax.legend(
        handles=[Patch(facecolor=GROUP_COLORS[group],
                       label=f'{group}: {count} ({100 * count / total:.0f}%)')
                 for group, count in totals.items()],
        loc='lower right', fontsize=9, frameon=False)
    fig.text(0.01, 0.01, textwrap.fill(
        'The judge compares each patch with the human reference patch. The verdict '
        'measures similarity only; no build or test is behind it.', width=140),
        fontsize=7.5, color='#555555', ha='left', va='bottom')
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def print_summary(bars: list[tuple[str, str, str, int]]) -> None:
    """Print the figures the chart shows, for quoting into a report."""
    total = sum(count for *_rest, count in bars)
    print(f'Judged patches: {total}')
    for group, count in group_totals(bars).items():
        print(f'  {group:<32} {count:>4}  ({100 * count / total:5.1f}%)')
    for judgment, _label, group, count in bars:
        print(f'    {judgment:<18} {count:>4}  [{group}]')


def main() -> None:
    """Entry point for the judge-verdict plotting tool."""
    parser = argparse.ArgumentParser(
        description='Plot the judge verdicts of a bulk integration run.')
    parser.add_argument('judge_csv', type=Path,
                        help='judge_results.csv from tests/benchmark/judge_campaign.py')
    parser.add_argument('--output', '-o', type=Path, default=None,
                        help='PNG to write (default: judge_verdicts.png next to the CSV)')
    parser.add_argument('--title', default='Judge verdicts on AI-produced patches',
                        help='Chart title')
    args = parser.parse_args()

    try:
        import matplotlib  # noqa: F401
    except ImportError:
        print('error: matplotlib is required for this script but is not installed.\n'
              'This is a standalone dev tool; matplotlib is intentionally not a runtime\n'
              'dependency of yocto-security-tools. Install it with:\n\n'
              '    pip install matplotlib\n', file=sys.stderr)
        raise SystemExit(1) from None

    bars = ordered_bars(read_verdicts(args.judge_csv))
    print_summary(bars)
    out_path = args.output or args.judge_csv.with_name('judge_verdicts.png')
    plot_verdicts(bars, args.title, out_path)
    print(f'\nwrote {out_path}')


if __name__ == '__main__':
    main()
