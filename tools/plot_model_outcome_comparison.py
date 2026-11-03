#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Compare two models' cve-agent outcome distributions side by side.

``plot_corrector_results.py`` classifies every CVE a bulk
``test_cve_corrector.sh`` run produced into an outcome family (direct
success, agent-resolved, needs review, skipped, failed -- see its module
docstring). This tool reads two such runs' ``results_full.csv`` and draws
one grouped bar per family, model A next to model B, so you can see at a
glance whether a different model backend resolved more CVEs cleanly, left
more for review, or failed more often -- using the exact same family
taxonomy and colors as the single-run chart.

**Resumed runs are not a fair re-test.** A bulk run started with
``--resume`` against a seeded ``results_full.csv`` (as
``tests/integration/test_cve_corrector.sh --agent-only --resume`` is meant to
be used, to only retry the rows that need a different model) keeps every row
it did not re-attempt -- most commonly ``IDENTICAL`` and ``SUCCESS``, which
never call the AI backend at all. Comparing those shared rows between two
runs that only differ in which rows were *retried* makes the two models look
more similar than they are. Pass ``--fresh-only MODEL=CVE_LIST_FILE`` (one
CVE ID per line, e.g. extracted from the run's chain.log fresh-attempt
lines) to restrict a model's side of the chart to the CVEs it actually
attempted; without it, the chart includes every row and the caption says so.

This is a standalone, dev-only tool. It is NOT part of the installed package
and requires matplotlib, which is not a runtime dependency (see AGENTS.md
"Minimize Dependencies").

Usage:
    pip install matplotlib
    python3 tools/plot_model_outcome_comparison.py \\
        --model-a qwen=tests/integration/test-results/resume-seed \\
        --model-b claude-opus-5.5=tests/integration/test-results/opus-run-merged \\
        --output model_outcomes.png
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from plot_corrector_results import (  # noqa: E402
    DISPLAY_ORDER,
    FAMILY_COLORS,
    apply_failure_codes,
    family_counts,
    find_results_csv,
    fits_label,
    read_results_csv,
)


def parse_model_arg(spec: str) -> tuple[str, Path]:
    """Parse one ``--model-a``/``--model-b`` ``name=results_dir`` argument.

    Args:
        spec: A raw ``name=path`` string.

    Returns:
        The ``(name, path)`` pair.

    Raises:
        SystemExit: If the spec has no ``=`` or no model name.
    """
    if '=' not in spec:
        raise SystemExit(f"error: '{spec}' is not name=results_dir")
    name, _, raw_path = spec.partition('=')
    if not name:
        raise SystemExit(f"error: '{spec}' has no model name before '='")
    return name, Path(raw_path)


def load_family_counts(results_dir: Path, mode: str | None,
                       restrict_to: set[str] | None) -> dict[str, Counter[str]]:
    """Load one model's results CSV and group it into outcome families.

    Args:
        results_dir: Bulk test-results directory (``results_<mode>.csv`` inside).
        mode: Explicit mode suffix, or ``None`` to auto-detect.
        restrict_to: If given, only rows whose ``cve_id`` is in this set are
            counted (see :func:`read_fresh_cve_list`).

    Returns:
        As returned by :func:`plot_corrector_results.family_counts`.
    """
    rows = apply_failure_codes(read_results_csv(find_results_csv(results_dir, mode)))
    if restrict_to is not None:
        rows = [row for row in rows if row['cve_id'] in restrict_to]
    return family_counts(Counter(row['status'] for row in rows))


def read_fresh_cve_list(path: Path) -> set[str]:
    """Read a plain-text list of CVE IDs, one per line.

    Args:
        path: Path to the list (blank lines and ``#``-comments are ignored).

    Returns:
        The CVE IDs, as a set.

    Raises:
        SystemExit: If the file does not exist.
    """
    if not path.is_file():
        raise SystemExit(f'error: {path} does not exist')
    return {line.strip() for line in path.read_text(encoding='utf-8').splitlines()
            if line.strip() and not line.strip().startswith('#')}


def plot_outcome_comparison(counts_a: dict[str, Counter[str]], counts_b: dict[str, Counter[str]],
                            model_a: str, model_b: str, total_a: int, total_b: int,
                            fresh_only: bool, title: str | None, out_path: Path) -> None:
    """Grouped horizontal bar chart: each model's outcome family counts.

    Args:
        counts_a: Model A's family counts, as returned by :func:`load_family_counts`.
        counts_b: Model B's family counts.
        model_a: Model A's display name.
        model_b: Model B's display name.
        total_a: Model A's total row count (for percentages).
        total_b: Model B's total row count.
        fresh_only: Whether both sides were restricted to freshly attempted
            CVEs (changes the caption).
        title: Chart title, or ``None`` for ``"<model_a> vs <model_b>"``.
        out_path: PNG output path.
    """
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    families = [f for f in DISPLAY_ORDER
                if sum(counts_a.get(f, Counter()).values())
                or sum(counts_b.get(f, Counter()).values())]
    if not families:
        raise SystemExit('error: neither model has any row to plot')
    values_a = [sum(counts_a.get(f, Counter()).values()) for f in families]
    values_b = [sum(counts_b.get(f, Counter()).values()) for f in families]
    top = max((*values_a, *values_b), default=0)

    fig, ax = plt.subplots(figsize=(10, 0.62 * len(families) + 2.2))
    ypos = list(range(len(families)))
    bar_height = 0.34
    colors = [FAMILY_COLORS[f] for f in families]
    bars_a = ax.barh([y + bar_height / 2 for y in ypos], values_a, height=bar_height,
                     color=colors, edgecolor='black', linewidth=0.7)
    bars_b = ax.barh([y - bar_height / 2 for y in ypos], values_b, height=bar_height,
                     color=colors, edgecolor='black', linewidth=0.7, alpha=0.45, hatch='////')
    for bar_obj, value, total in zip(
            (*bars_a, *bars_b), (*values_a, *values_b), (*([total_a] * len(families)),
                                                         *([total_b] * len(families))),
            strict=True):
        if value:
            pct = 100 * value / total if total else 0.0
            ax.text(bar_obj.get_width() + max(top, 1) * 0.015,
                    bar_obj.get_y() + bar_obj.get_height() / 2,
                    f'{value}  ({pct:.0f}%)', va='center', fontsize=9)
    ax.set_yticks(ypos)
    ax.set_yticklabels(families)
    ax.invert_yaxis()
    ax.set_xlim(0, max(top, 1) * 1.3)
    ax.set_xlabel('CVEs')
    ax.set_title(title or f'{model_a} vs {model_b}', fontsize=13, fontweight='bold')
    ax.grid(axis='x', alpha=0.25, linestyle=':')
    ax.set_axisbelow(True)
    ax.legend(
        handles=[Patch(facecolor='#777777', edgecolor='black', linewidth=0.7,
                       label=f'{model_a}  (n={total_a})'),
                 Patch(facecolor='#777777', edgecolor='black', linewidth=0.7, alpha=0.45,
                       hatch='////', label=f'{model_b}  (n={total_b})')],
        loc='lower right', fontsize=9.5, frameon=False)
    if fresh_only:
        caption = 'Only CVEs each model actually attempted.'
    else:
        caption = 'All CVEs, including rows a resumed run reused without retrying.'
    fig.text(0.01, 0.005, caption, fontsize=7.5, color='#555555', ha='left', va='bottom',
              wrap=True)
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def print_summary(counts_a: dict[str, Counter[str]], counts_b: dict[str, Counter[str]],
                  model_a: str, model_b: str, total_a: int, total_b: int) -> None:
    """Print the figures the chart shows, for quoting into a report."""
    families = [f for f in DISPLAY_ORDER
                if sum(counts_a.get(f, Counter()).values())
                or sum(counts_b.get(f, Counter()).values())]
    print(f'{model_a}  (n={total_a})  vs  {model_b}  (n={total_b}):')
    for family in families:
        a_count = sum(counts_a.get(family, Counter()).values())
        b_count = sum(counts_b.get(family, Counter()).values())
        a_pct = 100 * a_count / total_a if total_a else 0.0
        b_pct = 100 * b_count / total_b if total_b else 0.0
        print(f'  {family:<32} {model_a}={a_count:>4} ({a_pct:4.1f}%)   '
              f'{model_b}={b_count:>4} ({b_pct:4.1f}%)')


def plot_stacked_comparison(counts_a: dict[str, Counter[str]], counts_b: dict[str, Counter[str]],
                            model_a: str, model_b: str, total_a: int, total_b: int,
                            fresh_only: bool, title: str | None, out_path: Path) -> None:
    """Two single-stacked-bar rows, one per model, styled like ``plot_family_breakdown``.

    Each model gets one horizontal bar, left to right in :data:`DISPLAY_ORDER`,
    annotated the same way as the single-run ``family_breakdown.png`` chart --
    a count/percentage label inside a wide-enough segment, the full figure for
    every segment in the legend below. The two bars share an x-axis scaled to
    the larger total, so a size difference between the two runs is visible,
    not just the per-family proportions.

    Args:
        counts_a: Model A's family counts, as returned by :func:`load_family_counts`.
        counts_b: Model B's family counts.
        model_a: Model A's display name.
        model_b: Model B's display name.
        total_a: Model A's total row count.
        total_b: Model B's total row count.
        fresh_only: Whether both sides were restricted to freshly attempted
            CVEs (changes the caption).
        title: Chart title, or ``None`` for ``"<model_a> vs <model_b>"``.
        out_path: PNG output path.
    """
    import textwrap

    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    all_families = [family for family in DISPLAY_ORDER
                    if sum(counts_a.get(family, Counter()).values())
                    or sum(counts_b.get(family, Counter()).values())]
    if not all_families:
        raise SystemExit('error: neither model has any row to plot')

    axis_max = max(total_a, total_b, 1)
    # A dedicated legend axes (height scales with the number of families)
    # instead of letting a figure-relative legend/caption fight tight_layout
    # for space: the row heights below are fixed fractions of the figure, so
    # adding families only grows the figure, not the bar panel's share of it.
    legend_cols = min(2, len(all_families)) or 1
    legend_rows = -(-len(all_families) // legend_cols)  # ceil: rows the legend really needs
    fig = plt.figure(figsize=(9.5, 3.0 + 0.3 * legend_rows))
    gs = fig.add_gridspec(3, 1, height_ratios=[3.0, 0.3 * legend_rows + 0.3, 0.6],
                          hspace=0.9)
    ax = fig.add_subplot(gs[0])
    legend_ax = fig.add_subplot(gs[1])
    legend_ax.axis('off')
    caption_ax = fig.add_subplot(gs[2])
    caption_ax.axis('off')

    # Row 0 = model A, row 1 = model B, matching the y-tick labels below;
    # invert_yaxis() puts A on top, the usual "first model, second model"
    # top-to-bottom reading order.
    rows = ((0, counts_a, total_a), (1, counts_b, total_b))
    for row, grouped, total in rows:
        left = 0.0
        for family in all_families:
            count = sum(grouped.get(family, Counter()).values())
            if not count:
                continue
            ax.barh([row], [count], left=[left], height=0.55, color=FAMILY_COLORS[family],
                   edgecolor='white', linewidth=1.0)
            if fits_label(count, total):
                pct = 100 * count / total if total else 0.0
                ax.text(left + count / 2, row, f'{count}\n({pct:.0f}%)', ha='center',
                        va='center', color='white', fontsize=9, fontweight='bold')
            left += count

    legend_handles = [
        Patch(facecolor=FAMILY_COLORS[family],
              label=f'{family}:  {sum(counts_a.get(family, Counter()).values())} vs '
                    f'{sum(counts_b.get(family, Counter()).values())}')
        for family in all_families
    ]

    ax.set_xlim(0, axis_max)
    ax.set_ylim(-0.4, 1.4)
    ax.set_yticks([0, 1])
    ax.set_yticklabels([f'{model_a}  (n={total_a})', f'{model_b}  (n={total_b})'])
    ax.invert_yaxis()
    ax.set_xlabel('CVEs')
    ax.set_title(title or f'{model_a} vs {model_b}', fontsize=13, fontweight='bold')
    legend_ax.legend(handles=legend_handles, loc='upper center', ncol=legend_cols,
                     fontsize=8.5, frameon=False,
                     title=f'outcome family:  {model_a} vs {model_b}', title_fontsize=8.5)
    if fresh_only:
        caption = 'Only CVEs each model actually attempted.'
    else:
        caption = 'All CVEs, including rows a resumed run reused without retrying.'
    caption_ax.text(0.0, 0.5, textwrap.fill(caption, width=150), fontsize=7.5, color='#555555',
                    ha='left', va='center', transform=caption_ax.transAxes)
    fig.savefig(out_path, dpi=150, bbox_inches='tight')
    plt.close(fig)


def main() -> None:
    """Entry point for the model-vs-model outcome comparison tool."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--model-a', required=True, metavar='NAME=RESULTS_DIR',
                        help='Model A name and its bulk test-results directory')
    parser.add_argument('--model-b', required=True, metavar='NAME=RESULTS_DIR',
                        help='Model B name and its bulk test-results directory')
    parser.add_argument('--mode', default=None,
                        help='Mode suffix of the results CSV (e.g. full). '
                             'Auto-detected if each directory has exactly one results_*.csv.')
    parser.add_argument('--fresh-only', action='append', default=[], dest='fresh_only',
                        metavar='MODEL=CVE_LIST_FILE',
                        help='Restrict a model\'s side to the CVE IDs listed in this file '
                             '(one per line). Repeatable; a model without one keeps every row.')
    parser.add_argument('--title', default=None,
                        help='Chart title (default: "<model A> vs <model B>")')
    parser.add_argument('--style', choices=('stacked', 'grouped'), default='stacked',
                        help='"stacked" (default): two single-stacked-bar rows, one per model, '
                             'like plot_corrector_results.py\'s family_breakdown.png. '
                             '"grouped": one pair of bars per family.')
    parser.add_argument('-o', '--output', type=Path, default=Path('model_outcomes.png'),
                        help='PNG output path (default: model_outcomes.png)')
    parser.add_argument('--no-plot', action='store_true',
                        help='Print the summary only; skip the chart (no matplotlib needed)')
    args = parser.parse_args()

    name_a, dir_a = parse_model_arg(args.model_a)
    name_b, dir_b = parse_model_arg(args.model_b)
    restrict: dict[str, set[str]] = {}
    for spec in args.fresh_only:
        model, list_path = parse_model_arg(spec)
        restrict[model] = read_fresh_cve_list(list_path)

    counts_a = load_family_counts(dir_a, args.mode, restrict.get(name_a))
    counts_b = load_family_counts(dir_b, args.mode, restrict.get(name_b))
    total_a = sum(sum(c.values()) for c in counts_a.values())
    total_b = sum(sum(c.values()) for c in counts_b.values())
    fresh_only = bool(restrict)

    print_summary(counts_a, counts_b, name_a, name_b, total_a, total_b)
    if not args.no_plot:
        plot = plot_stacked_comparison if args.style == 'stacked' else plot_outcome_comparison
        plot(counts_a, counts_b, name_a, name_b, total_a, total_b, fresh_only, args.title,
             args.output)
        print(f'\nChart written to {args.output}')


if __name__ == '__main__':
    main()
