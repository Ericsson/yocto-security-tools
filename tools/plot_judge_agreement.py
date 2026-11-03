#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Compare the judge verdicts of the same review-required rows across judge models.

``tests/benchmark/judge_campaign.py`` refuses to mix judge models in one
``judge_results.csv``, so comparing models means running it once per model
against separate copies of the same results directory (same
``results_full.csv``, same saved reference/candidate patches). This tool reads
two or more of the resulting ``judge_results.csv`` files, keyed by ``cve_id``,
and classifies each CVE both judges rated as:

  * full consensus: every judge gave the exact same verdict;
  * same group, different verdict: every judge's verdict falls in the same
    coarse group (equivalent to the reference / meaningfully different / not
    comparable, as in ``plot_judge_results.py``) but the verdicts differ (for
    example ``stylistic`` vs ``comment-only``);
  * disagreement: at least one judge's verdict falls in a different group
    from another's (for example ``stylistic`` vs ``meaningful``) -- this is
    the case worth a human looking at the diff.

A CVE only one judge covered (not yet judged by the others, or a `no-patch`/
`no-reference` short-circuit that still ran for every judge) is included only
if every given CSV has a row for it; use ``--require-all`` (default) to drop
the rest, or ``--allow-partial`` to compare on whatever subset each pair
shares pairwise (summary only, no chart).

This is a standalone, dev-only tool. It is NOT part of the installed package
and requires matplotlib, which is not a runtime dependency (see AGENTS.md
"Minimize Dependencies").

Usage:
    pip install matplotlib
    python3 tools/plot_judge_agreement.py \\
        claude-opus-5.5=tests/integration/test-results/opus-run-merged/judge/judge_results.csv \\
        claude-sonnet-5.5=tests/integration/test-results/opus-run-merged-judge-sonnet/judge/judge_results.csv \\
        claude-opus-4.6=tests/integration/test-results/opus-run-merged-judge-opus46/judge/judge_results.csv \\
        --output judge_agreement.png
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

GROUP_EQUIVALENT = 'equivalent to the reference'
GROUP_DIVERGENT = 'meaningfully different'
GROUP_NOT_COMPARABLE = 'no comparable patch'
GROUP_OTHER = 'other / unrecognised verdict'

# Mirrors plot_judge_results.py's VERDICTS grouping, so "disagreement" means
# the same thing in both tools.
VERDICT_GROUP = {
    'identical': GROUP_EQUIVALENT,
    'stylistic': GROUP_EQUIVALENT,
    'comment-only': GROUP_EQUIVALENT,
    'structural-only': GROUP_EQUIVALENT,
    'meaningful': GROUP_DIVERGENT,
    'no-patch': GROUP_NOT_COMPARABLE,
    'no-reference': GROUP_NOT_COMPARABLE,
    'file-mismatch': GROUP_NOT_COMPARABLE,
}

CAT_CONSENSUS = 'full consensus'
CAT_SAME_GROUP = 'same group, different verdict'
CAT_DISAGREE = 'disagreement'

# Okabe-Ito palette, consistent with plot_judge_results.py: green for
# agreement, a muted blue for the harmless wording-only split, orange (the
# GROUP_DIVERGENT color there) for a real disagreement worth reviewing.
CAT_COLORS = {
    CAT_CONSENSUS: '#009E73',
    CAT_SAME_GROUP: '#56B4E9',
    CAT_DISAGREE: '#E69F00',
}


def read_judge_csv(path: Path) -> dict[str, str]:
    """Return ``{cve_id: judgment}`` for one ``judge_results.csv``.

    Args:
        path: Path to the judge results CSV.

    Returns:
        The judgment per CVE, in file order (last row wins on a duplicate).

    Raises:
        SystemExit: If the file is missing or has no ``cve_id``/``judgment`` column.
    """
    if not path.is_file():
        raise SystemExit(f'error: {path} does not exist')
    with open(path, newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        fields = reader.fieldnames or ()
        if 'cve_id' not in fields or 'judgment' not in fields:
            raise SystemExit(f'error: {path} has no cve_id/judgment columns')
        return {row['cve_id']: row['judgment'] for row in reader if row['judgment']}


def parse_sources(specs: list[str]) -> list[tuple[str, Path]]:
    """Parse ``model=path`` arguments into ``(model, path)`` pairs.

    Args:
        specs: Raw ``model=path`` strings from the command line.

    Returns:
        One ``(model, path)`` pair per spec, in the given order.

    Raises:
        SystemExit: If fewer than two sources are given or a spec has no ``=``.
    """
    if len(specs) < 2:
        raise SystemExit('error: give at least two model=path sources to compare')
    sources = []
    for spec in specs:
        if '=' not in spec:
            raise SystemExit(f"error: '{spec}' is not model=path")
        model, _, raw_path = spec.partition('=')
        if not model:
            raise SystemExit(f"error: '{spec}' has no model name before '='")
        sources.append((model, Path(raw_path)))
    return sources


def classify(verdicts: list[str]) -> str:
    """Classify one CVE's per-judge verdicts into a consensus category.

    Args:
        verdicts: One verdict string per judge, same CVE.

    Returns:
        :data:`CAT_CONSENSUS`, :data:`CAT_SAME_GROUP` or :data:`CAT_DISAGREE`.
    """
    groups = {VERDICT_GROUP.get(v, GROUP_OTHER) for v in verdicts}
    if len(groups) > 1:
        return CAT_DISAGREE
    if len(set(verdicts)) > 1:
        return CAT_SAME_GROUP
    return CAT_CONSENSUS


def compare(sources: list[tuple[str, Path]], *, require_all: bool = True) -> dict[str, dict]:
    """Compare judge verdicts across sources for every shared CVE.

    Args:
        sources: ``(model, path)`` pairs, as returned by :func:`parse_sources`.
        require_all: Keep only CVEs every source judged. If ``False``, keep
            every CVE at least two sources judged (verdicts missing from a
            source are simply left out of that CVE's comparison).

    Returns:
        ``{cve_id: {"verdicts": {model: judgment}, "category": str}}``,
        sorted by ``cve_id``.
    """
    per_model = {model: read_judge_csv(path) for model, path in sources}
    all_cves: set[str] = set()
    for verdicts in per_model.values():
        all_cves |= verdicts.keys()

    result: dict[str, dict] = {}
    for cve_id in sorted(all_cves):
        row = {model: verdicts[cve_id] for model, verdicts in per_model.items()
               if cve_id in verdicts}
        if require_all and len(row) != len(sources):
            continue
        if len(row) < 2:
            continue
        result[cve_id] = {'verdicts': row, 'category': classify(list(row.values()))}
    return result


def plot_agreement(comparison: dict[str, dict], models: list[str], title: str,
                    out_path: Path) -> None:
    """Bar chart of how many compared CVEs fall in each consensus category.

    Args:
        comparison: As returned by :func:`compare`.
        models: Model names, in display order, for the chart subtitle.
        title: Chart title.
        out_path: PNG output path.
    """
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    counts = Counter(row['category'] for row in comparison.values())
    total = sum(counts.values())
    if total == 0:
        raise SystemExit('error: no CVEs are common to every judge CSV -- nothing to plot')
    order = [CAT_CONSENSUS, CAT_SAME_GROUP, CAT_DISAGREE]
    bars = [(cat, counts[cat]) for cat in order if counts[cat]]

    fig, ax = plt.subplots(figsize=(8, 0.7 * len(bars) + 2.6))
    ypos = list(range(len(bars)))
    ax.barh(ypos, [count for _cat, count in bars], height=0.55,
            color=[CAT_COLORS[cat] for cat, _c in bars], edgecolor='white', linewidth=0.8)
    top = max(count for _cat, count in bars)
    for y, (_cat, count) in enumerate(bars):
        ax.text(count + top * 0.015, y, f'{count}  ({100 * count / total:.0f}%)',
                va='center', fontsize=10)
    ax.set_yticks(ypos)
    ax.set_yticklabels([cat for cat, _c in bars])
    ax.invert_yaxis()
    ax.set_xlim(0, top * 1.2)
    ax.set_xlabel(' vs '.join(models))
    ax.set_title(f'{title}  (n={total})', fontsize=13, fontweight='bold')
    ax.grid(axis='x', alpha=0.25, linestyle=':')
    ax.set_axisbelow(True)
    ax.legend(
        handles=[Patch(facecolor=CAT_COLORS[cat], label=f'{cat}: {count} ({100*count/total:.0f}%)')
                 for cat, count in bars],
        loc='lower right', fontsize=9, frameon=False)
    fig.text(0.01, 0.01,
              'Each judge compares the same candidate patch with the same human reference. '
              '"Disagreement" means the judges landed in different similarity groups '
              '(equivalent / meaningfully different / not comparable) for the same CVE.',
              fontsize=7.5, color='#555555', ha='left', va='bottom', wrap=True)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def print_summary(comparison: dict[str, dict], models: list[str]) -> None:
    """Print the figures the chart shows, and every disagreement, by CVE."""
    total = len(comparison)
    counts = Counter(row['category'] for row in comparison.values())
    print(f'Compared CVEs ({" vs ".join(models)}): {total}')
    for cat in (CAT_CONSENSUS, CAT_SAME_GROUP, CAT_DISAGREE):
        if counts[cat]:
            print(f'  {cat:<32} {counts[cat]:>4}  ({100 * counts[cat] / total:5.1f}%)')
    disagreements = {cve: row for cve, row in comparison.items()
                      if row['category'] == CAT_DISAGREE}
    if disagreements:
        print(f'\nDisagreements ({len(disagreements)}):')
        for cve_id, row in disagreements.items():
            verdicts = ', '.join(f'{model}={verdict}' for model, verdict in row['verdicts'].items())
            print(f'  {cve_id:<22} {verdicts}')


def main() -> None:
    """Entry point for the judge-agreement comparison tool."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('sources', nargs='+', metavar='MODEL=JUDGE_CSV',
                        help='One judge_results.csv per model, as model=path')
    parser.add_argument('--allow-partial', action='store_true',
                        help='Keep CVEs at least two judges covered, not necessarily all')
    parser.add_argument('--title', default='Judge agreement across models',
                        help='Chart title')
    parser.add_argument('-o', '--output', type=Path, default=Path('judge_agreement.png'),
                        help='PNG output path (default: judge_agreement.png)')
    parser.add_argument('--no-plot', action='store_true',
                        help='Print the summary only; skip the chart (no matplotlib needed)')
    args = parser.parse_args()

    sources = parse_sources(args.sources)
    models = [model for model, _path in sources]
    comparison = compare(sources, require_all=not args.allow_partial)
    if not comparison:
        sys.exit('error: no CVEs are judged by every given source')

    print_summary(comparison, models)
    if not args.no_plot:
        plot_agreement(comparison, models, args.title, args.output)
        print(f'\nChart written to {args.output}')


if __name__ == '__main__':
    main()
