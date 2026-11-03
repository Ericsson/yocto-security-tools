#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Compare two candidate models' review-required patches, judge by judge.

``tests/benchmark/judge_campaign.py`` rates how close a *candidate model's*
patch for a CVE is to the human reference patch -- it does not compare two
candidate models against each other. This tool does that: for every CVE both
candidate models left ``SECURITY_REVIEW_REQUIRED`` (or
``WORKFLOW_COMPLETED_UNVERIFIED``), it reads the same judge's verdict on each
model's own patch and compares them.

By default, each CVE's per-judge verdicts are collapsed into one majority
verdict per model (:func:`majority_verdict`: 2-of-3 agreement, or the
worst-ranked verdict on a genuine split) before counting, so the chart is a
single panel: one pair of bars per verdict category (identical, stylistic,
meaningful, ...), using the same categories and colors as
``plot_judge_results.py``. This still keeps *what kind* of agreement it is
visible -- two models whose majority is both ``meaningful`` reads as "both
diverged from the reference", not as a plain, unqualified "tie" -- while not
drowning the chart in one panel per judge. Pass ``--per-judge`` for the
one-panel-per-judge detail view instead (useful when the judges disagree
often enough that the majority view would hide it).

Each judge is independent (``tests/benchmark/judge_campaign.py`` refuses to
mix judge models in one ``judge_results.csv``, so one judge's opinion of
model A and model B lives in two separate CSVs).

This is a standalone, dev-only tool. It is NOT part of the installed package
and requires matplotlib, which is not a runtime dependency (see AGENTS.md
"Minimize Dependencies").

Usage:
    pip install matplotlib
    python3 tools/plot_model_judge_comparison.py \\
        --model-a qwen=tests/integration/test-results/resume-seed \\
        --model-b claude-opus-5.5=tests/integration/test-results/opus-run-merged \\
        --judge "claude-opus-5.5=.../qwen/judge/judge_results.csv,.../opus/judge/judge_results.csv" \\
        --judge "claude-sonnet-5.5=.../qwen/judge/judge_results.csv,.../opus/judge/judge_results.csv" \\
        --judge "claude-opus-4.6=.../qwen/judge/judge_results.csv,.../opus/judge/judge_results.csv" \\
        --output model_comparison.png
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

RANK_ORDER = {
    'identical': 0,
    'stylistic': 1,
    'comment-only': 1,
    'structural-only': 1,
    'meaningful': 2,
    'no-patch': 3,
    'no-reference': 3,
    'file-mismatch': 3,
    'failed-to-generate': 3,
}
WORST_RANK = max(RANK_ORDER.values())

REVIEW_STATUSES = ('SECURITY_REVIEW_REQUIRED', 'WORKFLOW_COMPLETED_UNVERIFIED')

# Pseudo-verdicts for a CVE one model left for review (so the judge rated
# it) but the other did not: a FAIL_* status means that model produced no
# patch at all; AGENT_RESOLVED means its patch passed the semantic security
# gate and so was never sent to the judge. The latter has no rank -- how
# close it is to the reference was never measured -- so it is shown but
# left out of the win/tie/loss rollup.
FAILED_TO_GENERATE = 'failed-to-generate'
AGENT_RESOLVED_UNJUDGED = 'agent-resolved'

GROUP_EQUIVALENT = 'equivalent to the reference'
GROUP_DIVERGENT = 'meaningfully different'
GROUP_NOT_COMPARABLE = 'no comparable patch'
GROUP_FAILED = 'failed to generate a patch'
GROUP_UNJUDGED = 'resolved, verified (not judged)'
GROUP_OTHER = 'other / unrecognised verdict'

# Same verdict -> (group, label) as plot_judge_results.py's VERDICTS, so a
# verdict means the same thing, and draws in the same color, in both charts.
VERDICTS = {
    'identical': (GROUP_EQUIVALENT, 'identical to the reference'),
    'stylistic': (GROUP_EQUIVALENT, 'stylistic difference only'),
    'comment-only': (GROUP_EQUIVALENT, 'comment-only difference'),
    'structural-only': (GROUP_EQUIVALENT, 'only the touched files differ'),
    'meaningful': (GROUP_DIVERGENT, 'meaningful difference'),
    'no-patch': (GROUP_NOT_COMPARABLE, 'no patch committed'),
    'no-reference': (GROUP_NOT_COMPARABLE, 'no reference patch'),
    'file-mismatch': (GROUP_NOT_COMPARABLE, 'no files in common'),
    FAILED_TO_GENERATE: (GROUP_FAILED, 'failed to generate a patch'),
    AGENT_RESOLVED_UNJUDGED: (GROUP_UNJUDGED, 'resolved, verified (not judged)'),
}
VERDICT_ORDER = list(VERDICTS)

# Okabe-Ito palette, matching plot_judge_results.py's GROUP_COLORS exactly;
# the two extra groups reuse plot_corrector_results.py's "failed (AI)" and
# "agent-resolved (verified)" colors.
GROUP_COLORS = {
    GROUP_EQUIVALENT: '#009E73',
    GROUP_DIVERGENT: '#E69F00',
    GROUP_NOT_COMPARABLE: '#56B4E9',
    GROUP_FAILED: '#D55E00',
    GROUP_UNJUDGED: '#0072B2',
    GROUP_OTHER: '#999999',
}

OUTCOME_A_BETTER = 'model A closer to reference'
OUTCOME_TIE = 'tie'
OUTCOME_B_BETTER = 'model B closer to reference'
OUTCOME_UNRANKED = 'not ranked (a side was resolved without a judge)'


def read_statuses(results_dir: Path, csv_name: str = 'results_full.csv') -> dict[str, str]:
    """Return ``{cve_id: status}`` for a results directory.

    Args:
        results_dir: An integration results directory (``results_full.csv`` inside).
        csv_name: The results CSV file name.

    Raises:
        SystemExit: If the CSV is missing or has no ``status``/``cve_id`` columns.
    """
    path = results_dir / csv_name
    if not path.is_file():
        raise SystemExit(f'error: {path} does not exist')
    with path.open(newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        fields = reader.fieldnames or ()
        if 'status' not in fields or 'cve_id' not in fields:
            raise SystemExit(f'error: {path} has no status/cve_id columns')
        return {row['cve_id']: row['status'] for row in reader}


def read_review_rows(results_dir: Path, csv_name: str = 'results_full.csv') -> set[str]:
    """Return the CVE IDs a results directory left review-required.

    Args:
        results_dir: An integration results directory (``results_full.csv`` inside).
        csv_name: The results CSV file name.

    Returns:
        CVE IDs with status ``SECURITY_REVIEW_REQUIRED`` or
        ``WORKFLOW_COMPLETED_UNVERIFIED``.

    Raises:
        SystemExit: If the CSV is missing or has no ``status``/``cve_id`` columns.
    """
    return {cve for cve, status in read_statuses(results_dir, csv_name).items()
            if status in REVIEW_STATUSES}


def read_judge_csv(path: Path) -> dict[str, str]:
    """Return ``{cve_id: judgment}`` for one ``judge_results.csv``.

    Args:
        path: Path to the judge results CSV.

    Returns:
        The judgment per CVE that has one (rows with an empty judgment, which
        should not occur in a finished run, are skipped).

    Raises:
        SystemExit: If the file is missing or has no ``cve_id``/``judgment`` column.
    """
    if not path.is_file():
        raise SystemExit(f'error: {path} does not exist')
    with path.open(newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        fields = reader.fieldnames or ()
        if 'cve_id' not in fields or 'judgment' not in fields:
            raise SystemExit(f'error: {path} has no cve_id/judgment columns')
        return {row['cve_id']: row['judgment'] for row in reader if row['judgment']}


def rank_of(judgment: str) -> int:
    """Return a judgment's rank, best (0) to worst (3); an unknown verdict ranks worst."""
    return RANK_ORDER.get(judgment, WORST_RANK)


def find_inherited(dir_a: Path, dir_b: Path, statuses_a: dict[str, str],
                   statuses_b: dict[str, str]) -> set[str]:
    """Return CVEs both runs hold with the same status and a byte-identical patch.

    A run started with ``--resume`` from another run's results keeps the rows
    it did not retry, artifacts included. Such a CVE was only attempted once,
    by whichever model produced the seed, so it says nothing about how the two
    models compare and is left out.
    """
    inherited = set()
    for cve_id, status in statuses_a.items():
        if statuses_b.get(cve_id) != status:
            continue
        patch_a = dir_a / f'{cve_id}_full_artifacts' / 'final-commits.patch'
        patch_b = dir_b / f'{cve_id}_full_artifacts' / 'final-commits.patch'
        if (patch_a.is_file() and patch_b.is_file()
                and patch_a.read_bytes() == patch_b.read_bytes()):
            inherited.add(cve_id)
    return inherited


def side_verdict(cve_id: str, review: set[str], judge: dict[str, str],
                 statuses: dict[str, str] | None) -> str | None:
    """Return one model's verdict for a CVE, or ``None`` if it has none to compare.

    A review-required CVE takes the judge's verdict. Otherwise, when the
    model's full statuses are known, a ``FAIL_*`` status becomes
    :data:`FAILED_TO_GENERATE` and ``AGENT_RESOLVED`` becomes
    :data:`AGENT_RESOLVED_UNJUDGED`; anything else (skipped, direct success,
    not in the run) has nothing to compare.
    """
    if cve_id in review:
        return judge.get(cve_id)
    status = (statuses or {}).get(cve_id, '')
    if status.startswith('FAIL_'):
        return FAILED_TO_GENERATE
    if status == 'AGENT_RESOLVED':
        # judge_campaign.py --status AGENT_RESOLVED rates these too; only a
        # resolved CVE nobody judged stays unranked.
        return judge.get(cve_id, AGENT_RESOLVED_UNJUDGED)
    return None


def compare_models(review_a: set[str], review_b: set[str], judge_a: dict[str, str],
                    judge_b: dict[str, str], statuses_a: dict[str, str] | None = None,
                    statuses_b: dict[str, str] | None = None,
                    exclude: set[str] | None = None) -> dict[str, dict]:
    """Compare model A's and model B's patches for one judge, CVE by CVE.

    Args:
        review_a: CVE IDs model A left review-required.
        review_b: CVE IDs model B left review-required.
        judge_a: ``{cve_id: judgment}`` from the judge's rating of model A's patches.
        judge_b: ``{cve_id: judgment}`` from the judge's rating of model B's patches.
        statuses_a: Model A's ``{cve_id: status}``. When both status maps are
            given, every CVE at least one model's patch was judged for (review
            required, or ``AGENT_RESOLVED`` with a verdict) is included, with
            the other side's verdict from :func:`side_verdict` (most usefully
            :data:`FAILED_TO_GENERATE`). Without them, only CVEs both models
            left review-required are compared.
        statuses_b: Model B's ``{cve_id: status}``.
        exclude: CVE IDs to leave out, e.g. rows a resumed run inherited
            from the other run unchanged (see :func:`find_inherited`).

    Returns:
        ``{cve_id: {"judgment_a": str, "judgment_b": str, "outcome": str}}``,
        sorted by ``cve_id``.
    """
    with_statuses = statuses_a is not None and statuses_b is not None
    if with_statuses:
        resolved_a = {c for c, s in (statuses_a or {}).items()
                      if s == 'AGENT_RESOLVED' and c in judge_a}
        resolved_b = {c for c, s in (statuses_b or {}).items()
                      if s == 'AGENT_RESOLVED' and c in judge_b}
        candidates = review_a | review_b | resolved_a | resolved_b
    else:
        candidates = review_a & review_b
    candidates -= exclude or set()
    result: dict[str, dict] = {}
    for cve_id in sorted(candidates):
        verdict_a = side_verdict(cve_id, review_a, judge_a, statuses_a)
        verdict_b = side_verdict(cve_id, review_b, judge_b, statuses_b)
        if verdict_a is None or verdict_b is None:
            continue
        if AGENT_RESOLVED_UNJUDGED in (verdict_a, verdict_b):
            outcome = OUTCOME_UNRANKED
        elif rank_of(verdict_a) < rank_of(verdict_b):
            outcome = OUTCOME_A_BETTER
        elif rank_of(verdict_b) < rank_of(verdict_a):
            outcome = OUTCOME_B_BETTER
        else:
            outcome = OUTCOME_TIE
        result[cve_id] = {'judgment_a': verdict_a, 'judgment_b': verdict_b, 'outcome': outcome}
    return result


def verdict_counts(judgments: list[str]) -> dict[str, int]:
    """Count judgments by verdict, keeping only the verdicts that occur.

    Args:
        judgments: Judgment strings, one per CVE.

    Returns:
        ``{judgment: count}``, including a verdict this tool does not
        recognise under its own literal key rather than dropping it.
    """
    return dict(Counter(judgments))


def verdicts_present(*counts: dict[str, int]) -> list[str]:
    """Return the verdicts present in any of several count dicts, display order.

    Known verdicts (:data:`VERDICT_ORDER`) come first, in their fixed
    display order; an unrecognised verdict follows, sorted, and exactly
    once even if it appears in more than one of the given count dicts.

    Args:
        counts: One or more ``{verdict: count}`` dicts, as returned by
            :func:`verdict_counts`.

    Returns:
        Each verdict that has a nonzero count in at least one dict, with no
        duplicates.
    """
    all_verdicts: set[str] = set()
    for count in counts:
        all_verdicts |= {v for v, c in count.items() if c}
    known = [v for v in VERDICT_ORDER if v in all_verdicts]
    unknown = sorted(all_verdicts - set(VERDICT_ORDER))
    return known + unknown


def majority_verdict(verdicts: list[str]) -> str:
    """Return the majority verdict among several judges' ratings of one patch.

    Args:
        verdicts: One verdict per judge, same CVE, same model.

    Returns:
        The verdict most judges gave. On a tie for first place (including a
        true N-way split with no verdict ahead), returns the worst-ranked
        verdict among those tied for first, so a disagreement is not
        resolved by quietly picking the most forgiving opinion.

    Raises:
        ValueError: If ``verdicts`` is empty.
    """
    if not verdicts:
        raise ValueError('majority_verdict() needs at least one verdict')
    counts = Counter(verdicts)
    top_count = counts.most_common(1)[0][1]
    tied_for_first = [v for v, c in counts.items() if c == top_count]
    return max(tied_for_first, key=rank_of)


def combine_judges(per_judge: dict[str, dict[str, dict]]) -> dict[str, dict]:
    """Collapse several judges' per-CVE verdicts into one majority verdict each.

    Args:
        per_judge: ``{judge_name: compare_models() result}``.

    Returns:
        ``{cve_id: {"judgment_a": str, "judgment_b": str, "n_judges": int}}``
        for every CVE at least one judge rated for both models; ``n_judges``
        is how many judges contributed to that CVE's majority (fewer than
        ``len(per_judge)`` when a judge has not yet rated that CVE).
    """
    all_cves: set[str] = set()
    for result in per_judge.values():
        all_cves |= result.keys()

    combined: dict[str, dict] = {}
    for cve_id in sorted(all_cves):
        verdicts_a = [result[cve_id]['judgment_a'] for result in per_judge.values()
                      if cve_id in result]
        verdicts_b = [result[cve_id]['judgment_b'] for result in per_judge.values()
                      if cve_id in result]
        if not verdicts_a:
            continue
        combined[cve_id] = {'judgment_a': majority_verdict(verdicts_a),
                            'judgment_b': majority_verdict(verdicts_b),
                            'n_judges': len(verdicts_a)}
    return combined


def plot_comparison(per_judge: dict[str, dict[str, dict]], model_a: str, model_b: str,
                    title: str | None, out_path: Path) -> None:
    """One panel per judge: each model's own verdict distribution, bar by bar.

    Unlike a win/tie/loss rollup, this keeps the verdict categories from
    ``plot_judge_results.py`` visible (identical, stylistic, meaningful, ...),
    so two models tying on ``meaningful`` reads as "both diverged from the
    reference", not as a plain, unqualified "tie".

    Args:
        per_judge: ``{judge_name: compare_models() result}``.
        model_a: Model A's display name.
        model_b: Model B's display name.
        title: Chart title, or ``None`` for ``"<model_a> vs <model_b>"``.
        out_path: PNG output path.
    """
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    judges = list(per_judge)
    counts_a = {judge: verdict_counts([row['judgment_a'] for row in result.values()])
               for judge, result in per_judge.items()}
    counts_b = {judge: verdict_counts([row['judgment_b'] for row in result.values()])
               for judge, result in per_judge.items()}
    totals = {judge: len(result) for judge, result in per_judge.items()}
    if not any(totals.values()):
        raise SystemExit('error: no CVE is covered by both models and a judge -- nothing to plot')

    verdicts = verdicts_present(*counts_a.values(), *counts_b.values())
    top = max((max(counts_a[j].get(v, 0), counts_b[j].get(v, 0)) for j in judges for v in verdicts),
              default=0)

    fig, axes = plt.subplots(len(judges), 1, figsize=(10, 2.3 * len(judges) + 1.4), squeeze=False)
    for ax, judge in zip(axes[:, 0], judges, strict=True):
        ypos = list(range(len(verdicts)))
        values_a = [counts_a[judge].get(v, 0) for v in verdicts]
        values_b = [counts_b[judge].get(v, 0) for v in verdicts]
        colors = [GROUP_COLORS[VERDICTS.get(v, (GROUP_OTHER, v))[0]] for v in verdicts]
        bar_height = 0.34
        bars_a = ax.barh([y + bar_height / 2 for y in ypos], values_a, height=bar_height,
                         color=colors, edgecolor='black', linewidth=0.6)
        bars_b = ax.barh([y - bar_height / 2 for y in ypos], values_b, height=bar_height,
                         color=colors, edgecolor='black', linewidth=0.6, alpha=0.45,
                         hatch='////')
        for bar_obj, value in zip((*bars_a, *bars_b), (*values_a, *values_b), strict=True):
            if value:
                ax.text(bar_obj.get_width() + max(top, 1) * 0.015,
                        bar_obj.get_y() + bar_obj.get_height() / 2, str(value),
                        va='center', fontsize=8.5)
        ax.set_yticks(ypos)
        ax.set_yticklabels([VERDICTS.get(v, (None, v))[1] for v in verdicts], fontsize=9.5)
        ax.invert_yaxis()
        ax.set_xlim(0, max(top, 1) * 1.22)
        ax.set_title(f'{judge}  (n={totals[judge]})', fontsize=10.5, fontweight='bold', loc='left')
        ax.grid(axis='x', alpha=0.25, linestyle=':')
        ax.set_axisbelow(True)
    axes[-1, 0].set_xlabel('CVEs at least one model left review-required (per judge)')
    fig.suptitle(title or f'{model_a} vs {model_b}', fontsize=13.5, fontweight='bold', y=0.995)
    fig.legend(
        # Model B's bar sits above model A's in each pair, so list it first.
        handles=[Patch(facecolor='#777777', edgecolor='black', linewidth=0.6, alpha=0.45,
                       hatch='////', label=model_b),
                 Patch(facecolor='#777777', edgecolor='black', linewidth=0.6, label=model_a)],
        loc='upper right', fontsize=9.5, frameon=False, ncol=2,
        bbox_to_anchor=(0.995, 1.0))
    fig.text(0.01, 0.005, 'Verdicts compare each patch with the human reference.',
              fontsize=7.5, color='#555555', ha='left', va='bottom')
    fig.tight_layout(rect=(0, 0.035, 1, 0.97))
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_majority_comparison(combined: dict[str, dict], model_a: str, model_b: str,
                             n_judges: int, title: str | None, out_path: Path,
                             by_group: bool = True) -> None:
    """Single-panel bar chart: each model's majority-verdict distribution.

    Collapses every judge's opinion of a CVE into one majority verdict per
    model (see :func:`majority_verdict`) before counting, so the chart has
    one pair of bars per category instead of one panel per judge.

    Args:
        combined: As returned by :func:`combine_judges`.
        model_a: Model A's display name.
        model_b: Model B's display name.
        n_judges: How many judges fed the majority vote (for the caption).
        title: Chart title, or ``None`` for ``"<model_a> vs <model_b>"``.
        out_path: PNG output path.
        by_group: Draw one bar pair per color group (equivalent, meaningfully
            different, ...). If ``False``, draw one per verdict instead, with
            the group totals in a legend below.
    """
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    total = len(combined)
    if not total:
        raise SystemExit('error: no CVE is covered by both models -- nothing to plot')
    counts_a = verdict_counts([row['judgment_a'] for row in combined.values()])
    counts_b = verdict_counts([row['judgment_b'] for row in combined.values()])
    totals_a = group_totals(counts_a)
    totals_b = group_totals(counts_b)
    groups = [g for g in GROUP_COLORS if totals_a.get(g) or totals_b.get(g)]

    if by_group:
        categories = groups
        values_a = [totals_a.get(g, 0) for g in groups]
        values_b = [totals_b.get(g, 0) for g in groups]
        colors = [GROUP_COLORS[g] for g in groups]
        labels = groups
    else:
        categories = verdicts_present(counts_a, counts_b)
        values_a = [counts_a.get(v, 0) for v in categories]
        values_b = [counts_b.get(v, 0) for v in categories]
        colors = [GROUP_COLORS[VERDICTS.get(v, (GROUP_OTHER, v))[0]] for v in categories]
        labels = [VERDICTS.get(v, (None, v))[1] for v in categories]
    top = max((*values_a, *values_b), default=0)

    fig, ax = plt.subplots(figsize=(9, 0.62 * len(categories) + 2.2))
    ypos = list(range(len(categories)))
    bar_height = 0.34
    bars_a = ax.barh([y + bar_height / 2 for y in ypos], values_a, height=bar_height,
                     color=colors, edgecolor='black', linewidth=0.7)
    bars_b = ax.barh([y - bar_height / 2 for y in ypos], values_b, height=bar_height,
                     color=colors, edgecolor='black', linewidth=0.7, alpha=0.45, hatch='////')
    for bar_obj, value in zip((*bars_a, *bars_b), (*values_a, *values_b), strict=True):
        if value:
            ax.text(bar_obj.get_width() + max(top, 1) * 0.015,
                    bar_obj.get_y() + bar_obj.get_height() / 2,
                    f'{value}  ({100 * value / total:.0f}%)', va='center', fontsize=9)
    ax.set_yticks(ypos)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlim(0, max(top, 1) * 1.28)
    ax.set_xlabel('CVEs at least one model left review-required')
    ax.set_title(f'{title or f"{model_a} vs {model_b}"}  (n={total})', fontsize=13,
                 fontweight='bold')
    ax.grid(axis='x', alpha=0.25, linestyle=':')
    ax.set_axisbelow(True)
    ax.legend(
        # Model B's bar sits above model A's in each pair, so list it first.
        handles=[Patch(facecolor='#777777', edgecolor='black', linewidth=0.7, alpha=0.45,
                       hatch='////', label=model_b),
                 Patch(facecolor='#777777', edgecolor='black', linewidth=0.7, label=model_a)],
        loc='lower right', fontsize=9.5, frameon=False)

    legend_rows = 0
    if not by_group:
        # Overall share per color group, like plot_judge_results.py's legend,
        # with both models' figures side by side.
        legend_rows = len(groups)
        fig.legend(
            handles=[Patch(facecolor=GROUP_COLORS[g],
                           label=f'{g}:  {model_a} {totals_a.get(g, 0)} '
                                 f'({100 * totals_a.get(g, 0) / total:.0f}%)  ·  '
                                 f'{model_b} {totals_b.get(g, 0)} '
                                 f'({100 * totals_b.get(g, 0) / total:.0f}%)')
                     for g in groups],
            loc='lower center', bbox_to_anchor=(0.5, 0.035), ncol=1, fontsize=9, frameon=False)
    judge_word = 'judge' if n_judges == 1 else f'{n_judges} judges'
    fig.text(0.01, 0.01, f'Majority verdict of {judge_word}, compared with the human reference.',
              fontsize=7.5, color='#555555', ha='left', va='bottom')
    fig.tight_layout(rect=(0, 0.035 + 0.03 * legend_rows + 0.02, 1, 1))
    fig.savefig(out_path, dpi=150, bbox_inches='tight')
    plt.close(fig)


def group_totals(counts: dict[str, int]) -> dict[str, int]:
    """Sum verdict counts per color group (see :data:`VERDICTS`).

    Args:
        counts: ``{verdict: count}``, as returned by :func:`verdict_counts`.

    Returns:
        ``{group: count}`` for the groups that occur; an unrecognised verdict
        counts toward :data:`GROUP_OTHER`.
    """
    totals: dict[str, int] = {}
    for verdict, count in counts.items():
        group = VERDICTS.get(verdict, (GROUP_OTHER, verdict))[0]
        totals[group] = totals.get(group, 0) + count
    return totals


def print_summary(per_judge: dict[str, dict[str, dict]], model_a: str, model_b: str) -> None:
    """Print the figures the chart shows, and the CVEs the judges disagree on which model won."""
    for judge, result in per_judge.items():
        total = len(result)
        counts = Counter(row['outcome'] for row in result.values())
        print(f'\n{judge}  (n={total}):')
        for outcome in (OUTCOME_A_BETTER, OUTCOME_TIE, OUTCOME_B_BETTER, OUTCOME_UNRANKED):
            if counts[outcome]:
                label = outcome.replace('model A', model_a).replace('model B', model_b)
                print(f'  {label:<32} {counts[outcome]:>4}  ({100 * counts[outcome] / total:5.1f}%)')

    judges = list(per_judge)
    if len(judges) < 2:
        return
    shared_cves = set.intersection(*(set(result) for result in per_judge.values()))
    cross_judge_disagreements = [
        cve for cve in sorted(shared_cves)
        if len({per_judge[judge][cve]['outcome'] for judge in judges}) > 1
    ]
    if cross_judge_disagreements:
        print(f'\nCVEs where judges disagree on which model won ({len(cross_judge_disagreements)}):')
        for cve_id in cross_judge_disagreements:
            parts = ', '.join(
                f'{judge}='
                f'{per_judge[judge][cve_id]["outcome"].replace("model A", model_a).replace("model B", model_b)}'
                for judge in judges)
            print(f'  {cve_id:<22} {parts}')


def print_majority_summary(combined: dict[str, dict], model_a: str, model_b: str) -> None:
    """Print each model's majority-verdict distribution and the win/tie/loss rollup.

    Args:
        combined: As returned by :func:`combine_judges`.
        model_a: Model A's display name.
        model_b: Model B's display name.
    """
    total = len(combined)
    print(f'Majority verdict across judges (n={total}):')
    counts_a = verdict_counts([row['judgment_a'] for row in combined.values()])
    counts_b = verdict_counts([row['judgment_b'] for row in combined.values()])
    for verdict in VERDICT_ORDER:
        if counts_a.get(verdict) or counts_b.get(verdict):
            label = VERDICTS[verdict][1]
            print(f'  {label:<32} {model_a}={counts_a.get(verdict, 0):>4}  '
                  f'{model_b}={counts_b.get(verdict, 0):>4}')

    totals_a, totals_b = group_totals(counts_a), group_totals(counts_b)
    print('\nBy group:')
    for group in GROUP_COLORS:
        if totals_a.get(group) or totals_b.get(group):
            a, b = totals_a.get(group, 0), totals_b.get(group, 0)
            print(f'  {group:<32} {model_a}={a:>4} ({100 * a / total:4.1f}%)  '
                  f'{model_b}={b:>4} ({100 * b / total:4.1f}%)')

    wins_a = wins_b = ties = unranked = 0
    for row in combined.values():
        if AGENT_RESOLVED_UNJUDGED in (row['judgment_a'], row['judgment_b']):
            unranked += 1
            continue
        rank_a, rank_b = rank_of(row['judgment_a']), rank_of(row['judgment_b'])
        if rank_a < rank_b:
            wins_a += 1
        elif rank_b < rank_a:
            wins_b += 1
        else:
            ties += 1
    print(f'\n{model_a} closer to reference: {wins_a:>4}  ({100 * wins_a / total:5.1f}%)')
    print(f'tie:                         {ties:>4}  ({100 * ties / total:5.1f}%)')
    print(f'{model_b} closer to reference: {wins_b:>4}  ({100 * wins_b / total:5.1f}%)')
    if unranked:
        print(f'not ranked (one side resolved, not judged): {unranked:>4}  '
              f'({100 * unranked / total:5.1f}%)')


def parse_judge_arg(spec: str) -> tuple[str, Path]:
    """Parse one ``--judge model=path`` argument.

    Args:
        spec: A raw ``model=path`` string.

    Returns:
        The ``(model, path)`` pair.

    Raises:
        SystemExit: If the spec has no ``=`` or no model name.
    """
    if '=' not in spec:
        raise SystemExit(f"error: '{spec}' is not model=path")
    model, _, raw_path = spec.partition('=')
    if not model:
        raise SystemExit(f"error: '{spec}' has no model name before '='")
    return model, Path(raw_path)


def main() -> None:
    """Entry point for the model-vs-model judge comparison tool."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--model-a', required=True, metavar='NAME=RESULTS_DIR',
                        help='Model A name and its integration results directory')
    parser.add_argument('--model-b', required=True, metavar='NAME=RESULTS_DIR',
                        help='Model B name and its integration results directory')
    parser.add_argument('--judge', action='append', dest='judges', required=True,
                        metavar='JUDGE_NAME=A_JUDGE_CSV,B_JUDGE_CSV',
                        help='One judge: its name and both models\' judge_results.csv, '
                             'comma-separated as A_PATH,B_PATH. Repeatable.')
    parser.add_argument('--csv', default='results_full.csv', help='Results CSV name')
    parser.add_argument('--title', default=None,
                        help='Chart title (default: "<model A> vs <model B>")')
    parser.add_argument('-o', '--output', type=Path, default=Path('model_comparison.png'),
                        help='PNG output path (default: model_comparison.png)')
    parser.add_argument('--per-judge', action='store_true',
                        help='Draw one panel per judge instead of the default single panel '
                             '(majority verdict across judges)')
    parser.add_argument('--detailed', action='store_true',
                        help='Draw one bar pair per verdict (identical, stylistic, ...) instead '
                             'of the default one per group, with the group totals below')
    parser.add_argument('--shared-only', action='store_true',
                        help='Only compare CVEs both models left review-required. By default '
                             'a CVE only one model left for review is included too, with the '
                             'other side shown as "failed to generate a patch" (FAIL_*) or '
                             '"resolved, verified (not judged)" (AGENT_RESOLVED)')
    parser.add_argument('--attempted', type=Path, metavar='FILE',
                        help='File of CVE IDs (whitespace-separated) both models actually '
                             'attempted. They are kept even when both runs hold the same '
                             'status and a byte-identical patch, which otherwise marks a '
                             'row a resumed run inherited without retrying')
    parser.add_argument('--no-plot', action='store_true',
                        help='Print the summary only; skip the chart (no matplotlib needed)')
    args = parser.parse_args()

    name_a, dir_a = parse_judge_arg(args.model_a)
    name_b, dir_b = parse_judge_arg(args.model_b)
    statuses_a = read_statuses(dir_a, args.csv)
    statuses_b = read_statuses(dir_b, args.csv)
    review_a = {cve for cve, status in statuses_a.items() if status in REVIEW_STATUSES}
    review_b = {cve for cve, status in statuses_b.items() if status in REVIEW_STATUSES}
    if not (review_a | review_b):
        sys.exit(f'error: neither {name_a} nor {name_b} has a review-required CVE')
    inherited = find_inherited(dir_a, dir_b, statuses_a, statuses_b)
    if args.attempted:
        # Both models really attempted these; an identical patch is a genuine tie.
        inherited -= set(args.attempted.read_text(encoding='utf-8').split())
    if inherited:
        print(f'Leaving out {len(inherited)} CVEs both runs hold with the same patch '
              '(inherited by a resumed run, not attempted by both models).')
    if args.shared_only:
        statuses_a = statuses_b = None

    per_judge: dict[str, dict[str, dict]] = {}
    for spec in args.judges:
        judge_name, raw_paths = parse_judge_arg(spec)
        if ',' not in str(raw_paths):
            sys.exit(f"error: --judge {spec!r} needs A_PATH,B_PATH after the judge name")
        path_a, path_b = (Path(p) for p in str(raw_paths).split(',', 1))
        judge_a = read_judge_csv(path_a)
        judge_b = read_judge_csv(path_b)
        result = compare_models(review_a, review_b, judge_a, judge_b, statuses_a, statuses_b,
                                exclude=inherited)
        if result:
            per_judge[judge_name] = result

    if not per_judge:
        sys.exit('error: no judge covers any CVE shared by both models')

    if args.per_judge:
        print_summary(per_judge, name_a, name_b)
        if not args.no_plot:
            plot_comparison(per_judge, name_a, name_b, args.title, args.output)
            print(f'\nChart written to {args.output}')
    else:
        combined = combine_judges(per_judge)
        print_majority_summary(combined, name_a, name_b)
        if not args.no_plot:
            plot_majority_comparison(combined, name_a, name_b, len(per_judge), args.title,
                                     args.output, by_group=not args.detailed)
            print(f'\nChart written to {args.output}')


if __name__ == '__main__':
    main()
