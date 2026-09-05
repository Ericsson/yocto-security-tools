#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Standalone plotting of cve-agent model benchmark results.

Reads ``agent_results.csv`` and ``judge_results.csv`` from a benchmark results
directory (produced by ``tests/benchmark/run_benchmark.sh``), joins them on
``(cve_id, model)``, collapses each run into a single *outcome* (see
:func:`classify_outcome`), and generates PNG charts:

  1. outcome_by_model.png      - stacked run outcomes per model, plus each
                                 model's reference-equivalent rate
  2. bucket_by_model.png       - the raw diff_bucket distribution per model,
                                 i.e. the signal *before* the judge reclassifies
                                 a large-but-equivalent diff as a success
  3. cost_by_model.png         - total credits, credits per run, and credits
                                 per usable (reference-equivalent) backport
  4. quality_vs_cost.png       - avg credits per run vs. reference-equivalent
                                 rate, one point per model
  5. effort_by_model.png       - avg wall-clock duration and avg tool calls
  6. outcome_matrix.png        - per-CVE x per-model outcome grid, which shows
                                 whether a bad column is a weak model or a bad
                                 row is a CVE that defeats every model

The central idea is the outcome collapse: no single CSV column answers "did the
model do the job?" on its own. ``diff_bucket`` says how far the generated patch
drifted from the human reference backport, and the judge says whether that
drift is behavioral. A ``major`` diff judged ``stylistic`` is a success; a
``partial`` diff judged ``meaningful`` is not.

``exit_status`` is deliberately *not* read as a pass/fail flag. It carries a
durable ``ResultOutcome.summary_state`` whenever the run recorded one, so a run
that completed and produced a comparable patch still reports a non-zero-looking
state there when the release gate declined to accept it. Those runs are scored
on patch equivalence; only the states in :data:`FAILED_STATUSES` mean the run
produced nothing to compare. Two dispositions are kept separate from both
success and failure: ``escalated`` (the model asked for a human, which is the
correct answer for an out-of-scope fix) and ``gate-rejected`` (the host's
semantic validation rejected the result, which can happen even for a patch
textually identical to the reference).

Colors come from the Okabe-Ito palette (distinguishable under the common forms
of color blindness) and every bar is annotated with its value, so no chart
depends on hue alone being read correctly.

This is a standalone, dev-only tool. It is NOT part of the installed
yocto-security-tools package and requires matplotlib, which is not a runtime
dependency of the project (see AGENTS.md "Minimize Dependencies").

Usage:
    pip install matplotlib
    python3 tools/plot_benchmark_results.py \
        tests/benchmark/test-results/bench_20260828_145923 --output-dir plots/
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

# --- Outcome taxonomy ------------------------------------------------------

OUTCOME_EQUIVALENT = 'equivalent'
OUTCOME_DIVERGENT = 'divergent'
OUTCOME_UNJUDGED = 'unjudged'
OUTCOME_GATE_REJECTED = 'gate-rejected'
OUTCOME_ESCALATED = 'escalated'
OUTCOME_NO_PATCH = 'no-patch'
OUTCOME_FAILED = 'failed'

# Stack/plot order: best outcome first, so every bar reads left-to-right as
# quality descending. 'escalated' ranks above 'no-patch' because asking for a
# human is a safe, defensible answer, whereas dismissing a CVE as
# not-applicable can silently leave a live vulnerability.
OUTCOME_ORDER = (
    OUTCOME_EQUIVALENT,
    OUTCOME_DIVERGENT,
    OUTCOME_UNJUDGED,
    OUTCOME_GATE_REJECTED,
    OUTCOME_ESCALATED,
    OUTCOME_NO_PATCH,
    OUTCOME_FAILED,
)

OUTCOME_COLORS = {
    OUTCOME_EQUIVALENT: '#009E73',
    OUTCOME_DIVERGENT: '#E69F00',
    OUTCOME_UNJUDGED: '#999999',
    OUTCOME_GATE_REJECTED: '#CC79A7',
    OUTCOME_ESCALATED: '#0072B2',
    OUTCOME_NO_PATCH: '#56B4E9',
    OUTCOME_FAILED: '#D55E00',
}

OUTCOME_LABELS = {
    OUTCOME_EQUIVALENT: 'equivalent to reference',
    OUTCOME_DIVERGENT: 'meaningfully different',
    OUTCOME_UNJUDGED: 'diverged, not judged',
    OUTCOME_GATE_REJECTED: 'rejected by semantic validation',
    OUTCOME_ESCALATED: 'escalated to a human',
    OUTCOME_NO_PATCH: 'no patch produced',
    OUTCOME_FAILED: 'run failed',
}

# Short glyphs for the dense CVE x model grid, so a cell is readable without
# resolving its color against the legend.
OUTCOME_GLYPHS = {
    OUTCOME_EQUIVALENT: '=',
    OUTCOME_DIVERGENT: '\u2260',
    OUTCOME_UNJUDGED: '?',
    OUTCOME_GATE_REJECTED: '!',
    OUTCOME_ESCALATED: '\u2191',
    OUTCOME_NO_PATCH: '\u2013',
    OUTCOME_FAILED: 'x',
}

# ``exit_status`` holds either a durable ResultOutcome.summary_state, a raw
# process exit code, or one of run_benchmark.sh's own markers. These states mean
# the run never reached a result worth comparing.
FAILED_STATUSES = (
    'WORKFLOW_FAILED',
    'HOST_INITIALIZATION_ERROR',
    'PROVIDER_TIMEOUT',
    'AGENT_NO_PROGRESS',
    'TIMEOUT',
    'SETUP_FAILED',
)

# The host's semantic validation actively rejected the result. Kept separate
# from both success and failure: a rejection can accompany a patch that is
# textually identical to the reference (e.g. a missing prerequisite), so
# folding it into 'equivalent' would hide a real security finding while
# folding it into 'failed' would misreport a correct patch.
GATE_REJECTED_STATUS = 'SECURITY_REJECTED'

# Durable state for a run that produced nothing to compare by design.
SKIPPED_STATUS = 'SKIPPED'

# Buckets that run_benchmark.sh never sends to the judge because the generated
# patch is already close enough to the human reference to be a success.
EQUIVALENT_BUCKETS = ('identical', 'minor')

# Buckets the judge does evaluate (mirrors bench_lib.JUDGEABLE_BUCKETS, kept
# local so this dev tool has no import dependency on the test package).
JUDGEABLE_BUCKETS = ('moderate', 'major', 'partial')

# Verdicts meaning "the code does the same thing". 'structural-only' and
# 'comment-only' are recorded by run_benchmark.sh without a judge call.
EQUIVALENT_VERDICTS = ('stylistic', 'comment-only', 'structural-only')

# diff_bucket values in CSV order, plus 'skipped' (cve-agent exited 0 without
# producing a patch) and '-' (no bucket recorded, i.e. the run failed).
BUCKET_ORDER = (
    'identical',
    'minor',
    'moderate',
    'major',
    'partial',
    'file-mismatch',
    'skipped',
    '-',
)

BUCKET_COLORS = {
    'identical': '#005f45',
    'minor': '#009E73',
    'moderate': '#F0E442',
    'major': '#E69F00',
    'partial': '#56B4E9',
    'file-mismatch': '#CC79A7',
    'skipped': '#999999',
    '-': '#D55E00',
}

TIER_RANK = {'easy': 0, 'medium': 1, 'hard': 2}


# --- Data loading ----------------------------------------------------------


def read_csv(path: Path) -> list[dict[str, str]]:
    """Read a CSV into a list of row dicts.

    Args:
        path: CSV file path. A missing file is not an error, since a run may
            have been made with ``--skip-judge``.

    Returns:
        Row dicts in file order, or an empty list if the file does not exist.
    """
    if not path.is_file():
        return []
    with open(path, newline='', encoding='utf-8') as fh:
        return list(csv.DictReader(fh))


def _to_float(value: str | None) -> float | None:
    """Parse a CSV cell as a float, tolerating blanks and '-' placeholders."""
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def classify_outcome(agent_row: dict[str, str], judge_row: dict[str, str] | None) -> str:
    """Collapse one benchmark run into a single outcome.

    Two independent signals are combined. The ``outcome`` column carries
    cve-agent's own ``ResultStatus`` (recorded from the durable ``result.json``)
    and says what the *run* did; ``diff_bucket`` plus the judge say how close
    the *patch* is to the human reference.

    ``exit_status`` is not a pass/fail flag: it holds a durable
    ``summary_state`` whenever one was recorded, so a completed run that the
    release gate declined still reports e.g. ``SECURITY_REVIEW_REQUIRED``
    there. Such runs did produce a comparable patch — ``run_benchmark.sh``
    deliberately keeps them comparable — so they are scored on patch
    equivalence rather than written off.

    Flat rules, evaluated in order:

    1. ``skipped`` -> ``no-patch``: exited without producing a patch.
    2. ``escalated`` -> ``escalated``: the model declined to guess and asked
       for a human. That is the correct answer for a fix it cannot make in
       scope, so it must not score as a breakage.
    3. ``failed``, or an ``exit_status`` in :data:`FAILED_STATUSES` -> ``failed``.
    4. No ``outcome`` recorded and a non-``'0'`` ``exit_status`` -> ``failed``.
       All that is known is a raw exit code, a timeout, or a setup failure.
    5. :data:`GATE_REJECTED_STATUS` -> ``gate-rejected``.
    6. ``diff_bucket == 'skipped'`` -> ``no-patch``.
    7. ``diff_bucket`` in :data:`EQUIVALENT_BUCKETS` -> ``equivalent``.
    8. A judgeable bucket whose verdict is in :data:`EQUIVALENT_VERDICTS`
       -> ``equivalent``; ``meaningful`` -> ``divergent``; missing verdict
       row -> ``unjudged``.
    9. Anything else (e.g. ``file-mismatch``, which stays unjudged by design)
       -> ``unjudged``.

    Args:
        agent_row: A row from ``agent_results.csv``.
        judge_row: The matching ``judge_results.csv`` row, or ``None`` if the
            pair was never judged.

    Returns:
        One of the ``OUTCOME_*`` constants.
    """
    outcome = (agent_row.get('outcome') or '').strip()
    status = (agent_row.get('exit_status') or '').strip()

    if outcome == 'skipped' or status == SKIPPED_STATUS:
        return OUTCOME_NO_PATCH
    if outcome == 'escalated':
        return OUTCOME_ESCALATED
    if outcome == 'failed' or status in FAILED_STATUSES:
        return OUTCOME_FAILED
    if not outcome and status != '0':
        return OUTCOME_FAILED
    if status == GATE_REJECTED_STATUS:
        return OUTCOME_GATE_REJECTED

    bucket = (agent_row.get('diff_bucket') or '').strip()
    if bucket == 'skipped':
        return OUTCOME_NO_PATCH
    if bucket in EQUIVALENT_BUCKETS:
        return OUTCOME_EQUIVALENT

    if bucket in JUDGEABLE_BUCKETS:
        verdict = (judge_row or {}).get('judgment', '').strip()
        if verdict in EQUIVALENT_VERDICTS:
            return OUTCOME_EQUIVALENT
        if verdict == 'meaningful':
            return OUTCOME_DIVERGENT
        return OUTCOME_UNJUDGED

    return OUTCOME_UNJUDGED


@dataclass
class ModelStats:
    """Aggregated benchmark figures for one model."""

    model: str
    outcomes: Counter[str] = field(default_factory=Counter)
    buckets: Counter[str] = field(default_factory=Counter)
    credits: list[float] = field(default_factory=list)
    durations: list[float] = field(default_factory=list)
    commands: list[float] = field(default_factory=list)

    @property
    def runs(self) -> int:
        """Number of benchmark runs recorded for this model."""
        return sum(self.outcomes.values())

    @property
    def total_credits(self) -> float:
        """Sum of credits over runs that reported a credit figure."""
        return sum(self.credits)

    @property
    def avg_credits(self) -> float:
        """Mean credits per run that reported a credit figure."""
        return self.total_credits / len(self.credits) if self.credits else 0.0

    @property
    def avg_duration(self) -> float:
        """Mean wall-clock seconds per run."""
        return sum(self.durations) / len(self.durations) if self.durations else 0.0

    @property
    def avg_commands(self) -> float:
        """Mean tool-call count per run."""
        return sum(self.commands) / len(self.commands) if self.commands else 0.0

    @property
    def equivalent(self) -> int:
        """Count of runs that landed a reference-equivalent backport."""
        return self.outcomes[OUTCOME_EQUIVALENT]

    @property
    def equivalent_rate(self) -> float:
        """Fraction of runs that landed a reference-equivalent backport (0..1)."""
        return self.equivalent / self.runs if self.runs else 0.0

    @property
    def credits_per_equivalent(self) -> float | None:
        """Total credits divided by usable backports produced.

        Returns:
            Cost per usable result, or ``None`` when the model produced none —
            the ratio is undefined then, not infinite, and callers must render
            that distinctly so "cheap but useless" cannot read as "cheap".
        """
        return self.total_credits / self.equivalent if self.equivalent else None


def aggregate(
    agent_rows: list[dict[str, str]], judge_rows: list[dict[str, str]]
) -> dict[str, ModelStats]:
    """Join agent and judge rows on ``(cve_id, model)`` and aggregate per model.

    Args:
        agent_rows: Rows from ``agent_results.csv``.
        judge_rows: Rows from ``judge_results.csv``.

    Returns:
        Mapping of model name to its :class:`ModelStats`.
    """
    judge_by_key = {(r['cve_id'], r['model']): r for r in judge_rows}
    stats: dict[str, ModelStats] = {}
    for row in agent_rows:
        model = row['model']
        entry = stats.setdefault(model, ModelStats(model=model))
        judge_row = judge_by_key.get((row['cve_id'], model))
        entry.outcomes[classify_outcome(row, judge_row)] += 1
        bucket = (row.get('diff_bucket') or '-').strip() or '-'
        entry.buckets[bucket] += 1
        for value, target in (
            (_to_float(row.get('credits')), entry.credits),
            (_to_float(row.get('duration_s')), entry.durations),
            (_to_float(row.get('commands')), entry.commands),
        ):
            if value is not None:
                target.append(value)
    return stats


def rank_models(stats: dict[str, ModelStats]) -> list[ModelStats]:
    """Order models best-first: highest equivalent rate, then cheapest."""
    return sorted(
        stats.values(),
        key=lambda s: (-s.equivalent_rate, s.total_credits, s.model),
    )


def build_matrix(
    agent_rows: list[dict[str, str]], judge_rows: list[dict[str, str]]
) -> tuple[list[str], dict[str, str], dict[tuple[str, str], str]]:
    """Build the per-CVE x per-model outcome grid.

    Args:
        agent_rows: Rows from ``agent_results.csv``.
        judge_rows: Rows from ``judge_results.csv``.

    Returns:
        ``(cves, tier_of, grid)`` where ``cves`` is ordered easy->hard then
        alphabetically, ``tier_of`` maps CVE to its tier, and ``grid`` maps
        ``(cve_id, model)`` to an outcome constant.
    """
    judge_by_key = {(r['cve_id'], r['model']): r for r in judge_rows}
    tier_of: dict[str, str] = {}
    grid: dict[tuple[str, str], str] = {}
    for row in agent_rows:
        cve = row['cve_id']
        tier_of.setdefault(cve, row.get('tier', ''))
        grid[(cve, row['model'])] = classify_outcome(
            row, judge_by_key.get((cve, row['model']))
        )
    cves = sorted(tier_of, key=lambda c: (TIER_RANK.get(tier_of[c], 3), c))
    return cves, tier_of, grid


# --- Charts ----------------------------------------------------------------


def _caption(fig, text: str) -> None:
    """Attach a small explanatory caption under a figure."""
    fig.text(0.01, 0.01, text, fontsize=7.5, color='#555555', ha='left', va='bottom')


def plot_outcome_by_model(ranked: list[ModelStats], out_path: Path) -> None:
    """Stacked horizontal bars of run outcomes per model."""
    import matplotlib.pyplot as plt

    models = [s.model for s in ranked]
    ypos = list(range(len(models)))
    fig, ax = plt.subplots(figsize=(9.5, 5.0))

    left = [0.0] * len(models)
    for outcome in OUTCOME_ORDER:
        widths = [float(s.outcomes[outcome]) for s in ranked]
        if not any(widths):
            continue
        ax.barh(
            ypos, widths, left=left, height=0.62,
            color=OUTCOME_COLORS[outcome], label=OUTCOME_LABELS[outcome],
            edgecolor='white', linewidth=0.8,
        )
        for y, (width, start) in enumerate(zip(widths, left)):
            if width:
                ax.text(start + width / 2, y, f'{int(width)}', ha='center', va='center',
                        color='white', fontsize=9, fontweight='bold')
        left = [a + b for a, b in zip(left, widths)]

    max_runs = max(left) if left else 1
    for y, stat in enumerate(ranked):
        ax.text(max_runs + max_runs * 0.03, y, f'{stat.equivalent_rate * 100:.0f}%',
                va='center', fontsize=10, fontweight='bold',
                color=OUTCOME_COLORS[OUTCOME_EQUIVALENT])

    ax.set_yticks(ypos)
    ax.set_yticklabels(models)
    ax.invert_yaxis()
    ax.set_xlabel('runs (one per roster CVE)')
    ax.set_xlim(0, max_runs * 1.16)
    ax.set_title('Backport outcome by model', fontsize=13, fontweight='bold')
    # Below the axis, not inside it: an in-axes legend covers the bottom bar
    # once the roster is small enough that bars reach the right edge.
    ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.16), ncol=3, fontsize=8.5,
              frameon=False)
    ax.grid(axis='x', alpha=0.25, linestyle=':')
    ax.set_axisbelow(True)
    _caption(fig, 'Green figure on the right is the reference-equivalent rate: '
                  'runs whose patch matched the human backport or differed only stylistically.')
    fig.tight_layout(rect=(0, 0.035, 1, 1))
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_bucket_by_model(ranked: list[ModelStats], out_path: Path) -> None:
    """Stacked bars of the raw diff_bucket distribution per model."""
    import matplotlib.pyplot as plt

    models = [s.model for s in ranked]
    ypos = list(range(len(models)))
    present = [b for b in BUCKET_ORDER if any(s.buckets[b] for s in ranked)]
    fig, ax = plt.subplots(figsize=(9.5, 5.0))

    left = [0.0] * len(models)
    for bucket in present:
        widths = [float(s.buckets[bucket]) for s in ranked]
        label = 'no patch / failed' if bucket == '-' else bucket
        ax.barh(ypos, widths, left=left, height=0.62, color=BUCKET_COLORS[bucket],
                label=label, edgecolor='white', linewidth=0.8)
        for y, (width, start) in enumerate(zip(widths, left)):
            if width:
                ax.text(start + width / 2, y, f'{int(width)}', ha='center', va='center',
                        color='#222222' if bucket == 'moderate' else 'white',
                        fontsize=9, fontweight='bold')
        left = [a + b for a, b in zip(left, widths)]

    ax.set_yticks(ypos)
    ax.set_yticklabels(models)
    ax.invert_yaxis()
    ax.set_xlabel('runs')
    ax.set_title('Raw diff bucket vs. the human reference patch', fontsize=13, fontweight='bold')
    ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.16), ncol=4, fontsize=8.5,
              frameon=False)
    ax.grid(axis='x', alpha=0.25, linestyle=':')
    ax.set_axisbelow(True)
    _caption(fig, 'Bucket measures textual distance only. A large diff can still be '
                  'behaviorally equivalent, which is what the judge pass decides — '
                  'compare with outcome_by_model.png.')
    fig.tight_layout(rect=(0, 0.035, 1, 1))
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_cost_by_model(ranked: list[ModelStats], out_path: Path) -> None:
    """Total credits, credits per run, and credits per usable backport."""
    import matplotlib.pyplot as plt

    models = [s.model for s in ranked]
    ypos = list(range(len(models)))
    fig, axes = plt.subplots(1, 3, figsize=(13, 4.6), sharey=True)

    panels = (
        ('Total credits', [s.total_credits for s in ranked], '#0072B2', '{:.2f}'),
        ('Avg credits per run', [s.avg_credits for s in ranked], '#56B4E9', '{:.2f}'),
    )
    for ax, (title, values, color, fmt) in zip(axes, panels):
        ax.barh(ypos, values, height=0.6, color=color)
        for y, value in enumerate(values):
            ax.text(value + max(values) * 0.02, y, fmt.format(value), va='center', fontsize=9)
        ax.set_title(title, fontsize=11, fontweight='bold')
        ax.set_xlim(0, max(values) * 1.25 if max(values) else 1)
        ax.grid(axis='x', alpha=0.25, linestyle=':')
        ax.set_axisbelow(True)

    # A model with zero usable backports has an undefined ratio. Draw it
    # full-width in the failure color and label it, rather than dropping the
    # bar (which would read as "free").
    per_win = [s.credits_per_equivalent for s in ranked]
    finite = [v for v in per_win if v is not None]
    ceiling = max(finite) * 1.1 if finite else 1.0
    ax = axes[2]
    for y, value in enumerate(per_win):
        if value is None:
            ax.barh([y], [ceiling], height=0.6, color=OUTCOME_COLORS[OUTCOME_FAILED])
            ax.text(ceiling * 0.03, y, 'no usable backport', va='center', fontsize=8.5,
                    color='white', fontweight='bold')
        else:
            ax.barh([y], [value], height=0.6, color=OUTCOME_COLORS[OUTCOME_EQUIVALENT])
            ax.text(value + ceiling * 0.02, y, f'{value:.2f}', va='center', fontsize=9)
    ax.set_title('Credits per usable backport', fontsize=11, fontweight='bold')
    ax.set_xlim(0, ceiling * 1.25)
    ax.grid(axis='x', alpha=0.25, linestyle=':')
    ax.set_axisbelow(True)

    axes[0].set_yticks(ypos)
    axes[0].set_yticklabels(models)
    axes[0].invert_yaxis()
    fig.suptitle('Cost by model', fontsize=13, fontweight='bold')
    _caption(fig, "Credits are kiro-cli's own reported figures; runs with no credit figure "
                  'are excluded from the means, not counted as zero.')
    fig.tight_layout(rect=(0, 0.04, 1, 0.94))
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_quality_vs_cost(ranked: list[ModelStats], out_path: Path) -> None:
    """Scatter of average cost per run against reference-equivalent rate."""
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(8.5, 5.6))
    for stat in ranked:
        color = (OUTCOME_COLORS[OUTCOME_EQUIVALENT] if stat.equivalent_rate >= 0.5
                 else OUTCOME_COLORS[OUTCOME_DIVERGENT])
        ax.scatter(stat.avg_credits, stat.equivalent_rate * 100, s=170, color=color,
                   edgecolor='white', linewidth=1.5, zorder=3)
        ax.annotate(
            stat.model,
            (stat.avg_credits, stat.equivalent_rate * 100),
            textcoords='offset points', xytext=(11, 6), fontsize=9.5,
        )

    ax.set_xlabel('avg credits per run')
    ax.set_ylabel('reference-equivalent rate (%)')
    ax.set_ylim(-6, 106)
    max_cost = max((s.avg_credits for s in ranked), default=1.0)
    ax.set_xlim(-max_cost * 0.08, max_cost * 1.3)
    ax.axhline(50, color='#cccccc', linestyle='--', linewidth=1)
    ax.set_title('Quality vs cost', fontsize=13, fontweight='bold')
    ax.grid(alpha=0.25, linestyle=':')
    ax.set_axisbelow(True)
    _caption(fig, 'Up and to the left is better: more usable backports for fewer credits. '
                  'Dashed line marks a 50% equivalent rate.')
    fig.tight_layout(rect=(0, 0.035, 1, 1))
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_effort_by_model(ranked: list[ModelStats], out_path: Path) -> None:
    """Average wall-clock duration and average tool-call count per model."""
    import matplotlib.pyplot as plt

    models = [s.model for s in ranked]
    ypos = list(range(len(models)))
    fig, axes = plt.subplots(1, 2, figsize=(11, 4.4), sharey=True)

    for ax, (title, values, color, unit) in zip(
        axes,
        (
            ('Avg duration', [s.avg_duration for s in ranked], '#0072B2', 's'),
            ('Avg tool calls', [s.avg_commands for s in ranked], '#CC79A7', ''),
        ),
    ):
        ax.barh(ypos, values, height=0.6, color=color)
        top = max(values) if values else 1.0
        for y, value in enumerate(values):
            ax.text(value + top * 0.02, y, f'{value:.0f}{unit}', va='center', fontsize=9)
        ax.set_title(title, fontsize=11, fontweight='bold')
        ax.set_xlim(0, top * 1.2)
        ax.grid(axis='x', alpha=0.25, linestyle=':')
        ax.set_axisbelow(True)

    axes[0].set_yticks(ypos)
    axes[0].set_yticklabels(models)
    axes[0].invert_yaxis()
    fig.suptitle('Effort by model', fontsize=13, fontweight='bold')
    _caption(fig, 'A high tool-call count paired with a low equivalent rate is thrashing, '
                  'not thoroughness.')
    fig.tight_layout(rect=(0, 0.04, 1, 0.93))
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


def plot_outcome_matrix(
    agent_rows: list[dict[str, str]],
    judge_rows: list[dict[str, str]],
    ranked: list[ModelStats],
    out_path: Path,
) -> None:
    """Per-CVE x per-model outcome grid."""
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch, Rectangle

    cves, tier_of, grid = build_matrix(agent_rows, judge_rows)
    models = [s.model for s in ranked]

    fig, ax = plt.subplots(figsize=(1.55 * len(models) + 3.6, 0.62 * len(cves) + 2.6))
    for row, cve in enumerate(cves):
        for col, model in enumerate(models):
            outcome = grid.get((cve, model))
            color = OUTCOME_COLORS[outcome] if outcome else '#f2f2f2'
            ax.add_patch(Rectangle((col, row), 0.94, 0.88, facecolor=color, edgecolor='white'))
            if outcome:
                ax.text(col + 0.47, row + 0.44, OUTCOME_GLYPHS[outcome], ha='center',
                        va='center', color='white', fontsize=13, fontweight='bold')

    ax.set_xlim(0, len(models))
    ax.set_ylim(0, len(cves))
    ax.set_xticks([c + 0.47 for c in range(len(models))])
    ax.set_xticklabels(models, fontsize=9, rotation=20, ha='right')
    ax.set_yticks([r + 0.44 for r in range(len(cves))])
    ax.set_yticklabels([f'{c}  ({tier_of[c]})' for c in cves], fontsize=9)
    ax.invert_yaxis()
    ax.xaxis.set_ticks_position('top')
    ax.tick_params(length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.set_title('Outcome per CVE and model', fontsize=13, fontweight='bold', pad=34)
    ax.legend(
        handles=[Patch(facecolor=OUTCOME_COLORS[o],
                       label=f'{OUTCOME_GLYPHS[o]}  {OUTCOME_LABELS[o]}')
                 for o in OUTCOME_ORDER],
        loc='upper center', bbox_to_anchor=(0.5, -0.04), ncol=3, fontsize=8.5, frameon=False,
    )
    _caption(fig, 'A row that is uniformly one color is a property of that CVE (or of its '
                  'reference patch), not of the models.')
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    fig.savefig(out_path, dpi=150)
    plt.close(fig)


# --- Text summary ----------------------------------------------------------


def print_summary(ranked: list[ModelStats], agent_rows: list[dict[str, str]],
                  judge_rows: list[dict[str, str]]) -> None:
    """Print the same figures the charts show, for quoting into a report."""
    total_credits = sum(s.total_credits for s in ranked)
    print(f'Runs: {len(agent_rows)}   Models: {len(ranked)}   '
          f'Judged pairs: {len(judge_rows)}   Total credits: {total_credits:.2f}')
    print()
    header = (f'{"model":<20} {"runs":>4} {"equiv":>6} {"diff":>5} {"broken":>7} '
              f'{"rate":>6} {"credits":>8} {"cr/win":>7} {"dur_s":>7} {"calls":>6}')
    print(header)
    print('-' * len(header))
    for stat in ranked:
        broken = stat.outcomes[OUTCOME_FAILED] + stat.outcomes[OUTCOME_NO_PATCH]
        per_win = stat.credits_per_equivalent
        per_win_text = f'{per_win:7.2f}' if per_win is not None else f'{"n/a":>7}'
        print(f'{stat.model:<20} {stat.runs:>4} {stat.equivalent:>6} '
              f'{stat.outcomes[OUTCOME_DIVERGENT]:>5} {broken:>7} '
              f'{stat.equivalent_rate * 100:>5.0f}% {stat.total_credits:>8.2f} '
              f'{per_win_text} {stat.avg_duration:>7.0f} {stat.avg_commands:>6.0f}')

    cves, tier_of, grid = build_matrix(agent_rows, judge_rows)
    print()
    print('Per-CVE equivalent rate across models (low = hard for everyone):')
    for cve in cves:
        outcomes = [grid[(cve, s.model)] for s in ranked if (cve, s.model) in grid]
        wins = sum(1 for o in outcomes if o == OUTCOME_EQUIVALENT)
        pct = 100 * wins / len(outcomes) if outcomes else 0.0
        print(f'  {cve:<16} ({tier_of[cve]:<6}) {wins}/{len(outcomes)}  {pct:>3.0f}%')


# --- Entry point -----------------------------------------------------------


CHART_BUILDERS = (
    ('outcome_by_model.png', 'stacked run outcomes per model'),
    ('bucket_by_model.png', 'raw diff_bucket distribution per model'),
    ('cost_by_model.png', 'total / per-run / per-usable-backport credits'),
    ('quality_vs_cost.png', 'avg credits per run vs equivalent rate'),
    ('effort_by_model.png', 'avg duration and avg tool calls'),
    ('outcome_matrix.png', 'per-CVE x per-model outcome grid'),
)


def main() -> None:
    """Entry point for the benchmark plotting tool."""
    parser = argparse.ArgumentParser(
        description='Plot cve-agent model benchmark results from a results directory.'
    )
    parser.add_argument(
        'results_dir', type=Path,
        help='Benchmark results directory (e.g. tests/benchmark/test-results/bench_*)',
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

    agent_csv = args.results_dir / 'agent_results.csv'
    agent_rows = read_csv(agent_csv)
    if not agent_rows:
        raise SystemExit(
            f'error: {agent_csv} has no data rows — nothing to plot.\n'
            'An empty CSV means that benchmark run produced no results '
            '(interrupted, or every case was skipped).'
        )
    judge_rows = read_csv(args.results_dir / 'judge_results.csv')

    stats = aggregate(agent_rows, judge_rows)
    ranked = rank_models(stats)
    print_summary(ranked, agent_rows, judge_rows)

    out_dir = args.output_dir or args.results_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    plot_outcome_by_model(ranked, out_dir / 'outcome_by_model.png')
    plot_bucket_by_model(ranked, out_dir / 'bucket_by_model.png')
    plot_cost_by_model(ranked, out_dir / 'cost_by_model.png')
    plot_quality_vs_cost(ranked, out_dir / 'quality_vs_cost.png')
    plot_effort_by_model(ranked, out_dir / 'effort_by_model.png')
    plot_outcome_matrix(agent_rows, judge_rows, ranked, out_dir / 'outcome_matrix.png')

    print()
    for name, description in CHART_BUILDERS:
        print(f'wrote {out_dir / name}  -- {description}')


if __name__ == '__main__':
    main()
