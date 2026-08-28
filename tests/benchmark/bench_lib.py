# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Pure-Python helpers for the CVE agent model benchmark.

No I/O beyond reading the CSV/JSON paths passed in by the caller (no network,
no subprocess, no writes). Flat, documented threshold constants are used
instead of a weighted-score formula so difficulty tiers stay easy to eyeball
and retune.
"""
from __future__ import annotations

import csv
import re
import subprocess
from pathlib import Path

from cve_agent.metrics import parse_kiro_credits, strip_ansi

# --- Tiering ---------------------------------------------------------------

# A backport whose diff is bigger than this (in changed lines, e.g. from
# `git diff --stat`) is no longer a "quick read" for a reviewer — bump it to
# 'medium'. Tune here; nothing else in this module depends on the exact value.
MEDIUM_DIFF_LINES_THRESHOLD = 50


def score_tier(exit_code: int, diff_lines: int, series_len: int) -> str:
    """Classify a CVE backport run into a difficulty tier.

    Flat rules, evaluated in order — no weighted formula:

    1. ``exit_code != 0`` (the corrector/agent hit a conflict or other
       non-clean exit) -> ``'hard'``.
    2. Clean exit (``exit_code == 0``) but either the diff is larger than
       :data:`MEDIUM_DIFF_LINES_THRESHOLD` lines or the fix is a commit
       series (``series_len > 1``) -> ``'medium'``.
    3. Otherwise (clean, small, single-commit) -> ``'easy'``.

    Args:
        exit_code: cve-corrector/cve-agent exit code for the run.
        diff_lines: Number of changed lines in the resulting patch.
        series_len: Number of commits in the fix's dependent chain (1 for a
            single-commit fix).

    Returns:
        One of ``'easy'``, ``'medium'``, ``'hard'``.
    """
    if exit_code != 0:
        return 'hard'
    if diff_lines > MEDIUM_DIFF_LINES_THRESHOLD or series_len > 1:
        return 'medium'
    return 'easy'


# A cherry-pick that fails purely because the local mirror is missing the
# fix commit (or a commit in its dependency chain) is a mirror-completeness
# problem, not evidence that the backport itself is hard. git surfaces this
# as "bad object <hash>" (rev-list/cherry-pick couldn't find the commit) or
# "unknown revision or path not in the working tree" (rev-parse on a
# missing hash, e.g. via `git diff <hash>~1`) -- neither implies any actual
# content clash was ever evaluated. A genuine content conflict instead
# prints git's own "CONFLICT (content):" marker.
_MIRROR_GAP_RE = re.compile(r'bad object|unknown revision or path not in the working tree')
_CONTENT_CONFLICT_RE = re.compile(r'CONFLICT \(content\)')


def is_mirror_gap_only(log_text: str) -> bool:
    """Return True if a failed run's log shows only mirror-gap errors.

    Distinguishes a git mirror missing commits (an infrastructure gap that
    would fail identically for every model, regardless of quality) from a
    genuine content conflict (real backport difficulty, useful tiering
    signal). Only meaningful for a run whose exit code was non-zero --
    callers should check that first.

    Args:
        log_text: Full text of the corrector/agent log for one run.

    Returns:
        True if the log contains at least one mirror-gap marker and no
        genuine content-conflict marker; False otherwise (including logs
        with neither marker, since those failures aren't confirmed to be
        mirror gaps).
    """
    return bool(_MIRROR_GAP_RE.search(log_text)) and not _CONTENT_CONFLICT_RE.search(log_text)


def count_conflict_markers(log_text: str) -> int:
    """Count genuine content-conflict markers in a corrector/agent log.

    A rough proxy for how messy a hard-tier CVE's conflict really is.
    Not meaningful for a clean (exit_code == 0) run,
    or a run that :func:`is_mirror_gap_only` reports as a pure mirror gap.

    Args:
        log_text: Full text of the corrector/agent log for one run.

    Returns:
        The number of ``CONFLICT (content):`` markers found. ``0`` for a
        marker-free log.
    """
    return len(_CONTENT_CONFLICT_RE.findall(log_text))


# --- Agent environment-failure detection ------------------------------------

# Markers meaning the AI agent never actually ran because its runtime
# environment was unusable -- the backend CLI is missing/unauthenticated, or
# its required agent configs could not be installed. These strings are
# emitted by cve_agent itself: cve_agent/setup.py's ensure_agents()
# ("kiro-cli not found on PATH.", "Failed to install agents.",
# "Failed to refresh installed agents."), cve_agent/__main__.py's non-kiro
# backend check ("prerequisites not met"), and
# cve_agent/kiro_backend.py's run_session() ("kiro-cli not found. Install it
# or add to PATH."). Such a failure is NOT a model-quality signal -- it would
# recur identically for every model and every CVE -- so the benchmark should
# abort rather than record a wall of identical failures.
_AGENT_ENV_FAILURE_RE = re.compile(
    r"kiro-cli not found"                       # ensure_agents / kiro run_session
    r"|prerequisites not met"                   # __main__ backend availability check
    r"|Failed to install agents"                # install_agents() hard failure
    r"|Failed to refresh installed agents",     # ensure_agents() refresh failure
    re.IGNORECASE,
)


def is_agent_env_failure(log_text: str) -> bool:
    """Return True if a run's log shows the AI agent never ran for an
    environment reason (missing/unusable backend CLI or agent config).

    Distinguishes an unusable benchmark environment -- which would fail
    identically for every model and every CVE -- from a genuine per-CVE
    agent failure (a real conflict/build/ptest the model could not resolve).
    The orchestrator should stop the whole run on the former, but keep going
    on the latter.

    Args:
        log_text: Full text of one run's cve-agent log.

    Returns:
        True if any known agent-environment-failure marker is present;
        False otherwise (including empty/marker-free logs).
    """
    return bool(_AGENT_ENV_FAILURE_RE.search(log_text))


# --- Commands-executed metric ------------------------------------------------

# kiro-cli echoes each tool invocation on its own line as it happens, e.g.:
#   I will run the following command: ls -la /tmp (using tool: shell)
#   Reading directory: /tmp (using tool: read, max depth: 0, ...)
#   I'll create the following file: /tmp/foo.txt (using tool: write)
# Verified directly against real `kiro-cli chat --no-interactive` output
# (captured via a throwaway probe run); the marker is always
# "(using tool: <name>...)" regardless of which tool ran, so counting matches
# of that literal substring counts tool calls without needing to enumerate
# tool names (fs_read/fs_write/execute_bash, as named in this backend's
# tool_preamble, are the *permission-config* names — the printed marker uses
# the shorter shell/read/write names instead).
_TOOL_CALL_RE = re.compile(r"\(using tool: [^)]*\)")


def count_tool_calls(transcript: str) -> int:
    """Count tool invocations in a captured kiro-cli transcript.

    Args:
        transcript: Captured combined stdout/stderr of a `kiro-cli chat`
            session (may contain ANSI colour codes).

    Returns:
        The number of ``(using tool: ...)`` markers found, after stripping
        ANSI escape sequences. ``0`` for an empty or marker-free transcript.
    """
    if not transcript:
        return 0
    clean = strip_ansi(transcript)
    return len(_TOOL_CALL_RE.findall(clean))


# --- Roster case selection (--list-cases / --run-case) -----------------------

# Canonical tier ordering used to enumerate roster "cases". Mirrors
# run_benchmark.sh's own easy->medium->hard processing loop; within a tier
# CVEs are sorted alphabetically (matching the shell's `cves_for_tier`
# `sorted(...)`), so a given case number is stable across runs regardless of
# JSON key order.
TIER_ORDER = ('easy', 'medium', 'hard')


def ordered_roster_cases(roster: dict) -> list[dict]:
    """Enumerate roster entries in canonical run order with 1-based indices.

    Ordering matches run_benchmark.sh: tiers ``easy`` -> ``medium`` -> ``hard``,
    alphabetical by CVE id within each tier. Any tier not in
    :data:`TIER_ORDER` is appended after the known tiers (also alphabetical),
    so an unexpected tier value still yields a stable, complete listing rather
    than silently dropping a CVE. The ``_comment`` meta key is ignored.

    Args:
        roster: Parsed ``benchmark-roster.json`` mapping ``cve_id`` -> info
            dict (each info has at least ``tier`` and ``recipe``).

    Returns:
        A list of ``{'case': int, 'cve_id': str, 'tier': str, 'recipe': str}``
        dicts, ordered as above and numbered from 1.
    """
    entries = {k: v for k, v in roster.items() if k != '_comment'}
    present_tiers = {info.get('tier') for info in entries.values()}
    extra_tiers = sorted(t for t in present_tiers
                         if t not in TIER_ORDER and t is not None)

    ordered: list[tuple[str, dict]] = []
    for tier in (*TIER_ORDER, *extra_tiers):
        for cve in sorted(c for c, info in entries.items()
                          if info.get('tier') == tier):
            ordered.append((cve, entries[cve]))

    return [
        {'case': i, 'cve_id': cve,
         'tier': info.get('tier', ''), 'recipe': info.get('recipe', '')}
        for i, (cve, info) in enumerate(ordered, 1)
    ]


def select_cases(ordered_cases: list[dict], indices: list[int]) -> list[dict]:
    """Pick cases by 1-based index, in canonical order, de-duplicated.

    Args:
        ordered_cases: Output of :func:`ordered_roster_cases`.
        indices: 1-based case numbers requested (any order, may repeat).

    Returns:
        The selected case dicts, in ascending case order, duplicates removed.

    Raises:
        ValueError: If ``indices`` is empty, or if any index is outside
            ``[1, len(ordered_cases)]``. The message lists the offending
            value(s) and the valid range.
    """
    n = len(ordered_cases)
    if not indices:
        raise ValueError(f"No case numbers given (valid range is 1..{n}).")
    bad = sorted({i for i in indices if i < 1 or i > n})
    if bad:
        raise ValueError(
            f"Case index out of range: {', '.join(map(str, bad))}. "
            f"Valid range is 1..{n} (see --list-cases)."
        )
    by_case = {c['case']: c for c in ordered_cases}
    return [by_case[i] for i in sorted(set(indices))]


# --- Model roster ------------------------------------------------------------

# Relative cost multipliers, as given by the user. These are NOT credit
# predictions — see relative_cost_weight() below.
MODELS: dict[str, dict] = {
    'claude-opus-5': {'multiplier': 2.20, 'tier': 'default'},
    'claude-sonnet-5': {'multiplier': 1.30, 'tier': 'default'},
    'claude-opus-4.8': {'multiplier': 2.20, 'tier': 'full'},
    'claude-opus-4.7': {'multiplier': 2.20, 'tier': 'full'},
    'claude-opus-4.6': {'multiplier': 2.20, 'tier': 'full'},
    'claude-sonnet-4.6': {'multiplier': 1.30, 'tier': 'full'},
    'claude-opus-4.5': {'multiplier': 2.20, 'tier': 'full'},
    'claude-sonnet-4.5': {'multiplier': 1.30, 'tier': 'full'},
    'claude-sonnet-4': {'multiplier': 1.30, 'tier': 'full'},
    'claude-haiku-4.5': {'multiplier': 0.40, 'tier': 'default'},
    'minimax-m2.5': {'multiplier': 0.25, 'tier': 'default'},
    'minimax-m2.1': {'multiplier': 0.15, 'tier': 'full'},
    'qwen3-coder-next': {'multiplier': 0.05, 'tier': 'default'},
}


def resolve_models(selector: str) -> list[dict]:
    """Resolve a model selector into a list of model entries.

    Args:
        selector: ``'default'`` for the 5 tier='default' models, ``'full'``
            for all models in :data:`MODELS`, or a comma-separated list of
            exact model names (e.g. ``'claude-sonnet-5,minimax-m2.5'``).

    Returns:
        A list of dicts, each the model's :data:`MODELS` entry plus its own
        ``'name'`` key.

    Raises:
        ValueError: If ``selector`` is a name list and any name is not a
            known model. The message lists the valid names.
    """
    if selector == 'default':
        names = [name for name, info in MODELS.items() if info['tier'] == 'default']
    elif selector == 'full':
        names = list(MODELS.keys())
    else:
        names = [n.strip() for n in selector.split(',') if n.strip()]
        unknown = [n for n in names if n not in MODELS]
        if unknown:
            raise ValueError(
                f"Unknown model name(s): {', '.join(unknown)}. "
                f"Valid names: {', '.join(sorted(MODELS.keys()))}"
            )

    return [{'name': name, **MODELS[name]} for name in names]


def relative_cost_weight(models: list[dict], num_cves: int) -> float:
    """Compute a relative cost weight for running ``models`` over ``num_cves``.

    This is a RELATIVE/COMPARATIVE weight for ranking model selections
    against each other before a run — it is NOT a prediction of actual
    credits that will be spent. Use :func:`observed_avg_credits` /
    :func:`project_remaining_cost` for that once real runs have produced
    data.

    Args:
        models: Model entries as returned by :func:`resolve_models`.
        num_cves: Number of CVEs the selection will be run against.

    Returns:
        ``sum(multiplier for each model) * num_cves``.
    """
    return sum(m['multiplier'] for m in models) * num_cves


# --- Observed cost from run CSVs --------------------------------------------

def observed_avg_credits(agent_csv_path: str | Path) -> float | None:
    """Compute the mean ``credits`` value observed in an agent results CSV.

    Expected schema (header row): ``cve_id,tier,model,exit_status,credits,
    duration_s,commands,diff_bucket,diff_lines``.

    Args:
        agent_csv_path: Path to ``agent_results.csv``.

    Returns:
        The mean of the numeric ``credits`` column, or ``None`` if the file
        is missing, empty, or has no valid ``credits`` values.
    """
    path = Path(agent_csv_path)
    if not path.is_file():
        return None

    values: list[float] = []
    with open(path, newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            raw = row.get('credits', '')
            try:
                values.append(float(raw))
            except (TypeError, ValueError):
                continue

    if not values:
        return None
    return sum(values) / len(values)


def project_remaining_cost(agent_csv_path: str | Path,
                            remaining_runs: int) -> float | None:
    """Project the cost of remaining runs from the observed average so far.

    Args:
        agent_csv_path: Path to ``agent_results.csv``.
        remaining_runs: Number of runs not yet completed.

    Returns:
        ``observed_avg_credits(agent_csv_path) * remaining_runs``, or
        ``None`` if there is no observed average yet (see
        :func:`observed_avg_credits`).
    """
    avg = observed_avg_credits(agent_csv_path)
    if avg is None:
        return None
    return avg * remaining_runs


def total_spent(agent_csv_path: str | Path,
                 judge_csv_path: str | Path) -> float:
    """Sum credits actually spent so far across the agent and judge CSVs.

    Args:
        agent_csv_path: Path to ``agent_results.csv`` (column ``credits``).
        judge_csv_path: Path to a judge results CSV with schema
            ``cve_id,model,judgment,judge_credits`` (column ``judge_credits``).

    Returns:
        Sum of both columns. A missing file contributes ``0.0`` rather than
        raising.
    """
    return (_sum_csv_column(agent_csv_path, 'credits')
            + _sum_csv_column(judge_csv_path, 'judge_credits'))


def _sum_csv_column(csv_path: str | Path, column: str) -> float:
    """Sum a numeric column in a CSV, treating a missing file as 0.0."""
    path = Path(csv_path)
    if not path.is_file():
        return 0.0

    total = 0.0
    with open(path, newline='', encoding='utf-8') as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            raw = row.get(column, '')
            try:
                total += float(raw)
            except (TypeError, ValueError):
                continue
    return total

# --- Diff-bucket classification (phase 1 result comparison) ----------------

# Thresholds for bucketing how far a generated patch's line-count diverges
# from the reference (human) patch, per compare_patches_detailed's
# "Differences: N lines" output. Mirrors generate_differences_report.py's
# categories so both reports agree on what counts as "minor" vs "moderate"
# vs "major".
MINOR_DIFF_LINES_THRESHOLD = 10


def classify_diff_bucket(differences_text: str | None) -> str:
    """Bucket a compare_patches_detailed differences report by size.

    Args:
        differences_text: Contents of the ``<cve_id>_differences.txt`` file
            written by ``compare_patches_detailed`` (see
            ``tests/integration/test_common.sh``), or ``None``/empty if that
            file could not be read (e.g. the comparison itself failed).

    Returns:
        ``'file-mismatch'`` if ``differences_text`` is falsy, or if the
        report says a file is missing/extra on either side. ``'identical'``
        if the patches are equivalent. Otherwise ``'minor'``
        (<= :data:`MINOR_DIFF_LINES_THRESHOLD` lines), ``'moderate'``
        (<= :data:`MEDIUM_DIFF_LINES_THRESHOLD` lines), or ``'major'``.
    """
    if not differences_text:
        return 'file-mismatch'
    if 'Missing in generated:' in differences_text or 'Extra in generated:' in differences_text:
        return 'file-mismatch'
    if 'Patches are equivalent.' in differences_text:
        return 'identical'

    match = re.search(r'Differences: (\d+) lines', differences_text)
    n = int(match.group(1)) if match else 0
    if n <= MINOR_DIFF_LINES_THRESHOLD:
        return 'minor'
    if n <= MEDIUM_DIFF_LINES_THRESHOLD:
        return 'moderate'
    return 'major'




# --- Judge phase (phase 2) ---------------------------------------------------

# Buckets that are considered a "meaningful enough divergence to ask the
# judge about" — mirrors generate_differences_report.py's thresholds
# (moderate = 11-50 diff lines, major = 50+). identical/minor/file-mismatch
# are excluded: identical/minor are self-evidently close to the reference,
# and a file-mismatch is a structural difference no wording judgment helps
# with.
JUDGEABLE_BUCKETS = ('moderate', 'major')

_JUDGMENT_RE = re.compile(r'\b(MEANINGFUL|STYLISTIC)\b', re.IGNORECASE)


def filter_for_judging(agent_rows: list[dict],
                        judge_rows: list[dict]) -> list[dict]:
    """Select agent_results.csv rows that still need a judge verdict.

    Args:
        agent_rows: Rows from ``agent_results.csv`` (as `csv.DictReader`
            dicts), each with at least ``cve_id``, ``model``, ``diff_bucket``.
        judge_rows: Rows already in ``judge_results.csv``, each with at
            least ``cve_id``, ``model``.

    Returns:
        The subset of ``agent_rows`` whose ``diff_bucket`` is in
        :data:`JUDGEABLE_BUCKETS` and whose ``(cve_id, model)`` pair is not
        already present in ``judge_rows``.
    """
    already_judged = {(row['cve_id'], row['model']) for row in judge_rows}
    return [
        row for row in agent_rows
        if row.get('diff_bucket') in JUDGEABLE_BUCKETS
        and (row['cve_id'], row['model']) not in already_judged
    ]


def judge_diff(diff_text: str,
                model: str = 'claude-opus-4.8') -> tuple[str, float | None]:
    """Ask a fixed judge model whether a diff is meaningful or stylistic-only.

    Invokes a one-shot, non-interactive ``kiro-cli chat`` call with a compact
    classification prompt. No agent config is needed — a bare model
    classification prompt works without ``--agent``.

    Args:
        diff_text: The unified diff to classify (backport vs. reference
            patch, as produced by ``compare_patches_detailed``).
        model: The judge model to invoke. Kept as a parameter (rather than
            hardcoded) so callers/tests can pass a different or mocked model;
            the benchmark's own fixed judge model is ``claude-opus-4.8``,
            deliberately not part of the roster being benchmarked.

    Returns:
        A ``(judgment, judge_credits)`` tuple. ``judgment`` is
        ``'meaningful'`` or ``'stylistic'``; defaults to ``'meaningful'``
        (the more conservative reading) if the response has neither keyword.
        ``judge_credits`` is the parsed credits figure, or ``None`` if not
        present in the response.
    """
    prompt = (
        "You are classifying a unified diff between two CVE backport "
        "patches (an AI-generated backport vs. a human reference backport "
        "for the same CVE). Decide whether the difference is MEANINGFUL "
        "(a functional or semantic difference — different logic, different "
        "conditions, a different fix approach) or STYLISTIC (whitespace, "
        "variable renames, comment wording, or equivalent logic expressed "
        "differently, with no behavior change).\n\n"
        "Answer with exactly one word, MEANINGFUL or STYLISTIC, on the "
        "first line. Nothing else on that line.\n\n"
        f"--- DIFF ---\n{diff_text}\n--- END DIFF ---"
    )
    result = subprocess.run(
        ['kiro-cli', 'chat', '--model', model, '--no-interactive', prompt],
        capture_output=True, text=True, check=False,
    )
    output = strip_ansi(result.stdout or '')
    match = _JUDGMENT_RE.search(output)
    judgment = match.group(1).lower() if match else 'meaningful'
    credits = parse_kiro_credits(output)
    return judgment, credits
