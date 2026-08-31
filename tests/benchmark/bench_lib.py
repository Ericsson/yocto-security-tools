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

# score_tier() thresholds on conflict_markers (one per conflicting hunk) and
# files_involved (distinct files with at least one conflict). Calibrated
# against the 24 CVEs across the three committed rosters that actually need
# resolution (all exit_code == EXIT_CONFLICT at calibration time): markers
# ranged 0-45, roughly terciled at 3 and 10. 'hard' additionally fires on
# files_involved alone, since a conflict spread across many files is a
# different (and typically harder) shape of problem than the same marker
# count concentrated in one file. Tune here; nothing else in this module
# depends on the exact values.
EASY_MAX_MARKERS = 3
MEDIUM_MAX_MARKERS = 10
HARD_MIN_FILES = 4


def score_tier(exit_code: int, conflict_markers: int,
               files_involved: int) -> str:
    """Classify a CVE that needs resolution by conflict/file complexity.

    Only meaningful for a recoverable exit (see
    ``cve_agent.RECOVERABLE_EXITS`` — ``EXIT_CONFLICT``, ``EXIT_PTEST_ERROR``,
    ``EXIT_BUILD_ERROR``): a clean exit (``0``) has no conflict to size, and
    is not a resolution case at all — see the ``clean-apply`` roster instead
    of tiering it here. An unrecoverable exit (metadata/checkout/git errors)
    is also out of scope: the corrector bailed before reaching a conflict, so
    there is nothing here to measure.

    Flat rules, evaluated in order — no weighted formula:

    1. ``files_involved >= HARD_MIN_FILES`` -> ``'hard'``, regardless of
       marker count. Touching many files is a structurally harder resolution
       even if each file's conflict is small.
    2. ``conflict_markers > MEDIUM_MAX_MARKERS`` -> ``'hard'``.
    3. ``conflict_markers > EASY_MAX_MARKERS`` -> ``'medium'``.
    4. Otherwise -> ``'easy'``.

    Args:
        exit_code: cve-corrector/cve-agent exit code for the run. Must be a
            recoverable exit; a caller with a clean or unrecoverable exit
            should not be calling this at all (see above).
        conflict_markers: Number of ``CONFLICT (content):`` marker lines from
            the run's log (:func:`count_conflict_markers`).
        files_involved: Number of distinct files with at least one conflict
            marker (:func:`count_conflicted_files`).

    Returns:
        One of ``'easy'``, ``'medium'``, ``'hard'``.

    Raises:
        ValueError: if ``exit_code`` is not a recoverable exit.
    """
    from cve_agent import RECOVERABLE_EXITS
    if exit_code not in RECOVERABLE_EXITS:
        raise ValueError(
            f"score_tier is only for a recoverable exit "
            f"({sorted(RECOVERABLE_EXITS)}); got {exit_code}. A clean exit "
            f"(0) belongs in the clean-apply roster, not tiered here; an "
            f"unrecoverable exit means the corrector bailed before reaching "
            f"a conflict and has nothing to tier.")
    if files_involved >= HARD_MIN_FILES:
        return 'hard'
    if conflict_markers > MEDIUM_MAX_MARKERS:
        return 'hard'
    if conflict_markers > EASY_MAX_MARKERS:
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
# git's own conflict line names the file: "CONFLICT (content): Merge
# conflict in <path>". Captures the path so distinct files can be counted
# separately from the marker count (one conflict marker per *hunk*, so a
# single badly-diverged file can rack up several markers on its own —
# files_involved is the complementary "how much of the tree is touched"
# signal score_tier needs alongside conflict_markers).
_CONTENT_CONFLICT_FILE_RE = re.compile(
    r'CONFLICT \(content\): Merge conflict in (\S+)')


def count_conflicted_files(log_text: str) -> int:
    """Count distinct files with a content conflict in a corrector/agent log.

    Complements :func:`count_conflict_markers`: a marker is recorded once per
    conflicting hunk, so one badly-diverged file can produce several markers
    on its own, while this counts how many separate files were touched by any
    conflict at all. :func:`score_tier` uses both, since a conflict spread
    across many files is a different (and typically harder) kind of problem
    than the same marker count concentrated in one file.

    Args:
        log_text: Full text of the corrector/agent log for one run.

    Returns:
        Number of distinct file paths named in a ``CONFLICT (content):``
        line. ``0`` for a marker-free log.
    """
    return len(set(_CONTENT_CONFLICT_FILE_RE.findall(log_text)))


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

    The clean-apply roster's schema has no ``tier`` key at all (it uses
    ``phase: "clean_apply"`` instead — see README "Clean-apply roster"); its
    entries fall into the ``extra_tiers`` bucket via ``info.get('phase')``,
    keyed on the literal string ``'clean_apply'``, so listing that roster
    still works through this same function.

    Args:
        roster: Parsed ``benchmark-roster.json`` mapping ``cve_id`` -> info
            dict (each info has at least ``tier`` or ``phase``, and
            ``recipe``).

    Returns:
        A list of ``{'case': int, 'cve_id': str, 'tier': str, 'recipe': str}``
        dicts, ordered as above and numbered from 1. ``tier`` is the entry's
        ``phase`` when it has no ``tier`` key (clean-apply roster).
    """
    entries = {k: v for k, v in roster.items() if k != '_comment'}

    def _tier(info: dict) -> str | None:
        return info.get('tier') or info.get('phase')

    present_tiers = {_tier(info) for info in entries.values()}
    extra_tiers = sorted(t for t in present_tiers
                         if t not in TIER_ORDER and t is not None)

    ordered: list[tuple[str, dict]] = []
    for tier in (*TIER_ORDER, *extra_tiers):
        for cve in sorted(c for c, info in entries.items()
                          if _tier(info) == tier):
            ordered.append((cve, entries[cve]))

    return [
        {'case': i, 'cve_id': cve,
         'tier': _tier(info) or '', 'recipe': info.get('recipe', '')}
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
    'claude-sonnet-4.6': {'multiplier': 1.30, 'tier': 'default'},
    'claude-opus-4.8': {'multiplier': 2.20, 'tier': 'full'},
    'claude-opus-4.7': {'multiplier': 2.20, 'tier': 'full'},
    'claude-opus-4.6': {'multiplier': 2.20, 'tier': 'full'},
    'claude-opus-4.5': {'multiplier': 2.20, 'tier': 'full'},
    'claude-sonnet-4.5': {'multiplier': 1.30, 'tier': 'full'},
    'claude-sonnet-4': {'multiplier': 1.30, 'tier': 'full'},
    'claude-haiku-4.5': {'multiplier': 0.40, 'tier': 'default'},
    # minimax-m2.5 is deliberately not in the default set: in
    # bench_20260828_145923 it cost 21.12 credits per reference-equivalent
    # backport (2x claude-opus-5) while resolving only 1 of 7 roster CVEs, so
    # it buys the least information per credit of any model measured. Still
    # selectable by name via --models for a follow-up comparison.
    'minimax-m2.5': {'multiplier': 0.25, 'tier': 'full'},
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
# A judge-diff bucket boundary, unrelated to score_tier's conflict/file
# thresholds above -- this one sizes an already-clean model-vs-reference
# diff, not conflict complexity.
MODERATE_DIFF_LINES_THRESHOLD = 50


def classify_diff_bucket(differences_text: str | None) -> str:
    """Bucket a compare_patches_detailed differences report by size.

    Args:
        differences_text: Contents of the ``<cve_id>_differences.txt`` file
            written by ``compare_patches_detailed`` (see
            ``tests/integration/test_common.sh``), or ``None``/empty if that
            file could not be read (e.g. the comparison itself failed).

    Returns:
        ``'file-mismatch'`` if ``differences_text`` is falsy, or if the report
        says files are missing/extra AND the two patch sets share no files.
        ``'partial'`` if files are missing/extra but the sets still share at
        least one file (a judgeable overlap — see
        :func:`scope_diff_to_common_files`). ``'identical'`` if the patches are
        equivalent. Otherwise ``'minor'`` (<= :data:`MINOR_DIFF_LINES_THRESHOLD`
        lines), ``'moderate'`` (<= :data:`MODERATE_DIFF_LINES_THRESHOLD` lines),
        or ``'major'``.
    """
    if not differences_text:
        return 'file-mismatch'
    if ('Missing in generated:' in differences_text
            or 'Extra in generated:' in differences_text):
        # Fileset mismatch. When the two patch sets still share at least one
        # file, those common files are a meaningful backport-vs-reference
        # comparison, so classify as 'partial' (judgeable on the intersection,
        # see scope_diff_to_common_files) rather than discarding the run as a
        # purely structural 'file-mismatch'. Fall back to 'file-mismatch' when
        # the filesets are disjoint, or when the report lacks the 'Files
        # touched' header needed to prove an overlap.
        if _common_file_count(differences_text) > 0:
            return 'partial'
        return 'file-mismatch'
    if 'Patches are equivalent.' in differences_text:
        return 'identical'

    match = re.search(r'Differences: (\d+) lines', differences_text)
    n = int(match.group(1)) if match else 0
    if n <= MINOR_DIFF_LINES_THRESHOLD:
        return 'minor'
    if n <= MODERATE_DIFF_LINES_THRESHOLD:
        return 'moderate'
    return 'major'


def _count_listed_files(differences_text: str, label: str) -> int:
    """Count the comma-separated filenames on the report line under ``label``.

    ``compare_patches_detailed`` writes the missing/extra file lists as a
    single indented line, e.g. ``  Missing in generated: a.c, b.c``. Returns 0
    when no line starts with ``label`` (after stripping leading whitespace).
    """
    for line in differences_text.splitlines():
        stripped = line.strip()
        if stripped.startswith(label):
            rest = stripped[len(label):].strip()
            return len([f for f in rest.split(',') if f.strip()])
    return 0


def _common_file_count(differences_text: str) -> int:
    """Number of files touched by BOTH patch sets, per a differences report.

    Derived from ``compare_patches_detailed``'s header::

        Files touched - original: A, generated: B
          Missing in generated: <M comma-separated files>

    The intersection size is ``A - M`` (files in the original that are not
    missing from the generated set). Returns 0 when the ``Files touched``
    header is absent — without it an overlap cannot be proven, so callers
    should treat the run as a pure ``file-mismatch``.
    """
    m = re.search(r'Files touched - original: (\d+), generated: (\d+)',
                  differences_text)
    if not m:
        return 0
    original_count = int(m.group(1))
    missing = _count_listed_files(differences_text, 'Missing in generated:')
    return original_count - missing




# --- Judge phase (phase 2) ---------------------------------------------------

# Buckets worth asking the judge about. ``moderate`` (11-50 diff lines) and
# ``major`` (50+) are whole-patch line divergences. ``partial`` is a fileset
# overlap where the shared files still differ — judged on the intersection
# alone (see scope_diff_to_common_files), not the one-sided missing/extra
# files. ``minor`` is also sent to the judge (a deliberate choice to get a
# verdict even on a small divergence, rather than assuming small == stylistic).
# ``identical`` is excluded: a zero-line diff is self-evidently a match, so
# there is nothing for a wording judgment to add. A pure ``file-mismatch``
# (disjoint filesets) is excluded for a different reason: there is no
# shared-file diff text to hand the judge at all.
JUDGEABLE_BUCKETS = ('minor', 'moderate', 'major', 'partial')


_JUDGMENT_RE = re.compile(r'\b(MEANINGFUL|STYLISTIC)\b', re.IGNORECASE)

# Upper bound on the judge's stored justification. Long enough for the two
# sentences the prompt asks for, short enough that judge_results.csv stays
# readable in a terminal.
JUDGE_REASON_MAX_CHARS = 300

# kiro-cli appends a usage/credits footer to its response; it is not part of
# the judge's reasoning and must not leak into the stored reason.
_CREDITS_FOOTER_RE = re.compile(r'credits?\s*(used|remaining|:)', re.IGNORECASE)

# Unified-diff hunk header: '@@ -<old_start>[,<old_len>] +<new_start>[,<new_len>] @@'.
# A missing length field means 1 (git/difflib convention).
_HUNK_RE = re.compile(r'^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@')

# Separator that tests/integration/test_utils.py writes into a
# <cve>_differences_diff.patch between the delta on files touched by both
# patch sets and the one-sided blocks. Must stay byte-identical to that
# module's ONE_SIDED_MARKER (asserted by
# tests/integration/test_patch_compare.py);
# it cannot be imported from there because tests/integration is not a package.
ONE_SIDED_MARKER = '=== files touched by only one side (not comparable) ==='


def scope_diff_to_common_files(diff_patch_text: str) -> str:
    """Keep only the per-file diff blocks for files present on BOTH sides.

    ``compare_patches_detailed`` (see ``tests/integration/test_utils.py``)
    writes ``<cve>_differences_diff.patch`` with the files touched by both
    patch sets first, then — when some file is one-sided — the
    :data:`ONE_SIDED_MARKER` line followed by the one-sided blocks. For a
    ``partial`` fileset overlap only the common-file blocks are a meaningful
    backport-vs-reference comparison, so this returns just the text ahead of
    that marker.

    Reports written before the marker existed (the pre-interdiff line-set
    format, still produced as a fallback on hosts without ``patchutils``)
    have no marker: those are scoped with the legacy heuristic, where a file
    on only one side renders either as an all-removed / all-added block (a
    hunk whose new-span or old-span is 0, e.g. ``@@ -1,23 +0,0 @@``) or as a
    manual ``/dev/null`` block with no hunk header at all. A block counts as
    common when it has at least one hunk and its summed old-span AND new-span
    are both greater than zero; because unified diffs include context lines
    (which count toward both spans), a span is 0 only when that side's file
    is entirely absent.

    Args:
        diff_patch_text: Full text of a ``<cve>_differences_diff.patch`` file.

    Returns:
        The concatenated common-file blocks (blank-line separated, trailing
        newline), or ``''`` when there are none (e.g. the shared files are
        byte-identical and were therefore omitted from the diff patch).
    """
    if ONE_SIDED_MARKER in diff_patch_text:
        common = diff_patch_text.split(ONE_SIDED_MARKER, 1)[0].rstrip('\n')
        return common + '\n' if common.strip() else ''
    lines = diff_patch_text.splitlines()
    # A file block starts at a '--- ' header immediately followed by a '+++ '
    # header. Requiring the pair (rather than any '--- ' line) avoids splitting
    # mid-block on a removed source line that happens to start with '--- '.
    starts = [
        i for i in range(len(lines) - 1)
        if lines[i].startswith('--- ') and lines[i + 1].startswith('+++ ')
    ]
    kept: list[str] = []
    for idx, start in enumerate(starts):
        end = starts[idx + 1] if idx + 1 < len(starts) else len(lines)
        block = lines[start:end]
        old_span = new_span = 0
        saw_hunk = False
        for line in block[2:]:
            m = _HUNK_RE.match(line)
            if m:
                saw_hunk = True
                old_span += int(m.group(1)) if m.group(1) is not None else 1
                new_span += int(m.group(2)) if m.group(2) is not None else 1
        if saw_hunk and old_span > 0 and new_span > 0:
            while block and block[-1] == '':
                block.pop()
            kept.append('\n'.join(block))
    return ('\n\n'.join(kept) + '\n') if kept else ''


def count_diff_changed_lines(diff_text: str) -> int:
    """Count changed (added/removed) lines in a unified diff.

    Counts lines starting with ``+`` or ``-``, excluding the ``+++ ``/``--- ``
    file-header lines (``@@`` hunk headers start with neither and are ignored
    too). Used to report a ``partial`` row's ``diff_lines`` scoped to the
    shared files — i.e. counted over :func:`scope_diff_to_common_files`'s output,
    which is what the judge actually sees — rather than the whole-patch
    divergence dominated by the missing/extra files.
    """
    n = 0
    for line in diff_text.splitlines():
        if line.startswith('+++ ') or line.startswith('--- '):
            continue
        if line.startswith(('+', '-')):
            n += 1
    return n


# --- Comment-only change filtering -----------------------------------------

# Extensions whose comments are '//', '/* ... */' (and continuation lines
# starting with '*' inside a block comment).
_C_LIKE_SUFFIXES = (
    '.c', '.h', '.cc', '.cpp', '.cxx', '.hh', '.hpp', '.hxx', '.m',
    '.java', '.js', '.ts', '.go', '.rs', '.cs', '.php', '.swift', '.kt',
    '.scala', '.d', '.dts', '.dtsi',
)

# Extensions whose comments start with '#'. Deliberately excludes C-like
# files, where '#if'/'#include'/'#define' are preprocessor directives whose
# change is very much meaningful.
_HASH_SUFFIXES = (
    '.sh', '.bash', '.py', '.pl', '.rb', '.mk', '.am', '.ac', '.m4',
    '.cmake', '.yaml', '.yml', '.toml', '.cfg', '.conf', '.bb', '.bbappend',
    '.bbclass', '.inc', '.service', '.spec',
)

_HASH_FILENAMES = ('makefile', 'makefile.am', 'makefile.in', 'cmakelists.txt',
                   'dockerfile', 'kconfig')


def _comment_styles_for(path: str) -> tuple[bool, bool]:
    """Pick the comment syntaxes that apply to ``path``.

    Args:
        path: A file path from a unified-diff header (prefixes already
            stripped, or not — only the basename/suffix is inspected).

    Returns:
        ``(c_like, hash_style)``. An unrecognized extension gets ``c_like``
        only: assuming ``#`` is a comment there risks silently ignoring a
        preprocessor-directive change, which is the more damaging mistake.
    """
    name = path.rsplit('/', 1)[-1].lower()
    if name in _HASH_FILENAMES:
        return False, True
    if name.endswith(_HASH_SUFFIXES):
        return False, True
    if name.endswith(_C_LIKE_SUFFIXES):
        return True, False
    return True, False


def _code_outside_comments(content: str, in_block: bool) -> tuple[str, bool]:
    """Strip C-style comments from one line, carrying block state across lines.

    Args:
        content: The line's content (the diff's ``+``/``-``/`` `` marker
            already removed).
        in_block: Whether the line starts inside a ``/* ... */`` block.

    Returns:
        ``(code, in_block_after)`` where ``code`` is what remains once
        comments are removed. String literals are not tracked, so a ``/*``
        inside a quoted string is misread as a comment start — the cost is a
        line being treated as comment-only when it is not, which is why
        callers only ever *skip* such lines rather than acting on them.
    """
    code = []
    i = 0
    n = len(content)
    while i < n:
        if in_block:
            end = content.find('*/', i)
            if end == -1:
                return ''.join(code), True
            i = end + 2
            in_block = False
            continue
        if content.startswith('//', i):
            break
        if content.startswith('/*', i):
            in_block = True
            i += 2
            continue
        code.append(content[i])
        i += 1
    return ''.join(code), in_block


def strip_comment_only_changes(diff_text: str) -> str:
    """Drop changed lines that only add/remove a comment.

    A backport that rewords, drops, or adds a comment relative to the
    reference patch has not changed what the code does, so those lines are
    noise for the judge — and a diff made up entirely of them used to be
    classified as a genuine divergence. Context lines, hunk headers, and file
    headers are preserved so the surviving delta stays readable; hunk line
    counts are intentionally *not* recomputed, since the result is fed to a
    model for reading, not to ``patch``.

    Block-comment state is tracked separately for the two sides of the diff
    (removed lines and context belong to the old side, added lines and context
    to the new one), so a line inside a ``/* ... */`` block is recognized
    without resorting to a "starts with ``*``" guess — which would misread
    C pointer code such as ``*p++ = *s++;``. Blank changed lines are kept:
    they are whitespace, not comments. The comment syntax is chosen per file
    from the header preceding each block (see :func:`_comment_styles_for`).

    Args:
        diff_text: A unified diff.

    Returns:
        The diff with comment-only ``+``/``-`` lines removed.
    """
    kept: list[str] = []
    c_like, hash_style = True, False
    in_block_old = in_block_new = False

    for line in diff_text.splitlines():
        if line.startswith(('--- ', '+++ ')):
            c_like, hash_style = _comment_styles_for(
                line.split(' ', 1)[1].split('\t')[0].strip()
                if ' ' in line else '')
            in_block_old = in_block_new = False
            kept.append(line)
            continue
        if line.startswith(('diff -u ', 'diff --git ')):
            parts = line.split()
            if len(parts) >= 4:
                c_like, hash_style = _comment_styles_for(parts[3])
            in_block_old = in_block_new = False
            kept.append(line)
            continue
        if line.startswith('@@'):
            # Hunks are not contiguous, so a block comment cannot be assumed
            # to span the gap between them.
            in_block_old = in_block_new = False
            kept.append(line)
            continue

        if not line.startswith(('+', '-', ' ')):
            kept.append(line)
            continue

        marker, content = line[0], line[1:]
        if hash_style:
            # Only a full-line '#' comment counts: splitting on a bare '#'
            # would misread a '#' inside a shell or Python string literal.
            if marker in '+-' and content.strip().startswith('#'):
                continue
            kept.append(line)
            continue
        if not c_like:
            kept.append(line)
            continue

        if marker == '-':
            code, in_block_old = _code_outside_comments(content, in_block_old)
        elif marker == '+':
            code, in_block_new = _code_outside_comments(content, in_block_new)
        else:
            # A context line exists on both sides, so advance both states —
            # they can differ when one side opened a block the other did not.
            code, in_block_old = _code_outside_comments(content, in_block_old)
            _, in_block_new = _code_outside_comments(content, in_block_new)

        if marker in '+-' and content.strip() and not code.strip():
            continue
        kept.append(line)

    return '\n'.join(kept) + ('\n' if diff_text.endswith('\n') else '')


def has_substantive_changes(diff_text: str) -> bool:
    """Whether a diff still changes code once comment-only lines are ignored.

    Args:
        diff_text: A unified diff.

    Returns:
        ``True`` when at least one non-comment ``+``/``-`` line remains.
    """
    return count_diff_changed_lines(strip_comment_only_changes(diff_text)) > 0


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
                model: str = 'claude-opus-4.8') -> tuple[str, str, float | None]:
    """Ask a fixed judge model whether a diff is meaningful or stylistic-only.

    Invokes a one-shot, non-interactive ``kiro-cli chat`` call with a compact
    classification prompt. No agent config is needed — a bare model
    classification prompt works without ``--agent``.

    Comment-only changes are removed from the diff before it is sent (see
    :func:`strip_comment_only_changes`): a reworded or dropped comment is not
    a behavioral difference. When nothing but comment changes remain, the
    verdict is ``'comment-only'`` and no model call is made at all.

    Args:
        diff_text: The unified diff to classify (backport vs. reference
            patch, as produced by ``compare_patches_detailed``).
        model: The judge model to invoke. Kept as a parameter (rather than
            hardcoded) so callers/tests can pass a different or mocked model;
            the benchmark's own fixed judge model is ``claude-opus-4.8``,
            deliberately not part of the roster being benchmarked.

    Returns:
        A ``(judgment, reason, judge_credits)`` tuple. ``judgment`` is
        ``'meaningful'``, ``'stylistic'``, or ``'comment-only'``; it defaults
        to ``'meaningful'`` (the more conservative reading) if the response
        has neither keyword. ``reason`` is the judge's own one-or-two-sentence
        justification, flattened to a single line and truncated to
        :data:`JUDGE_REASON_MAX_CHARS`; it is ``''`` when the model offered
        none. ``judge_credits`` is the parsed credits figure, or ``None`` if
        not present in the response (and always ``None`` when no call was
        made).
    """
    code_diff = strip_comment_only_changes(diff_text)
    if count_diff_changed_lines(code_diff) == 0:
        return ('comment-only',
                'Only comment lines differ; the code changes are identical.',
                None)

    prompt = (
        "You are classifying a unified diff between two CVE backport "
        "patches (an AI-generated backport vs. a human reference backport "
        "for the same CVE). Decide whether the difference is MEANINGFUL "
        "(a functional or semantic difference — different logic, different "
        "conditions, a different fix approach) or STYLISTIC (whitespace, "
        "variable renames, comment wording, or equivalent logic expressed "
        "differently, with no behavior change).\n\n"
        "Ignore comment-only differences entirely: a reworded, added, or "
        "dropped comment is never MEANINGFUL on its own.\n\n"
        "Answer with exactly one word, MEANINGFUL or STYLISTIC, on the "
        "first line. Nothing else on that line. Then, on the following "
        "line, give one or two sentences naming the specific construct that "
        "drove your decision.\n\n"
        f"--- DIFF ---\n{code_diff}\n--- END DIFF ---"
    )
    result = subprocess.run(
        ['kiro-cli', 'chat', '--model', model, '--no-interactive', prompt],
        capture_output=True, text=True, check=False,
    )
    output = strip_ansi(result.stdout or '')
    match = _JUDGMENT_RE.search(output)
    judgment = match.group(1).lower() if match else 'meaningful'
    reason = _extract_judge_reason(output, match.end() if match else 0)
    credits = parse_kiro_credits(output)
    return judgment, reason, credits


def _extract_judge_reason(output: str, verdict_end: int) -> str:
    """Pull the justification that follows the judge's verdict keyword.

    Args:
        output: The judge's full (ANSI-stripped) response.
        verdict_end: Offset just past the matched verdict keyword, so the
            keyword itself is not repeated in the reason. ``0`` when no
            keyword matched, in which case the whole response is considered.

    Returns:
        The first one or two sentences after the verdict, flattened to a
        single line and truncated to :data:`JUDGE_REASON_MAX_CHARS`. Empty
        when the judge gave no prose. Credit/usage footers that ``kiro-cli``
        appends are dropped.
    """
    tail = output[verdict_end:]
    lines = []
    for raw in tail.splitlines():
        line = raw.strip()
        if not line:
            continue
        if _CREDITS_FOOTER_RE.search(line):
            break
        lines.append(line)
    text = ' '.join(lines).strip()
    if not text:
        return ''
    # Split only on a period followed by whitespace. Splitting on '!' or '?'
    # too would cut C identifiers apart ('!S_ISLNK', '!=', '?:'), and a period
    # with no following space keeps filenames like 'tar.c' intact.
    sentences = re.split(r'(?<=\.)\s+', text)
    reason = ' '.join(s.strip() for s in sentences[:2]).strip()
    if len(reason) > JUDGE_REASON_MAX_CHARS:
        reason = reason[:JUDGE_REASON_MAX_CHARS - 1].rstrip() + '…'
    return reason
