# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Length budget for the AI's ``Conflicts Resolved:`` commit notes.

``AGENT_INSTRUCTIONS.md`` caps each per-file stanza of the AI-written
``Conflicts Resolved:`` block at a few bullets and a few dozen words: the block
must state the *adaptation*, not the investigation that led to it. Nothing
enforced that cap, so the notes grew into multi-paragraph narration.

This module is the single source of truth for the budget. It is deliberately
pure — it parses a commit message string and returns violations, with no git
calls and no imports from the rest of the package — so the same rules serve
three callers:

* the ``commit-msg`` hook installed into the devtool workspace for the
  duration of an AI session (:func:`cve_agent.git.install_notes_hook`), which
  runs this module as a script and rejects the commit outright;
* the post-session validator in the orchestrator, which bounces a resolution
  attempt back to the AI with the overage as feedback;
* ``cve_agent.review``, which reuses :data:`DEDUPE_BLOCK_MARKERS` to find the
  same block when de-duplicating notes across retries.

Two counting decisions matter for fairness, because a rejection costs the AI a
whole session:

* **Bullets, not physical lines.** A 40-word note wrapped at 72 columns spans
  four or five physical lines, so counting those would make the word budget
  unreachable. Continuation lines fold into the bullet they belong to.
* **Prose is never silently exempt.** Text inside the block that sits under no
  recognizable ``<file> (<N> conflict[s]):`` header is charged to a synthetic
  stanza, so a malformed header cannot switch enforcement off.

Severities are split so guidance can stay softer than enforcement: a stanza a
few words over the ~40-word guideline is reported but committed, while one past
:data:`MAX_WORDS_REJECT` (or over :data:`MAX_BULLETS_PER_FILE` bullets) blocks
the commit.
"""
import dataclasses
import re
import sys
from pathlib import Path

#: Hard cap on bullets per file stanza. Exceeding it rejects the commit.
MAX_BULLETS_PER_FILE = 3

#: Word count per file stanza above which a warning is emitted (non-blocking).
MAX_WORDS_SOFT = 40

#: Word count per file stanza above which the commit is rejected.
MAX_WORDS_REJECT = 48

#: Line prefixes that open the AI's backport-note block, kept as the canonical
#: spellings. Recognition itself goes through :func:`is_note_block_start`,
#: which also accepts the decorated and misspelled variants the AI emits.
NOTE_BLOCK_MARKERS = (
    'Conflicts Resolved:',
    '## Conflicts Resolved',
    '### Conflicts Resolved',
)

#: Markers :mod:`cve_agent.review` uses to collapse duplicate note blocks.
#: Deliberately broader than :data:`NOTE_BLOCK_MARKERS`: for de-duplication a
#: false positive is harmless, whereas for the budget a bare ``## `` heading in
#: a preserved upstream body would charge upstream prose to the AI.
DEDUPE_BLOCK_MARKERS = (*NOTE_BLOCK_MARKERS, '## ')

# Headings that open the note block, ignoring markdown decoration (``#``,
# ``>``, ``*``, ``_``) and case. Matching the block's *name* rather than an
# exact prefix closes the evasion where a variant spelling the instructions
# forbid (``#### Conflicts Resolved``, ``**Conflicts Resolved:**``, lowercase,
# a blockquote) would exempt the whole block — while still not mistaking an
# unrelated ``## Description`` heading for notes.
_BLOCK_START_RE = re.compile(
    r'^[#>*_\s]*(?:conflicts?\s+resolved|conflicts?\s+resolution'
    r'|backport\s+(?:notes|changes))\b',
    re.IGNORECASE,
)

#: Severity of a budget violation that blocks the commit.
HARD = 'hard'

#: Severity of a budget violation that is reported but allowed through.
SOFT = 'soft'

#: Stanza name used for note text that names no file.
UNATTRIBUTED = '(notes outside any file stanza)'

#: Exit code :func:`main` uses to signal "notes are over budget, reject this
#: commit". Deliberately not ``1``: the interpreter itself exits 1 on an
#: uncaught exception and on ``-m <missing module>``, and 2 on a usage error,
#: so reusing those would make a broken environment look like a rejection and
#: deadlock a session that is instructed never to bypass the hook.
EXIT_NOTES_REJECTED = 3

# ``<file> (<N> conflict[s]):`` — opens a per-file stanza. ``0`` is valid: a
# ptest- or build-phase fix documents a file that had no merge conflict.
_STANZA_RE = re.compile(r'^(?P<file>\S.*?) \((?P<count>\d+) conflicts?\):$')

# ``<file>: omitted (<why>)`` — a one-line entry with no body, exempt from the
# budget. Only honoured outside a stanza: inside one it is ordinary prose.
_OMITTED_RE = re.compile(r'^(?P<file>\S.*?): omitted\b')

# A git trailer key must be a known one. Matching any ``Word:`` prefix would
# silently truncate the block at an ordinary body line such as ``Note: ...``.
_TRAILER_RE = re.compile(r'^(?P<key>[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)*):\s')
_TRAILER_KEYS = frozenset({
    'acked-by', 'assisted-by', 'bug', 'cc', 'change-id', 'closes',
    'co-authored-by', 'cve', 'fixes', 'link', 'origin', 'patch-mainline',
    'references', 'reported-by', 'reviewed-by', 'signed-off-by',
    'suggested-by', 'tested-by', 'upstream-status',
})

# The change summary cve-agent itself appends after the AI's notes.
_AGENT_SUMMARY_PREFIX = 'Changes from upstream commit'

# Bullet markers stripped before counting words, so list punctuation does not
# eat into the budget. Numbered forms count too — otherwise a numbered list
# would fold into a single "bullet" and bypass the bullet cap.
_BULLET_RE = re.compile(r'^(?:[-*+]|\d+[.)])\s+')


def is_note_block_start(line: str) -> bool:
    """Whether a line opens the AI's backport-note block.

    Args:
        line: A commit-message line (leading/trailing space is ignored).

    Returns:
        ``True`` for any spelling of the notes heading, decorated or not.
    """
    return bool(_BLOCK_START_RE.match(line.strip()))


def _is_trailer(line: str) -> bool:
    """Whether a line is a git trailer (``Assisted-by:``, ``CVE:``, ...)."""
    match = _TRAILER_RE.match(line)
    if match is None:
        return False
    return match.group('key').lower() in _TRAILER_KEYS


@dataclasses.dataclass
class FileStanza:
    """One ``<file> (<N> conflict[s]):`` entry and its bullets.

    Attributes:
        filename: Path as written in the stanza header, or
            :data:`UNATTRIBUTED` for note text under no header.
        conflicts: Conflict count declared in the header (``0`` when the
            stanza is synthetic).
        bullets: One entry per bullet, continuation lines already folded in.
    """

    filename: str
    conflicts: int
    bullets: list[str]

    @property
    def bullet_count(self) -> int:
        """Number of bullets (folded, so wrapping is not penalised)."""
        return len(self.bullets)

    @property
    def word_count(self) -> int:
        """Number of whitespace-separated words, excluding bullet markers."""
        return sum(len(bullet.split()) for bullet in self.bullets)


@dataclasses.dataclass(frozen=True)
class Violation:
    """A stanza that breaches the budget.

    Attributes:
        filename: File whose stanza is over budget.
        bullets: Actual bullet count.
        words: Actual word count.
        severity: :data:`HARD` (blocks the commit) or :data:`SOFT` (warns).
        max_bullets: Bullet cap in force.
        max_words_soft: Word guideline in force.
        max_words_reject: Word cap in force.
    """

    filename: str
    bullets: int
    words: int
    severity: str
    max_bullets: int = MAX_BULLETS_PER_FILE
    max_words_soft: int = MAX_WORDS_SOFT
    max_words_reject: int = MAX_WORDS_REJECT

    @property
    def over_bullets(self) -> bool:
        """Whether the bullet cap is exceeded."""
        return self.bullets > self.max_bullets

    @property
    def over_word_limit(self) -> bool:
        """Whether the rejecting word cap is exceeded."""
        return self.words > self.max_words_reject

    def describe(self) -> str:
        """Render a one-line, actionable description of the overage."""
        if self.severity == HARD:
            causes = []
            if self.over_bullets:
                causes.append(f"{self.bullets} bullets (max {self.max_bullets})")
            if self.over_word_limit:
                causes.append(f"{self.words} words (max {self.max_words_reject})")
            if not causes:
                causes.append(f"{self.bullets} bullets, {self.words} words")
            return f"REJECTED {self.filename}: " + ', '.join(causes)
        return (f"WARNING  {self.filename}: {self.words} words "
                f"(guideline ~{self.max_words_soft})")


def _find_block_start(lines: list[str]) -> int | None:
    """Index of the line opening the notes block, or ``None`` if absent."""
    for index, line in enumerate(lines):
        if is_note_block_start(line):
            return index
    return None


def parse_conflict_notes(commit_msg: str) -> list[FileStanza]:
    """Extract the per-file stanzas of the ``Conflicts Resolved:`` block.

    The block starts at the first heading :func:`is_note_block_start`
    recognises. Git trailers close the current stanza (so an ``Assisted-by:``
    trailer is not charged to it), and the agent-generated change summary ends
    parsing. ``<file>: omitted (...)`` one-liners are exempt wherever they
    appear, including their wrapped continuation lines — but the same text as a
    bullet inside a stanza is ordinary prose and counts.

    Nothing inside the block is silently exempt: text under no recognisable
    header is collected into a single synthetic :data:`UNATTRIBUTED` stanza,
    including text the AI appends after the trailers.

    Args:
        commit_msg: Full commit message.

    Returns:
        Stanzas in the order they appear. Empty when the message has no
        backport-note block (a verbatim cherry-pick).
    """
    lines = commit_msg.splitlines()
    start = _find_block_start(lines)
    if start is None:
        return []

    stanzas: list[FileStanza] = []
    current: FileStanza | None = None
    unattributed: FileStanza | None = None
    in_omitted = False

    for line in lines[start:]:
        stripped = line.strip()
        if not stripped:
            continue

        bullet = _BULLET_RE.match(stripped)

        header = _STANZA_RE.match(stripped)
        if header:
            current = FileStanza(header.group('file'),
                                 int(header.group('count')), [])
            stanzas.append(current)
            in_omitted = False
            continue

        # Everything from the agent's own change summary onward belongs to
        # cve-agent, not the AI — stop reading.
        if stripped.startswith(_AGENT_SUMMARY_PREFIX):
            break

        # An omitted-file one-liner is exempt and closes the open stanza. As a
        # bullet inside a stanza it is prose about another file, so it counts.
        if not bullet and _OMITTED_RE.match(stripped):
            current = None
            in_omitted = True
            continue
        # Wrapped continuation of an omitted reason — still exempt.
        if in_omitted and not bullet:
            continue
        in_omitted = False

        if _is_trailer(stripped):
            # Trailers close the block's last stanza. Prose after them is not
            # exempt: it is charged to the unattributed stanza below.
            current = None
            continue

        if is_note_block_start(stripped):
            current = None
            continue

        if current is None:
            # One synthetic stanza per message, so prose split across several
            # spots cannot each stay under the cap.
            if unattributed is None:
                unattributed = FileStanza(UNATTRIBUTED, 0, [])
                stanzas.append(unattributed)
            current = unattributed

        if bullet or not current.bullets:
            current.bullets.append(_BULLET_RE.sub('', stripped))
        else:
            # Wrapped continuation of the previous bullet.
            current.bullets[-1] += ' ' + stripped

    return stanzas


def check_note_budget(commit_msg: str) -> list[Violation]:
    """Check every file stanza in a commit message against the budget.

    Args:
        commit_msg: Full commit message.

    Returns:
        One :class:`Violation` per offending stanza, in message order. Empty
        when the notes fit (or when there are no notes at all).
    """
    violations: list[Violation] = []
    for stanza in parse_conflict_notes(commit_msg):
        bullets, words = stanza.bullet_count, stanza.word_count
        if bullets > MAX_BULLETS_PER_FILE or words > MAX_WORDS_REJECT:
            severity = HARD
        elif words > MAX_WORDS_SOFT:
            severity = SOFT
        else:
            continue
        violations.append(Violation(
            filename=stanza.filename, bullets=bullets, words=words,
            severity=severity,
        ))
    return violations


def has_hard_violation(violations: list[Violation]) -> bool:
    """Whether any violation blocks the commit.

    Args:
        violations: Result of :func:`check_note_budget`.

    Returns:
        ``True`` if at least one violation has severity :data:`HARD`.
    """
    return any(v.severity == HARD for v in violations)


def format_violations(violations: list[Violation]) -> str:
    """Render violations as an operator- and AI-readable report.

    Args:
        violations: Result of :func:`check_note_budget`.

    Returns:
        Multi-line report, or an empty string when there is nothing to report.
    """
    if not violations:
        return ''

    report = [
        "Commit notes exceed the per-file budget "
        "(AGENT_INSTRUCTIONS.md, 'Commit Message Format'):",
        '',
    ]
    report.extend(f"  {v.describe()}" for v in violations)
    report.append('')

    if has_hard_violation(violations):
        report.extend([
            f"Keep each file to at most {MAX_BULLETS_PER_FILE} bullets and "
            f"~{MAX_WORDS_SOFT} words. State only the adaptation: what changed "
            f"and why the stable branch differs.",
            "Drop the investigation that led there — no upstream-history "
            "checks, no 'no companion commit exists', no test-run counts, no "
            "step-by-step narration.",
            "Shorten the notes and retry: rewrite .git/MERGE_MSG (or your "
            "message file) with your file-writing tool, then re-run "
            "'git cherry-pick --no-edit --continue' or "
            "'git commit --amend -F <file>'.",
            "Do NOT run 'git cherry-pick --abort' or '--skip', and do NOT run "
            "'git commit --amend --no-edit' — that resubmits the same "
            "rejected message and will be rejected again.",
        ])
        if any(v.filename == UNATTRIBUTED for v in violations):
            report.append(
                f"'{UNATTRIBUTED}' means text in the block sits under no "
                f"'<file> (<N> conflict[s]):' header — add the header (use "
                f"'(0 conflicts)' for a file with no merge conflict) or drop "
                f"the text.")
    else:
        report.append(
            f"Within the hard cap ({MAX_WORDS_REJECT} words) — allowed, but "
            f"trim toward ~{MAX_WORDS_SOFT} words per file.")
    return '\n'.join(report)


def strip_comments(commit_msg: str) -> str:
    """Drop git's ``#`` comment lines from a raw commit-message file.

    Mirrors git's ``--cleanup=default`` behavior closely enough for counting.
    Markdown note headers are kept: ``## Conflicts Resolved`` also starts with
    ``#``, and discarding it would hide the whole block from the budget.

    Args:
        commit_msg: Raw contents of a commit-message file.

    Returns:
        The message with comment lines removed.
    """
    return '\n'.join(
        line for line in commit_msg.splitlines()
        if not line.startswith('#') or is_note_block_start(line)
    )


def main(argv: list[str] | None = None) -> int:
    """Check a commit-message file; entry point for the ``commit-msg`` hook.

    Args:
        argv: Argument list; the first entry is the message file path.
            Defaults to ``sys.argv[1:]``.

    Returns:
        :data:`EXIT_NOTES_REJECTED` when a hard violation was found (the hook
        turns that into a rejection), ``0`` when the notes fit or only warrant
        a warning, and ``2`` when the check could not run. Any other status
        means the checker itself failed; the hook treats everything except
        :data:`EXIT_NOTES_REJECTED` as "allow", so a broken environment never
        blocks a commit.
    """
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m cve_agent.commit_notes <commit-msg-file>",
              file=sys.stderr)
        return 2

    try:
        raw = Path(args[0]).read_text(encoding='utf-8', errors='replace')
    except OSError as err:
        print(f"cve-agent note check skipped: {err}", file=sys.stderr)
        return 2

    violations = check_note_budget(strip_comments(raw))
    if violations:
        print(format_violations(violations), file=sys.stderr)
    return EXIT_NOTES_REJECTED if has_hard_violation(violations) else 0


if __name__ == '__main__':  # pragma: no cover - exercised via subprocess
    sys.exit(main())
