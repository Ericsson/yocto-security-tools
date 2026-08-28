# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent.commit_notes — the ``Conflicts Resolved:`` budget."""
import subprocess
import sys
from pathlib import Path

import pytest

from cve_agent.commit_notes import (
    EXIT_NOTES_REJECTED,
    HARD,
    MAX_BULLETS_PER_FILE,
    MAX_WORDS_REJECT,
    MAX_WORDS_SOFT,
    SOFT,
    UNATTRIBUTED,
    check_note_budget,
    format_violations,
    has_hard_violation,
    main,
    parse_conflict_notes,
    strip_comments,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

COMPLIANT = """\
Fix a use-after-free in the parser

Upstream commit body, preserved verbatim.

Conflicts Resolved:

src/foo.c (2 conflicts):
- Adapted foo_v2() to the foo_v1() signature present in 1.2.x.
- Member renamed netdev->ndev in the original patch.

Assisted-by: kiro:claude-sonnet-4-20250514
"""


def words(count: int) -> str:
    """Build a bullet line with exactly ``count`` words."""
    return '- ' + ' '.join(f'w{i}' for i in range(count))


def notes(*body: str) -> str:
    """Wrap stanza lines in a minimal commit message with a notes block."""
    return 'Subject line\n\nConflicts Resolved:\n\n' + '\n'.join(body) + '\n'


# --- parse_conflict_notes ---

def test_no_notes_block_yields_no_stanzas():
    assert parse_conflict_notes("Fix CVE-2024-1234\n\nUpstream body.\n") == []


def test_parses_header_and_bullets():
    stanzas = parse_conflict_notes(COMPLIANT)
    assert len(stanzas) == 1
    assert stanzas[0].filename == 'src/foo.c'
    assert stanzas[0].conflicts == 2
    assert stanzas[0].bullet_count == 2


def test_blank_lines_inside_stanza_are_not_counted():
    msg = notes('src/foo.c (1 conflict):', '- one two', '', '- three four')
    stanza = parse_conflict_notes(msg)[0]
    assert stanza.bullet_count == 2
    assert stanza.word_count == 4


def test_wrapped_bullet_counts_as_one_bullet():
    """A note wrapped at 72 columns must not be penalised for wrapping."""
    msg = notes(
        'src/foo.c (1 conflict):',
        '- Adapted extract_file_v2() to the 1.34 extract_file() signature,',
        '  which never gained the flags argument on the stable branch.',
    )
    stanza = parse_conflict_notes(msg)[0]
    assert stanza.bullet_count == 1
    assert stanza.word_count == 17
    assert check_note_budget(msg) == []


def test_three_wrapped_bullets_near_the_word_guideline_pass():
    """The bullet cap must leave the word budget reachable."""
    msg = notes(
        'src/foo.c (3 conflicts):',
        '- ' + ' '.join(f'a{i}' for i in range(8)),
        '  ' + ' '.join(f'b{i}' for i in range(8)),
        '- ' + ' '.join(f'c{i}' for i in range(8)),
        '- ' + ' '.join(f'd{i}' for i in range(8)),
    )
    stanza = parse_conflict_notes(msg)[0]
    assert stanza.bullet_count == 3
    assert stanza.word_count == 32
    assert check_note_budget(msg) == []


def test_trailer_ends_the_block():
    msg = notes(
        'src/foo.c (1 conflict):',
        '- one two three',
        '',
        'Assisted-by: kiro:model',
        'CVE: CVE-2024-1234',
    )
    stanza = parse_conflict_notes(msg)[0]
    assert stanza.bullet_count == 1
    assert stanza.word_count == 3


def test_unknown_key_prefix_is_body_text_not_a_trailer():
    """``Note:``/``Reason:`` lines are prose — they must not truncate the block."""
    msg = notes(
        'src/foo.c (1 conflict):',
        '- one two',
        'Reason: ' + ' '.join(f'w{i}' for i in range(60)),
        '',
        'src/bar.c (1 conflict):',
        words(60),
    )
    stanzas = parse_conflict_notes(msg)
    assert [s.filename for s in stanzas] == ['src/foo.c', 'src/bar.c']
    assert stanzas[0].word_count > MAX_WORDS_REJECT
    assert {v.filename for v in check_note_budget(msg)} == {
        'src/foo.c', 'src/bar.c'}


def test_agent_change_summary_ends_the_block():
    msg = notes(
        'src/foo.c (1 conflict):',
        '- one two three',
        '',
        'Changes from upstream commit abc123456789:',
        '  - src/foo.c: adapted from upstream',
    )
    stanzas = parse_conflict_notes(msg)
    assert len(stanzas) == 1
    assert stanzas[0].bullet_count == 1


def test_omitted_entries_are_skipped():
    msg = notes(
        'src/foo.c: omitted (not in branch)',
        'tests/bar.c: omitted (depends on missing harness)',
    )
    assert parse_conflict_notes(msg) == []


def test_omitted_entry_after_a_stanza_is_still_exempt():
    """The documented position for omitted files is after the stanzas."""
    msg = notes(
        'src/parse.c (1 conflict):',
        '- Adapted parse_v2() to the stable parse() signature.',
        '',
        'tests/bar.c: omitted (' + ' '.join(f'w{i}' for i in range(40)) + ')',
    )
    stanzas = parse_conflict_notes(msg)
    assert [s.filename for s in stanzas] == ['src/parse.c']
    assert check_note_budget(msg) == []


def test_wrapped_omitted_reason_is_exempt():
    """A wrapped omitted reason must not become an unattributed violation."""
    msg = notes(
        'src/parse.c (1 conflict):',
        '- Adapted parse_v2() to the stable parse() signature.',
        '',
        'tests/bar.c: omitted (depends on the shared fixture helper that',
        '  the stable branch never gained, and on the generated golden',
        '  output files that only exist upstream after the rewrite)',
    )
    assert [s.filename for s in parse_conflict_notes(msg)] == ['src/parse.c']
    assert check_note_budget(msg) == []


def test_omitted_line_inside_a_stanza_is_prose():
    """An omitted-looking bullet must not silently close the stanza."""
    msg = notes(
        'src/foo.c (1 conflict):',
        '- src/other.c: omitted (not in branch)',
        words(60),
    )
    stanzas = parse_conflict_notes(msg)
    assert len(stanzas) == 1
    assert stanzas[0].word_count > MAX_WORDS_REJECT
    assert has_hard_violation(check_note_budget(msg))


def test_prose_after_the_trailers_is_charged():
    """Narration appended below `Assisted-by:` is not exempt."""
    msg = notes(
        'src/foo.c (1 conflict):',
        '- Adapted foo_v2() to the stable API.',
        '',
        'Assisted-by: kiro:model',
        '',
        words(60),
    )
    violations = check_note_budget(msg)
    assert [v.filename for v in violations] == [UNATTRIBUTED]
    assert violations[0].severity == HARD


def test_unattributed_prose_is_summed_across_the_message():
    """Splitting prose into two blocks must not halve it under the cap."""
    chunk = ' '.join(f'w{i}' for i in range(30))
    msg = ('Subject\n\nConflicts Resolved:\n\n- ' + chunk
           + '\n\nConflicts Resolved:\n\n- ' + chunk + '\n')
    stanzas = parse_conflict_notes(msg)
    assert [s.filename for s in stanzas] == [UNATTRIBUTED]
    assert stanzas[0].word_count == 60
    assert has_hard_violation(check_note_budget(msg))


def test_numbered_lists_count_as_bullets():
    """A numbered list must not fold into one bullet and dodge the cap."""
    msg = notes(
        'src/foo.c (1 conflict):',
        '1. one two', '2. three four', '3. five six', '4. seven eight',
    )
    stanza = parse_conflict_notes(msg)[0]
    assert stanza.bullet_count == 4
    assert has_hard_violation(check_note_budget(msg))


def test_multiple_stanzas_parsed_independently():
    msg = notes(
        'src/foo.c (1 conflict):',
        '- one two',
        '',
        'src/bar.c (3 conflicts):',
        '- three four five',
    )
    stanzas = parse_conflict_notes(msg)
    assert [s.filename for s in stanzas] == ['src/foo.c', 'src/bar.c']
    assert [s.conflicts for s in stanzas] == [1, 3]
    assert [s.word_count for s in stanzas] == [2, 3]


def test_zero_conflict_stanza_is_recognised():
    """A ptest/build-only fix documents a file with no merge conflict."""
    msg = notes('tests/tar.tests (0 conflicts):', '- Adapted the expected output.')
    stanza = parse_conflict_notes(msg)[0]
    assert stanza.conflicts == 0
    assert check_note_budget(msg) == []


def test_bullet_markers_do_not_count_as_words():
    stanza = parse_conflict_notes(notes('a.c (1 conflict):', '- one two'))[0]
    assert stanza.word_count == 2


def test_prose_under_a_malformed_header_is_charged_not_dropped():
    """A header the parser cannot read must not disable the budget."""
    msg = notes('src/foo.c (2 hunks):', words(30), words(30))
    stanzas = parse_conflict_notes(msg)
    assert [s.filename for s in stanzas] == [UNATTRIBUTED]
    violations = check_note_budget(msg)
    assert [v.filename for v in violations] == [UNATTRIBUTED]
    assert violations[0].severity == HARD


def test_bare_bullets_with_no_header_are_charged():
    msg = notes(words(30), words(30))
    assert [v.filename for v in check_note_budget(msg)] == [UNATTRIBUTED]


def test_markdown_heading_in_upstream_body_does_not_open_a_block():
    """A `## ` heading in the preserved upstream body is not a notes block."""
    msg = ("Fix a bug\n\n## Description\n\n"
           + ' '.join(f'w{i}' for i in range(80)) + "\n")
    assert parse_conflict_notes(msg) == []
    assert check_note_budget(msg) == []


# --- check_note_budget ---

def test_compliant_message_has_no_violations():
    assert check_note_budget(COMPLIANT) == []


def test_over_bullet_budget_is_a_hard_violation():
    body = [words(3) for _ in range(MAX_BULLETS_PER_FILE + 1)]
    violations = check_note_budget(notes('src/foo.c (1 conflict):', *body))
    assert len(violations) == 1
    assert violations[0].severity == HARD
    assert violations[0].over_bullets
    assert not violations[0].over_word_limit
    assert has_hard_violation(violations)


def test_word_count_between_soft_and_reject_is_a_warning_only():
    total = MAX_WORDS_SOFT + 4
    assert total <= MAX_WORDS_REJECT
    msg = notes('src/foo.c (1 conflict):', words(total // 2),
                words(total - total // 2))
    violations = check_note_budget(msg)
    assert len(violations) == 1
    assert violations[0].severity == SOFT
    assert violations[0].words == total
    assert not has_hard_violation(violations)


def test_word_count_over_the_reject_cap_is_a_hard_violation():
    msg = notes('src/foo.c (1 conflict):', words(25), words(25))
    violations = check_note_budget(msg)
    assert len(violations) == 1
    assert violations[0].severity == HARD
    assert violations[0].words == 50
    assert violations[0].over_word_limit
    assert not violations[0].over_bullets


def test_only_the_offending_file_is_reported():
    msg = notes(
        'src/ok.c (1 conflict):',
        '- Adapted the helper call to the stable signature.',
        '',
        'src/bad.c (2 conflicts):',
        words(25), words(25),
    )
    violations = check_note_budget(msg)
    assert [v.filename for v in violations] == ['src/bad.c']


def test_omitted_entries_are_exempt_from_the_budget():
    long_reason = 'src/foo.c: omitted (' + ' '.join(
        f'w{i}' for i in range(60)) + ')'
    assert check_note_budget(notes(long_reason)) == []


def test_markdown_header_variant_is_still_checked():
    msg = ('Subject line\n\n### Conflicts Resolved\n\n'
           'src/foo.c (1 conflict):\n'
           + '\n'.join(words(25) for _ in range(2)) + '\n')
    violations = check_note_budget(msg)
    assert len(violations) == 1
    assert violations[0].severity == HARD


@pytest.mark.parametrize("heading", [
    'Conflicts Resolved:',
    '## Conflicts Resolved',
    '#### Conflicts Resolved',
    '**Conflicts Resolved:**',
    'conflicts resolved:',
    'Conflict Resolution:',
    '> Conflicts Resolved:',
    'Backport notes:',
    'Backport changes:',
])
def test_all_heading_variants_are_enforced(heading):
    """A variant spelling must not exempt the block from the budget."""
    msg = f"Subject\n\n{heading}\n\nsrc/foo.c (1 conflict):\n{words(60)}\n"
    assert has_hard_violation(check_note_budget(msg)), heading


@pytest.mark.parametrize("heading", ['## Description', '## Notes', '### Testing'])
def test_unrelated_headings_do_not_open_a_block(heading):
    """Upstream body headings must not be charged to the AI."""
    msg = f"Subject\n\n{heading}\n\n" + ' '.join(f'w{i}' for i in range(80))
    assert check_note_budget(msg) == []


def test_trailer_words_are_not_charged_to_the_last_stanza():
    msg = notes(
        'src/foo.c (1 conflict):',
        words(MAX_WORDS_SOFT - 1),
        '',
        'Assisted-by: kiro:claude-sonnet-4-20250514',
        'Signed-off-by: A Developer <dev@example.com>',
    )
    assert check_note_budget(msg) == []


# --- format_violations ---

def test_format_violations_empty_is_blank():
    assert format_violations([]) == ''


def test_format_violations_names_file_and_counts_for_hard():
    body = [words(3) for _ in range(MAX_BULLETS_PER_FILE + 1)]
    report = format_violations(
        check_note_budget(notes('src/foo.c (1 conflict):', *body)))
    assert 'REJECTED src/foo.c' in report
    assert f"max {MAX_BULLETS_PER_FILE}" in report
    assert 'MERGE_MSG' in report
    assert '--abort' in report
    assert '--amend --no-edit' in report


def test_format_violations_explains_unattributed_stanza():
    report = format_violations(check_note_budget(notes(words(60))))
    assert UNATTRIBUTED in report
    assert '(0 conflicts)' in report


def test_format_violations_soft_report_is_advisory():
    total = MAX_WORDS_SOFT + 4
    report = format_violations(check_note_budget(
        notes('src/foo.c (1 conflict):', words(total))))
    assert 'WARNING' in report
    assert 'REJECTED' not in report
    assert str(MAX_WORDS_REJECT) in report


# --- strip_comments ---

def test_strip_comments_drops_git_comment_lines():
    raw = "Subject\n# Please enter the commit message\nBody\n"
    assert strip_comments(raw) == "Subject\nBody"


def test_strip_comments_keeps_markdown_note_headers():
    raw = "Subject\n\n## Conflicts Resolved\n\na.c (1 conflict):\n- one two\n"
    assert '## Conflicts Resolved' in strip_comments(raw)


# --- main / CLI ---

def _write(tmp_path, text):
    path = tmp_path / 'COMMIT_EDITMSG'
    path.write_text(text, encoding='utf-8')
    return path


def test_main_accepts_compliant_message(tmp_path, capsys):
    assert main([str(_write(tmp_path, COMPLIANT))]) == 0
    assert capsys.readouterr().err == ''


def test_main_accepts_but_reports_soft_violation(tmp_path, capsys):
    msg = notes('src/foo.c (1 conflict):', words(MAX_WORDS_SOFT + 4))
    assert main([str(_write(tmp_path, msg))]) == 0
    assert 'WARNING' in capsys.readouterr().err


def test_main_rejects_hard_violation(tmp_path, capsys):
    msg = notes('src/foo.c (1 conflict):', words(25), words(25))
    assert main([str(_write(tmp_path, msg))]) == EXIT_NOTES_REJECTED
    assert 'REJECTED src/foo.c' in capsys.readouterr().err


def test_rejection_status_is_distinct_from_interpreter_failures(tmp_path):
    """1 and 2 mean 'the checker broke'; only the sentinel means 'reject'."""
    assert EXIT_NOTES_REJECTED not in (0, 1, 2)


def test_main_rejects_over_budget_markdown_block_through_the_cli(tmp_path):
    """Comment stripping must not hide a `## Conflicts Resolved` block."""
    msg = ('Subject\n\n## Conflicts Resolved\n\nsrc/foo.c (1 conflict):\n'
           + words(60) + '\n')
    assert main([str(_write(tmp_path, msg))]) == EXIT_NOTES_REJECTED


def test_main_ignores_git_comment_lines(tmp_path):
    msg = notes('src/foo.c (1 conflict):', '- one two') + (
        '# ' + ' '.join(f'w{i}' for i in range(80)) + '\n')
    assert main([str(_write(tmp_path, msg))]) == 0


def test_main_reports_usage_error(capsys):
    assert main([]) == 2
    assert 'usage' in capsys.readouterr().err


def test_main_signals_unreadable_file_without_rejecting(tmp_path, capsys):
    """rc=2 tells the hook the check could not run, so it fails open."""
    assert main([str(tmp_path / 'missing')]) == 2
    assert 'skipped' in capsys.readouterr().err


def test_module_is_runnable_as_a_script(tmp_path):
    msg = _write(tmp_path, notes('src/foo.c (1 conflict):', words(25), words(25)))
    result = subprocess.run(
        [sys.executable, '-m', 'cve_agent.commit_notes', str(msg)],
        cwd=REPO_ROOT, capture_output=True, text=True, check=False,
    )
    assert result.returncode == EXIT_NOTES_REJECTED
    assert 'REJECTED src/foo.c' in result.stderr
