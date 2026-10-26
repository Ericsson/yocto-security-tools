#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the pure-data layer of tools/plot_corrector_results.py.

Deliberately does not import matplotlib — the plotting functions in that
script import it lazily so this module can run in CI without adding a
dependency (see AGENTS.md "Minimize Dependencies").
"""
from __future__ import annotations

import csv
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))

import pytest  # noqa: E402
from plot_corrector_results import (  # noqa: E402
    DISPLAY_ORDER,
    FAMILY_AGENT_VERIFIED,
    FAMILY_AI_FAILED,
    FAMILY_DIRECT_SUCCESS,
    FAMILY_NEEDS_REVIEW,
    FAMILY_PREEXISTING_FAILED,
    FAMILY_REVIEW_DIVERGENT,
    FAMILY_REVIEW_EQUIVALENT,
    FAMILY_REVIEW_NOT_COMPARABLE,
    FAMILY_SKIPPED,
    FAMILY_TOOL_FAILED,
    JUDGMENT_STATUS,
    STATUS_REVIEW_DIVERGENT,
    STATUS_REVIEW_EQUIVALENT,
    STATUS_REVIEW_NOT_COMPARABLE,
    STATUS_TOOL_PREFIX,
    TOOL_FAILURE_CODES,
    apply_failure_codes,
    apply_judge,
    classify_family,
    families_for_recipes,
    families_in_order,
    family_counts,
    find_results_csv,
    fits_label,
    legend_label,
    plot_family_breakdown,
    plot_recipe_breakdown,
    plot_status_distribution,
    read_judge_csv,
    read_results_csv,
    recipe_breakdown,
    status_counts,
)


class TestClassifyFamily:
    """classify_family() maps every known status to the right family."""

    def test_identical_is_direct_success(self):
        assert classify_family('IDENTICAL') == FAMILY_DIRECT_SUCCESS

    def test_success_is_direct_success(self):
        assert classify_family('SUCCESS') == FAMILY_DIRECT_SUCCESS

    def test_already_applied_is_direct_success(self):
        assert classify_family('ALREADY_APPLIED') == FAMILY_DIRECT_SUCCESS

    def test_agent_resolved_is_agent_verified(self):
        assert classify_family('AGENT_RESOLVED') == FAMILY_AGENT_VERIFIED

    def test_security_review_required_is_needs_review(self):
        assert classify_family('SECURITY_REVIEW_REQUIRED') == FAMILY_NEEDS_REVIEW

    def test_workflow_completed_unverified_is_needs_review(self):
        assert classify_family('WORKFLOW_COMPLETED_UNVERIFIED') == FAMILY_NEEDS_REVIEW

    def test_any_skip_prefixed_status_is_skipped(self):
        assert classify_family('SKIP_BUILD_PREEXISTING') == FAMILY_SKIPPED
        assert classify_family('SKIP_NOT_APPLICABLE') == FAMILY_SKIPPED
        assert classify_family('SKIP') == FAMILY_SKIPPED
        assert classify_family('SKIP_FETCH') == FAMILY_SKIPPED

    def test_any_fail_prefixed_status_is_failed(self):
        assert classify_family('FAIL_WORKFLOW_FAILED') == FAMILY_AI_FAILED
        assert classify_family('FAIL_UNKNOWN_17') == FAMILY_AI_FAILED

    def test_agent_failures_are_ai_failed(self):
        for status in ('FAIL_WORKFLOW_FAILED', 'FAIL_SECURITY_REJECTED',
                       'FAIL_PROVIDER_TIMEOUT', 'FAIL_AGENT_NO_PROGRESS',
                       'FAIL_CONFLICT', 'FAIL_BUILD_ERROR', 'FAIL_TIMEOUT'):
            assert classify_family(status) == FAMILY_AI_FAILED, status

    def test_corrector_and_environment_failures_are_preexisting_failed(self):
        # cve-agent never runs for these exit codes, so they cannot be an AI fail.
        for status in ('FAIL_GIT_ERROR', 'FAIL_DEVTOOL_ERROR', 'FAIL_CHECKOUT_ERROR',
                       'FAIL_PREP_BASE_MISMATCH', 'FAIL_BUILD_PREEXISTING'):
            assert classify_family(status) == FAMILY_PREEXISTING_FAILED, status

    def test_preexisting_suffix_is_only_matched_on_fail_statuses(self):
        # SKIP_BUILD_PREEXISTING stays skipped; a bare suffix is not a FAIL status.
        assert classify_family('SKIP_BUILD_PREEXISTING') == FAMILY_SKIPPED
        assert classify_family('GIT_ERROR') == FAMILY_AI_FAILED

    def test_unrecognized_status_defaults_to_failed_not_dropped(self):
        # A future status this script doesn't know about yet must still show
        # up on a chart as a failure rather than silently vanishing.
        assert classify_family('SOME_NEW_STATUS_FROM_THE_FUTURE') == FAMILY_AI_FAILED

    def test_review_statuses_are_distinct_from_agent_verified(self):
        # The whole point of the taxonomy: "produced a patch" must not read
        # as the same thing as "verified correct".
        assert classify_family('SECURITY_REVIEW_REQUIRED') != classify_family('AGENT_RESOLVED')


class TestStatusCounts:
    """status_counts() tallies the raw status column."""

    def test_counts_each_status_once_per_row(self):
        rows = [
            {'status': 'IDENTICAL'},
            {'status': 'IDENTICAL'},
            {'status': 'AGENT_RESOLVED'},
        ]
        counts = status_counts(rows)
        assert counts == Counter({'IDENTICAL': 2, 'AGENT_RESOLVED': 1})

    def test_empty_rows_yields_empty_counter(self):
        assert status_counts([]) == Counter()


class TestFamilyCounts:
    """family_counts() groups raw statuses under their family."""

    def test_groups_statuses_under_the_right_family(self):
        counts = Counter({'IDENTICAL': 3, 'AGENT_RESOLVED': 1, 'FAIL_WORKFLOW_FAILED': 2,
                          'FAIL_GIT_ERROR': 4})
        grouped = family_counts(counts)
        assert sum(grouped[FAMILY_DIRECT_SUCCESS].values()) == 3
        assert sum(grouped[FAMILY_AGENT_VERIFIED].values()) == 1
        assert sum(grouped[FAMILY_AI_FAILED].values()) == 2
        assert sum(grouped[FAMILY_PREEXISTING_FAILED].values()) == 4
        assert sum(grouped[FAMILY_NEEDS_REVIEW].values()) == 0
        assert sum(grouped[FAMILY_SKIPPED].values()) == 0

    def test_every_family_key_present_even_when_empty(self):
        # A chart that iterates FAMILY_ORDER must not KeyError on a family
        # with zero occurrences in a given run.
        grouped = family_counts(Counter({'IDENTICAL': 1}))
        assert set(grouped) == {
            FAMILY_DIRECT_SUCCESS, FAMILY_AGENT_VERIFIED, FAMILY_NEEDS_REVIEW,
            FAMILY_SKIPPED, FAMILY_PREEXISTING_FAILED, FAMILY_AI_FAILED,
        }

    def test_preserves_raw_status_composition_within_a_family(self):
        counts = Counter({'SKIP_BUILD_PREEXISTING': 2, 'SKIP_NOT_APPLICABLE': 1})
        grouped = family_counts(counts)
        assert grouped[FAMILY_SKIPPED] == Counter(
            {'SKIP_BUILD_PREEXISTING': 2, 'SKIP_NOT_APPLICABLE': 1}
        )


class TestRecipeBreakdown:
    """recipe_breakdown() aggregates outcome families per recipe."""

    def test_groups_by_recipe(self):
        rows = [
            {'recipe': 'openssh', 'status': 'IDENTICAL'},
            {'recipe': 'openssh', 'status': 'SECURITY_REVIEW_REQUIRED'},
            {'recipe': 'vim-tiny', 'status': 'AGENT_RESOLVED'},
        ]
        breakdown = recipe_breakdown(rows)
        assert breakdown['openssh'][FAMILY_DIRECT_SUCCESS] == 1
        assert breakdown['openssh'][FAMILY_NEEDS_REVIEW] == 1
        assert breakdown['vim-tiny'][FAMILY_AGENT_VERIFIED] == 1

    def test_missing_recipe_field_falls_back_to_unknown(self):
        rows = [{'recipe': '', 'status': 'IDENTICAL'}]
        breakdown = recipe_breakdown(rows)
        assert breakdown['(unknown)'][FAMILY_DIRECT_SUCCESS] == 1


class TestReadResultsCsv:
    """read_results_csv() loads a results CSV and fails loudly when empty."""

    def test_reads_rows_in_file_order(self, tmp_path):
        path = tmp_path / 'results_full.csv'
        with path.open('w', newline='', encoding='utf-8') as fh:
            writer = csv.writer(fh)
            writer.writerow(['cve_id', 'recipe', 'status'])
            writer.writerow(['CVE-2024-0001', 'openssh', 'IDENTICAL'])
            writer.writerow(['CVE-2024-0002', 'vim-tiny', 'AGENT_RESOLVED'])
        rows = read_results_csv(path)
        assert [r['cve_id'] for r in rows] == ['CVE-2024-0001', 'CVE-2024-0002']

    def test_missing_file_raises_system_exit(self, tmp_path):
        try:
            read_results_csv(tmp_path / 'does_not_exist.csv')
            raise AssertionError('expected SystemExit')
        except SystemExit:
            pass

    def test_header_only_csv_raises_system_exit(self, tmp_path):
        path = tmp_path / 'results_full.csv'
        path.write_text('cve_id,recipe,status\n', encoding='utf-8')
        try:
            read_results_csv(path)
            raise AssertionError('expected SystemExit')
        except SystemExit:
            pass


class TestFindResultsCsv:
    """find_results_csv() resolves the CSV path, explicit or auto-detected."""

    def test_explicit_mode_builds_the_expected_filename(self, tmp_path):
        path = find_results_csv(tmp_path, 'full-enriched')
        assert path == tmp_path / 'results_full-enriched.csv'

    def test_auto_detects_a_single_candidate(self, tmp_path):
        (tmp_path / 'results_full-enriched.csv').write_text('x\n', encoding='utf-8')
        path = find_results_csv(tmp_path, None)
        assert path == tmp_path / 'results_full-enriched.csv'

    def test_no_candidates_raises_system_exit(self, tmp_path):
        try:
            find_results_csv(tmp_path, None)
            raise AssertionError('expected SystemExit')
        except SystemExit:
            pass

    def test_ambiguous_candidates_raise_system_exit_rather_than_guessing(self, tmp_path):
        (tmp_path / 'results_full.csv').write_text('x\n', encoding='utf-8')
        (tmp_path / 'results_full-enriched.csv').write_text('x\n', encoding='utf-8')
        try:
            find_results_csv(tmp_path, None)
            raise AssertionError('expected SystemExit')
        except SystemExit:
            pass


def _review_rows():
    return [
        {'cve_id': 'CVE-1', 'recipe': 'a', 'status': 'SECURITY_REVIEW_REQUIRED'},
        {'cve_id': 'CVE-2', 'recipe': 'a', 'status': 'WORKFLOW_COMPLETED_UNVERIFIED'},
        {'cve_id': 'CVE-3', 'recipe': 'b', 'status': 'SECURITY_REVIEW_REQUIRED'},
        {'cve_id': 'CVE-4', 'recipe': 'b', 'status': 'SECURITY_REVIEW_REQUIRED'},
        {'cve_id': 'CVE-5', 'recipe': 'b', 'status': 'IDENTICAL'},
    ]


class TestJudgedFamilies:
    """The judge verdict splits the "needs review" family, and nothing else."""

    def test_pseudo_statuses_map_to_their_own_families(self):
        assert classify_family(STATUS_REVIEW_EQUIVALENT) == FAMILY_REVIEW_EQUIVALENT
        assert classify_family(STATUS_REVIEW_DIVERGENT) == FAMILY_REVIEW_DIVERGENT
        assert classify_family(STATUS_REVIEW_NOT_COMPARABLE) == FAMILY_REVIEW_NOT_COMPARABLE

    def test_every_verdict_maps_to_a_pseudo_status(self):
        assert JUDGMENT_STATUS['stylistic'] == STATUS_REVIEW_EQUIVALENT
        assert JUDGMENT_STATUS['identical'] == STATUS_REVIEW_EQUIVALENT
        assert JUDGMENT_STATUS['comment-only'] == STATUS_REVIEW_EQUIVALENT
        assert JUDGMENT_STATUS['structural-only'] == STATUS_REVIEW_EQUIVALENT
        assert JUDGMENT_STATUS['meaningful'] == STATUS_REVIEW_DIVERGENT
        for verdict in ('no-patch', 'no-reference', 'file-mismatch'):
            assert JUDGMENT_STATUS[verdict] == STATUS_REVIEW_NOT_COMPARABLE

    def test_apply_judge_refines_only_review_rows_with_a_known_verdict(self):
        verdicts = {'CVE-1': 'stylistic', 'CVE-2': 'meaningful', 'CVE-3': 'pending',
                    'CVE-5': 'meaningful'}
        statuses = {r['cve_id']: r['status'] for r in apply_judge(_review_rows(), verdicts)}
        assert statuses == {
            'CVE-1': STATUS_REVIEW_EQUIVALENT,
            'CVE-2': STATUS_REVIEW_DIVERGENT,
            'CVE-3': 'SECURITY_REVIEW_REQUIRED',   # unknown verdict: unchanged
            'CVE-4': 'SECURITY_REVIEW_REQUIRED',   # no verdict: unchanged
            'CVE-5': 'IDENTICAL',                  # not a review row: unchanged
        }

    def test_apply_judge_does_not_modify_its_input(self):
        rows = _review_rows()
        apply_judge(rows, {'CVE-1': 'stylistic'})
        assert rows[0]['status'] == 'SECURITY_REVIEW_REQUIRED'

    def test_family_counts_adds_judged_families_only_when_present(self):
        plain = family_counts(Counter({'SECURITY_REVIEW_REQUIRED': 2}))
        assert FAMILY_REVIEW_EQUIVALENT not in plain
        judged = family_counts(Counter({STATUS_REVIEW_EQUIVALENT: 2, 'IDENTICAL': 1}))
        assert sum(judged[FAMILY_REVIEW_EQUIVALENT].values()) == 2
        assert sum(judged[FAMILY_NEEDS_REVIEW].values()) == 0

    def test_families_in_order_puts_judged_families_beside_needs_review(self):
        grouped = family_counts(Counter({
            'IDENTICAL': 1, STATUS_REVIEW_DIVERGENT: 1, STATUS_REVIEW_EQUIVALENT: 1,
            'SECURITY_REVIEW_REQUIRED': 1, 'FAIL_X': 1}))
        ordered = families_in_order(grouped)
        assert ordered == [f for f in DISPLAY_ORDER if f in grouped]
        assert ordered.index(FAMILY_REVIEW_EQUIVALENT) < ordered.index(
            FAMILY_REVIEW_DIVERGENT) < ordered.index(FAMILY_NEEDS_REVIEW)

    def test_recipe_chart_draws_the_judged_families_in_display_order(self):
        rows = apply_judge(_review_rows(), {'CVE-1': 'stylistic', 'CVE-3': 'meaningful'})
        assert families_for_recipes(recipe_breakdown(rows)) == [
            FAMILY_DIRECT_SUCCESS, FAMILY_REVIEW_EQUIVALENT, FAMILY_REVIEW_DIVERGENT,
            FAMILY_NEEDS_REVIEW]

    def test_recipe_breakdown_counts_the_judged_families(self):
        rows = apply_judge(_review_rows(), {'CVE-1': 'stylistic', 'CVE-3': 'meaningful'})
        per_recipe = recipe_breakdown(rows)
        assert per_recipe['a'][FAMILY_REVIEW_EQUIVALENT] == 1
        assert per_recipe['b'][FAMILY_REVIEW_DIVERGENT] == 1


def _failure_rows():
    return [
        {'cve_id': 'CVE-1', 'recipe': 'a', 'status': 'FAIL_WORKFLOW_FAILED',
         'failure_code': 'HANDOFF_REFERENCE_DRIFT'},
        {'cve_id': 'CVE-2', 'recipe': 'a', 'status': 'FAIL_WORKFLOW_FAILED',
         'failure_code': 'TRANSFER_UNSUPPORTED_FILE_TYPE'},
        {'cve_id': 'CVE-3', 'recipe': 'b', 'status': 'FAIL_WORKFLOW_FAILED',
         'failure_code': 'TRANSFER_NO_TARGET_PATH'},
        {'cve_id': 'CVE-4', 'recipe': 'b', 'status': 'FAIL_WORKFLOW_FAILED',
         'failure_code': 'HANDOFF_UNKNOWN_OUT_OF_SCOPE'},
        {'cve_id': 'CVE-5', 'recipe': 'b', 'status': 'FAIL_AGENT_NO_PROGRESS',
         'failure_code': 'model_no_progress'},
        {'cve_id': 'CVE-6', 'recipe': 'c', 'status': 'FAIL_PREP_BASE_MISMATCH',
         'failure_code': 'PREP_BASE_MISMATCH'},
        {'cve_id': 'CVE-7', 'recipe': 'c', 'status': 'SECURITY_REVIEW_REQUIRED',
         'failure_code': 'HANDOFF_REFERENCE_DRIFT'},
        {'cve_id': 'CVE-8', 'recipe': 'c', 'status': 'FAIL_WORKFLOW_FAILED'},
    ]


class TestToolFailures:
    """A FAIL_* row with a handoff/transfer failure code is "failed (tool)"."""

    def test_the_listed_codes_are_the_ones_agreed(self):
        assert TOOL_FAILURE_CODES == (
            'HANDOFF_REFERENCE_DRIFT', 'TRANSFER_NO_TARGET_PATH',
            'TRANSFER_UNSUPPORTED_FILE_TYPE')

    def test_tool_status_is_its_own_family(self):
        assert classify_family(STATUS_TOOL_PREFIX + 'HANDOFF_REFERENCE_DRIFT') == (
            FAMILY_TOOL_FAILED)
        assert FAMILY_TOOL_FAILED not in (FAMILY_AI_FAILED, FAMILY_PREEXISTING_FAILED)

    def test_only_listed_codes_on_fail_rows_are_marked(self):
        statuses = {r['cve_id']: r['status'] for r in apply_failure_codes(_failure_rows())}
        assert statuses == {
            'CVE-1': 'FAIL_TOOL_HANDOFF_REFERENCE_DRIFT',
            'CVE-2': 'FAIL_TOOL_TRANSFER_UNSUPPORTED_FILE_TYPE',
            'CVE-3': 'FAIL_TOOL_TRANSFER_NO_TARGET_PATH',
            'CVE-4': 'FAIL_WORKFLOW_FAILED',        # unlisted handoff code stays AI
            'CVE-5': 'FAIL_AGENT_NO_PROGRESS',
            'CVE-6': 'FAIL_PREP_BASE_MISMATCH',
            'CVE-7': 'SECURITY_REVIEW_REQUIRED',    # not a FAIL_ row
            'CVE-8': 'FAIL_WORKFLOW_FAILED',        # no failure_code at all
        }

    def test_the_failure_families_end_up_separate(self):
        grouped = family_counts(status_counts(apply_failure_codes(_failure_rows())))
        assert sum(grouped[FAMILY_TOOL_FAILED].values()) == 3
        assert sum(grouped[FAMILY_PREEXISTING_FAILED].values()) == 1
        assert sum(grouped[FAMILY_AI_FAILED].values()) == 3

    def test_input_rows_are_not_modified(self):
        rows = _failure_rows()
        apply_failure_codes(rows)
        assert rows[0]['status'] == 'FAIL_WORKFLOW_FAILED'

    def test_a_csv_without_failure_codes_is_left_alone(self):
        rows = [{'cve_id': 'CVE-1', 'recipe': 'a', 'status': 'FAIL_WORKFLOW_FAILED'}]
        assert apply_failure_codes(rows) == rows

    def test_tool_family_is_drawn_only_when_present_and_before_ai(self):
        without = family_counts(Counter({'FAIL_WORKFLOW_FAILED': 1}))
        assert FAMILY_TOOL_FAILED not in without
        grouped = family_counts(status_counts(apply_failure_codes(_failure_rows())))
        ordered = families_in_order(grouped)
        assert ordered.index(FAMILY_PREEXISTING_FAILED) < ordered.index(
            FAMILY_TOOL_FAILED) < ordered.index(FAMILY_AI_FAILED)

    def test_all_charts_render_with_the_tool_family(self, tmp_path):
        pytest.importorskip('matplotlib')
        rows = apply_failure_codes(_failure_rows())
        counts = status_counts(rows)
        plot_status_distribution(counts, tmp_path / 'a.png')
        plot_family_breakdown(family_counts(counts), len(rows), tmp_path / 'b.png')
        plot_recipe_breakdown(recipe_breakdown(rows), tmp_path / 'c.png')
        assert all((tmp_path / n).stat().st_size > 0 for n in ('a.png', 'b.png', 'c.png'))


class TestToolFailuresInTheCommand:
    def test_the_command_reports_the_tool_family(self, tmp_path):
        pytest.importorskip('matplotlib')
        import subprocess
        header = 'cve_id,recipe,status,failure_code\n'
        (tmp_path / 'results_full.csv').write_text(
            header + 'CVE-1,a,FAIL_WORKFLOW_FAILED,HANDOFF_REFERENCE_DRIFT\n'
                     'CVE-2,b,FAIL_AGENT_NO_PROGRESS,model_no_progress\n', encoding='utf-8')
        script = Path(__file__).resolve().parents[2] / 'tools' / 'plot_corrector_results.py'
        done = subprocess.run(
            [sys.executable, str(script), str(tmp_path), '--output-dir', str(tmp_path / 'out')],
            capture_output=True, text=True, check=True)
        assert 'failed (tool)' in done.stdout
        assert 'FAIL_TOOL_HANDOFF_REFERENCE_DRIFT' in done.stdout
        assert 'failed (AI)' in done.stdout


class TestFamilyChartText:
    def test_only_wide_bars_get_a_label_on_the_chart(self, tmp_path, monkeypatch):
        plt = pytest.importorskip('matplotlib.pyplot')
        figures = []
        monkeypatch.setattr(plt, 'close', figures.append)
        counts = Counter({'IDENTICAL': 95, 'FAIL_GIT_ERROR': 2, 'FAIL_WORKFLOW_FAILED': 3})
        plot_family_breakdown(family_counts(counts), 100, tmp_path / 'b.png')
        assert [t.get_text() for t in figures[0].axes[0].texts] == ['95\n(95%)']


class TestReadJudgeCsv:
    """read_judge_csv() returns the verdict per CVE and rejects bad input."""

    def test_reads_the_verdicts(self, tmp_path):
        path = tmp_path / 'judge_results.csv'
        path.write_text('cve_id,recipe,judgment,reason\nCVE-1,a,stylistic,"x, y"\n',
                        encoding='utf-8')
        assert read_judge_csv(path) == {'CVE-1': 'stylistic'}

    def test_missing_file_raises_system_exit(self, tmp_path):
        with pytest.raises(SystemExit, match='does not exist'):
            read_judge_csv(tmp_path / 'nope.csv')

    def test_wrong_columns_raise_system_exit(self, tmp_path):
        path = tmp_path / 'judge_results.csv'
        path.write_text('cve_id,model,judgment_x\nCVE-1,m,stylistic\n', encoding='utf-8')
        with pytest.raises(SystemExit, match='no cve_id/judgment columns'):
            read_judge_csv(path)


class TestJudgedCharts:
    """The three charts render with judged families (skipped without matplotlib)."""

    def test_all_charts_render(self, tmp_path):
        pytest.importorskip('matplotlib')
        rows = apply_judge(_review_rows(), {'CVE-1': 'stylistic', 'CVE-2': 'meaningful',
                                            'CVE-3': 'no-patch'})
        counts = status_counts(rows)
        grouped = family_counts(counts)
        plot_status_distribution(counts, tmp_path / 'a.png')
        plot_family_breakdown(grouped, len(rows), tmp_path / 'b.png')
        plot_recipe_breakdown(recipe_breakdown(rows), tmp_path / 'c.png')
        assert all((tmp_path / name).stat().st_size > 0 for name in ('a.png', 'b.png', 'c.png'))


class TestBarLabels:
    """Wide bars are labelled in place; every family is labelled in the legend."""

    def test_wide_bars_are_labelled_inside(self):
        assert fits_label(436, 753)
        assert fits_label(122, 753)

    def test_narrow_bars_are_not(self):
        assert not fits_label(37, 753)
        assert not fits_label(5, 753)

    def test_a_bar_exactly_at_the_share_is_labelled_inside(self):
        assert fits_label(7, 100)
        assert not fits_label(6, 100)

    def test_empty_total_labels_nothing(self):
        assert not fits_label(0, 0)

    def test_legend_text_carries_the_count_and_share(self):
        assert legend_label('failed (tool)', 5, 753) == 'failed (tool):  5 (1%)'
        assert legend_label('direct success', 436, 753) == 'direct success:  436 (58%)'
        assert legend_label('x', 0, 0) == 'x:  0 (0%)'

    def test_the_family_chart_legend_lists_every_drawn_family_with_its_count(
            self, tmp_path, monkeypatch):
        plt = pytest.importorskip('matplotlib.pyplot')
        figures = []
        monkeypatch.setattr(plt, 'close', figures.append)
        rows = apply_failure_codes(_failure_rows())
        counts = status_counts(rows)
        plot_family_breakdown(family_counts(counts), len(rows), tmp_path / 'b.png')
        legend = figures[0].axes[0].get_legend()
        texts = [t.get_text() for t in legend.get_texts()]
        assert sorted(texts) == sorted([
            'failed (pre-existing):  1 (12%)', 'failed (tool):  3 (38%)',
            'failed (AI):  3 (38%)', 'produced a patch, needs review:  1 (12%)'])
