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
    FAMILY_DIRECT_SUCCESS,
    FAMILY_FAILED,
    FAMILY_NEEDS_REVIEW,
    FAMILY_REVIEW_DIVERGENT,
    FAMILY_REVIEW_EQUIVALENT,
    FAMILY_REVIEW_NOT_COMPARABLE,
    FAMILY_SKIPPED,
    JUDGMENT_STATUS,
    STATUS_REVIEW_DIVERGENT,
    STATUS_REVIEW_EQUIVALENT,
    STATUS_REVIEW_NOT_COMPARABLE,
    apply_judge,
    classify_family,
    families_for_recipes,
    families_in_order,
    family_counts,
    find_results_csv,
    label_levels,
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
        assert classify_family('FAIL_WORKFLOW_FAILED') == FAMILY_FAILED
        assert classify_family('FAIL_GIT_ERROR') == FAMILY_FAILED
        assert classify_family('FAIL_UNKNOWN_17') == FAMILY_FAILED

    def test_unrecognized_status_defaults_to_failed_not_dropped(self):
        # A future status this script doesn't know about yet must still show
        # up on a chart as a failure rather than silently vanishing.
        assert classify_family('SOME_NEW_STATUS_FROM_THE_FUTURE') == FAMILY_FAILED

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
        counts = Counter({'IDENTICAL': 3, 'AGENT_RESOLVED': 1, 'FAIL_GIT_ERROR': 2})
        grouped = family_counts(counts)
        assert sum(grouped[FAMILY_DIRECT_SUCCESS].values()) == 3
        assert sum(grouped[FAMILY_AGENT_VERIFIED].values()) == 1
        assert sum(grouped[FAMILY_FAILED].values()) == 2
        assert sum(grouped[FAMILY_NEEDS_REVIEW].values()) == 0
        assert sum(grouped[FAMILY_SKIPPED].values()) == 0

    def test_every_family_key_present_even_when_empty(self):
        # A chart that iterates FAMILY_ORDER must not KeyError on a family
        # with zero occurrences in a given run.
        grouped = family_counts(Counter({'IDENTICAL': 1}))
        assert set(grouped) == {
            FAMILY_DIRECT_SUCCESS, FAMILY_AGENT_VERIFIED, FAMILY_NEEDS_REVIEW,
            FAMILY_SKIPPED, FAMILY_FAILED,
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


class TestLabelLevels:
    """label_levels() keeps narrow bars' labels from overlapping."""

    def test_wide_bars_are_labelled_inside(self):
        assert label_levels([436, 122], 753) == [None, None]

    def test_narrow_bars_alternate_between_two_levels(self):
        # 37, 41, 10 and 52 of 753 are all under the 7% share.
        assert label_levels([436, 37, 122, 41, 10, 52, 55], 753) == [
            None, 0, None, 1, 0, 1, None]

    def test_a_bar_exactly_at_the_share_is_labelled_inside(self):
        assert label_levels([7, 93], 100) == [None, None]

    def test_empty_total_labels_nothing_inside(self):
        assert label_levels([0], 0) == [0]
