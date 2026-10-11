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

from plot_corrector_results import (  # noqa: E402
    FAMILY_AGENT_VERIFIED,
    FAMILY_DIRECT_SUCCESS,
    FAMILY_FAILED,
    FAMILY_NEEDS_REVIEW,
    FAMILY_SKIPPED,
    classify_family,
    family_counts,
    find_results_csv,
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
