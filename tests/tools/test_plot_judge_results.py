#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the pure-data layer of tools/plot_judge_results.py.

Does not import matplotlib at module level; the one render test is skipped
when it is not installed (see AGENTS.md "Minimize Dependencies").
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))

from plot_judge_results import (  # noqa: E402
    GROUP_COLORS,
    GROUP_DIVERGENT,
    GROUP_EQUIVALENT,
    GROUP_NOT_COMPARABLE,
    GROUP_OTHER,
    group_totals,
    ordered_bars,
    plot_verdicts,
    read_verdicts,
)

ALL = ['stylistic', 'identical', 'identical', 'meaningful', 'no-patch', 'comment-only',
       'structural-only', 'file-mismatch', 'no-reference']


class TestReadVerdicts:
    def test_reads_the_judgment_column_in_file_order(self, tmp_path):
        path = tmp_path / 'judge_results.csv'
        path.write_text('cve_id,judgment,reason\nA,stylistic,"x, y"\nB,meaningful,z\n',
                        encoding='utf-8')
        assert read_verdicts(path) == ['stylistic', 'meaningful']

    def test_missing_file_raises_system_exit(self, tmp_path):
        with pytest.raises(SystemExit, match='does not exist'):
            read_verdicts(tmp_path / 'nope.csv')

    def test_missing_column_raises_system_exit(self, tmp_path):
        path = tmp_path / 'judge_results.csv'
        path.write_text('cve_id,verdict\nA,stylistic\n', encoding='utf-8')
        with pytest.raises(SystemExit, match='no judgment column'):
            read_verdicts(path)

    def test_header_only_file_raises_system_exit(self, tmp_path):
        path = tmp_path / 'judge_results.csv'
        path.write_text('cve_id,judgment\n', encoding='utf-8')
        with pytest.raises(SystemExit, match='nothing to plot'):
            read_verdicts(path)


class TestOrderedBars:
    def test_counts_each_verdict_in_the_fixed_display_order(self):
        bars = ordered_bars(ALL)
        assert [(b[0], b[3]) for b in bars] == [
            ('identical', 2), ('stylistic', 1), ('comment-only', 1), ('structural-only', 1),
            ('meaningful', 1), ('no-patch', 1), ('no-reference', 1), ('file-mismatch', 1)]

    def test_verdicts_that_do_not_occur_are_left_out(self):
        assert [b[0] for b in ordered_bars(['stylistic', 'stylistic'])] == ['stylistic']

    def test_each_verdict_lands_in_the_right_group(self):
        groups = {b[0]: b[2] for b in ordered_bars(ALL)}
        for verdict in ('identical', 'stylistic', 'comment-only', 'structural-only'):
            assert groups[verdict] == GROUP_EQUIVALENT
        assert groups['meaningful'] == GROUP_DIVERGENT
        for verdict in ('no-patch', 'no-reference', 'file-mismatch'):
            assert groups[verdict] == GROUP_NOT_COMPARABLE

    def test_an_unknown_verdict_is_kept_in_its_own_group_not_dropped(self):
        bars = ordered_bars(['stylistic', 'pending', 'pending'])
        assert bars[-1] == ('pending', 'pending', GROUP_OTHER, 2)


class TestGroupTotals:
    def test_sums_counts_per_group(self):
        assert group_totals(ordered_bars(ALL)) == {
            GROUP_EQUIVALENT: 5, GROUP_DIVERGENT: 1, GROUP_NOT_COMPARABLE: 3}

    def test_groups_that_do_not_occur_are_absent(self):
        assert group_totals(ordered_bars(['meaningful'])) == {GROUP_DIVERGENT: 1}


def test_every_group_has_a_colour():
    assert {GROUP_EQUIVALENT, GROUP_DIVERGENT, GROUP_NOT_COMPARABLE, GROUP_OTHER} <= set(
        GROUP_COLORS)


def test_the_chart_renders(tmp_path):
    pytest.importorskip('matplotlib')
    out = tmp_path / 'verdicts.png'
    plot_verdicts(ordered_bars(ALL + ['pending']), 'Judge verdicts', out)
    assert out.stat().st_size > 0
