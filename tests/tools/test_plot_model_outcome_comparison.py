#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the pure-data layer of tools/plot_model_outcome_comparison.py.

Does not import matplotlib at module level; the one render test is skipped
when it is not installed (see AGENTS.md "Minimize Dependencies").
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))

from plot_corrector_results import FAMILY_AGENT_VERIFIED, FAMILY_DIRECT_SUCCESS  # noqa: E402
from plot_model_outcome_comparison import (  # noqa: E402
    load_family_counts,
    parse_model_arg,
    plot_outcome_comparison,
    plot_stacked_comparison,
    print_summary,
    read_fresh_cve_list,
)

HEADER = ('cve_id,recipe,status,exit_code,diff_changes,diff_patches,diff_files,duration_s,'
          'schema_version,workflow_status,build_status,security_status,failure_class,'
          'failure_code,legacy_status,summary_state')


def write_results_csv(path, rows):
    lines = [HEADER] + [f'{cve_id},recipe,{status},,,,,,,,,,,,,' for cve_id, status in rows]
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


class TestParseModelArg:
    def test_parses_name_equals_path(self):
        assert parse_model_arg('qwen=some/dir') == ('qwen', Path('some/dir'))

    def test_missing_equals_raises_system_exit(self):
        with pytest.raises(SystemExit, match='not name=results_dir'):
            parse_model_arg('qwen')

    def test_missing_name_raises_system_exit(self):
        with pytest.raises(SystemExit, match='no model name'):
            parse_model_arg('=some/dir')


class TestReadFreshCveList:
    def test_reads_one_cve_per_line(self, tmp_path):
        path = tmp_path / 'fresh.txt'
        path.write_text('CVE-1\nCVE-2\n', encoding='utf-8')
        assert read_fresh_cve_list(path) == {'CVE-1', 'CVE-2'}

    def test_ignores_blank_lines_and_comments(self, tmp_path):
        path = tmp_path / 'fresh.txt'
        path.write_text('CVE-1\n\n# a comment\nCVE-2\n', encoding='utf-8')
        assert read_fresh_cve_list(path) == {'CVE-1', 'CVE-2'}

    def test_missing_file_raises_system_exit(self, tmp_path):
        with pytest.raises(SystemExit, match='does not exist'):
            read_fresh_cve_list(tmp_path / 'nope.txt')


class TestLoadFamilyCounts:
    def test_groups_rows_into_families(self, tmp_path):
        write_results_csv(tmp_path / 'results_full.csv', [
            ('CVE-1', 'IDENTICAL'), ('CVE-2', 'AGENT_RESOLVED'),
            ('CVE-3', 'SECURITY_REVIEW_REQUIRED'),
        ])
        counts = load_family_counts(tmp_path, 'full', None)
        assert sum(counts[FAMILY_DIRECT_SUCCESS].values()) == 1
        assert sum(counts[FAMILY_AGENT_VERIFIED].values()) == 1

    def test_restrict_to_keeps_only_the_given_cve_ids(self, tmp_path):
        write_results_csv(tmp_path / 'results_full.csv', [
            ('CVE-1', 'IDENTICAL'), ('CVE-2', 'IDENTICAL'),
        ])
        counts = load_family_counts(tmp_path, 'full', {'CVE-1'})
        assert sum(counts[FAMILY_DIRECT_SUCCESS].values()) == 1


def test_print_summary_reports_both_models(capsys):
    from collections import Counter
    counts_a = {FAMILY_DIRECT_SUCCESS: Counter({'IDENTICAL': 5})}
    counts_b = {FAMILY_DIRECT_SUCCESS: Counter({'IDENTICAL': 8})}
    print_summary(counts_a, counts_b, 'qwen', 'opus', 10, 10)
    out = capsys.readouterr().out
    assert 'qwen' in out and 'opus' in out
    assert FAMILY_DIRECT_SUCCESS in out
    assert '=   5' in out
    assert '=   8' in out


def test_the_chart_renders(tmp_path):
    pytest.importorskip('matplotlib')
    from collections import Counter
    counts_a = {FAMILY_DIRECT_SUCCESS: Counter({'IDENTICAL': 5}),
               FAMILY_AGENT_VERIFIED: Counter({'AGENT_RESOLVED': 2})}
    counts_b = {FAMILY_DIRECT_SUCCESS: Counter({'IDENTICAL': 8}),
               FAMILY_AGENT_VERIFIED: Counter({'AGENT_RESOLVED': 4})}
    out = tmp_path / 'outcomes.png'
    plot_outcome_comparison(counts_a, counts_b, 'qwen', 'opus-5.5', 7, 12, False,
                            'Model outcomes', out)
    assert out.stat().st_size > 0


def test_the_stacked_chart_renders(tmp_path):
    pytest.importorskip('matplotlib')
    from collections import Counter
    counts_a = {FAMILY_DIRECT_SUCCESS: Counter({'IDENTICAL': 5}),
               FAMILY_AGENT_VERIFIED: Counter({'AGENT_RESOLVED': 2})}
    counts_b = {FAMILY_DIRECT_SUCCESS: Counter({'IDENTICAL': 8}),
               FAMILY_AGENT_VERIFIED: Counter({'AGENT_RESOLVED': 4})}
    out = tmp_path / 'stacked.png'
    plot_stacked_comparison(counts_a, counts_b, 'qwen', 'opus-5.5', 7, 12, False,
                            'Model outcomes', out)
    assert out.stat().st_size > 0


def test_the_stacked_chart_renders_with_fresh_only_caption(tmp_path):
    pytest.importorskip('matplotlib')
    from collections import Counter
    counts_a = {FAMILY_DIRECT_SUCCESS: Counter({'IDENTICAL': 5})}
    counts_b = {FAMILY_DIRECT_SUCCESS: Counter({'IDENTICAL': 8})}
    out = tmp_path / 'stacked_fresh.png'
    plot_stacked_comparison(counts_a, counts_b, 'qwen', 'opus-5.5', 5, 8, True,
                            None, out)
    assert out.stat().st_size > 0


def test_the_stacked_chart_assigns_each_model_its_own_row_and_total(tmp_path, monkeypatch):
    # Regression test: a row/label mix-up used to draw model B's bar at the
    # position labeled with model A's name (and vice versa). Capture the
    # bars matplotlib actually draws before the function closes its figure.
    pytest.importorskip('matplotlib')
    from collections import Counter

    import matplotlib.pyplot as plt

    captured = {}
    real_close = plt.close

    def spy_close(fig=None):
        axes = plt.gcf().axes
        if axes:
            captured['yticklabels'] = [t.get_text() for t in axes[0].get_yticklabels()]
            captured['bars'] = list(axes[0].patches)
        real_close(fig)

    monkeypatch.setattr(plt, 'close', spy_close)

    counts_a = {FAMILY_DIRECT_SUCCESS: Counter({'IDENTICAL': 5})}
    counts_b = {FAMILY_DIRECT_SUCCESS: Counter({'IDENTICAL': 8})}
    plot_stacked_comparison(counts_a, counts_b, 'qwen', 'opus-5.5', 5, 8, False, None,
                            tmp_path / 'rows.png')

    labels = captured['yticklabels']
    assert any('qwen' in label and '(n=5)' in label for label in labels)
    assert any('opus-5.5' in label and '(n=8)' in label for label in labels)
    widths_by_y: dict[int, float] = {}
    for bar in captured['bars']:
        y = round(bar.get_y() + bar.get_height() / 2)
        widths_by_y[y] = widths_by_y.get(y, 0) + bar.get_width()
    assert set(widths_by_y.values()) == {5, 8}
