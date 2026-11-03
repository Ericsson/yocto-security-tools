#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the pure-data layer of tools/plot_judge_agreement.py.

Does not import matplotlib at module level; the one render test is skipped
when it is not installed (see AGENTS.md "Minimize Dependencies").
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))

from plot_judge_agreement import (  # noqa: E402
    CAT_COLORS,
    CAT_CONSENSUS,
    CAT_DISAGREE,
    CAT_SAME_GROUP,
    classify,
    compare,
    parse_sources,
    plot_agreement,
    print_summary,
    read_judge_csv,
)


def write_csv(path, rows):
    header = 'cve_id,recipe,status,bucket,diff_lines,judgment,reason,judge_model,judge_credits,scope'
    lines = [header]
    for cve_id, judgment in rows:
        lines.append(f'{cve_id},recipe,SECURITY_REVIEW_REQUIRED,minor,1,{judgment},reason,m,1,full')
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


class TestReadJudgeCsv:
    def test_reads_cve_id_to_judgment(self, tmp_path):
        path = tmp_path / 'judge_results.csv'
        write_csv(path, [('CVE-1', 'identical'), ('CVE-2', 'meaningful')])
        assert read_judge_csv(path) == {'CVE-1': 'identical', 'CVE-2': 'meaningful'}

    def test_missing_file_raises_system_exit(self, tmp_path):
        with pytest.raises(SystemExit, match='does not exist'):
            read_judge_csv(tmp_path / 'nope.csv')

    def test_missing_columns_raises_system_exit(self, tmp_path):
        path = tmp_path / 'judge_results.csv'
        path.write_text('cve_id,verdict\nCVE-1,identical\n', encoding='utf-8')
        with pytest.raises(SystemExit, match='no cve_id/judgment columns'):
            read_judge_csv(path)

    def test_rows_with_empty_judgment_are_skipped(self, tmp_path):
        path = tmp_path / 'judge_results.csv'
        write_csv(path, [('CVE-1', 'identical')])
        path.write_text(path.read_text(encoding='utf-8') + 'CVE-2,recipe,SECURITY_REVIEW_REQUIRED,'
                        'moderate,10,,pending,,,\n', encoding='utf-8')
        assert read_judge_csv(path) == {'CVE-1': 'identical'}


class TestParseSources:
    def test_parses_model_equals_path_pairs(self):
        sources = parse_sources(['opus=a.csv', 'sonnet=b.csv'])
        assert sources == [('opus', Path('a.csv')), ('sonnet', Path('b.csv'))]

    def test_fewer_than_two_sources_raises_system_exit(self):
        with pytest.raises(SystemExit, match='at least two'):
            parse_sources(['opus=a.csv'])

    def test_missing_equals_sign_raises_system_exit(self):
        with pytest.raises(SystemExit, match='not model=path'):
            parse_sources(['opus=a.csv', 'b.csv'])

    def test_missing_model_name_raises_system_exit(self):
        with pytest.raises(SystemExit, match='no model name'):
            parse_sources(['opus=a.csv', '=b.csv'])


class TestClassify:
    def test_identical_verdicts_are_full_consensus(self):
        assert classify(['identical', 'identical', 'identical']) == CAT_CONSENSUS

    def test_same_group_different_verdict_is_same_group(self):
        # stylistic and comment-only are both "equivalent to the reference"
        assert classify(['stylistic', 'comment-only']) == CAT_SAME_GROUP

    def test_different_groups_is_disagreement(self):
        assert classify(['stylistic', 'meaningful']) == CAT_DISAGREE

    def test_three_way_split_is_disagreement(self):
        assert classify(['identical', 'meaningful', 'no-patch']) == CAT_DISAGREE

    def test_unknown_verdict_is_its_own_group(self):
        # 'pending' is not in VERDICT_GROUP; two 'pending' judges still agree
        assert classify(['pending', 'pending']) == CAT_CONSENSUS
        assert classify(['pending', 'identical']) == CAT_DISAGREE


class TestCompare:
    def test_keeps_only_cves_every_source_judged_by_default(self, tmp_path):
        a = tmp_path / 'a.csv'
        b = tmp_path / 'b.csv'
        write_csv(a, [('CVE-1', 'identical'), ('CVE-2', 'meaningful')])
        write_csv(b, [('CVE-1', 'identical')])
        result = compare([('A', a), ('B', b)])
        assert set(result) == {'CVE-1'}

    def test_allow_partial_keeps_cves_at_least_two_sources_judged(self, tmp_path):
        a = tmp_path / 'a.csv'
        b = tmp_path / 'b.csv'
        c = tmp_path / 'c.csv'
        write_csv(a, [('CVE-1', 'identical'), ('CVE-2', 'meaningful')])
        write_csv(b, [('CVE-1', 'identical')])
        write_csv(c, [('CVE-1', 'identical')])
        result = compare([('A', a), ('B', b), ('C', c)], require_all=False)
        assert set(result) == {'CVE-1'}

    def test_categorizes_each_shared_cve(self, tmp_path):
        a = tmp_path / 'a.csv'
        b = tmp_path / 'b.csv'
        write_csv(a, [('CVE-1', 'identical'), ('CVE-2', 'stylistic'), ('CVE-3', 'meaningful')])
        write_csv(b, [('CVE-1', 'identical'), ('CVE-2', 'comment-only'), ('CVE-3', 'stylistic')])
        result = compare([('A', a), ('B', b)])
        assert result['CVE-1']['category'] == CAT_CONSENSUS
        assert result['CVE-2']['category'] == CAT_SAME_GROUP
        assert result['CVE-3']['category'] == CAT_DISAGREE
        assert result['CVE-3']['verdicts'] == {'A': 'meaningful', 'B': 'stylistic'}


def test_every_category_has_a_colour():
    assert {CAT_CONSENSUS, CAT_SAME_GROUP, CAT_DISAGREE} <= set(CAT_COLORS)


def test_print_summary_lists_disagreements(capsys):
    comparison = {
        'CVE-1': {'verdicts': {'A': 'identical', 'B': 'identical'}, 'category': CAT_CONSENSUS},
        'CVE-2': {'verdicts': {'A': 'stylistic', 'B': 'meaningful'}, 'category': CAT_DISAGREE},
    }
    print_summary(comparison, ['A', 'B'])
    out = capsys.readouterr().out
    assert 'CVE-2' in out
    assert 'A=stylistic' in out
    assert 'B=meaningful' in out


def test_the_chart_renders(tmp_path):
    pytest.importorskip('matplotlib')
    comparison = {
        'CVE-1': {'verdicts': {'A': 'identical', 'B': 'identical'}, 'category': CAT_CONSENSUS},
        'CVE-2': {'verdicts': {'A': 'stylistic', 'B': 'comment-only'}, 'category': CAT_SAME_GROUP},
        'CVE-3': {'verdicts': {'A': 'stylistic', 'B': 'meaningful'}, 'category': CAT_DISAGREE},
    }
    out = tmp_path / 'agreement.png'
    plot_agreement(comparison, ['A', 'B'], 'Judge agreement', out)
    assert out.stat().st_size > 0
