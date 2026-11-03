#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the pure-data layer of tools/plot_model_judge_comparison.py.

Does not import matplotlib at module level; the one render test is skipped
when it is not installed (see AGENTS.md "Minimize Dependencies").
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))

from plot_model_judge_comparison import (  # noqa: E402
    AGENT_RESOLVED_UNJUDGED,
    FAILED_TO_GENERATE,
    GROUP_COLORS,
    GROUP_DIVERGENT,
    GROUP_EQUIVALENT,
    GROUP_FAILED,
    GROUP_NOT_COMPARABLE,
    GROUP_OTHER,
    GROUP_UNJUDGED,
    OUTCOME_A_BETTER,
    OUTCOME_B_BETTER,
    OUTCOME_TIE,
    OUTCOME_UNRANKED,
    VERDICTS,
    combine_judges,
    compare_models,
    group_totals,
    majority_verdict,
    parse_judge_arg,
    plot_comparison,
    plot_majority_comparison,
    print_majority_summary,
    print_summary,
    rank_of,
    read_judge_csv,
    read_review_rows,
    verdict_counts,
    verdicts_present,
)


def write_results_csv(path, rows):
    header = 'cve_id,recipe,status'
    lines = [header] + [f'{cve_id},recipe,{status}' for cve_id, status in rows]
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def write_judge_csv(path, rows):
    header = 'cve_id,recipe,status,bucket,diff_lines,judgment,reason,judge_model,judge_credits,scope'
    lines = [header] + [
        f'{cve_id},recipe,SECURITY_REVIEW_REQUIRED,minor,1,{judgment},reason,m,1,full'
        for cve_id, judgment in rows]
    path.write_text('\n'.join(lines) + '\n', encoding='utf-8')


class TestRankOf:
    def test_identical_ranks_best(self):
        assert rank_of('identical') == 0

    def test_equivalent_verdicts_share_a_rank(self):
        assert rank_of('stylistic') == rank_of('comment-only') == rank_of('structural-only')

    def test_meaningful_ranks_worse_than_equivalent(self):
        assert rank_of('meaningful') > rank_of('stylistic')

    def test_no_patch_ranks_worst(self):
        assert rank_of('no-patch') > rank_of('meaningful')

    def test_unknown_verdict_ranks_worst(self):
        assert rank_of('pending') == rank_of('no-patch')


class TestReadReviewRows:
    def test_keeps_only_review_required_statuses(self, tmp_path):
        path = tmp_path
        write_results_csv(path / 'results_full.csv', [
            ('CVE-1', 'SECURITY_REVIEW_REQUIRED'),
            ('CVE-2', 'WORKFLOW_COMPLETED_UNVERIFIED'),
            ('CVE-3', 'SUCCESS'),
            ('CVE-4', 'IDENTICAL'),
        ])
        assert read_review_rows(path) == {'CVE-1', 'CVE-2'}

    def test_missing_file_raises_system_exit(self, tmp_path):
        with pytest.raises(SystemExit, match='does not exist'):
            read_review_rows(tmp_path)

    def test_missing_columns_raises_system_exit(self, tmp_path):
        (tmp_path / 'results_full.csv').write_text('a,b\n1,2\n', encoding='utf-8')
        with pytest.raises(SystemExit, match='no status/cve_id columns'):
            read_review_rows(tmp_path)


class TestReadJudgeCsv:
    def test_reads_cve_id_to_judgment(self, tmp_path):
        path = tmp_path / 'judge_results.csv'
        write_judge_csv(path, [('CVE-1', 'identical'), ('CVE-2', 'meaningful')])
        assert read_judge_csv(path) == {'CVE-1': 'identical', 'CVE-2': 'meaningful'}

    def test_missing_file_raises_system_exit(self, tmp_path):
        with pytest.raises(SystemExit, match='does not exist'):
            read_judge_csv(tmp_path / 'nope.csv')


class TestParseJudgeArg:
    def test_parses_model_equals_path(self):
        assert parse_judge_arg('qwen=some/dir') == ('qwen', Path('some/dir'))

    def test_missing_equals_raises_system_exit(self):
        with pytest.raises(SystemExit, match='not model=path'):
            parse_judge_arg('qwen')

    def test_missing_name_raises_system_exit(self):
        with pytest.raises(SystemExit, match='no model name'):
            parse_judge_arg('=some/dir')


class TestCompareModels:
    def test_model_a_wins_when_its_rank_is_better(self):
        result = compare_models({'CVE-1'}, {'CVE-1'}, {'CVE-1': 'identical'}, {'CVE-1': 'meaningful'})
        assert result['CVE-1']['outcome'] == OUTCOME_A_BETTER

    def test_model_b_wins_when_its_rank_is_better(self):
        result = compare_models({'CVE-1'}, {'CVE-1'}, {'CVE-1': 'meaningful'}, {'CVE-1': 'identical'})
        assert result['CVE-1']['outcome'] == OUTCOME_B_BETTER

    def test_same_rank_is_a_tie_even_with_different_verdict(self):
        # stylistic and comment-only are both rank 1 ("equivalent to the reference")
        result = compare_models({'CVE-1'}, {'CVE-1'}, {'CVE-1': 'stylistic'},
                                 {'CVE-1': 'comment-only'})
        assert result['CVE-1']['outcome'] == OUTCOME_TIE

    def test_only_cves_both_models_left_review_required_are_compared(self):
        result = compare_models({'CVE-1', 'CVE-2'}, {'CVE-1'}, {'CVE-1': 'identical',
                                 'CVE-2': 'identical'}, {'CVE-1': 'identical'})
        assert set(result) == {'CVE-1'}

    def test_cves_the_judge_did_not_rate_for_either_model_are_skipped(self):
        result = compare_models({'CVE-1'}, {'CVE-1'}, {}, {'CVE-1': 'identical'})
        assert result == {}

    def test_preserves_judgment_strings_alongside_the_outcome(self):
        result = compare_models({'CVE-1'}, {'CVE-1'}, {'CVE-1': 'identical'},
                                 {'CVE-1': 'meaningful'})
        assert result['CVE-1']['judgment_a'] == 'identical'
        assert result['CVE-1']['judgment_b'] == 'meaningful'

    def test_without_statuses_a_cve_only_one_model_reviewed_is_left_out(self):
        result = compare_models({'CVE-1'}, set(), {'CVE-1': 'meaningful'}, {})
        assert result == {}

    def test_a_failed_side_is_failed_to_generate_and_loses(self):
        result = compare_models(set(), {'CVE-1'}, {}, {'CVE-1': 'meaningful'},
                                 {'CVE-1': 'FAIL_AGENT_NO_PROGRESS'},
                                 {'CVE-1': 'SECURITY_REVIEW_REQUIRED'})
        assert result['CVE-1']['judgment_a'] == FAILED_TO_GENERATE
        assert result['CVE-1']['outcome'] == OUTCOME_B_BETTER

    def test_failed_to_generate_ties_with_no_patch(self):
        result = compare_models({'CVE-1'}, set(), {'CVE-1': 'no-patch'}, {},
                                 {'CVE-1': 'SECURITY_REVIEW_REQUIRED'},
                                 {'CVE-1': 'FAIL_WORKFLOW_FAILED'})
        assert result['CVE-1']['outcome'] == OUTCOME_TIE

    def test_an_agent_resolved_side_is_shown_but_not_ranked(self):
        result = compare_models({'CVE-1'}, set(), {'CVE-1': 'stylistic'}, {},
                                 {'CVE-1': 'SECURITY_REVIEW_REQUIRED'},
                                 {'CVE-1': 'AGENT_RESOLVED'})
        assert result['CVE-1']['judgment_b'] == AGENT_RESOLVED_UNJUDGED
        assert result['CVE-1']['outcome'] == OUTCOME_UNRANKED

    def test_a_judged_agent_resolved_side_uses_the_verdict_and_is_ranked(self):
        result = compare_models({'CVE-1'}, set(), {'CVE-1': 'meaningful'},
                                 {'CVE-1': 'identical'},
                                 {'CVE-1': 'SECURITY_REVIEW_REQUIRED'},
                                 {'CVE-1': 'AGENT_RESOLVED'})
        assert result['CVE-1']['judgment_b'] == 'identical'
        assert result['CVE-1']['outcome'] == OUTCOME_B_BETTER

    def test_a_side_with_nothing_comparable_drops_the_cve(self):
        # e.g. the other model skipped it or it resolved without the agent
        result = compare_models({'CVE-1'}, set(), {'CVE-1': 'stylistic'}, {},
                                 {'CVE-1': 'SECURITY_REVIEW_REQUIRED'},
                                 {'CVE-1': 'SKIP_NOT_APPLICABLE'})
        assert result == {}


def test_every_verdict_group_has_a_colour():
    groups = {group for group, _label in VERDICTS.values()}
    assert groups <= {GROUP_EQUIVALENT, GROUP_DIVERGENT, GROUP_NOT_COMPARABLE, GROUP_FAILED,
                      GROUP_UNJUDGED}
    assert groups <= set(GROUP_COLORS)
    assert GROUP_OTHER in GROUP_COLORS


def test_print_majority_summary_keeps_unranked_rows_out_of_win_tie_loss(capsys):
    combined = {
        'CVE-1': {'judgment_a': 'stylistic', 'judgment_b': AGENT_RESOLVED_UNJUDGED,
                  'n_judges': 3},
        'CVE-2': {'judgment_a': FAILED_TO_GENERATE, 'judgment_b': 'identical', 'n_judges': 3},
    }
    print_majority_summary(combined, 'qwen', 'opus')
    out = capsys.readouterr().out
    assert 'opus closer to reference:    1' in out
    assert 'not ranked' in out


class TestGroupTotals:
    def test_sums_verdicts_into_their_color_group(self):
        totals = group_totals({'identical': 2, 'stylistic': 3, 'meaningful': 1,
                               FAILED_TO_GENERATE: 4})
        assert totals == {GROUP_EQUIVALENT: 5, GROUP_DIVERGENT: 1, GROUP_FAILED: 4}

    def test_unknown_verdict_counts_as_other(self):
        assert group_totals({'pending': 2}) == {GROUP_OTHER: 2}


class TestVerdictCounts:
    def test_counts_each_verdict(self):
        assert verdict_counts(['identical', 'identical', 'meaningful']) == {
            'identical': 2, 'meaningful': 1}

    def test_empty_input_is_an_empty_dict(self):
        assert verdict_counts([]) == {}


def test_print_summary_reports_cross_judge_disagreement(capsys):
    per_judge = {
        'judge-x': {'CVE-1': {'judgment_a': 'identical', 'judgment_b': 'meaningful',
                               'outcome': OUTCOME_A_BETTER}},
        'judge-y': {'CVE-1': {'judgment_a': 'meaningful', 'judgment_b': 'identical',
                               'outcome': OUTCOME_B_BETTER}},
    }
    print_summary(per_judge, 'qwen', 'opus')
    out = capsys.readouterr().out
    assert 'CVE-1' in out
    assert 'judge-x=qwen closer to reference' in out
    assert 'judge-y=opus closer to reference' in out


def test_the_chart_renders(tmp_path):
    pytest.importorskip('matplotlib')
    per_judge = {
        'judge-x': {
            'CVE-1': {'judgment_a': 'identical', 'judgment_b': 'meaningful',
                      'outcome': OUTCOME_A_BETTER},
            'CVE-2': {'judgment_a': 'stylistic', 'judgment_b': 'comment-only',
                      'outcome': OUTCOME_TIE},
            'CVE-3': {'judgment_a': 'meaningful', 'judgment_b': 'identical',
                      'outcome': OUTCOME_B_BETTER},
        },
    }
    out = tmp_path / 'comparison.png'
    plot_comparison(per_judge, 'qwen', 'opus-5.5', 'Model comparison', out)
    assert out.stat().st_size > 0


class TestMajorityVerdict:
    def test_a_single_verdict_is_its_own_majority(self):
        assert majority_verdict(['identical']) == 'identical'

    def test_two_of_three_wins(self):
        assert majority_verdict(['stylistic', 'stylistic', 'meaningful']) == 'stylistic'

    def test_unanimous_verdict_wins(self):
        assert majority_verdict(['meaningful', 'meaningful', 'meaningful']) == 'meaningful'

    def test_a_two_way_split_picks_the_worst_ranked_of_the_tied_verdicts(self):
        # identical (rank 0) and meaningful (rank 2) tie 1-1; meaningful is worse
        assert majority_verdict(['identical', 'meaningful']) == 'meaningful'

    def test_a_three_way_split_with_no_majority_picks_the_worst_ranked(self):
        # identical, stylistic, meaningful all tie 1-1-1; meaningful ranks worst
        assert majority_verdict(['identical', 'stylistic', 'meaningful']) == 'meaningful'

    def test_empty_input_raises_value_error(self):
        with pytest.raises(ValueError, match='at least one verdict'):
            majority_verdict([])


class TestCombineJudges:
    def test_majority_per_cve_across_judges(self):
        per_judge = {
            'judge-x': {'CVE-1': {'judgment_a': 'identical', 'judgment_b': 'meaningful'}},
            'judge-y': {'CVE-1': {'judgment_a': 'identical', 'judgment_b': 'meaningful'}},
            'judge-z': {'CVE-1': {'judgment_a': 'stylistic', 'judgment_b': 'identical'}},
        }
        combined = combine_judges(per_judge)
        assert combined['CVE-1']['judgment_a'] == 'identical'
        assert combined['CVE-1']['judgment_b'] == 'meaningful'
        assert combined['CVE-1']['n_judges'] == 3

    def test_a_cve_only_some_judges_rated_still_gets_a_majority(self):
        per_judge = {
            'judge-x': {'CVE-1': {'judgment_a': 'identical', 'judgment_b': 'identical'}},
            'judge-y': {},
        }
        combined = combine_judges(per_judge)
        assert combined['CVE-1']['n_judges'] == 1

    def test_a_cve_no_judge_rated_is_absent(self):
        per_judge = {'judge-x': {}, 'judge-y': {}}
        assert combine_judges(per_judge) == {}


def test_print_majority_summary_reports_win_tie_loss(capsys):
    combined = {
        'CVE-1': {'judgment_a': 'identical', 'judgment_b': 'meaningful', 'n_judges': 3},
        'CVE-2': {'judgment_a': 'stylistic', 'judgment_b': 'comment-only', 'n_judges': 3},
    }
    print_majority_summary(combined, 'qwen', 'opus')
    out = capsys.readouterr().out
    assert 'qwen closer to reference' in out
    assert 'tie' in out
    assert '(n=2)' in out


def test_the_majority_chart_renders(tmp_path):
    pytest.importorskip('matplotlib')
    combined = {
        'CVE-1': {'judgment_a': 'identical', 'judgment_b': 'meaningful', 'n_judges': 3},
        'CVE-2': {'judgment_a': 'stylistic', 'judgment_b': 'comment-only', 'n_judges': 3},
        'CVE-3': {'judgment_a': 'meaningful', 'judgment_b': 'identical', 'n_judges': 3},
    }
    out = tmp_path / 'majority.png'
    plot_majority_comparison(combined, 'qwen', 'opus-5.5', 3, 'Model comparison', out)
    assert out.stat().st_size > 0


class TestVerdictsPresent:
    def test_known_verdicts_in_fixed_display_order(self):
        counts = {'meaningful': 1, 'identical': 2}
        assert verdicts_present(counts) == ['identical', 'meaningful']

    def test_a_verdict_present_in_only_one_dict_is_included(self):
        assert verdicts_present({'identical': 1}, {'meaningful': 1}) == [
            'identical', 'meaningful']

    def test_a_verdict_present_in_both_dicts_is_listed_only_once(self):
        # Regression test: a set-operator precedence bug used to list a
        # verdict both dicts had a nonzero count for twice.
        assert verdicts_present({'identical': 1}, {'identical': 1}) == ['identical']

    def test_a_zero_count_does_not_count_as_present(self):
        assert verdicts_present({'identical': 0, 'meaningful': 1}) == ['meaningful']

    def test_unknown_verdicts_follow_known_ones_sorted(self):
        assert verdicts_present({'identical': 1, 'zzz-unknown': 1, 'aaa-unknown': 1}) == [
            'identical', 'aaa-unknown', 'zzz-unknown']


def test_the_majority_chart_renders_with_no_duplicate_categories(tmp_path):
    pytest.importorskip('matplotlib')
    combined = {
        'CVE-1': {'judgment_a': 'identical', 'judgment_b': 'meaningful', 'n_judges': 3},
        'CVE-2': {'judgment_a': 'stylistic', 'judgment_b': 'comment-only', 'n_judges': 3},
    }
    out = tmp_path / 'dedup.png'
    plot_majority_comparison(combined, 'qwen', 'opus-5.5', 3, 'Model comparison', out)
    assert out.stat().st_size > 0


def test_the_detailed_majority_chart_renders(tmp_path):
    pytest.importorskip('matplotlib')
    combined = {
        'CVE-1': {'judgment_a': 'identical', 'judgment_b': 'meaningful', 'n_judges': 3},
        'CVE-2': {'judgment_a': FAILED_TO_GENERATE, 'judgment_b': 'comment-only', 'n_judges': 3},
    }
    out = tmp_path / 'detailed.png'
    plot_majority_comparison(combined, 'qwen', 'opus-5.5', 3, None, out, by_group=False)
    assert out.stat().st_size > 0


class TestResolvedAndInherited:
    def test_a_cve_both_models_resolved_and_the_judge_rated_is_compared(self):
        result = compare_models(set(), set(), {'CVE-1': 'identical'}, {'CVE-1': 'meaningful'},
                                 {'CVE-1': 'AGENT_RESOLVED'}, {'CVE-1': 'AGENT_RESOLVED'})
        assert result['CVE-1']['outcome'] == OUTCOME_A_BETTER

    def test_an_unjudged_resolved_cve_on_both_sides_is_left_out(self):
        result = compare_models(set(), set(), {}, {},
                                 {'CVE-1': 'AGENT_RESOLVED'}, {'CVE-1': 'AGENT_RESOLVED'})
        assert result == {}

    def test_excluded_cves_are_left_out(self):
        result = compare_models({'CVE-1'}, {'CVE-1'}, {'CVE-1': 'identical'},
                                 {'CVE-1': 'identical'},
                                 {'CVE-1': 'SECURITY_REVIEW_REQUIRED'},
                                 {'CVE-1': 'SECURITY_REVIEW_REQUIRED'}, exclude={'CVE-1'})
        assert result == {}

    def test_find_inherited_needs_same_status_and_identical_patch(self, tmp_path):
        from plot_model_judge_comparison import find_inherited
        a, b = tmp_path / 'a', tmp_path / 'b'
        for cve, pa, pb in (('CVE-1', 'x', 'x'), ('CVE-2', 'x', 'y'), ('CVE-3', 'x', 'x')):
            for root, body in ((a, pa), (b, pb)):
                art = root / f'{cve}_full_artifacts'
                art.mkdir(parents=True)
                (art / 'final-commits.patch').write_text(body, encoding='utf-8')
        statuses_a = {'CVE-1': 'AGENT_RESOLVED', 'CVE-2': 'AGENT_RESOLVED',
                      'CVE-3': 'AGENT_RESOLVED'}
        statuses_b = {'CVE-1': 'AGENT_RESOLVED', 'CVE-2': 'AGENT_RESOLVED',
                      'CVE-3': 'SECURITY_REVIEW_REQUIRED'}
        assert find_inherited(a, b, statuses_a, statuses_b) == {'CVE-1'}


def test_the_majority_legend_lists_model_b_first_matching_the_bars(tmp_path, monkeypatch):
    pytest.importorskip('matplotlib')
    import matplotlib.pyplot as plt
    closed = []
    monkeypatch.setattr(plt, 'close', lambda fig=None: closed.append(fig))
    combined = {'CVE-1': {'judgment_a': 'identical', 'judgment_b': 'meaningful', 'n_judges': 3}}
    plot_majority_comparison(combined, 'qwen', 'opus-5.5', 3, 'Model comparison',
                             tmp_path / 'm.png')
    legend = closed[-1].axes[0].get_legend()
    assert [t.get_text() for t in legend.get_texts()] == ['opus-5.5', 'qwen']


def test_attempted_keeps_an_identical_patch_cve_as_a_tie(tmp_path, monkeypatch, capsys):
    import plot_model_judge_comparison as mod
    a, b = tmp_path / 'a', tmp_path / 'b'
    for root in (a, b):
        root.mkdir()
        write_results_csv(root / 'results_full.csv', [('CVE-1', 'SECURITY_REVIEW_REQUIRED')])
        art = root / 'CVE-1_full_artifacts'
        art.mkdir()
        (art / 'final-commits.patch').write_text('same', encoding='utf-8')
        write_judge_csv(root / 'judge.csv', [('CVE-1', 'identical')])
    attempted = tmp_path / 'attempted.txt'
    attempted.write_text('CVE-1\n', encoding='utf-8')
    base = ['prog', '--model-a', f'qwen={a}', '--model-b', f'opus={b}',
            '--judge', f'j={a / "judge.csv"},{b / "judge.csv"}', '--no-plot']

    monkeypatch.setattr(sys, 'argv', base)
    with pytest.raises(SystemExit):  # the only CVE is inherited, so nothing is left
        mod.main()
    capsys.readouterr()

    monkeypatch.setattr(sys, 'argv', base + ['--attempted', str(attempted)])
    mod.main()
    out = capsys.readouterr().out
    assert 'Leaving out' not in out
    assert 'n=1' in out
