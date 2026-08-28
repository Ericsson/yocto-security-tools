# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for tests.benchmark.bench_lib."""
from unittest.mock import MagicMock, patch

import pytest

from tests.benchmark.bench_lib import (
    MEDIUM_DIFF_LINES_THRESHOLD,
    MINOR_DIFF_LINES_THRESHOLD,
    MODELS,
    classify_diff_bucket,
    count_conflict_markers,
    count_tool_calls,
    filter_for_judging,
    is_agent_env_failure,
    is_mirror_gap_only,
    judge_diff,
    observed_avg_credits,
    ordered_roster_cases,
    project_remaining_cost,
    relative_cost_weight,
    resolve_models,
    score_tier,
    select_cases,
    total_spent,
)


class TestScoreTier:
    def test_nonzero_exit_is_hard(self):
        assert score_tier(1, 0, 1) == 'hard'
        assert score_tier(4, 5, 1) == 'hard'

    def test_clean_small_single_commit_is_easy(self):
        assert score_tier(0, MEDIUM_DIFF_LINES_THRESHOLD, 1) == 'easy'
        assert score_tier(0, 0, 1) == 'easy'

    def test_clean_large_diff_is_medium(self):
        assert score_tier(0, MEDIUM_DIFF_LINES_THRESHOLD + 1, 1) == 'medium'

    def test_clean_series_is_medium(self):
        assert score_tier(0, 0, 2) == 'medium'

    def test_clean_large_diff_and_series_is_medium(self):
        assert score_tier(0, 500, 5) == 'medium'


class TestIsMirrorGapOnly:
    def test_pure_mirror_gap_bad_object(self):
        # Real snippet shape from CVE-2024-3596's tier probe log: every
        # cherry-pick candidate hash is missing from the local mirror.
        log_text = (
            "[27/28] Skipping 7d41c6ea (bad object)\n"
            "[28/28] Skipping 7af62285 (bad object)\n"
            "All cherry-picks failed, finding commit with least conflicts\n"
            "Failed to apply any fix\n"
            "Conflict detected\n"
        )
        assert is_mirror_gap_only(log_text) is True

    def test_pure_mirror_gap_unknown_revision(self):
        # Real snippet shape from CVE-2025-0684: git diff on a missing hash.
        log_text = (
            "git diff failed for 47b2dfc7: fatal: ambiguous argument "
            "'47b2dfc7953f70f98ddf35dfdd6e7f4f20283b10~1': unknown revision "
            "or path not in the working tree.\n"
            "All cherry-picks failed, finding commit with least conflicts\n"
            "Failed to apply any fix\n"
        )
        assert is_mirror_gap_only(log_text) is True

    def test_genuine_content_conflict_is_not_mirror_gap(self):
        log_text = (
            "Running: git cherry-pick abc123\n"
            "CONFLICT (content): Merge conflict in grub-core/kern/main.c\n"
            "error: could not apply abc123\n"
        )
        assert is_mirror_gap_only(log_text) is False

    def test_content_conflict_alongside_bad_object_is_not_mirror_gap(self):
        # A run can hit a stale hash for one commit in a series but still
        # have a genuine content clash on another -- that's real difficulty
        # signal, not purely an infrastructure gap.
        log_text = (
            "[2/5] Skipping 836aeb93 (bad object)\n"
            "CONFLICT (content): Merge conflict in foo.c\n"
        )
        assert is_mirror_gap_only(log_text) is False

    def test_neither_marker_present_is_not_mirror_gap(self):
        log_text = "Some other unrelated failure occurred.\n"
        assert is_mirror_gap_only(log_text) is False

    def test_empty_log_is_not_mirror_gap(self):
        assert is_mirror_gap_only('') is False


class TestCountConflictMarkers:
    def test_counts_multiple_markers(self):
        log_text = (
            "CONFLICT (content): Merge conflict in a.c\n"
            "CONFLICT (content): Merge conflict in b.c\n"
            "CONFLICT (content): Merge conflict in a.c\n"
        )
        assert count_conflict_markers(log_text) == 3

    def test_no_markers_is_zero(self):
        assert count_conflict_markers("clean run, no conflicts\n") == 0

    def test_empty_log_is_zero(self):
        assert count_conflict_markers('') == 0


class TestIsAgentEnvFailure:
    def test_kiro_cli_not_found_on_path(self):
        # cve_agent/setup.py ensure_agents() when kiro-cli is missing.
        log_text = (
            "Error: kiro-cli not found on PATH.\n"
            "Install it from: https://kiro.dev/docs/install\n"
        )
        assert is_agent_env_failure(log_text) is True

    def test_kiro_cli_not_found_at_session_start(self):
        # cve_agent/kiro_backend.py run_session()'s FileNotFoundError branch.
        log_text = "kiro-cli not found. Install it or add to PATH.\n"
        assert is_agent_env_failure(log_text) is True

    def test_backend_prerequisites_not_met(self):
        # cve_agent/__main__.py non-kiro backend availability check.
        log_text = (
            "Error: backend 'claude' prerequisites not met — "
            "is the required CLI installed and on PATH?\n"
        )
        assert is_agent_env_failure(log_text) is True

    def test_failed_to_install_agents(self):
        log_text = "Error: Failed to install agents.\n"
        assert is_agent_env_failure(log_text) is True

    def test_failed_to_refresh_installed_agents(self):
        log_text = "Error: Failed to refresh installed agents.\n"
        assert is_agent_env_failure(log_text) is True

    def test_case_insensitive(self):
        assert is_agent_env_failure("KIRO-CLI NOT FOUND on path") is True

    def test_genuine_conflict_is_not_env_failure(self):
        # A real per-CVE conflict must NOT be mistaken for an env failure,
        # otherwise the benchmark would abort on the first hard CVE.
        log_text = (
            "CONFLICT (content): Merge conflict in src/foo.c\n"
            "Conflict detected\n"
        )
        assert is_agent_env_failure(log_text) is False

    def test_empty_log_is_not_env_failure(self):
        assert is_agent_env_failure('') is False


# A roster shaped like benchmark-roster.json: unordered keys, a _comment
# meta key, and the same easy/medium/hard tiers the shell iterates.
_ROSTER = {
    "_comment": "meta, must be ignored",
    "CVE-2025-1153": {"tier": "hard", "recipe": "binutils"},
    "CVE-2025-4373": {"tier": "easy", "recipe": "glib-2.0"},
    "CVE-2024-32487": {"tier": "hard", "recipe": "less"},
    "CVE-2026-0990": {"tier": "medium", "recipe": "libxml2"},
    "CVE-2024-6345": {"tier": "hard", "recipe": "python3-setuptools"},
}


class TestOrderedRosterCases:
    def test_order_is_tier_then_alpha_and_comment_ignored(self):
        cases = ordered_roster_cases(_ROSTER)
        assert [(c["case"], c["cve_id"]) for c in cases] == [
            (1, "CVE-2025-4373"),   # easy
            (2, "CVE-2026-0990"),   # medium
            (3, "CVE-2024-32487"),  # hard, alphabetical
            (4, "CVE-2024-6345"),
            (5, "CVE-2025-1153"),
        ]

    def test_entries_carry_tier_and_recipe(self):
        first = ordered_roster_cases(_ROSTER)[0]
        assert first == {"case": 1, "cve_id": "CVE-2025-4373",
                         "tier": "easy", "recipe": "glib-2.0"}

    def test_unknown_tier_appended_last_not_dropped(self):
        roster = dict(_ROSTER)
        roster["CVE-2030-0001"] = {"tier": "weird", "recipe": "z-recipe"}
        cases = ordered_roster_cases(roster)
        # nothing dropped, and the unknown tier lands after the known ones
        assert len(cases) == 6
        assert cases[-1]["cve_id"] == "CVE-2030-0001"

    def test_numbering_is_contiguous_from_one(self):
        cases = ordered_roster_cases(_ROSTER)
        assert [c["case"] for c in cases] == list(range(1, len(cases) + 1))


class TestSelectCases:
    def test_selects_in_canonical_order_regardless_of_arg_order(self):
        cases = ordered_roster_cases(_ROSTER)
        sel = select_cases(cases, [3, 1])
        assert [c["cve_id"] for c in sel] == ["CVE-2025-4373", "CVE-2024-32487"]

    def test_deduplicates(self):
        cases = ordered_roster_cases(_ROSTER)
        sel = select_cases(cases, [2, 2, 2])
        assert [c["cve_id"] for c in sel] == ["CVE-2026-0990"]

    def test_empty_indices_raises(self):
        cases = ordered_roster_cases(_ROSTER)
        with pytest.raises(ValueError, match="No case numbers"):
            select_cases(cases, [])

    def test_out_of_range_low_raises(self):
        cases = ordered_roster_cases(_ROSTER)
        with pytest.raises(ValueError, match="out of range"):
            select_cases(cases, [0])

    def test_out_of_range_high_raises_and_lists_bad_values(self):
        cases = ordered_roster_cases(_ROSTER)  # len 5
        with pytest.raises(ValueError, match=r"6, 9"):
            select_cases(cases, [1, 6, 9])


class TestClassifyDiffBucket:
    def test_none_is_file_mismatch(self):
        assert classify_diff_bucket(None) == 'file-mismatch'

    def test_empty_string_is_file_mismatch(self):
        assert classify_diff_bucket('') == 'file-mismatch'

    def test_missing_in_generated_is_file_mismatch(self):
        text = "Missing in generated:\n  some/file.patch\n"
        assert classify_diff_bucket(text) == 'file-mismatch'

    def test_extra_in_generated_is_file_mismatch(self):
        text = "Extra in generated:\n  some/file.patch\n"
        assert classify_diff_bucket(text) == 'file-mismatch'

    def test_equivalent_is_identical(self):
        assert classify_diff_bucket('Patches are equivalent.\n') == 'identical'

    def test_at_minor_threshold_is_minor(self):
        text = f'Differences: {MINOR_DIFF_LINES_THRESHOLD} lines\n'
        assert classify_diff_bucket(text) == 'minor'

    def test_just_above_minor_threshold_is_moderate(self):
        text = f'Differences: {MINOR_DIFF_LINES_THRESHOLD + 1} lines\n'
        assert classify_diff_bucket(text) == 'moderate'

    def test_at_medium_threshold_is_moderate(self):
        text = f'Differences: {MEDIUM_DIFF_LINES_THRESHOLD} lines\n'
        assert classify_diff_bucket(text) == 'moderate'

    def test_just_above_medium_threshold_is_major(self):
        text = f'Differences: {MEDIUM_DIFF_LINES_THRESHOLD + 1} lines\n'
        assert classify_diff_bucket(text) == 'major'

    def test_no_differences_line_defaults_to_minor(self):
        # Text that isn't file-mismatch/identical and has no parseable
        # "Differences: N lines" line falls back to n=0, i.e. minor.
        assert classify_diff_bucket('some unrelated text\n') == 'minor'


class TestResolveModels:
    def test_default_returns_five(self):
        models = resolve_models('default')
        names = {m['name'] for m in models}
        assert names == {
            'claude-opus-5', 'claude-sonnet-5', 'claude-haiku-4.5',
            'minimax-m2.5', 'qwen3-coder-next',
        }
        assert all(m['tier'] == 'default' for m in models)

    def test_full_returns_all_models(self):
        models = resolve_models('full')
        assert len(models) == len(MODELS)
        assert {m['name'] for m in models} == set(MODELS.keys())

    def test_explicit_list(self):
        models = resolve_models('claude-sonnet-5,minimax-m2.5')
        names = {m['name'] for m in models}
        assert names == {'claude-sonnet-5', 'minimax-m2.5'}
        assert len(models) == 2

    def test_unknown_model_raises(self):
        with pytest.raises(ValueError, match='bogus-model'):
            resolve_models('bogus-model')

    def test_unknown_model_error_lists_valid_names(self):
        with pytest.raises(ValueError, match='claude-sonnet-5'):
            resolve_models('bogus-model')

    def test_each_entry_has_own_name(self):
        for model in resolve_models('default'):
            assert model['name'] in MODELS


class TestRelativeCostWeight:
    def test_arithmetic(self):
        models = resolve_models('claude-sonnet-5,minimax-m2.5')
        # 1.30 + 0.25 = 1.55, * 10 CVEs = 15.5
        assert relative_cost_weight(models, 10) == pytest.approx(15.5)

    def test_zero_cves(self):
        models = resolve_models('default')
        assert relative_cost_weight(models, 0) == 0.0

    def test_empty_models(self):
        assert relative_cost_weight([], 10) == 0.0


class TestObservedAvgCredits:
    def _write_csv(self, tmp_path, rows):
        path = tmp_path / "agent_results.csv"
        header = ("cve_id,tier,model,exit_status,credits,duration_s,"
                   "commands,diff_bucket,diff_lines")
        lines = [header] + rows
        path.write_text('\n'.join(lines) + '\n')
        return path

    def test_missing_file_returns_none(self, tmp_path):
        assert observed_avg_credits(tmp_path / "nope.csv") is None

    def test_empty_file_returns_none(self, tmp_path):
        path = tmp_path / "agent_results.csv"
        path.write_text("")
        assert observed_avg_credits(path) is None

    def test_no_valid_credits_returns_none(self, tmp_path):
        path = self._write_csv(tmp_path, [
            "CVE-1,easy,m,0,,10,3,small,5",
        ])
        assert observed_avg_credits(path) is None

    def test_mean_of_valid_rows(self, tmp_path):
        path = self._write_csv(tmp_path, [
            "CVE-1,easy,m,0,2.0,10,3,small,5",
            "CVE-2,medium,m,0,4.0,20,6,large,80",
        ])
        assert observed_avg_credits(path) == pytest.approx(3.0)

    def test_skips_rows_with_invalid_credits(self, tmp_path):
        path = self._write_csv(tmp_path, [
            "CVE-1,easy,m,0,2.0,10,3,small,5",
            "CVE-2,medium,m,1,,20,6,large,80",
        ])
        assert observed_avg_credits(path) == pytest.approx(2.0)


class TestProjectRemainingCost:
    def test_missing_file_returns_none(self, tmp_path):
        assert project_remaining_cost(tmp_path / "nope.csv", 5) is None

    def test_projects_from_average(self, tmp_path):
        path = tmp_path / "agent_results.csv"
        header = ("cve_id,tier,model,exit_status,credits,duration_s,"
                   "commands,diff_bucket,diff_lines")
        path.write_text(
            header + '\n'
            "CVE-1,easy,m,0,2.0,10,3,small,5\n"
            "CVE-2,medium,m,0,4.0,20,6,large,80\n"
        )
        assert project_remaining_cost(path, 10) == pytest.approx(30.0)


class TestTotalSpent:
    def _agent_csv(self, tmp_path, rows):
        path = tmp_path / "agent_results.csv"
        header = ("cve_id,tier,model,exit_status,credits,duration_s,"
                   "commands,diff_bucket,diff_lines")
        path.write_text(header + '\n' + '\n'.join(rows) + '\n')
        return path

    def _judge_csv(self, tmp_path, rows):
        path = tmp_path / "judge_results.csv"
        header = "cve_id,model,judgment,judge_credits"
        path.write_text(header + '\n' + '\n'.join(rows) + '\n')
        return path

    def test_sums_both_csvs(self, tmp_path):
        agent_csv = self._agent_csv(tmp_path, [
            "CVE-1,easy,m,0,2.0,10,3,small,5",
            "CVE-2,medium,m,0,4.0,20,6,large,80",
        ])
        judge_csv = self._judge_csv(tmp_path, [
            "CVE-1,m,pass,0.5",
            "CVE-2,m,fail,0.5",
        ])
        assert total_spent(agent_csv, judge_csv) == pytest.approx(7.0)

    def test_missing_agent_csv_returns_judge_only(self, tmp_path):
        judge_csv = self._judge_csv(tmp_path, ["CVE-1,m,pass,0.5"])
        assert total_spent(tmp_path / "nope.csv", judge_csv) == pytest.approx(0.5)

    def test_missing_judge_csv_returns_agent_only(self, tmp_path):
        agent_csv = self._agent_csv(tmp_path, ["CVE-1,easy,m,0,2.0,10,3,small,5"])
        assert total_spent(agent_csv, tmp_path / "nope.csv") == pytest.approx(2.0)

    def test_both_missing_returns_zero(self, tmp_path):
        assert total_spent(tmp_path / "a.csv", tmp_path / "j.csv") == 0.0


class TestCountToolCalls:
    def test_empty_transcript_is_zero(self):
        assert count_tool_calls("") == 0

    def test_no_markers_is_zero(self):
        assert count_tool_calls("Some plain text with no tool calls.\n") == 0

    def test_single_call(self):
        transcript = (
            "I will run the following command: ls -la /tmp "
            "(using tool: shell)\n"
        )
        assert count_tool_calls(transcript) == 1

    def test_multiple_calls(self):
        transcript = (
            "I will run the following command: ls -la /tmp (using tool: shell)\n"
            "Reading directory: /tmp (using tool: read, max depth: 0, "
            "max entries: 1000, excluding: defaults)\n"
            "I'll create the following file: /tmp/foo.txt (using tool: write)\n"
        )
        assert count_tool_calls(transcript) == 3

    def test_ansi_colored_transcript(self):
        # Captured shape from a real `kiro-cli chat --no-interactive` run.
        transcript = (
            "\x1b[?25l\x1b[0m\x1b[0mI will run the following command: "
            "\x1b[38;5;141mls -la /tmp\x1b[38;5;244m (using tool: shell)"
            "\x1b[0m\n"
            "\x1b[38;5;10m \x1b[0mSuccessfully read directory "
            "\x1b[38;5;141m/tmp\x1b[0m \x1b[38;5;244m(using tool: read, "
            "max depth: 0)\x1b[0m\n"
        )
        assert count_tool_calls(transcript) == 2


class TestFilterForJudging:
    def _agent_row(self, cve_id, model, bucket):
        return {'cve_id': cve_id, 'model': model, 'diff_bucket': bucket}

    def test_includes_moderate_and_major(self):
        rows = [
            self._agent_row('CVE-1', 'm', 'moderate'),
            self._agent_row('CVE-2', 'm', 'major'),
        ]
        result = filter_for_judging(rows, [])
        assert result == rows

    def test_excludes_minor_identical_file_mismatch(self):
        rows = [
            self._agent_row('CVE-1', 'm', 'minor'),
            self._agent_row('CVE-2', 'm', 'identical'),
            self._agent_row('CVE-3', 'm', 'file-mismatch'),
        ]
        assert filter_for_judging(rows, []) == []

    def test_excludes_already_judged_pairs(self):
        rows = [
            self._agent_row('CVE-1', 'm', 'moderate'),
            self._agent_row('CVE-2', 'm', 'major'),
        ]
        judge_rows = [{'cve_id': 'CVE-1', 'model': 'm'}]
        result = filter_for_judging(rows, judge_rows)
        assert result == [rows[1]]

    def test_same_cve_different_model_not_excluded(self):
        rows = [
            self._agent_row('CVE-1', 'model-a', 'moderate'),
            self._agent_row('CVE-1', 'model-b', 'moderate'),
        ]
        judge_rows = [{'cve_id': 'CVE-1', 'model': 'model-a'}]
        result = filter_for_judging(rows, judge_rows)
        assert result == [rows[1]]


class TestJudgeDiff:
    def _mock_result(self, stdout):
        result = MagicMock()
        result.stdout = stdout
        result.returncode = 0
        return result

    def test_prompt_contains_diff_and_model(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result("MEANINGFUL\n")
            judge_diff("--- a/foo\n+++ b/foo\n-old\n+new\n", model="claude-opus-4.8")

        args = mock_run.call_args[0][0]
        assert 'kiro-cli' in args
        assert 'claude-opus-4.8' in args
        prompt = args[-1]
        assert '-old' in prompt
        assert '+new' in prompt

    def test_no_interactive_and_no_agent_flag(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result("MEANINGFUL\n")
            judge_diff("diff text", model="claude-opus-4.8")

        args = mock_run.call_args[0][0]
        assert '--no-interactive' in args
        assert '--agent' not in args

    def test_parses_meaningful(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result("MEANINGFUL\nSome extra text.\n")
            judgment, _ = judge_diff("diff text")
        assert judgment == 'meaningful'

    def test_parses_stylistic_case_insensitive_with_surrounding_text(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result(
                "  stylistic  \nThis is a purely cosmetic change.\n")
            judgment, _ = judge_diff("diff text")
        assert judgment == 'stylistic'

    def test_defaults_to_meaningful_when_unparseable(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result("I am not sure.\n")
            judgment, _ = judge_diff("diff text")
        assert judgment == 'meaningful'

    def test_credits_parsing_delegates_to_parse_kiro_credits(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result(
                "MEANINGFUL\n\n Credits: 0.03 \u2022 Time: 1s\n")
            _, credits = judge_diff("diff text")
        assert credits == pytest.approx(0.03)

    def test_no_credits_line_returns_none(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result("STYLISTIC\n")
            _, credits = judge_diff("diff text")
        assert credits is None
