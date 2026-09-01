# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for tests.benchmark.bench_lib."""
from unittest.mock import MagicMock, patch

import pytest

from tests.benchmark.bench_lib import (
    EASY_MAX_MARKERS,
    HARD_MIN_FILES,
    HONEST_OUTCOMES,
    JUDGE_REASON_MAX_CHARS,
    MEDIUM_MAX_MARKERS,
    MINOR_DIFF_LINES_THRESHOLD,
    MODELS,
    MODERATE_DIFF_LINES_THRESHOLD,
    NON_BACKPORT_OUTCOMES,
    classify_diff_bucket,
    count_conflict_markers,
    count_conflicted_files,
    count_diff_changed_lines,
    count_tool_calls,
    filter_for_judging,
    has_substantive_changes,
    is_agent_env_failure,
    is_mirror_gap_only,
    judge_diff,
    observed_avg_credits,
    ordered_roster_cases,
    parse_agent_outcome,
    project_remaining_cost,
    relative_cost_weight,
    resolve_models,
    scope_diff_to_common_files,
    score_tier,
    select_cases,
    strip_comment_only_changes,
    total_spent,
)


class TestScoreTier:
    def test_easy_low_markers_one_file(self):
        assert score_tier(1, 0, 0) == 'easy'
        assert score_tier(1, EASY_MAX_MARKERS, 1) == 'easy'

    def test_medium_marker_count(self):
        assert score_tier(1, EASY_MAX_MARKERS + 1, 1) == 'medium'
        assert score_tier(1, MEDIUM_MAX_MARKERS, 2) == 'medium'

    def test_hard_marker_count(self):
        assert score_tier(1, MEDIUM_MAX_MARKERS + 1, 1) == 'hard'

    def test_hard_files_involved_overrides_low_markers(self):
        """Many files touched is hard even with few markers per file."""
        assert score_tier(1, EASY_MAX_MARKERS, HARD_MIN_FILES) == 'hard'
        assert score_tier(1, 1, HARD_MIN_FILES) == 'hard'

    def test_files_just_under_threshold_does_not_force_hard(self):
        assert score_tier(1, EASY_MAX_MARKERS, HARD_MIN_FILES - 1) == 'easy'

    @pytest.mark.parametrize("exit_code", [0, 2, 5, 6, 7, 8, 9, 10, 11, 12, 16])
    def test_non_recoverable_exit_raises(self, exit_code):
        """Clean (0) and unrecoverable exits have nothing to tier here --
        clean apply belongs in the clean-apply roster (no conflict to size);
        an unrecoverable exit means the corrector bailed before reaching a
        conflict."""
        with pytest.raises(ValueError, match="recoverable exit"):
            score_tier(exit_code, 0, 0)

    @pytest.mark.parametrize("exit_code", [1, 3, 4])
    def test_recoverable_exits_accepted(self, exit_code):
        score_tier(exit_code, 0, 0)  # must not raise


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


class TestCountConflictedFiles:
    def test_counts_distinct_files_not_markers(self):
        """A single file can have several conflicting hunks (several marker
        lines) but must only count once here -- the complement to
        count_conflict_markers, which counts every marker."""
        log_text = (
            "CONFLICT (content): Merge conflict in a.c\n"
            "CONFLICT (content): Merge conflict in b.c\n"
            "CONFLICT (content): Merge conflict in a.c\n"
        )
        assert count_conflicted_files(log_text) == 2
        assert count_conflict_markers(log_text) == 3

    def test_real_multi_file_conflict_shape(self):
        # Shape from CVE-2025-1153's binutils conflict (5 files, real log).
        log_text = (
            "CONFLICT (content): Merge conflict in ld/emultempl/vms.em\n"
            "CONFLICT (content): Merge conflict in ld/ldexp.c\n"
            "CONFLICT (content): Merge conflict in ld/ldlang.c\n"
            "CONFLICT (content): Merge conflict in ld/ldmain.c\n"
            "CONFLICT (content): Merge conflict in ld/ldmisc.c\n"
        )
        assert count_conflicted_files(log_text) == 5

    def test_no_markers_is_zero(self):
        assert count_conflicted_files("clean run, no conflicts\n") == 0

    def test_empty_log_is_zero(self):
        assert count_conflicted_files('') == 0

    def test_structural_failure_with_no_content_conflict_is_zero(self):
        """A non-content failure (e.g. merge-commit strategy failure, or an
        empty-cherry-pick 'nothing to commit') has no file to name."""
        log_text = (
            "The previous cherry-pick is now empty, possibly due to "
            "conflict resolution.\n"
            "error: no cherry-pick or revert in progress\n"
        )
        assert count_conflicted_files(log_text) == 0

    def test_conflict_modify_delete_is_not_a_content_conflict(self):
        """A modify/delete conflict line is a different git message shape and
        must not be mistaken for CONFLICT (content)."""
        log_text = (
            "CONFLICT (modify/delete): foo.c deleted in HEAD and modified "
            "in abc123.\n"
        )
        assert count_conflicted_files(log_text) == 0
        assert count_conflict_markers(log_text) == 0


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

    def test_clean_apply_phase_used_as_tier_fallback(self):
        """The clean-apply roster's schema has `phase: "clean_apply"` instead
        of `tier` (see README "Clean-apply roster") -- it must still list
        correctly, keyed on that value, rather than crash or vanish."""
        roster = {
            "CVE-2025-0001": {"phase": "clean_apply", "recipe": "acpica"},
            "CVE-2025-0002": {"phase": "clean_apply", "recipe": "screen"},
        }
        cases = ordered_roster_cases(roster)
        assert len(cases) == 2
        assert {c["tier"] for c in cases} == {"clean_apply"}
        assert [c["cve_id"] for c in cases] == [
            "CVE-2025-0001", "CVE-2025-0002"]  # alphabetical within the phase


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

    def test_missing_in_generated_without_header_is_file_mismatch(self):
        # No "Files touched" header -> overlap can't be proven -> file-mismatch.
        text = "Missing in generated:\n  some/file.patch\n"
        assert classify_diff_bucket(text) == 'file-mismatch'

    def test_extra_in_generated_without_header_is_file_mismatch(self):
        text = "Extra in generated:\n  some/file.patch\n"
        assert classify_diff_bucket(text) == 'file-mismatch'

    def test_missing_with_overlap_is_partial(self):
        # 7 original files, 6 missing -> 1 shared -> partial (judgeable).
        text = (
            "Files touched - original: 7, generated: 1\n"
            "  Missing in generated: a.c, b.c, c.c, d.c, e.c, f.c\n"
            "\nDifferences: 46 lines\n"
        )
        assert classify_diff_bucket(text) == 'partial'

    def test_extra_only_with_overlap_is_partial(self):
        # Generated is a superset: 2 original all present, 1 extra -> partial.
        text = (
            "Files touched - original: 2, generated: 3\n"
            "  Extra in generated:   extra.c\n"
            "\nDifferences: 20 lines\n"
        )
        assert classify_diff_bucket(text) == 'partial'

    def test_disjoint_filesets_is_file_mismatch(self):
        # 1 original file, it is missing, plus 1 unrelated extra -> 0 shared.
        text = (
            "Files touched - original: 1, generated: 1\n"
            "  Missing in generated: only_orig.c\n"
            "  Extra in generated:   only_gen.c\n"
            "\nDifferences: 30 lines\n"
        )
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
        text = f'Differences: {MODERATE_DIFF_LINES_THRESHOLD} lines\n'
        assert classify_diff_bucket(text) == 'moderate'

    def test_just_above_medium_threshold_is_major(self):
        text = f'Differences: {MODERATE_DIFF_LINES_THRESHOLD + 1} lines\n'
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
            'claude-opus-5', 'claude-sonnet-5', 'claude-sonnet-4.6',
            'claude-haiku-4.5', 'qwen3-coder-next',
        }
        assert all(m['tier'] == 'default' for m in models)

    def test_minimax_is_not_in_the_default_set(self):
        """Poor credits-per-usable-backport; selectable by name, not by default."""
        assert MODELS['minimax-m2.5']['tier'] == 'full'
        assert 'minimax-m2.5' not in {m['name'] for m in resolve_models('default')}

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


class TestParseAgentOutcome:
    """cve-agent's own verdict must be read from the log, not the exit code."""

    def test_empty_log_is_empty_string(self):
        assert parse_agent_outcome("") == ""

    def test_no_outcome_line_is_empty_string(self):
        # A timeout or kill leaves the log without a final verdict line.
        assert parse_agent_outcome("Building AI context...\nStarting kiro\n") == ""

    @pytest.mark.parametrize("status", [
        "success", "conflict_resolved", "failed", "escalated", "skipped",
    ])
    def test_each_result_status_is_parsed(self, status):
        assert parse_agent_outcome(f"\u2713 CVE-2024-1234: {status}\n") == status

    def test_real_shape_with_trailing_detail_lines(self):
        # cve_agent/__main__.py prints the verdict, then indented detail.
        log = (
            "\u26a0 Agent escalated to human review:\n"
            "  Wrong upstream SHA: 752250caabda is already an ancestor.\n"
            "\n"
            "\u2713 CVE-2024-6387: escalated\n"
            "  Max retries (3) exhausted at step 1\n"
            "  credits: 6.16 credits\n"
        )
        assert parse_agent_outcome(log) == "escalated"

    def test_ansi_colored_log(self):
        log = "\x1b[0m\u2713 \x1b[38;5;10mCVE-2025-1153\x1b[0m: skipped\x1b[0m\n"
        # The CVE id is wrapped in colour codes; stripping ANSI must expose it.
        assert parse_agent_outcome(log) == "skipped"

    def test_last_outcome_wins(self):
        # A resumed/retried log can hold more than one verdict; the run's final
        # word is the last one.
        log = (
            "\u2713 CVE-2024-1234: failed\n"
            "\u2713 CVE-2024-1234: conflict_resolved\n"
        )
        assert parse_agent_outcome(log) == "conflict_resolved"

    def test_unknown_status_word_is_not_matched(self):
        # Guards against drift if ResultStatus gains a value: an unrecognised
        # word yields '' (reported as "no outcome") rather than a bogus label.
        assert parse_agent_outcome("\u2713 CVE-2024-1234: pending\n") == ""

    def test_prose_mentioning_a_status_is_not_matched(self):
        log = "The cherry-pick was skipped because the commit is present.\n"
        assert parse_agent_outcome(log) == ""

    def test_skipped_is_flagged_as_a_non_backport(self):
        """The whole point: a 'skipped' run exits 0 but produced no patch."""
        assert "skipped" in NON_BACKPORT_OUTCOMES
        assert "conflict_resolved" not in NON_BACKPORT_OUTCOMES

    def test_escalated_is_flagged_as_honest(self):
        assert "escalated" in HONEST_OUTCOMES
        assert "failed" not in HONEST_OUTCOMES


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

    def test_includes_partial(self):
        rows = [self._agent_row('CVE-1', 'm', 'partial')]
        assert filter_for_judging(rows, []) == rows

    def test_includes_minor(self):
        rows = [self._agent_row('CVE-1', 'm', 'minor')]
        assert filter_for_judging(rows, []) == rows

    def test_excludes_identical_and_file_mismatch(self):
        rows = [
            self._agent_row('CVE-1', 'm', 'identical'),
            self._agent_row('CVE-2', 'm', 'file-mismatch'),
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


class TestScopeDiffToCommonFiles:
    # A diff patch shaped like compare_patches_detailed's output. Note how a
    # file missing from the generated set renders as an all-removed
    # (original)/(generated) block (@@ ... +0,0 @@), NOT a /dev/null block —
    # this is the real shape that a header-string filter would wrongly keep.
    _DIFF = (
        "--- a/get_header_tar.c (original)\n"
        "+++ b/get_header_tar.c (generated)\n"
        "@@ -1,3 +1,3 @@\n"
        " context\n"
        "-strip_unsafe_prefix(x);\n"
        "+overlapping_strcpy(x, strip_unsafe_prefix(x));\n"
        "\n"
        "--- a/data_extract_all.c (original)\n"
        "+++ b/data_extract_all.c (generated)\n"
        "@@ -1,4 +0,0 @@\n"
        "-line1\n"
        "-line2\n"
        "-line3\n"
        "-line4\n"
        "\n"
        "--- a/extra_file.c (original)\n"
        "+++ b/extra_file.c (generated)\n"
        "@@ -0,0 +1,2 @@\n"
        "+added1\n"
        "+added2\n"
        "\n"
    )

    def test_keeps_only_two_sided_common_block(self):
        scoped = scope_diff_to_common_files(self._DIFF)
        assert 'get_header_tar.c' in scoped
        assert 'overlapping_strcpy' in scoped
        assert '-strip_unsafe_prefix(x);' in scoped

    def test_drops_all_removed_missing_file(self):
        # +0,0 hunk -> new span 0 -> one-sided (missing) -> excluded.
        scoped = scope_diff_to_common_files(self._DIFF)
        assert 'data_extract_all.c' not in scoped

    def test_drops_all_added_extra_file(self):
        # -0,0 hunk -> old span 0 -> one-sided (extra) -> excluded.
        scoped = scope_diff_to_common_files(self._DIFF)
        assert 'extra_file.c' not in scoped

    def test_drops_manual_dev_null_blocks(self):
        # Belt-and-suspenders: the manual /dev/null blocks (no @@ hunk) are
        # also excluded because they have no hunk span at all.
        only_structural = (
            "--- a/only_orig.c (original)\n"
            "+++ /dev/null (missing in generated)\n"
            "-gone\n"
            "\n"
            "--- /dev/null (not in original)\n"
            "+++ b/only_gen.c (extra in generated)\n"
            "+added\n"
            "\n"
        )
        assert scope_diff_to_common_files(only_structural) == ''

    def test_empty_when_no_common_files(self):
        only_one_sided = (
            "--- a/missing.c (original)\n"
            "+++ b/missing.c (generated)\n"
            "@@ -1,2 +0,0 @@\n"
            "-a\n"
            "-b\n"
            "\n"
        )
        assert scope_diff_to_common_files(only_one_sided) == ''

    def test_empty_input_returns_empty(self):
        assert scope_diff_to_common_files('') == ''

    def test_multi_hunk_common_file_is_kept(self):
        # Spans summed across hunks; both sides nonzero -> common.
        diff = (
            "--- a/foo.c (original)\n"
            "+++ b/foo.c (generated)\n"
            "@@ -7,7 +7,7 @@\n"
            " ctx\n"
            "-old\n"
            "+new\n"
            "@@ -18,3 +18,4 @@\n"
            " more\n"
            "+added\n"
            "\n"
        )
        scoped = scope_diff_to_common_files(diff)
        assert 'foo.c' in scoped
        assert '+added' in scoped

    def test_does_not_split_on_removed_line_starting_with_dashes(self):
        # A removed source line rendered as '--- ...' must not be mistaken for
        # a file header: only a '--- '/'+++ ' *pair* starts a block.
        diff = (
            "--- a/foo.c (original)\n"
            "+++ b/foo.c (generated)\n"
            "@@ -1,2 +1,2 @@\n"
            "--- a decrement-style removed line\n"
            "+a replacement line\n"
            "\n"
        )
        scoped = scope_diff_to_common_files(diff)
        assert '--- a decrement-style removed line' in scoped
        assert '+a replacement line' in scoped


class TestCountDiffChangedLines:
    def test_empty_is_zero(self):
        assert count_diff_changed_lines('') == 0

    def test_counts_added_and_removed_excluding_headers(self):
        diff = (
            "--- a/foo.c (original)\n"
            "+++ b/foo.c (generated)\n"
            "@@ -1,3 +1,3 @@\n"
            " context\n"
            "-old line\n"
            "+new line\n"
        )
        # Only '-old line' and '+new line' count; the '---'/'+++' headers,
        # the '@@' hunk header, and the ' context' line do not.
        assert count_diff_changed_lines(diff) == 2

    def test_multiple_changes(self):
        diff = (
            "--- a/foo.c (original)\n"
            "+++ b/foo.c (generated)\n"
            "@@ -1,4 +1,4 @@\n"
            "-a\n"
            "-b\n"
            "+c\n"
            "+d\n"
            "+e\n"
        )
        assert count_diff_changed_lines(diff) == 5

    def test_file_headers_never_counted(self):
        # A diff that is only headers has no changed lines.
        diff = (
            "--- a/foo.c (original)\n"
            "+++ b/foo.c (generated)\n"
        )
        assert count_diff_changed_lines(diff) == 0

    def test_matches_scoped_diff(self):
        # The intended usage: count changes in a scoped intersection diff.
        raw = (
            "--- a/common.c (original)\n"
            "+++ b/common.c (generated)\n"
            "@@ -1,2 +1,2 @@\n"
            " ctx\n"
            "-x\n"
            "+y\n"
            "\n"
            "--- a/missing.c (original)\n"
            "+++ b/missing.c (generated)\n"
            "@@ -1,3 +0,0 @@\n"
            "-p\n"
            "-q\n"
            "-r\n"
            "\n"
        )
        scoped = scope_diff_to_common_files(raw)
        # Only common.c survives scoping -> 2 changed lines (-x, +y), NOT the
        # 3 removed lines of the missing file.
        assert count_diff_changed_lines(scoped) == 2


class TestJudgeDiff:
    def _mock_result(self, stdout):
        result = MagicMock()
        result.stdout = stdout
        result.returncode = 0
        return result

    def test_prompt_contains_diff_and_model(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result("MEANINGFUL\n")
            judge_diff("--- a/foo.c\n+++ b/foo.c\n-old\n+new\n",
                       model="claude-opus-4.8")

        args = mock_run.call_args[0][0]
        assert 'kiro-cli' in args
        assert 'claude-opus-4.8' in args
        prompt = args[-1]
        assert '-old' in prompt
        assert '+new' in prompt

    def test_no_interactive_and_no_agent_flag(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result("MEANINGFUL\n")
            judge_diff("-old\n+new\n", model="claude-opus-4.8")

        args = mock_run.call_args[0][0]
        assert '--no-interactive' in args
        assert '--agent' not in args

    def test_parses_meaningful(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result("MEANINGFUL\nSome extra text.\n")
            judgment, _, _ = judge_diff("-old\n+new\n")
        assert judgment == 'meaningful'

    def test_parses_stylistic_case_insensitive_with_surrounding_text(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result(
                "  stylistic  \nThis is a purely cosmetic change.\n")
            judgment, _, _ = judge_diff("-old\n+new\n")
        assert judgment == 'stylistic'

    def test_defaults_to_meaningful_when_unparseable(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result("I am not sure.\n")
            judgment, _, _ = judge_diff("-old\n+new\n")
        assert judgment == 'meaningful'

    def test_credits_parsing_delegates_to_parse_kiro_credits(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result(
                "MEANINGFUL\n\n Credits: 0.03 \u2022 Time: 1s\n")
            _, _, credits = judge_diff("-old\n+new\n")
        assert credits == pytest.approx(0.03)

    def test_no_credits_line_returns_none(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result("STYLISTIC\n")
            _, _, credits = judge_diff("-old\n+new\n")
        assert credits is None


class TestJudgeReason:
    """The verdict alone does not say why, which makes a surprising
    classification impossible to audit without re-reading the diff."""

    def _mock_result(self, stdout):
        result = MagicMock()
        result.stdout = stdout
        result.returncode = 0
        return result

    def test_prompt_asks_for_one_or_two_sentences(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result("MEANINGFUL\nWhy.\n")
            judge_diff("-old\n+new\n")
        prompt = mock_run.call_args[0][0][-1]
        assert 'one or two sentences' in prompt

    def test_captures_reason_after_verdict(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result(
                "MEANINGFUL\nThe backport adds a !S_ISLNK guard. "
                "That changes which links are restored.\n")
            judgment, reason, _ = judge_diff("-old\n+new\n")
        assert judgment == 'meaningful'
        assert reason == ("The backport adds a !S_ISLNK guard. "
                          "That changes which links are restored.")

    def test_keeps_at_most_two_sentences(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result(
                "STYLISTIC\nOne. Two. Three. Four.\n")
            _, reason, _ = judge_diff("-old\n+new\n")
        assert reason == "One. Two."

    def test_reason_is_a_single_line(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result(
                "MEANINGFUL\nFirst part\nwrapped onto two lines.\n")
            _, reason, _ = judge_diff("-old\n+new\n")
        assert '\n' not in reason
        assert reason == "First part wrapped onto two lines."

    def test_credits_footer_is_not_part_of_the_reason(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result(
                "STYLISTIC\nJust a rename.\n\n Credits: 0.02 \u2022 Time: 1s\n")
            _, reason, credits = judge_diff("-old\n+new\n")
        assert reason == "Just a rename."
        assert credits == pytest.approx(0.02)

    def test_empty_reason_when_verdict_only(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result("MEANINGFUL\n")
            _, reason, _ = judge_diff("-old\n+new\n")
        assert reason == ''

    def test_reason_is_length_capped(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = self._mock_result(
                "MEANINGFUL\n" + ("word " * 200) + "\n")
            _, reason, _ = judge_diff("-old\n+new\n")
        assert len(reason) <= JUDGE_REASON_MAX_CHARS


class TestCommentOnlyChanges:
    """A reworded comment is not a behavioral difference, so it must neither
    reach the judge nor be reported as a divergence."""

    C_HEADER = "--- b/archival/tar.c\n+++ b/archival/tar.c\n@@ -1,4 +1,4 @@\n"

    def test_line_comment_change_is_dropped(self):
        diff = self.C_HEADER + " code();\n-// old note\n+// new note\n"
        assert count_diff_changed_lines(
            strip_comment_only_changes(diff)) == 0
        assert not has_substantive_changes(diff)

    def test_block_comment_change_is_dropped(self):
        diff = self.C_HEADER + " code();\n-/* old note */\n+/* new note */\n"
        assert not has_substantive_changes(diff)

    def test_block_comment_continuation_is_dropped(self):
        diff = (self.C_HEADER + " /* GNU tar 1.34 examples:\n"
                "- * tar: Removing leading '/'\n"
                "+ * tar: Removing a leading slash\n"
                "  */\n")
        assert not has_substantive_changes(diff)

    def test_pointer_dereference_is_not_a_comment(self):
        """Regression guard: a 'starts with *' heuristic would drop this."""
        diff = self.C_HEADER + "-\t*p++ = *s++;\n+\t*p-- = *s--;\n"
        assert has_substantive_changes(diff)
        assert '*p++ = *s++;' in strip_comment_only_changes(diff)

    def test_code_with_trailing_comment_is_kept(self):
        diff = self.C_HEADER + "-\tlen += 3; /* open quote */\n+\tlen += 4; /* open quote */\n"
        assert has_substantive_changes(diff)

    def test_preprocessor_directive_is_not_a_comment(self):
        diff = self.C_HEADER + "-#if ENABLE_FEATURE_FOO\n+#if ENABLE_FEATURE_BAR\n"
        assert has_substantive_changes(diff)

    def test_hash_comment_dropped_in_shell_file(self):
        diff = ("--- b/scripts/run.sh\n+++ b/scripts/run.sh\n@@ -1,3 +1,3 @@\n"
                "-# old note\n+# new note\n exit 0\n")
        assert not has_substantive_changes(diff)

    def test_hash_code_change_kept_in_shell_file(self):
        diff = ("--- b/scripts/run.sh\n+++ b/scripts/run.sh\n@@ -1,3 +1,3 @@\n"
                "-exit 0\n+exit 1\n")
        assert has_substantive_changes(diff)

    def test_real_code_change_survives_alongside_comment_churn(self):
        diff = (self.C_HEADER
                + "-/* old note */\n+/* new note */\n"
                + "-\tif (a) {\n+\tif (a && b) {\n")
        filtered = strip_comment_only_changes(diff)
        assert has_substantive_changes(diff)
        assert 'if (a && b) {' in filtered
        assert 'new note' not in filtered

    def test_blank_changed_line_is_kept(self):
        """A blank line is whitespace, not a comment; dropping it silently
        would make a whitespace-only diff look empty for a different reason."""
        diff = self.C_HEADER + " code();\n-\n"
        assert count_diff_changed_lines(strip_comment_only_changes(diff)) == 1

    def test_headers_and_context_are_preserved(self):
        diff = self.C_HEADER + " code();\n-// note\n"
        filtered = strip_comment_only_changes(diff)
        assert '--- b/archival/tar.c' in filtered
        assert '+++ b/archival/tar.c' in filtered
        assert '@@ -1,4 +1,4 @@' in filtered
        assert ' code();' in filtered


class TestJudgeSkipsCommentOnlyDiffs:
    def test_comment_only_diff_is_not_sent_to_the_model(self):
        diff = ("--- b/foo.c\n+++ b/foo.c\n@@ -1,2 +1,2 @@\n"
                " code();\n-// old\n+// new\n")
        with patch('subprocess.run') as mock_run:
            judgment, reason, credits = judge_diff(diff)
        mock_run.assert_not_called()
        assert judgment == 'comment-only'
        assert credits is None
        assert reason

    def test_comment_lines_are_stripped_from_the_prompt(self):
        diff = ("--- b/foo.c\n+++ b/foo.c\n@@ -1,3 +1,3 @@\n"
                "-// chatty note\n+// other note\n"
                "-\tif (a) {\n+\tif (a && b) {\n")
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(
                stdout="MEANINGFUL\nAdded condition.\n", returncode=0)
            judge_diff(diff)
        prompt = mock_run.call_args[0][0][-1]
        assert 'chatty note' not in prompt
        assert 'if (a && b) {' in prompt

    def test_prompt_tells_the_judge_to_ignore_comments(self):
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = MagicMock(stdout="MEANINGFUL\n", returncode=0)
            judge_diff("--- b/f.c\n+++ b/f.c\n-a();\n+b();\n")
        prompt = mock_run.call_args[0][0][-1]
        assert 'comment-only differences' in prompt

