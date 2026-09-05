# SPDX-License-Identifier: MIT
"""Tests for tools/plot_benchmark_results.py.

Only the pure data layer is covered — outcome classification, aggregation,
ranking, and the CVE x model grid. The plotting functions require matplotlib,
which is deliberately not a dev dependency of this project, so they are not
imported here. The tool keeps its matplotlib imports inside the plotting
functions precisely so this module stays importable without it.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_TOOL_PATH = Path(__file__).resolve().parents[2] / "tools" / "plot_benchmark_results.py"


def _load_tool():
    """Import the standalone tools/ script as a module.

    tools/ is not a package (the scripts there are dev-only and not shipped),
    so it is loaded by path rather than imported by name.
    """
    spec = importlib.util.spec_from_file_location("plot_benchmark_results", _TOOL_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tool = _load_tool()


def _agent_row(**overrides: str) -> dict[str, str]:
    """Build an agent_results.csv row with sensible defaults."""
    row = {
        "cve_id": "CVE-2024-0001",
        "tier": "hard",
        "model": "model-a",
        "exit_status": "0",
        "credits": "1.0",
        "duration_s": "100",
        "commands": "10",
        "diff_bucket": "minor",
        "diff_lines": "2",
    }
    row.update(overrides)
    return row


class TestClassifyOutcome:
    """classify_outcome collapses (bucket, verdict) into one outcome."""

    def test_nonzero_exit_is_failed(self) -> None:
        assert tool.classify_outcome(_agent_row(exit_status="14"), None) == tool.OUTCOME_FAILED

    def test_timeout_is_failed(self) -> None:
        assert tool.classify_outcome(_agent_row(exit_status="TIMEOUT"), None) == (
            tool.OUTCOME_FAILED
        )

    def test_failed_run_ignores_any_judge_row(self) -> None:
        judge = {"judgment": "stylistic"}
        assert tool.classify_outcome(_agent_row(exit_status="14"), judge) == tool.OUTCOME_FAILED

    def test_skipped_bucket_is_no_patch(self) -> None:
        row = _agent_row(diff_bucket="skipped", diff_lines="-")
        assert tool.classify_outcome(row, None) == tool.OUTCOME_NO_PATCH

    @pytest.mark.parametrize("bucket", ["identical", "minor"])
    def test_close_buckets_are_equivalent_without_a_judge(self, bucket: str) -> None:
        assert tool.classify_outcome(_agent_row(diff_bucket=bucket), None) == (
            tool.OUTCOME_EQUIVALENT
        )

    @pytest.mark.parametrize("bucket", ["moderate", "major", "partial"])
    @pytest.mark.parametrize("verdict", ["stylistic", "comment-only", "structural-only"])
    def test_judged_equivalent_verdicts(self, bucket: str, verdict: str) -> None:
        row = _agent_row(diff_bucket=bucket)
        judge = {"judgment": verdict}
        assert tool.classify_outcome(row, judge) == tool.OUTCOME_EQUIVALENT

    @pytest.mark.parametrize("bucket", ["moderate", "major", "partial"])
    def test_meaningful_verdict_is_divergent(self, bucket: str) -> None:
        row = _agent_row(diff_bucket=bucket)
        assert tool.classify_outcome(row, {"judgment": "meaningful"}) == tool.OUTCOME_DIVERGENT

    def test_judgeable_bucket_without_verdict_is_unjudged(self) -> None:
        row = _agent_row(diff_bucket="major")
        assert tool.classify_outcome(row, None) == tool.OUTCOME_UNJUDGED

    def test_file_mismatch_is_unjudged(self) -> None:
        row = _agent_row(diff_bucket="file-mismatch")
        assert tool.classify_outcome(row, None) == tool.OUTCOME_UNJUDGED

    def test_major_diff_judged_stylistic_beats_minor_heuristics(self) -> None:
        """A large textual diff can still be a success — the point of the join."""
        big = _agent_row(diff_bucket="major", diff_lines="413")
        assert tool.classify_outcome(big, {"judgment": "stylistic"}) == tool.OUTCOME_EQUIVALENT


class TestClassifyDurableOutcome:
    """exit_status carries a durable summary_state, not a pass/fail flag.

    Scoring any non-'0' value as a failure wrote off 93 of the 100 rows in
    bench_20260904_165741, including 45 that completed and produced a
    comparable patch.
    """

    def test_review_required_is_scored_on_the_patch(self) -> None:
        """A completed run the release gate declined still made a patch.

        run_benchmark.sh deliberately keeps these comparable, so they must be
        judged on equivalence rather than discarded.
        """
        row = _agent_row(
            exit_status="SECURITY_REVIEW_REQUIRED",
            outcome="conflict_resolved", diff_bucket="minor")
        assert tool.classify_outcome(row, None) == tool.OUTCOME_EQUIVALENT

    def test_completed_unverified_is_scored_on_the_patch(self) -> None:
        row = _agent_row(
            exit_status="WORKFLOW_COMPLETED_UNVERIFIED",
            outcome="conflict_resolved", diff_bucket="major")
        assert tool.classify_outcome(
            row, {"judgment": "meaningful"}) == tool.OUTCOME_DIVERGENT

    def test_gate_rejection_is_its_own_outcome(self) -> None:
        row = _agent_row(
            exit_status="SECURITY_REJECTED",
            outcome="conflict_resolved", diff_bucket="file-mismatch")
        assert tool.classify_outcome(row, None) == tool.OUTCOME_GATE_REJECTED

    def test_gate_rejection_outranks_an_identical_patch(self) -> None:
        """Rejection can accompany a patch identical to the reference.

        Semantic validation rejects on grounds a textual diff cannot see (e.g.
        a missing prerequisite), so 'equivalent' would hide a real finding.
        """
        row = _agent_row(
            exit_status="SECURITY_REJECTED",
            outcome="conflict_resolved", diff_bucket="identical")
        assert tool.classify_outcome(row, None) == tool.OUTCOME_GATE_REJECTED

    def test_escalation_is_not_a_failure(self) -> None:
        """Asking for a human is the correct answer for an out-of-scope fix."""
        row = _agent_row(
            exit_status="SECURITY_REVIEW_REQUIRED", outcome="escalated",
            diff_bucket="-", diff_lines="-")
        assert tool.classify_outcome(row, None) == tool.OUTCOME_ESCALATED

    def test_workflow_failure_is_failed(self) -> None:
        row = _agent_row(
            exit_status="WORKFLOW_FAILED", outcome="failed",
            diff_bucket="-", diff_lines="-")
        assert tool.classify_outcome(row, None) == tool.OUTCOME_FAILED

    def test_durable_skip_is_no_patch(self) -> None:
        row = _agent_row(
            exit_status="SKIPPED", outcome="skipped",
            diff_bucket="skipped", diff_lines="-")
        assert tool.classify_outcome(row, None) == tool.OUTCOME_NO_PATCH

    def test_timeout_without_a_durable_outcome_is_failed(self) -> None:
        row = _agent_row(
            exit_status="TIMEOUT", outcome="", diff_bucket="-", diff_lines="-")
        assert tool.classify_outcome(row, None) == tool.OUTCOME_FAILED

    def test_raw_exit_code_without_an_outcome_stays_failed(self) -> None:
        """Older CSVs have no outcome column; the exit code is all there is."""
        row = _agent_row(exit_status="14", outcome="", diff_bucket="minor")
        assert tool.classify_outcome(row, None) == tool.OUTCOME_FAILED

    def test_every_outcome_has_a_color_label_and_glyph(self) -> None:
        for name in tool.OUTCOME_ORDER:
            assert name in tool.OUTCOME_COLORS
            assert name in tool.OUTCOME_LABELS
            assert name in tool.OUTCOME_GLYPHS


class TestAggregate:
    """aggregate joins the two CSVs and accumulates per-model figures."""

    def _rows(self) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        agent = [
            _agent_row(cve_id="CVE-1", model="a", diff_bucket="minor", credits="2.0"),
            _agent_row(cve_id="CVE-2", model="a", diff_bucket="major", credits="4.0"),
            _agent_row(cve_id="CVE-1", model="b", exit_status="14", credits="1.0",
                       diff_bucket="-", diff_lines="-"),
            _agent_row(cve_id="CVE-2", model="b", diff_bucket="partial", credits="",
                       duration_s="", commands=""),
        ]
        judge = [
            {"cve_id": "CVE-2", "model": "a", "judgment": "meaningful"},
            {"cve_id": "CVE-2", "model": "b", "judgment": "stylistic"},
        ]
        return agent, judge

    def test_outcomes_are_counted_per_model(self) -> None:
        agent, judge = self._rows()
        stats = tool.aggregate(agent, judge)
        assert stats["a"].outcomes[tool.OUTCOME_EQUIVALENT] == 1
        assert stats["a"].outcomes[tool.OUTCOME_DIVERGENT] == 1
        assert stats["b"].outcomes[tool.OUTCOME_FAILED] == 1
        assert stats["b"].outcomes[tool.OUTCOME_EQUIVALENT] == 1

    def test_buckets_are_counted_per_model(self) -> None:
        agent, judge = self._rows()
        stats = tool.aggregate(agent, judge)
        assert stats["a"].buckets["minor"] == 1
        assert stats["a"].buckets["major"] == 1
        assert stats["b"].buckets["-"] == 1

    def test_blank_numeric_cells_are_excluded_not_zeroed(self) -> None:
        """A missing credit figure must not drag the mean toward zero."""
        agent, judge = self._rows()
        stats = tool.aggregate(agent, judge)
        # Model b has two runs; only the first reports credits/duration/commands.
        assert stats["b"].credits == [1.0]
        assert stats["b"].avg_credits == pytest.approx(1.0)
        assert stats["b"].durations == [100.0]
        assert stats["b"].avg_duration == pytest.approx(100.0)
        assert stats["b"].commands == [10.0]

    def test_rates_and_cost_per_win(self) -> None:
        agent, judge = self._rows()
        stats = tool.aggregate(agent, judge)
        assert stats["a"].runs == 2
        assert stats["a"].equivalent_rate == pytest.approx(0.5)
        assert stats["a"].total_credits == pytest.approx(6.0)
        assert stats["a"].credits_per_equivalent == pytest.approx(6.0)

    def test_credits_per_equivalent_is_none_without_a_win(self) -> None:
        """Undefined, not infinite — so 'cheap but useless' cannot read as cheap."""
        agent = [_agent_row(model="z", exit_status="14", credits="5.0")]
        stats = tool.aggregate(agent, [])
        assert stats["z"].equivalent == 0
        assert stats["z"].credits_per_equivalent is None

    def test_empty_stats_have_zero_rate(self) -> None:
        empty = tool.ModelStats(model="none")
        assert empty.runs == 0
        assert empty.equivalent_rate == 0.0
        assert empty.credits_per_equivalent is None


class TestRankAndMatrix:
    """Ranking order and the per-CVE grid."""

    def test_rank_is_best_rate_then_cheapest(self) -> None:
        agent = [
            _agent_row(cve_id="CVE-1", model="good", diff_bucket="minor", credits="9.0"),
            _agent_row(cve_id="CVE-1", model="cheap-tie", diff_bucket="minor", credits="1.0"),
            _agent_row(cve_id="CVE-1", model="bad", exit_status="14", credits="0.1"),
        ]
        ranked = tool.rank_models(tool.aggregate(agent, []))
        assert [s.model for s in ranked] == ["cheap-tie", "good", "bad"]

    def test_matrix_orders_cves_easy_to_hard(self) -> None:
        agent = [
            _agent_row(cve_id="CVE-H", tier="hard", model="a"),
            _agent_row(cve_id="CVE-E", tier="easy", model="a"),
            _agent_row(cve_id="CVE-M", tier="medium", model="a"),
        ]
        cves, tier_of, grid = tool.build_matrix(agent, [])
        assert cves == ["CVE-E", "CVE-M", "CVE-H"]
        assert tier_of["CVE-M"] == "medium"
        assert grid[("CVE-H", "a")] == tool.OUTCOME_EQUIVALENT

    def test_matrix_omits_pairs_that_were_never_run(self) -> None:
        agent = [_agent_row(cve_id="CVE-1", model="a")]
        _, _, grid = tool.build_matrix(agent, [])
        assert ("CVE-1", "b") not in grid


class TestReadCsv:
    """CSV loading tolerates a missing judge file."""

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        assert tool.read_csv(tmp_path / "nope.csv") == []

    def test_header_only_file_returns_empty(self, tmp_path: Path) -> None:
        path = tmp_path / "agent_results.csv"
        path.write_text("cve_id,tier,model\n", encoding="utf-8")
        assert tool.read_csv(path) == []

    def test_rows_are_parsed(self, tmp_path: Path) -> None:
        path = tmp_path / "agent_results.csv"
        path.write_text("cve_id,model\nCVE-1,a\n", encoding="utf-8")
        assert tool.read_csv(path) == [{"cve_id": "CVE-1", "model": "a"}]
