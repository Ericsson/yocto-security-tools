# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for tests.benchmark.generate_benchmark_report."""
from pathlib import Path

from tests.benchmark.generate_benchmark_report import generate_report

AGENT_HEADER = "cve_id,tier,model,exit_status,credits,duration_s,commands,diff_bucket,diff_lines"
JUDGE_HEADER = "cve_id,model,judgment,reason,judge_credits,scope"


def _write_agent_csv(results_dir: Path, rows: list[str]) -> None:
    (results_dir / "agent_results.csv").write_text(
        AGENT_HEADER + "\n" + "\n".join(rows) + "\n"
    )


def _write_judge_csv(results_dir: Path, rows: list[str]) -> None:
    (results_dir / "judge_results.csv").write_text(
        JUDGE_HEADER + "\n" + "\n".join(rows) + "\n"
    )


class TestGenerateReport:
    def test_missing_agent_csv_exits(self, tmp_path):
        import pytest
        with pytest.raises(SystemExit):
            generate_report(tmp_path)

    def test_per_model_summary_table(self, tmp_path):
        _write_agent_csv(tmp_path, [
            "CVE-1,easy,model-a,0,2.0,10,3,identical,0",
            "CVE-2,medium,model-a,0,4.0,20,7,minor,5",
        ])
        _write_judge_csv(tmp_path, [])
        report = generate_report(tmp_path)

        assert "## Per-Model Summary" in report
        assert "| model-a | 2 | 6.00 | 15.0 | 5.0 |" in report

    def test_per_tier_bucket_distribution(self, tmp_path):
        _write_agent_csv(tmp_path, [
            "CVE-1,easy,model-a,0,1.0,10,3,identical,0",
            "CVE-2,easy,model-a,0,1.0,10,3,minor,5",
            "CVE-3,medium,model-a,0,1.0,10,3,moderate,20",
            "CVE-4,hard,model-a,1,1.0,10,3,major,80",
            "CVE-5,hard,model-a,0,1.0,10,3,partial,46",
        ])
        _write_judge_csv(tmp_path, [])
        report = generate_report(tmp_path)

        assert "## Per-Tier Bucket Distribution" in report
        # Columns: identical | minor | moderate | major | partial | file-mismatch
        lines = report.splitlines()
        easy_line = next(line for line in lines if line.startswith("| easy |"))
        assert easy_line == "| easy | 1 | 1 | 0 | 0 | 0 | 0 |"
        medium_line = next(line for line in lines if line.startswith("| medium |"))
        assert medium_line == "| medium | 0 | 0 | 1 | 0 | 0 | 0 |"
        hard_line = next(line for line in lines if line.startswith("| hard |"))
        assert hard_line == "| hard | 0 | 0 | 0 | 1 | 1 | 0 |"

    def test_meaningful_vs_stylistic_split(self, tmp_path):
        _write_agent_csv(tmp_path, [
            "CVE-1,medium,model-a,0,1.0,10,3,moderate,20",
            "CVE-2,hard,model-a,0,1.0,10,3,major,80",
            "CVE-3,hard,model-a,0,1.0,10,3,major,90",
            "CVE-4,hard,model-a,0,1.0,10,3,partial,46",
        ])
        _write_judge_csv(tmp_path, [
            "CVE-1,model-a,meaningful,Different bounds check.,0.1,full",
            "CVE-2,model-a,stylistic,Variable rename only.,0.1,full",
            "CVE-4,model-a,meaningful,Extra S_ISLNK guard.,0.1,partial",
        ])
        report = generate_report(tmp_path)

        assert "## Meaningful vs Stylistic (Judged Moderate/Major/Partial Diffs)" in report
        # meaningful=2 (CVE-1, CVE-4), stylistic=1 (CVE-2), comment-only=0,
        # structural-only=0, not-yet-judged=1 (CVE-3)
        assert "| model-a | 2 | 1 | 0 | 0 | 1 |" in report

    def test_structural_only_partial_counted_separately(self, tmp_path):
        # A 'partial' row whose shared files were identical is recorded as
        # 'structural-only' by run_benchmark.sh — it must land in its own
        # column, not "Not Yet Judged".
        _write_agent_csv(tmp_path, [
            "CVE-1,hard,model-a,0,1.0,10,3,partial,46",
            "CVE-2,hard,model-a,0,1.0,10,3,major,80",
        ])
        _write_judge_csv(tmp_path, [
            "CVE-1,model-a,structural-only,Shared files are identical.,,partial",
        ])
        report = generate_report(tmp_path)

        # meaningful=0, stylistic=0, comment-only=0, structural-only=1 (CVE-1),
        # not-yet-judged=1 (CVE-2, judgeable but no judge row)
        assert "| model-a | 0 | 0 | 0 | 1 | 1 |" in report

    def test_comment_only_counted_separately(self, tmp_path):
        # judge_diff answers 'comment-only' without a model call when every
        # remaining changed line is a comment; that is a pass, not a pending row.
        _write_agent_csv(tmp_path, [
            "CVE-1,hard,model-a,0,1.0,10,3,moderate,12",
        ])
        _write_judge_csv(tmp_path, [
            "CVE-1,model-a,comment-only,Only comment lines differ.,,full",
        ])
        report = generate_report(tmp_path)

        assert "| model-a | 0 | 0 | 1 | 0 | 0 |" in report
        assert "Comment-only" in report

    def test_minor_and_identical_excluded_from_judge_split(self, tmp_path):
        _write_agent_csv(tmp_path, [
            "CVE-1,easy,model-a,0,1.0,10,3,identical,0",
            "CVE-2,easy,model-a,0,1.0,10,3,minor,5",
        ])
        _write_judge_csv(tmp_path, [])
        report = generate_report(tmp_path)

        # Neither identical nor minor rows count toward the judged split —
        # model-a has zero judgeable (moderate/major) rows, so it gets no
        # row in that table at all.
        split_section = report.split("## Meaningful vs Stylistic")[1]
        assert "model-a" not in split_section

    def test_judge_model_note_present(self, tmp_path):
        _write_agent_csv(tmp_path, ["CVE-1,easy,model-a,0,1.0,10,3,identical,0"])
        _write_judge_csv(tmp_path, [])
        report = generate_report(tmp_path)
        assert "claude-opus-4.8" in report

    def test_missing_judge_csv_treated_as_empty(self, tmp_path):
        _write_agent_csv(tmp_path, [
            "CVE-1,medium,model-a,0,1.0,10,3,moderate,20",
        ])
        report = generate_report(tmp_path)
        # meaningful=0, stylistic=0, comment-only=0, structural-only=0,
        # not-yet-judged=1
        assert "| model-a | 0 | 0 | 0 | 0 | 1 |" in report

    def test_judge_reasoning_section_lists_verdict_justifications(self, tmp_path):
        _write_agent_csv(tmp_path, [
            "CVE-1,hard,model-a,0,1.0,10,3,major,80",
        ])
        _write_judge_csv(tmp_path, [
            "CVE-1,model-a,meaningful,\"Adds a !S_ISLNK guard, changing which "
            "links are restored.\",0.1,full",
        ])
        report = generate_report(tmp_path)

        assert "## Judge Reasoning" in report
        assert "Adds a !S_ISLNK guard" in report

    def test_reasoning_section_escapes_pipes(self, tmp_path):
        # The reason is free-form prose; a bare '|' would break the table.
        _write_agent_csv(tmp_path, [
            "CVE-1,hard,model-a,0,1.0,10,3,major,80",
        ])
        _write_judge_csv(tmp_path, [
            "CVE-1,model-a,meaningful,\"Uses a || instead of &&.\",0.1,full",
        ])
        report = generate_report(tmp_path)
        assert r"\|\|" in report

    def test_no_reasoning_section_for_legacy_rows_without_reason(self, tmp_path):
        # A results dir judged before the 'reason' column existed must not
        # render a table of blanks.
        _write_agent_csv(tmp_path, [
            "CVE-1,hard,model-a,0,1.0,10,3,major,80",
        ])
        (tmp_path / "judge_results.csv").write_text(
            "cve_id,model,judgment,judge_credits\nCVE-1,model-a,meaningful,0.1\n"
        )
        report = generate_report(tmp_path)
        assert "## Judge Reasoning" not in report
