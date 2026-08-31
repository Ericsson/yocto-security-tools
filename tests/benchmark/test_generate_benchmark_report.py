# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for tests.benchmark.generate_benchmark_report."""
import json
from pathlib import Path

from tests.benchmark.generate_benchmark_report import generate_report

AGENT_HEADER = ("cve_id,tier,model,exit_status,outcome,skip_reason,credits,"
                "duration_s,commands,diff_bucket,diff_lines")
# The pre-outcome-column schema, still readable by generate_report so existing
# results directories keep working.
LEGACY_AGENT_HEADER = ("cve_id,tier,model,exit_status,credits,duration_s,"
                       "commands,diff_bucket,diff_lines")
JUDGE_HEADER = "cve_id,model,judgment,reason,judge_credits,scope"


def _write_agent_csv(results_dir: Path, rows: list[str]) -> None:
    """Write agent_results.csv, defaulting the outcome column when omitted.

    Rows may be given in the legacy 9-field form (no ``outcome``); this
    inserts ``conflict_resolved`` after ``exit_status`` so tests that don't
    care about the outcome stay readable. Pass a full 10-field row to set it.
    """
    normalised = []
    for row in rows:
        fields = row.split(",")
        if len(fields) == 9:
            fields.insert(4, "conflict_resolved")
        if len(fields) == 10:
            # outcome present, skip_reason omitted
            fields.insert(5, "")
        normalised.append(",".join(fields))
    (results_dir / "agent_results.csv").write_text(
        AGENT_HEADER + "\n" + "\n".join(normalised) + "\n"
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

        assert "## Meaningful vs Stylistic (Judged Minor/Moderate/Major/Partial Diffs)" in report
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

    def test_identical_excluded_minor_pending_from_judge_split(self, tmp_path):
        _write_agent_csv(tmp_path, [
            "CVE-1,easy,model-a,0,1.0,10,3,identical,0",
            "CVE-2,easy,model-a,0,1.0,10,3,minor,5",
        ])
        _write_judge_csv(tmp_path, [])
        report = generate_report(tmp_path)

        # identical never counts toward the judged split. minor now does
        # (it's judgeable), but with no matching judge_results.csv row it
        # shows up as not-yet-judged rather than absent.
        split_section = report.split("## Meaningful vs Stylistic")[1]
        assert "model-a" in split_section
        assert "| model-a | 0 | 0 | 0 | 0 | 1 |" in split_section

    def test_judge_model_note_present(self, tmp_path):
        _write_agent_csv(tmp_path, ["CVE-1,easy,model-a,0,1.0,10,3,identical,0"])
        _write_judge_csv(tmp_path, [])
        report = generate_report(tmp_path)
        assert "claude-opus-4.8" in report

    def test_resolved_judge_identity_comes_from_manifest(self, tmp_path):
        _write_agent_csv(tmp_path, ["CVE-1,easy,model-a,0,1.0,10,3,identical,0"])
        _write_judge_csv(tmp_path, [])
        (tmp_path / "run-manifest.json").write_text(json.dumps({
            "judge": {
                "selector": "openai-private-judge",
                "model": "resolved-judge-model",
            },
        }), encoding="utf-8")

        report = generate_report(tmp_path)

        assert "openai-private-judge / resolved-judge-model" in report
        assert "claude-opus-4.8" not in report

    def test_per_model_outcome_table_separates_skipped_from_resolved(self, tmp_path):
        """A not-applicable verdict must not be tallied as a resolved backport.

        Both exit 0, so an exit-status-only view shows model-a and model-b as
        equally successful even though model-b produced no patch at all.
        """
        _write_agent_csv(tmp_path, [
            "CVE-1,hard,model-a,0,conflict_resolved,1.0,10,3,minor,4",
            "CVE-2,hard,model-a,0,conflict_resolved,1.0,10,3,minor,4",
            "CVE-1,hard,model-b,0,skipped,1.0,10,3,skipped,-",
            "CVE-2,hard,model-b,0,skipped,1.0,10,3,skipped,-",
        ])
        _write_judge_csv(tmp_path, [])
        report = generate_report(tmp_path)

        assert "## Per-Model Outcomes" in report
        outcomes = report.split("## Per-Model Outcomes")[1].split("##")[0]
        # conflict_resolved | success | skipped | escalated | failed | unknown
        assert "| model-a | 2 | 0 | 0 | 0 | 0 | 0 |" in outcomes
        assert "| model-b | 0 | 0 | 2 | 0 | 0 | 0 |" in outcomes

    def test_escalated_counted_separately_from_failed(self, tmp_path):
        """An honest escalation and a real breakage share exit 14; split them."""
        _write_agent_csv(tmp_path, [
            "CVE-1,hard,model-a,14,escalated,1.0,10,3,-,-",
            "CVE-2,hard,model-a,14,failed,1.0,10,3,-,-",
        ])
        _write_judge_csv(tmp_path, [])
        report = generate_report(tmp_path)

        outcomes = report.split("## Per-Model Outcomes")[1].split("##")[0]
        assert "| model-a | 0 | 0 | 0 | 1 | 1 | 0 |" in outcomes

    def test_legacy_csv_without_outcome_column_still_reports(self, tmp_path):
        """Results dirs predating the outcome column must not break the report."""
        (tmp_path / "agent_results.csv").write_text(
            LEGACY_AGENT_HEADER + "\n"
            + "CVE-1,hard,model-a,0,1.0,10,3,minor,4\n"
        )
        _write_judge_csv(tmp_path, [])
        report = generate_report(tmp_path)

        # Row is counted, but its outcome is unknown rather than guessed.
        outcomes = report.split("## Per-Model Outcomes")[1].split("##")[0]
        assert "| model-a | 0 | 0 | 0 | 0 | 0 | 1 |" in outcomes

    def test_not_applicable_audit_lists_dismissals_and_disagreement(self, tmp_path):
        """Skipped CVEs are listed with how many models dismissed them."""
        _write_agent_csv(tmp_path, [
            "CVE-9,hard,model-a,0,skipped,1.0,10,3,skipped,-",
            "CVE-9,hard,model-b,0,skipped,1.0,10,3,skipped,-",
            "CVE-9,hard,model-c,0,conflict_resolved,1.0,10,3,minor,4",
        ])
        _write_judge_csv(tmp_path, [])
        report = generate_report(tmp_path)

        assert "## Not-Applicable Verdicts (verify these)" in report
        audit = report.split("## Not-Applicable Verdicts (verify these)")[1]
        # 2 of the 3 runs dismissed it -> model-c disagreed, so one side is wrong.
        assert "| CVE-9 | 2 | 3 | model-a, model-b |" in audit

    def test_no_audit_section_when_nothing_was_dismissed(self, tmp_path):
        _write_agent_csv(tmp_path, [
            "CVE-1,hard,model-a,0,conflict_resolved,1.0,10,3,minor,4",
        ])
        _write_judge_csv(tmp_path, [])
        report = generate_report(tmp_path)
        assert "Not-Applicable Verdicts" not in report

    def test_mechanical_skips_excluded_from_the_dismissal_audit(self, tmp_path):
        """A build that was already broken is not a model dismissing a CVE.

        All five CVE-2025-64505 runs in bench_20260831_140123 were skipped
        because libpng did not build even unpatched. Counting those as
        not-applicable verdicts reads as a unanimous dismissal of a CVE no
        model was ever asked about.
        """
        (tmp_path / "agent_results.csv").write_text(
            "cve_id,tier,model,exit_status,outcome,skip_reason,credits,"
            "duration_s,commands,diff_bucket,diff_lines\n"
            "CVE-7,hard,model-a,0,skipped,build_preexisting,1.0,10,3,skipped,-\n"
            "CVE-7,hard,model-b,0,skipped,build_preexisting,1.0,10,3,skipped,-\n"
            "CVE-8,hard,model-a,0,skipped,ai_not_applicable,1.0,10,3,skipped,-\n"
        )
        _write_judge_csv(tmp_path, [])
        report = generate_report(tmp_path)

        audit = report.split("## Not-Applicable Verdicts (verify these)")[1]
        audit = audit.split("## ")[0]
        assert "CVE-8" in audit
        assert "CVE-7" not in audit
        # ...but the mechanical skips are still reported, just not as verdicts.
        mech = report.split("## Skips With a Mechanical Cause")[1]
        assert "build_preexisting" in mech
        assert "CVE-7" in mech

    def test_empty_cherry_pick_is_reported_as_mechanical(self, tmp_path):
        """An empty cherry-pick gave the model no other conclusion to draw."""
        (tmp_path / "agent_results.csv").write_text(
            "cve_id,tier,model,exit_status,outcome,skip_reason,credits,"
            "duration_s,commands,diff_bucket,diff_lines\n"
            "CVE-9,hard,model-a,0,skipped,empty_cherry_pick,1.0,10,3,skipped,-\n"
        )
        _write_judge_csv(tmp_path, [])
        report = generate_report(tmp_path)
        assert "Not-Applicable Verdicts" not in report
        assert "empty_cherry_pick" in report

    def test_skip_without_a_recorded_reason_is_still_audited(self, tmp_path):
        """Legacy rows have no skip_reason; treat them as claims, not noise."""
        _write_agent_csv(tmp_path, [
            "CVE-5,hard,model-a,0,skipped,1.0,10,3,skipped,-",
        ])
        _write_judge_csv(tmp_path, [])
        report = generate_report(tmp_path)
        assert "CVE-5" in report.split("## Not-Applicable Verdicts")[1]

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
