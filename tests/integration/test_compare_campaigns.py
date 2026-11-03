#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for tests/integration/compare_campaigns.py (no Yocto, no judge calls)."""
from __future__ import annotations

import csv
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import compare_campaigns as cc  # noqa: E402

REFERENCE = ("diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n@@ -1,1 +1,1 @@\n"
             "-\treturn 0;\n+\treturn 1;\n")
DIFFERENT = REFERENCE.replace("return 1", "return 2")


def make_run(root: Path, rows, *, patches=None, references=None) -> Path:
    """Build a results directory; ``rows`` is a list of (cve, status)."""
    root.mkdir(parents=True)
    with (root / "results_full.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["cve_id", "recipe", "status"])
        writer.writerows([cve, "recipe", status] for cve, status in rows)
    for cve, status in rows:
        (root / f"{cve}_full.log").write_text(status, encoding="utf-8")
    for cve, text in (references or {}).items():
        (root / f"full_{cve}_{cve}.patch").write_text(text, encoding="utf-8")
    for cve, text in (patches or {}).items():
        art = root / f"{cve}_full_artifacts"
        art.mkdir()
        (art / "final-commits.patch").write_text(text, encoding="utf-8")
    return root


def statuses(run_dir: Path) -> dict[str, str]:
    _, rows = cc.read_rows(run_dir / "results_full.csv")
    return {row["cve_id"]: row["status"] for row in rows}


class TestSeed:
    ROWS = [("CVE-1", "IDENTICAL"), ("CVE-2", "SUCCESS"), ("CVE-3", "SKIP_NOT_APPLICABLE"),
            ("CVE-4", "FAIL_PREP_BASE_MISMATCH"), ("CVE-5", "AGENT_RESOLVED"),
            ("CVE-6", "SECURITY_REVIEW_REQUIRED"), ("CVE-7", "FAIL_WORKFLOW_FAILED"),
            ("CVE-8", "WORKFLOW_COMPLETED_UNVERIFIED")]

    def test_keeps_only_rows_the_model_cannot_influence(self, tmp_path):
        source = make_run(tmp_path / "a", self.ROWS, patches={"CVE-1": REFERENCE,
                                                              "CVE-5": REFERENCE})
        seeded = cc.seed(source, tmp_path / "b", log=lambda _m: None)
        assert seeded == ["CVE-1", "CVE-2", "CVE-3", "CVE-4"]
        assert statuses(tmp_path / "b") == {
            "CVE-1": "IDENTICAL", "CVE-2": "SUCCESS", "CVE-3": "SKIP_NOT_APPLICABLE",
            "CVE-4": "FAIL_PREP_BASE_MISMATCH"}

    def test_copies_the_seeded_rows_files_and_nothing_else(self, tmp_path):
        source = make_run(tmp_path / "a", self.ROWS, patches={"CVE-1": REFERENCE,
                                                              "CVE-5": REFERENCE},
                          references={"CVE-1": REFERENCE, "CVE-5": REFERENCE})
        target = tmp_path / "b"
        cc.seed(source, target, log=lambda _m: None)
        assert (target / "CVE-1_full_artifacts" / "final-commits.patch").is_file()
        assert (target / "full_CVE-1_CVE-1.patch").is_file()
        assert (target / "CVE-2_full.log").is_file()
        assert not (target / "CVE-5_full_artifacts").exists()
        assert not (target / "full_CVE-5_CVE-5.patch").exists()
        assert not (target / "CVE-6_full.log").exists()

    def test_writes_the_seed_list(self, tmp_path):
        source = make_run(tmp_path / "a", self.ROWS)
        cc.seed(source, tmp_path / "b", log=lambda _m: None)
        assert cc.read_cve_list(tmp_path / "b" / cc.SEED_LIST) == {
            "CVE-1", "CVE-2", "CVE-3", "CVE-4"}

    def test_refuses_to_overwrite_an_existing_run(self, tmp_path):
        source = make_run(tmp_path / "a", self.ROWS)
        make_run(tmp_path / "b", [("CVE-9", "AGENT_RESOLVED")])
        with pytest.raises(SystemExit, match="refusing to overwrite"):
            cc.seed(source, tmp_path / "b", log=lambda _m: None)
        assert statuses(tmp_path / "b") == {"CVE-9": "AGENT_RESOLVED"}


class FakeJudge:
    def __init__(self):
        self.calls = 0

    def __call__(self, diff_text, model="", backend=""):
        self.calls += 1
        return "stylistic", "Same logic.", "Same logic.", 0.1


class TestJudge:
    def test_each_judge_model_gets_its_own_dir_and_resolved_rows_are_judged(self, tmp_path):
        run_dir = make_run(tmp_path / "a", [("CVE-1", "AGENT_RESOLVED"),
                                            ("CVE-2", "SECURITY_REVIEW_REQUIRED"),
                                            ("CVE-3", "IDENTICAL")],
                           patches={"CVE-1": DIFFERENT, "CVE-2": DIFFERENT},
                           references={"CVE-1": REFERENCE, "CVE-2": REFERENCE})
        fake = FakeJudge()
        cc.judge([run_dir], ["judge-x", "judge-y"], judge_fn=fake, log=lambda _m: None)
        for model in ("judge-x", "judge-y"):
            _, rows = cc.read_rows(cc.judge_dir(run_dir, model) / "judge_results.csv")
            assert {r["cve_id"]: r["judge_model"] for r in rows} == {
                "CVE-1": model, "CVE-2": model}
        assert fake.calls == 4

    def test_a_rerun_makes_no_new_calls(self, tmp_path):
        run_dir = make_run(tmp_path / "a", [("CVE-1", "AGENT_RESOLVED")],
                           patches={"CVE-1": DIFFERENT}, references={"CVE-1": REFERENCE})
        cc.judge([run_dir], ["j"], judge_fn=FakeJudge(), log=lambda _m: None)
        again = FakeJudge()
        cc.judge([run_dir], ["j"], judge_fn=again, log=lambda _m: None)
        assert again.calls == 0

    @pytest.mark.parametrize("name", ["", "a/b", ".."])
    def test_unusable_judge_names_are_rejected(self, tmp_path, name):
        with pytest.raises(SystemExit):
            cc.judge_dir(tmp_path, name)


class TestPlot:
    def _runs(self, tmp_path, judges=("j1", "j2")):
        run_a = make_run(tmp_path / "a", [("CVE-1", "IDENTICAL"), ("CVE-2", "AGENT_RESOLVED")])
        run_b = make_run(tmp_path / "b", [("CVE-1", "IDENTICAL"), ("CVE-2", "AGENT_RESOLVED")])
        (run_b / cc.SEED_LIST).write_text("# seeded\nCVE-1\n", encoding="utf-8")
        for run_dir in (run_a, run_b):
            for model in judges:
                d = cc.judge_dir(run_dir, model)
                d.mkdir()
                (d / "judge_results.csv").write_text("cve_id\n", encoding="utf-8")
        return run_a, run_b

    def test_attempted_by_both_leaves_out_seeded_cves(self, tmp_path):
        run_a, run_b = self._runs(tmp_path)
        assert cc.attempted_by_both(run_a, run_b) == {"CVE-2"}

    def test_draws_outcomes_judge_comparison_and_one_agreement_chart_per_run(self, tmp_path):
        run_a, run_b = self._runs(tmp_path)
        calls = []
        cc.plot(("Model A", run_a), ("Model B", run_b), ["j1", "j2"], tmp_path / "out",
                runner=lambda argv: calls.append(argv) or 0)
        tools = [Path(argv[1]).name for argv in calls]
        assert tools == ["plot_model_outcome_comparison.py", "plot_model_judge_comparison.py",
                         "plot_judge_agreement.py", "plot_judge_agreement.py"]
        judged = calls[1]
        assert judged[judged.index("--attempted") + 1] == str(
            tmp_path / "out" / "attempted-by-both.txt")
        assert sum(arg == "--judge" for arg in judged) == 2
        assert (tmp_path / "out" / "attempted-by-both.txt").read_text() == "CVE-2\n"
        assert calls[2][-1].endswith("judge_agreement_Model_A.png")

    def test_without_judges_only_the_outcome_chart_is_drawn(self, tmp_path):
        run_a, run_b = self._runs(tmp_path, judges=())
        calls = []
        cc.plot(("A", run_a), ("B", run_b), [], tmp_path / "out",
                runner=lambda argv: calls.append(argv) or 0)
        assert [Path(argv[1]).name for argv in calls] == ["plot_model_outcome_comparison.py"]

    def test_a_missing_judge_csv_is_reported(self, tmp_path):
        run_a, run_b = self._runs(tmp_path, judges=("j1",))
        with pytest.raises(SystemExit, match='run the "judge" step first'):
            cc.plot(("A", run_a), ("B", run_b), ["j1", "j2"], tmp_path / "out",
                    runner=lambda argv: 0)

    def test_a_failing_chart_stops_the_step(self, tmp_path):
        run_a, run_b = self._runs(tmp_path)
        with pytest.raises(SystemExit, match="plot_model_outcome_comparison.py failed"):
            cc.plot(("A", run_a), ("B", run_b), ["j1"], tmp_path / "out", runner=lambda argv: 1)


def test_parse_named_run_requires_name_and_path():
    assert cc.parse_named_run("Qwen3.8-27B=x/y") == ("Qwen3.8-27B", Path("x/y"))
    for bad in ("x/y", "=x", "name="):
        with pytest.raises(SystemExit):
            cc.parse_named_run(bad)
