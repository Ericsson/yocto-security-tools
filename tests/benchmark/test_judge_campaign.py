# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Offline tests for judging the review-required rows of a bulk run."""

import csv
from pathlib import Path

import pytest

from tests.benchmark.judge_campaign import (
    DEFAULT_JUDGE_MODEL,
    OUTPUT_COLUMNS,
    reference_patches,
    run,
)

CVE = "CVE-2026-0001"


def _patch(name: str, body: str) -> str:
    return (f"Upstream-Status: Backport [https://example.invalid/commit/abc]\n\n"
            f"diff --git a/{name} b/{name}\n--- a/{name}\n+++ b/{name}\n"
            f"@@ -1,3 +1,3 @@\n static int must_quote(char c)\n {{\n"
            f"-\treturn (c == 'x');\n+\treturn {body};\n }}\n")


REFERENCE = _patch("filename.c", "(c == '\\n')")
SAME = _patch("filename.c", "(c == '\\n')")
DIFFERENT = _patch("filename.c", "(c == '\\r')")
OTHER_FILE = _patch("other.c", "(c == 'y')")


class FakeJudge:
    """Stand-in for ``judge_diff`` that records what it was asked."""

    def __init__(self, reply=("stylistic", "Same logic.", "Same logic, in full.", 0.25)):
        self.reply = reply
        self.calls: list[tuple[str, str, str]] = []

    def __call__(self, diff_text, model="", backend=""):
        self.calls.append((diff_text, model, backend))
        return self.reply


def _make(tmp_path: Path, rows, *, candidates=None, references=None) -> Path:
    """Build a results directory; ``rows`` is a list of (cve, status)."""
    results = tmp_path / "res"
    results.mkdir()
    with (results / "results_full.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["cve_id", "recipe", "status"])
        for cve, status in rows:
            writer.writerow([cve, "recipe", status])
    for cve, text in (references or {}).items():
        (results / f"full_{cve}_{cve}.patch").write_text(text, encoding="utf-8")
    for cve, text in (candidates or {}).items():
        art = results / f"{cve}_full_artifacts"
        art.mkdir()
        (art / "final-commits.patch").write_text(text, encoding="utf-8")
    return results


def _output(results: Path) -> list[dict[str, str]]:
    with (results / "judge" / "judge_results.csv").open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _run(results, judge, **kwargs):
    return run(results, judge=judge, log=lambda _line: None, **kwargs)


def test_reference_patches_exclude_agent_copies_comparison_outputs_and_other_cves(tmp_path):
    for name in (
        f"full_{CVE}_{CVE}.patch",
        f"full_{CVE}_{CVE}-0002.patch",
        f"full_{CVE}_{CVE}_differences_diff.patch",
        f"full_{CVE}_agent_{CVE}.patch",
        f"full_agent_{CVE}_candidate.patch",
        "full_CVE-2026-0002_CVE-2026-0002.patch",
    ):
        (tmp_path / name).write_text("x", encoding="utf-8")
    assert [p.name for p in reference_patches(tmp_path, CVE)] == [
        f"full_{CVE}_{CVE}-0002.patch", f"full_{CVE}_{CVE}.patch"]


def test_identical_patch_is_not_sent_to_the_judge(tmp_path):
    results = _make(tmp_path, [(CVE, "SECURITY_REVIEW_REQUIRED")],
                    candidates={CVE: SAME}, references={CVE: REFERENCE})
    judge = FakeJudge()
    counts = _run(results, judge)
    assert judge.calls == []
    assert counts == {"identical": 1}
    assert _output(results)[0]["judgment"] == "identical"


def test_a_differing_patch_is_judged_with_the_configured_model(tmp_path):
    results = _make(tmp_path, [(CVE, "SECURITY_REVIEW_REQUIRED")],
                    candidates={CVE: DIFFERENT}, references={CVE: REFERENCE})
    judge = FakeJudge()
    _run(results, judge, backend="kiro")
    assert len(judge.calls) == 1
    diff_text, model, backend = judge.calls[0]
    assert "\\r" in diff_text and "\\n" in diff_text
    assert (model, backend) == (DEFAULT_JUDGE_MODEL, "kiro")
    row = _output(results)[0]
    assert (row["judgment"], row["bucket"], row["judge_model"], row["judge_credits"]) == (
        "stylistic", "minor", DEFAULT_JUDGE_MODEL, "0.25")
    assert set(row) == set(OUTPUT_COLUMNS)
    assert (results / "judge" / f"{CVE}_judge-reason.txt").read_text(
        encoding="utf-8") == "Same logic, in full.\n"


def test_default_judge_model_is_claude_opus_5_5():
    assert DEFAULT_JUDGE_MODEL == "claude-opus-5.5"


def test_a_row_with_no_committed_patch_is_recorded_without_a_judge_call(tmp_path):
    results = _make(tmp_path, [(CVE, "SECURITY_REVIEW_REQUIRED")],
                    candidates={CVE: ""}, references={CVE: REFERENCE})
    judge = FakeJudge()
    _run(results, judge)
    assert judge.calls == []
    assert _output(results)[0]["judgment"] == "no-patch"


def test_a_row_without_artifacts_is_recorded_as_no_patch(tmp_path):
    results = _make(tmp_path, [(CVE, "SECURITY_REVIEW_REQUIRED")], references={CVE: REFERENCE})
    _run(results, FakeJudge())
    assert _output(results)[0]["judgment"] == "no-patch"


def test_a_row_without_a_reference_is_recorded_as_no_reference(tmp_path):
    results = _make(tmp_path, [(CVE, "SECURITY_REVIEW_REQUIRED")], candidates={CVE: SAME})
    judge = FakeJudge()
    _run(results, judge)
    assert judge.calls == []
    assert _output(results)[0]["judgment"] == "no-reference"


def test_only_review_required_rows_are_considered(tmp_path):
    rows = [(CVE, "IDENTICAL"), ("CVE-2026-0002", "FAIL_AGENT_NO_PROGRESS"),
            ("CVE-2026-0003", "WORKFLOW_COMPLETED_UNVERIFIED")]
    results = _make(tmp_path, rows, candidates={"CVE-2026-0003": SAME},
                    references={"CVE-2026-0003": REFERENCE})
    _run(results, FakeJudge())
    assert [r["cve_id"] for r in _output(results)] == ["CVE-2026-0003"]


def test_an_empty_judge_reply_is_not_recorded_and_is_retried(tmp_path):
    results = _make(tmp_path, [(CVE, "SECURITY_REVIEW_REQUIRED")],
                    candidates={CVE: DIFFERENT}, references={CVE: REFERENCE})
    broken = FakeJudge(reply=("meaningful", "", "", None))
    assert _run(results, broken) == {"error": 1}
    assert _output(results) == []
    good = FakeJudge()
    _run(results, good)
    assert len(good.calls) == 1
    assert [r["judgment"] for r in _output(results)] == ["stylistic"]


def test_a_real_meaningful_verdict_with_no_credits_is_kept(tmp_path):
    results = _make(tmp_path, [(CVE, "SECURITY_REVIEW_REQUIRED")],
                    candidates={CVE: DIFFERENT}, references={CVE: REFERENCE})
    _run(results, FakeJudge(reply=("meaningful", "Different condition.", "x", None)))
    assert _output(results)[0]["judgment"] == "meaningful"


def test_a_second_run_skips_rows_already_judged(tmp_path):
    results = _make(tmp_path, [(CVE, "SECURITY_REVIEW_REQUIRED")],
                    candidates={CVE: DIFFERENT}, references={CVE: REFERENCE})
    _run(results, FakeJudge())
    again = FakeJudge()
    _run(results, again)
    assert again.calls == []
    assert len(_output(results)) == 1


def test_a_different_judge_model_is_refused_rather_than_mixed(tmp_path):
    results = _make(tmp_path, [(CVE, "SECURITY_REVIEW_REQUIRED"),
                               ("CVE-2026-0002", "SECURITY_REVIEW_REQUIRED")],
                    candidates={CVE: DIFFERENT, "CVE-2026-0002": DIFFERENT},
                    references={CVE: REFERENCE, "CVE-2026-0002": REFERENCE})
    _run(results, FakeJudge(), limit=1, judge_model="claude-opus-4.8")
    with pytest.raises(SystemExit, match="refusing to mix"):
        _run(results, FakeJudge(), judge_model="claude-opus-5.5")


def test_limit_caps_the_rows_done(tmp_path):
    cves = [f"CVE-2026-000{i}" for i in range(1, 4)]
    results = _make(tmp_path, [(c, "SECURITY_REVIEW_REQUIRED") for c in cves],
                    candidates=dict.fromkeys(cves, DIFFERENT),
                    references=dict.fromkeys(cves, REFERENCE))
    judge = FakeJudge()
    _run(results, judge, limit=2)
    assert len(judge.calls) == 2


def test_dry_run_makes_no_judge_call_and_writes_no_csv(tmp_path):
    results = _make(tmp_path, [(CVE, "SECURITY_REVIEW_REQUIRED")],
                    candidates={CVE: DIFFERENT}, references={CVE: REFERENCE})
    judge = FakeJudge()
    counts = _run(results, judge, dry_run=True)
    assert judge.calls == []
    assert counts == {"pending": 1}
    assert not (results / "judge" / "judge_results.csv").exists()


def test_files_only_one_side_touches_are_not_judged_when_the_shared_file_is_identical(tmp_path):
    results = _make(tmp_path, [(CVE, "SECURITY_REVIEW_REQUIRED")],
                    candidates={CVE: SAME + OTHER_FILE}, references={CVE: REFERENCE})
    judge = FakeJudge()
    _run(results, judge)
    row = _output(results)[0]
    assert judge.calls == []
    assert (row["bucket"], row["judgment"], row["scope"]) == (
        "partial", "structural-only", "partial")
