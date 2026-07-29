# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector.ptest — ptest operations."""
from unittest.mock import MagicMock, patch

import pytest

from cve_corrector.ptest import (
    check_ptest_in_recipe,
    compare_ptest_results,
    enable_ptest,
    run_ptest,
    summarize_ptest_log,
)
from cve_corrector.state import BuildPreexistingError


class TestEnablePtest:
    @patch("cve_corrector.ptest.run_cmd_capture")
    @patch("cve_corrector.ptest.get_build_path")
    def test_appends_when_missing(self, mock_bp, mock_run, tmp_path):
        mock_bp.return_value = tmp_path
        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "local.conf").write_text("# config\n")
        mock_run.return_value = MagicMock(stdout="DISTRO_FEATURES=opengl")
        enable_ptest()
        assert "ptest" in (tmp_path / "conf" / "local.conf").read_text()

    @patch("cve_corrector.ptest.run_cmd_capture")
    @patch("cve_corrector.ptest.get_build_path")
    def test_skips_when_present(self, mock_bp, mock_run, tmp_path):
        mock_bp.return_value = tmp_path
        (tmp_path / "conf").mkdir()
        conf = tmp_path / "conf" / "local.conf"
        conf.write_text("# config\n")
        mock_run.return_value = MagicMock(stdout="DISTRO_FEATURES=ptest opengl")
        enable_ptest()
        assert conf.read_text() == "# config\n"


class TestCheckPtestInRecipe:
    @patch("cve_corrector.ptest.run_cmd_capture")
    def test_enabled(self, mock_run):
        mock_run.return_value = MagicMock(stdout='PTEST_ENABLED="1"')
        assert check_ptest_in_recipe("busybox") is True

    @patch("cve_corrector.ptest.run_cmd_capture")
    def test_disabled(self, mock_run):
        mock_run.return_value = MagicMock(stdout='PTEST_ENABLED=""')
        assert check_ptest_in_recipe("busybox") is False


class TestRunPtest:
    @patch("cve_corrector.ptest.check_ptest_in_recipe", return_value=False)
    def test_no_ptest(self, _):
        assert run_ptest("busybox") is None

    @patch("cve_corrector.ptest.run_cmd", return_value=0)
    @patch("cve_corrector.ptest.run_cmd_capture")
    @patch("cve_corrector.ptest.check_ptest_in_recipe", return_value=True)
    @patch("cve_corrector.ptest.get_build_path")
    def test_full_run_with_results(self, mock_bp, mock_check, mock_capture, mock_cmd, tmp_path):
        mock_bp.return_value = tmp_path
        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "local.conf").write_text(
            "CORE_IMAGE_EXTRA_INSTALL = \"old\"\n")
        mock_capture.return_value = MagicMock(stdout="testimage enabled")

        # Create ptest log as a file (not directory)
        log_dir = (tmp_path / "tmp-glibc" / "work" / "x86" /
                   "core-image-minimal" / "1.0" / "testimage" /
                   "ptest_log")
        log_dir.mkdir(parents=True)
        log_file = log_dir / "busybox"
        log_file.write_text("PASS: test1\nPASS: test2\nFAIL: test3\nSKIP: test4")

        result = run_ptest("busybox")
        assert result is not None
        assert "PASSED: 2" in result
        assert "FAILED: 1" in result

    @patch("cve_corrector.ptest.run_cmd")
    @patch("cve_corrector.ptest.run_cmd_capture")
    @patch("cve_corrector.ptest.check_ptest_in_recipe", return_value=True)
    @patch("cve_corrector.ptest.get_build_path")
    def test_build_failure_exits(self, mock_bp, mock_check, mock_capture, mock_cmd, tmp_path):
        mock_bp.return_value = tmp_path
        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "local.conf").write_text("# config\n")
        mock_capture.return_value = MagicMock(stdout="testimage enabled")
        mock_cmd.return_value = 1  # build fails
        with pytest.raises(BuildPreexistingError):
            run_ptest("busybox")

    @patch("cve_corrector.ptest.run_cmd")
    @patch("cve_corrector.ptest.run_cmd_capture")
    @patch("cve_corrector.ptest.check_ptest_in_recipe", return_value=True)
    @patch("cve_corrector.ptest.get_build_path")
    def test_testimage_timeout(self, mock_bp, mock_check, mock_capture, mock_cmd, tmp_path):
        mock_bp.return_value = tmp_path
        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "local.conf").write_text("# config\n")
        mock_capture.return_value = MagicMock(stdout="testimage enabled")
        mock_cmd.side_effect = [0, -1]  # build ok, testimage timeout
        result = run_ptest("busybox")
        assert result is None

    @patch("cve_corrector.ptest.run_cmd", return_value=0)
    @patch("cve_corrector.ptest.run_cmd_capture")
    @patch("cve_corrector.ptest.check_ptest_in_recipe", return_value=True)
    @patch("cve_corrector.ptest.get_build_path")
    def test_no_ptest_logs(self, mock_bp, mock_check, mock_capture, mock_cmd, tmp_path):
        mock_bp.return_value = tmp_path
        (tmp_path / "conf").mkdir()
        (tmp_path / "conf" / "local.conf").write_text("# config\n")
        mock_capture.return_value = MagicMock(stdout="testimage enabled")
        result = run_ptest("busybox")
        assert result is None

    @patch("cve_corrector.ptest.run_cmd", return_value=0)
    @patch("cve_corrector.ptest.run_cmd_capture")
    @patch("cve_corrector.ptest.check_ptest_in_recipe", return_value=True)
    @patch("cve_corrector.ptest.get_build_path")
    def test_adds_testimage_config(self, mock_bp, mock_check, mock_capture, mock_cmd, tmp_path):
        mock_bp.return_value = tmp_path
        (tmp_path / "conf").mkdir()
        conf = tmp_path / "conf" / "local.conf"
        conf.write_text("# config\n")
        # First call checks IMAGE_CLASSES — return no testimage
        mock_capture.return_value = MagicMock(stdout="IMAGE_CLASSES = ''")
        run_ptest("busybox")
        # After run, local.conf should be restored to original
        content = conf.read_text()
        assert content == "# config\n"


# A trimmed excerpt of the real ptest-runner.log that surfaced this bug:
# the jq ptest hangs and is killed by the per-test timeout before it can
# print a PASS:/FAIL: result line for itself. Only its "optionaltest"
# sub-case reported PASS before the kill.
_JQ_TIMEOUT_LOG = """START: ptest-runner
2026-07-29T07:39
BEGIN: /usr/lib/jq/ptest
PASS: optionaltest
Timeout! System state:
Collected system state:
ERROR: Exited from signal Killed (9)
DURATION: 451
TIMEOUT: /usr/lib/jq/ptest
END: /usr/lib/jq/ptest
2026-07-29T07:46
STOP: ptest-runner
TOTAL: 1 FAIL: 2
"""


class TestSummarizePtestLog:
    def test_real_format_uses_single_colon(self):
        """ptest-runner emits 'PASS: name'/'FAIL: name'/'SKIP: name' (see
        test-manual/ptest.rst), not 'PASSED:'/'FAILED:'/'SKIPPED:'. Counting
        the wrong substrings means real logs always summarize as 0/0/0."""
        result = summarize_ptest_log("PASS: t1\nPASS: t2\nFAIL: t3\nSKIP: t4")
        assert "PASSED: 2" in result
        assert "FAILED: 1" in result
        assert "SKIPPED: 1" in result

    def test_killed_test_counted_as_aborted_not_silently_passing(self):
        """A ptest killed by the per-test timeout never emits a PASS/FAIL
        line for itself. It must show up as ABORTED, not be invisible."""
        result = summarize_ptest_log(_JQ_TIMEOUT_LOG)
        assert "PASSED: 1" in result   # optionaltest
        assert "FAILED: 0" in result  # jq itself never reported FAIL
        assert "ABORTED: 1" in result  # but it was killed — must be visible

    def test_runner_summary_line_not_mistaken_for_a_result(self):
        """The aggregate 'TOTAL: 1 FAIL: 2' summary line ptest-runner
        prints at the end must not be parsed as an individual FAIL: result
        (it is not anchored at line start in the same way and belongs to
        the runner, not a test case)."""
        result = summarize_ptest_log(_JQ_TIMEOUT_LOG)
        assert "Failing cases" not in result

    def test_incomplete_run_flagged_as_unreliable(self):
        """If STOP: ptest-runner is never reached (e.g. QEMU crashed before
        the runner finished), the PASS/FAIL counts are truncated and must
        be flagged rather than reported as a clean result."""
        truncated = _JQ_TIMEOUT_LOG.replace("STOP: ptest-runner\n", "")
        result = summarize_ptest_log(truncated)
        assert result.startswith("WARNING:")

    def test_complete_run_not_flagged(self):
        result = summarize_ptest_log(_JQ_TIMEOUT_LOG)
        assert not result.startswith("WARNING:")


class TestComparePtestResults:
    def test_aborted_increase_is_a_regression(self):
        before = "PASSED: 10, FAILED: 0, SKIPPED: 0, ABORTED: 0"
        after = "PASSED: 9, FAILED: 0, SKIPPED: 0, ABORTED: 1"
        assert compare_ptest_results(before, after) is False

    def test_same_aborted_count_not_a_regression(self):
        before = "PASSED: 9, FAILED: 0, SKIPPED: 0, ABORTED: 1"
        after = "PASSED: 9, FAILED: 0, SKIPPED: 0, ABORTED: 1"
        assert compare_ptest_results(before, after) is True

    def test_incomplete_after_run_is_a_regression(self):
        """An after-run summary flagged WARNING (never reached STOP:
        ptest-runner) is unreliable and must not be accepted as "no
        regression" just because its visible counts look unchanged."""
        before = "PASSED: 10, FAILED: 0, SKIPPED: 0, ABORTED: 0"
        after = summarize_ptest_log(_JQ_TIMEOUT_LOG.replace("STOP: ptest-runner\n", ""))
        assert compare_ptest_results(before, after) is False
