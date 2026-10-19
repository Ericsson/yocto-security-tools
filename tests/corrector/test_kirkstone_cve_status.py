# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Kirkstone CVE status handling.

Kirkstone has no ``CVE_STATUS`` (only ``CVE_CHECK_IGNORE``) and its
``bitbake-getvar`` has no ``--ignore-undefined``.
"""
import subprocess
from unittest.mock import patch

import pytest

import cve_corrector.bitbake_ops as bitbake_ops
from cve_corrector.bitbake_ops import check_cve_status, supports_cve_status
from cve_corrector.meta_layer import cve_status_line, write_cve_status
from cve_corrector.recipe_ops import restore_bbappend_extras, save_bbappend_extras


def _proc(stdout='', rc=0):
    return subprocess.CompletedProcess([], rc, stdout=stdout, stderr='')


@pytest.fixture
def kirkstone(monkeypatch):
    """Treat the build as kirkstone (no CVE_STATUS support)."""
    monkeypatch.setattr(bitbake_ops, '_cve_status_supported', False)


# --- feature detection ---

class TestSupportsCveStatus:
    @pytest.fixture(autouse=True)
    def _unprobed(self, monkeypatch):
        monkeypatch.setattr(bitbake_ops, '_cve_status_supported', None)

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_kirkstone_prints_none(self, mock_run):
        # Kirkstone's bitbake-getvar prints "None" for an undefined flag.
        mock_run.return_value = _proc('None\n')
        assert supports_cve_status() is False

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_newer_release_has_statusmap(self, mock_run):
        mock_run.return_value = _proc('Patched\n')
        assert supports_cve_status() is True

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_failure_means_unsupported(self, mock_run):
        mock_run.return_value = _proc('', rc=1)
        assert supports_cve_status() is False

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_result_is_cached(self, mock_run):
        mock_run.return_value = _proc('Patched\n')
        supports_cve_status()
        supports_cve_status()
        assert mock_run.call_count == 1


# --- check_cve_status ---

@pytest.mark.usefixtures("kirkstone")
class TestCheckCveStatusKirkstone:
    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_listed_in_cve_check_ignore(self, mock_run):
        mock_run.return_value = _proc('CVE-2022-0001 CVE-2024-1234\n')
        assert check_cve_status('curl', 'CVE-2024-1234') == ('Ignored', 'CVE_CHECK_IGNORE')
        cmd = mock_run.call_args[0][0]
        assert cmd[:2] == ['bitbake-getvar', 'CVE_CHECK_IGNORE']
        assert '--ignore-undefined' not in cmd

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_not_listed(self, mock_run):
        mock_run.return_value = _proc('CVE-2022-0001\n')
        assert check_cve_status('curl', 'CVE-2024-1234') is None

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_cve_id_prefix_is_not_a_match(self, mock_run):
        mock_run.return_value = _proc('CVE-2024-12345\n')
        assert check_cve_status('curl', 'CVE-2024-1234') is None


# --- write_cve_status ---

class TestCveStatusLine:
    def test_newer_release_uses_cve_status(self):
        line = cve_status_line('CVE-2024-1', 'requires feature not enabled')
        assert line == ('CVE_STATUS[CVE-2024-1] = '
                        '"not-applicable-config: requires feature not enabled"')

    @pytest.mark.usefixtures("kirkstone")
    def test_kirkstone_uses_cve_check_ignore_with_reason(self):
        line = cve_status_line('CVE-2024-1', 'requires feature\nnot enabled')
        assert line == ('# CVE-2024-1: requires feature not enabled\n'
                        'CVE_CHECK_IGNORE += "CVE-2024-1"')


@pytest.mark.usefixtures("kirkstone")
@patch("cve_corrector.meta_layer._export_commit_patch")
def test_write_cve_status_kirkstone(_mock_export, tmp_path):
    bbappend = tmp_path / 'meta-core' / 'recipes-support' / 'curl' / 'curl_7.82.0.bbappend'
    bbappend.parent.mkdir(parents=True)
    bbappend.write_text('SRC_URI += "file://a.patch"\n')
    with patch("cve_corrector.meta_layer.run_cmd", return_value=0):
        assert write_cve_status(tmp_path, 'curl', 'CVE-2024-1', 'not enabled in config',
                                skip_confirm=True)
    assert bbappend.read_text().endswith(
        '# CVE-2024-1: not enabled in config\nCVE_CHECK_IGNORE += "CVE-2024-1"\n')


def test_save_restore_keeps_cve_check_ignore(tmp_path):
    bbappend = tmp_path / 'recipes-support' / 'curl' / 'curl_%.bbappend'
    bbappend.parent.mkdir(parents=True)
    bbappend.write_text(
        'SRC_URI += "file://a.patch"\n'
        '# CVE-2024-1: not enabled in config\n'
        'CVE_CHECK_IGNORE += "CVE-2024-1"\n'
        'CVE_CHECK_IGNORE += "\\\n    CVE-2024-2 \\\n"\n')
    saved = save_bbappend_extras(tmp_path, 'curl')

    # devtool rewrites the bbappend, dropping everything but its own lines
    bbappend.write_text('SRC_URI += "file://new.patch"\n')
    restore_bbappend_extras(tmp_path, 'curl', saved)

    text = bbappend.read_text()
    assert '# CVE-2024-1: not enabled in config\nCVE_CHECK_IGNORE += "CVE-2024-1"\n' in text
    assert 'CVE_CHECK_IGNORE += "\\\n    CVE-2024-2 \\\n"\n' in text
    assert 'file://a.patch' in text and 'file://new.patch' in text


def test_restore_does_not_duplicate_cve_check_ignore(tmp_path):
    bbappend = tmp_path / 'curl_%.bbappend'
    original = '# CVE-2024-1: x\nCVE_CHECK_IGNORE += "CVE-2024-1"\n'
    bbappend.write_text(original)
    saved = save_bbappend_extras(tmp_path, 'curl')
    restore_bbappend_extras(tmp_path, 'curl', saved)
    assert bbappend.read_text() == original
