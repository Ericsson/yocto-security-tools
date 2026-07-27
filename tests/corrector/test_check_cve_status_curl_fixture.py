# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Regression tests for check_cve_status using real-world CVE_STATUS output.

Fixture values below were captured by running ``bitbake-getvar CVE_STATUS
-f <cve> -r curl --value --ignore-undefined`` against the real curl_8.7.1.bb
recipe in a Yocto Scarthgap oe-core checkout, whose CVE_STATUS entries are:

    CVE_STATUS[CVE-2024-32928] = "ignored: CURLOPT_SSL_VERIFYPEER was disabled
        on google cloud services causing a potential man in the middle attack"
    CVE_STATUS[CVE-2025-0725] = "not-applicable-config: gzip decompression of
        content-encoded HTTP responses with the `CURLOPT_ACCEPT_ENCODING`
        option, using zlib 1.2.0.3 or older"
    CVE_STATUS[CVE-2025-5025] = "${@bb.utils.contains('PACKAGECONFIG',
        'openssl', 'not-applicable-config: applicable only with
        wolfssl','unpatched',d)}"
    CVE_STATUS[CVE-2025-10966] = same conditional pattern as CVE-2025-5025

These exercise real conditional (PACKAGECONFIG-dependent) CVE_STATUS values,
which bitbake-getvar fully expands before we ever see the string — a case
synthetic fixtures tend to miss.
"""
from unittest.mock import MagicMock, patch

from cve_corrector.bitbake_ops import check_cve_status


@patch("cve_corrector.bitbake_ops.run_cmd_capture")
def test_curl_cve_2024_32928_ignored(mock_run):
    """Plain 'ignored:' reason maps to Ignored."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="ignored: CURLOPT_SSL_VERIFYPEER was disabled on google cloud "
               "services causing a potential man in the middle attack\n")
    state, raw = check_cve_status("curl", "CVE-2024-32928")
    assert state == "Ignored"
    assert "CURLOPT_SSL_VERIFYPEER" in raw


@patch("cve_corrector.bitbake_ops.run_cmd_capture")
def test_curl_cve_2025_0725_not_applicable_config(mock_run):
    """'not-applicable-config:' reason maps to Ignored."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="not-applicable-config: gzip decompression of content-encoded "
               "HTTP responses with the `CURLOPT_ACCEPT_ENCODING` option, "
               "using zlib 1.2.0.3 or older\n")
    state, raw = check_cve_status("curl", "CVE-2025-0725")
    assert state == "Ignored"
    assert "zlib" in raw


@patch("cve_corrector.bitbake_ops.run_cmd_capture")
def test_curl_cve_2025_5025_expanded_packageconfig_conditional(mock_run):
    """CVE_STATUS set via bb.utils.contains() is expanded by bitbake-getvar
    before we parse it — we only ever see the resolved string."""
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="not-applicable-config: applicable only with wolfssl\n")
    state, raw = check_cve_status("curl", "CVE-2025-5025")
    assert state == "Ignored"
    assert raw == "not-applicable-config: applicable only with wolfssl"


@patch("cve_corrector.bitbake_ops.run_cmd_capture")
def test_curl_cve_2025_5025_other_packageconfig_branch_is_unpatched(mock_run):
    """The same conditional's other branch ('unpatched') must not be
    treated as Ignored — the corrector should still attempt the backport."""
    mock_run.return_value = MagicMock(returncode=0, stdout="unpatched\n")
    state, raw = check_cve_status("curl", "CVE-2025-5025")
    assert state == "Unpatched"
    assert raw == "unpatched"


@patch("cve_corrector.bitbake_ops.run_cmd_capture")
def test_curl_cve_2025_10966_not_applicable_config(mock_run):
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="not-applicable-config: applicable only with wolfssl\n")
    state, raw = check_cve_status("curl", "CVE-2025-10966")
    assert state == "Ignored"


@patch("cve_corrector.bitbake_ops.run_cmd_capture")
def test_curl_cve_2026_9547_no_status_set_returns_none(mock_run):
    """CVE-2026-9547 (from cve-metadata-all.json) has no CVE_STATUS entry in
    curl_8.7.1.bb — bitbake-getvar --ignore-undefined returns an empty
    value, and the corrector must proceed with the normal backport flow."""
    mock_run.return_value = MagicMock(returncode=0, stdout="\n")
    assert check_cve_status("curl", "CVE-2026-9547") is None
