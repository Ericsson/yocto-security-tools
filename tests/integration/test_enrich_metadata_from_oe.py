# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for recovering upstream fix commits from OE-Core's own CVE patches.

Regression guard for a real gap: ``--roster balanced`` failed with exit 6
(``EXIT_METADATA_ERROR``) because 11 roster CVEs were absent from the metadata
fixture. ``cve-metadata-extractor`` resolved most of them, but for several the
commit it found was *not* the one OE-Core backported, and for
``python3-zipp``'s ``CVE-2024-5569.patch`` the only record of the real commit is
the ``From <sha>`` header — its ``Upstream-Status: Backport`` has no URL, so the
original ``UPSTREAM_RE``-only implementation returned nothing.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from tests.integration.enrich_metadata_from_oe import (
    find_hashes_from_oe,
    find_hashes_from_patch_headers,
    find_hashes_from_upstream_status,
)

_SCRIPT = (Path(__file__).resolve().parent.parent
           / 'integration' / 'enrich_metadata_from_oe.py')

# Shape of meta/recipes-devtools/python/python3-zipp/CVE-2024-5569.patch:
# a From header, and Upstream-Status: Backport with NO bracketed URL.
ZIPP_PATCH = """\
From b1804347ec2db16452a7bff2b469d2c66776b904 Mon Sep 17 00:00:00 2001
From: "Jason R. Coombs" <jaraco@jaraco.com>
Date: Mon, 1 Jul 2024 12:00:00 -0400
Subject: [PATCH] fix CVE-2024-5569

Upstream-Status: Backport
CVE: CVE-2024-5569
---
 zipp/__init__.py | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/zipp/__init__.py b/zipp/__init__.py
--- a/zipp/__init__.py
+++ b/zipp/__init__.py
@@ -1 +1 @@
-old
+new
"""

# Shape of a patch that records the URL instead (the case the original
# implementation handled).
URL_ONLY_PATCH = """\
Subject: [PATCH] fix things

Upstream-Status: Backport [https://github.com/gwsw/less/commit/007521ac3c95bc76e3d59c6dbfe75d06c8075c33]
CVE: CVE-2024-32487
---
"""

BOTH_PATCH = """\
From 4d4547cf13cca820ff7e0f859ba83e1a610b9fd0 Mon Sep 17 00:00:00 2001
From: Someone <a@b.c>
Subject: [PATCH] fix

Upstream-Status: Backport [https://github.com/acpica/acpica/commit/4d4547cf13cca820ff7e0f859ba83e1a610b9fd0]
CVE: CVE-2024-24856
---
"""


@pytest.fixture
def meta(tmp_path):
    """A minimal OE meta layer containing one patch per CVE."""
    root = tmp_path / 'meta'
    for rel, cve, body in (
        ('recipes-devtools/python/python3-zipp', 'CVE-2024-5569', ZIPP_PATCH),
        ('recipes-extended/less/files', 'CVE-2024-32487', URL_ONLY_PATCH),
        ('recipes-extended/acpica/files', 'CVE-2024-24856', BOTH_PATCH),
    ):
        d = root / rel
        d.mkdir(parents=True, exist_ok=True)
        (d / f'{cve}.patch').write_text(body, encoding='utf-8')
    return root


class TestFromHeaderFallback:
    """The gap that made CVE-2024-5569 unresolvable."""

    def test_from_header_hash_is_found(self, meta):
        found = find_hashes_from_patch_headers('CVE-2024-5569', meta)
        assert [h['hash'] for h in found] == [
            'b1804347ec2db16452a7bff2b469d2c66776b904']
        assert found[0]['source'] == 'oe_patch_header'
        assert found[0]['patch'] == 'CVE-2024-5569.patch'

    def test_upstream_status_alone_finds_nothing_for_zipp(self, meta):
        """Reproduces the original bug: no bracketed URL, so no hash."""
        assert find_hashes_from_upstream_status('CVE-2024-5569', meta) == []

    def test_combined_lookup_recovers_zipp(self, meta):
        """The combined entry point must succeed where the URL form fails."""
        assert [h['hash'] for h in find_hashes_from_oe('CVE-2024-5569', meta)] == [
            'b1804347ec2db16452a7bff2b469d2c66776b904']

    def test_author_from_line_is_not_mistaken_for_a_sha(self, meta):
        """``From: "Jason R. Coombs" <...>`` must not parse as a commit."""
        for h in find_hashes_from_patch_headers('CVE-2024-5569', meta):
            assert h['hash'] != 'Jason'
            assert all(c in '0123456789abcdef' for c in h['hash'])


class TestUpstreamStatusStillWorks:
    def test_bracketed_url_hash_is_found(self, meta):
        found = find_hashes_from_upstream_status('CVE-2024-32487', meta)
        assert [h['hash'] for h in found] == [
            '007521ac3c95bc76e3d59c6dbfe75d06c8075c33']
        assert found[0]['source'] == 'oe_patch'

    def test_url_only_patch_found_via_combined_lookup(self, meta):
        found = find_hashes_from_oe('CVE-2024-32487', meta)
        assert [h['hash'] for h in found] == [
            '007521ac3c95bc76e3d59c6dbfe75d06c8075c33']


class TestDeduplication:
    def test_same_commit_in_header_and_url_yields_one_hash(self, meta):
        """A patch recording the same sha both ways must not double-count."""
        found = find_hashes_from_oe('CVE-2024-24856', meta)
        assert len(found) == 1
        assert found[0]['hash'] == '4d4547cf13cca820ff7e0f859ba83e1a610b9fd0'
        # The Upstream-Status URL is the cherry-pickable reference, so it wins.
        assert found[0]['source'] == 'oe_patch'

    def test_url_hashes_come_before_header_only_hashes(self, tmp_path):
        """Ordering guard: a From-header sha is a last resort, not a primary.

        Leading with header SHAs turned 5 clean corrector runs into 5 conflicts
        (CVE-2024-5569, CVE-2025-68121, CVE-2025-11687, CVE-2025-32051,
        CVE-2025-46805), because a header sha is whatever tree the maintainer
        ran ``git format-patch`` in and often does not exist upstream.
        """
        d = tmp_path / 'meta' / 'files'
        d.mkdir(parents=True)
        (d / 'CVE-2025-0001.patch').write_text(
            "From aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa Mon Sep 17 "
            "00:00:00 2001\n"
            "Upstream-Status: Backport [https://example.com/commit/"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb]\n",
            encoding='utf-8')
        assert [h['hash'] for h in find_hashes_from_oe(
            'CVE-2025-0001', tmp_path / 'meta')] == [
            'b' * 40, 'a' * 40]


class TestNoMatch:
    def test_absent_cve_returns_empty(self, meta):
        assert find_hashes_from_oe('CVE-1999-9999', meta) == []

    def test_missing_meta_dir_returns_empty(self, tmp_path):
        assert find_hashes_from_oe('CVE-2024-5569', tmp_path / 'nope') == []


class TestScriptEntryPoint:
    def test_only_fills_entries_without_hashes(self, meta, tmp_path):
        """Existing hashes are authoritative and must not be overwritten."""
        path = tmp_path / 'meta.json'
        path.write_text(json.dumps({
            'CVE-2024-5569': {'name': 'python3-zipp', 'hashes': []},
            'CVE-2024-32487': {'name': 'less', 'hashes': ['keepme']},
        }), encoding='utf-8')
        result = subprocess.run(
            [sys.executable, str(_SCRIPT), str(path), str(meta)],
            capture_output=True, text=True, check=True)
        data = json.loads(path.read_text(encoding='utf-8'))
        assert data['CVE-2024-5569']['hashes'] == [
            'b1804347ec2db16452a7bff2b469d2c66776b904']
        assert data['CVE-2024-32487']['hashes'] == ['keepme']
        assert 'CVE-2024-5569' in result.stdout

    def test_reports_when_nothing_found(self, tmp_path):
        path = tmp_path / 'meta.json'
        path.write_text(json.dumps({'CVE-1999-9999': {'hashes': []}}),
                        encoding='utf-8')
        result = subprocess.run(
            [sys.executable, str(_SCRIPT), str(path), str(tmp_path / 'meta')],
            capture_output=True, text=True, check=True)
        assert 'No new hashes found' in result.stdout
