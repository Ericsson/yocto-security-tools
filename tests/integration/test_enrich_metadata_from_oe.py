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
    missing_upstream_hashes,
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


class TestCorrectExisting:
    """``--correct-existing`` repairs entries whose hashes are all wrong.

    Tracker data can name a release commit (u-boot's CVE-2025-24857 carried
    only "Prepare v2017.11"), a different project's commit (wpa-supplicant's
    CVE-2024-3596 carried 28 FreeRADIUS commits), or one commit of a series
    (binutils' CVE-2025-1153 needs three, including a partial revert). None of
    those are visible without comparing against what OE-Core actually
    backported.
    """

    def _run(self, path, meta, *extra):
        return subprocess.run(
            [sys.executable, str(_SCRIPT), str(path), str(meta), *extra],
            capture_output=True, text=True, check=True)

    def test_wrong_hash_is_corrected_and_kept_as_fallback(self, meta, tmp_path):
        """A single ground-truth commit is prepended, the guess kept behind it."""
        truth = find_hashes_from_upstream_status('CVE-2024-24856', meta)
        path = tmp_path / 'meta.json'
        path.write_text(json.dumps({
            'CVE-2024-24856': {'name': 'acpica', 'hashes': ['wrongguess']},
        }), encoding='utf-8')
        self._run(path, meta, '--correct-existing')
        entry = json.loads(path.read_text(encoding='utf-8'))['CVE-2024-24856']
        # Ground truth first, so cve-corrector tries it before the guess...
        assert entry['hashes'][0] == truth[0]['hash']
        # ...and the original is retained rather than discarded.
        assert 'wrongguess' in entry['hashes']
        # One commit is not a chain, so no series is invented.
        assert not entry.get('series')

    def test_multiple_patches_become_an_ordered_series(self, tmp_path):
        """Several Upstream-Status patches are a chain, not alternatives.

        cve-corrector treats ``hashes`` as alternatives and stops at the first
        that applies; for binutils' CVE-2025-1153 that would leave a partial
        fix, since the third patch reverts part of the first. Recording a
        series makes apply_series require all of them, in order.
        """
        root = tmp_path / 'meta' / 'recipes-devtools' / 'binutils'
        root.mkdir(parents=True)
        # Numeric prefixes are how OE orders them in SRC_URI; sorted() on the
        # filename must reproduce that order.
        for n, sha in (
            ('0019-CVE-2025-1153-1.patch', 'a' * 40),
            ('0020-CVE-2025-1153-2.patch', 'b' * 40),
            ('0021-CVE-2025-1153-3.patch', 'c' * 40),
        ):
            (root / n).write_text(
                'Upstream-Status: Backport '
                f'[https://sourceware.org/git/?p=binutils-gdb.git;a=commit;h={sha}]\n',
                encoding='utf-8')
        path = tmp_path / 'meta.json'
        path.write_text(json.dumps({
            'CVE-2025-1153': {'name': 'binutils', 'hashes': ['oldguess']},
        }), encoding='utf-8')
        result = self._run(path, tmp_path / 'meta', '--correct-existing')
        entry = json.loads(path.read_text(encoding='utf-8'))['CVE-2025-1153']

        assert entry['series'][0]['commits'] == ['a' * 40, 'b' * 40, 'c' * 40]
        assert entry['series'][0]['pull_url'] == 'oe_patch:0019-CVE-2025-1153-1.patch'
        # The chain must NOT be scattered into `hashes`, where the corrector
        # would treat each commit as a standalone alternative.
        assert entry['hashes'] == ['oldguess']
        assert 'SERIES' in result.stdout

    def test_prerequisite_chain_becomes_a_series_when_fix_already_recorded(
            self, tmp_path):
        """A chain stays a chain even if the entry already lists part of it.

        Regression test for setuptools' CVE-2025-47273. OE-Core ships
        ``CVE-2025-47273-pre1.patch`` (a refactor that extracts the helper) and
        ``CVE-2025-47273.patch`` (the real guard), which must be applied in
        that order. The entry already carried the fix commit, so only the
        prerequisite was *missing* -- and keying the series/hashes decision off
        the missing subset made it a single prepended alternative. The
        corrector then failed to apply either commit alone and fell back to
        shipping the refactor as the security fix.

        The decision must key off the full chain OE-Core ships, not the subset
        the entry lacks.
        """
        root = tmp_path / 'meta' / 'recipes-devtools' / 'python'
        root.mkdir(parents=True)
        # The real shas: a hash made only of digits is rejected by the URL
        # parser (it would otherwise swallow PR numbers), so the fixture has to
        # use realistic hex.
        pre = 'd8390feaa99091d1ba9626bec0e4ba7072fc507a'
        fix = '250a6d17978f9f6ac3ac887091f2d32886fbbb0b'
        # '-pre1.patch' sorts before '.patch', which is the order OE applies.
        for name, sha in (('CVE-2025-47273-pre1.patch', pre),
                          ('CVE-2025-47273.patch', fix)):
            (root / name).write_text(
                f'Upstream-Status: Backport [https://github.com/pypa/setuptools/commit/{sha}]\n',
                encoding='utf-8')
        path = tmp_path / 'meta.json'
        # The entry already knows the real fix -- but not that it needs the
        # prerequisite first.
        path.write_text(json.dumps({
            'CVE-2025-47273': {'name': 'python3-setuptools', 'hashes': [fix]},
        }), encoding='utf-8')

        result = self._run(path, tmp_path / 'meta', '--correct-existing')
        entry = json.loads(path.read_text(encoding='utf-8'))['CVE-2025-47273']

        assert entry['series'], 'the dependent pair was not recorded as a series'
        assert entry['series'][0]['commits'] == [pre, fix]
        assert entry['series'][0]['pull_url'] == 'oe_patch:CVE-2025-47273-pre1.patch'
        # Neither commit may remain in `hashes`: both belong to the chain, and
        # a standalone alternative is what shipped the refactor as the fix.
        assert entry['hashes'] == []
        assert 'SERIES' in result.stdout

    def test_chain_already_recorded_as_a_series_is_left_alone(self, tmp_path):
        """A correct series is not rewritten or duplicated on a re-run."""
        root = tmp_path / 'meta' / 'files'
        root.mkdir(parents=True)
        one, two = 'a' * 40, 'b' * 40
        for name, sha in (('CVE-2025-0003-1.patch', one),
                          ('CVE-2025-0003-2.patch', two)):
            (root / name).write_text(
                f'Upstream-Status: Backport [https://github.com/o/r/commit/{sha}]\n',
                encoding='utf-8')
        path = tmp_path / 'meta.json'
        path.write_text(json.dumps({
            'CVE-2025-0003': {
                'name': 'thing', 'hashes': [one, two],
                'series': [{'pull_url': 'oe_patch:CVE-2025-0003-1.patch',
                            'commits': [one, two]}],
            },
        }), encoding='utf-8')

        self._run(path, tmp_path / 'meta', '--correct-existing')
        entry = json.loads(path.read_text(encoding='utf-8'))['CVE-2025-0003']

        assert len(entry['series']) == 1, 'series was duplicated on re-run'
        assert entry['series'][0]['commits'] == [one, two]

    def test_chain_commits_are_stripped_from_hashes(self, tmp_path):
        """A chain commit must never also be a standalone alternative.

        For a metadata-driven series the corrector leaves
        ``require_all_commits`` False, so a failed series falls back to
        ``apply_single_commits`` over ``hashes``. If the chain's commits are
        also listed there, that fallback applies one of them alone — the exact
        partial fix the series exists to prevent. An earlier enrichment run
        left entries in this state, so the cleanup must happen even when the
        series itself is already correct.
        """
        root = tmp_path / 'meta' / 'files'
        root.mkdir(parents=True)
        one, two = 'ab' * 20, 'cd' * 20
        for name, sha in (('CVE-2025-0004-1.patch', one),
                          ('CVE-2025-0004-2.patch', two)):
            (root / name).write_text(
                f'Upstream-Status: Backport [https://github.com/o/r/commit/{sha}]\n',
                encoding='utf-8')
        path = tmp_path / 'meta.json'
        path.write_text(json.dumps({
            'CVE-2025-0004': {
                'name': 'thing',
                # The chain is correct here, but every commit also leaks into
                # `hashes` as an alternative.
                'hashes': [one, two, 'unrelatedguess'],
                'series': [{'pull_url': 'oe_patch:CVE-2025-0004-1.patch',
                            'commits': [one, two]}],
            },
        }), encoding='utf-8')

        self._run(path, tmp_path / 'meta', '--correct-existing')
        entry = json.loads(path.read_text(encoding='utf-8'))['CVE-2025-0004']

        assert entry['series'][0]['commits'] == [one, two]
        assert len(entry['series']) == 1, 'series was duplicated'
        assert entry['hashes'] == ['unrelatedguess'], (
            'chain commits are still offered as standalone alternatives')

    def test_series_is_prepended_ahead_of_existing_series(self, tmp_path):
        root = tmp_path / 'meta' / 'files'
        root.mkdir(parents=True)
        for n, sha in (('CVE-2025-0002-1.patch', 'd' * 40),
                       ('CVE-2025-0002-2.patch', 'e' * 40)):
            (root / n).write_text(
                f'Upstream-Status: Backport [https://github.com/o/r/commit/{sha}]\n',
                encoding='utf-8')
        path = tmp_path / 'meta.json'
        path.write_text(json.dumps({
            'CVE-2025-0002': {'name': 'r', 'hashes': ['x'],
                              'series': [{'pull_url': 'old', 'commits': ['y']}]},
        }), encoding='utf-8')
        self._run(path, tmp_path / 'meta', '--correct-existing')
        entry = json.loads(path.read_text(encoding='utf-8'))['CVE-2025-0002']
        assert [s['pull_url'] for s in entry['series']] == [
            'oe_patch:CVE-2025-0002-1.patch', 'old']

    def test_default_run_leaves_wrong_hashes_alone(self, meta, tmp_path):
        """Without the flag, behaviour is unchanged (existing hashes win)."""
        path = tmp_path / 'meta.json'
        path.write_text(json.dumps({
            'CVE-2024-24856': {'name': 'acpica', 'hashes': ['wrongguess']},
        }), encoding='utf-8')
        self._run(path, meta)
        data = json.loads(path.read_text(encoding='utf-8'))
        assert data['CVE-2024-24856']['hashes'] == ['wrongguess']

    def test_entry_already_holding_ground_truth_is_untouched(self, meta, tmp_path):
        """No churn for the 84-of-89 entries that were already correct."""
        truth = find_hashes_from_upstream_status('CVE-2024-24856', meta)
        assert truth, 'fixture should expose an Upstream-Status hash'
        path = tmp_path / 'meta.json'
        original = [truth[0]['hash'], 'extra-series-commit']
        path.write_text(json.dumps({
            'CVE-2024-24856': {'name': 'acpica', 'hashes': list(original)},
        }), encoding='utf-8')
        result = self._run(path, meta, '--correct-existing')
        data = json.loads(path.read_text(encoding='utf-8'))
        assert data['CVE-2024-24856']['hashes'] == original
        assert 'CVE-2024-24856' not in result.stdout

    def test_short_recorded_hash_counts_as_covering_the_full_one(self, meta, tmp_path):
        """A prefix match must not be treated as a missing commit."""
        truth = find_hashes_from_upstream_status('CVE-2024-24856', meta)
        path = tmp_path / 'meta.json'
        path.write_text(json.dumps({
            'CVE-2024-24856': {'name': 'acpica',
                               'hashes': [truth[0]['hash'][:12]]},
        }), encoding='utf-8')
        self._run(path, meta, '--correct-existing')
        data = json.loads(path.read_text(encoding='utf-8'))
        assert data['CVE-2024-24856']['hashes'] == [truth[0]['hash'][:12]]

    def test_missing_upstream_hashes_helper(self, meta):
        entry = {'hashes': ['somethingelse']}
        missing = missing_upstream_hashes('CVE-2024-24856', entry, meta)
        assert [h['hash'] for h in missing] == [
            '4d4547cf13cca820ff7e0f859ba83e1a610b9fd0']

    def test_helper_reports_nothing_when_covered(self, meta):
        entry = {'hashes': ['4d4547cf13cca820ff7e0f859ba83e1a610b9fd0']}
        assert missing_upstream_hashes('CVE-2024-24856', entry, meta) == []
