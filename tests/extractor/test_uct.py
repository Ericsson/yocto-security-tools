# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Tests for the Ubuntu CVE Tracker (UCT) source extractor.'''
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from cve_metadata_extractor.uct import UctSource, load_uct_record


def _write_record(repo, subdir, cve_id, text):
    path = os.path.join(repo, subdir, cve_id)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)


class TestLoadUctRecord(unittest.TestCase):
    '''Test raw record lookup from a local UCT clone.'''

    def test_finds_active_record(self):
        '''Record in active/ is found.'''
        with tempfile.TemporaryDirectory() as repo:
            _write_record(repo, 'active', 'CVE-2023-48795', 'Candidate: CVE-2023-48795\n')
            self.assertIn('CVE-2023-48795', load_uct_record(repo, 'CVE-2023-48795'))

    def test_active_wins_over_retired(self):
        '''When both active/ and retired/ have the record, active/ wins.'''
        with tempfile.TemporaryDirectory() as repo:
            _write_record(repo, 'active', 'CVE-2023-48795', 'from-active\n')
            _write_record(repo, 'retired', 'CVE-2023-48795', 'from-retired\n')
            self.assertEqual(
                load_uct_record(repo, 'CVE-2023-48795'), 'from-active\n')

    def test_falls_back_to_retired(self):
        '''Record only in retired/ is found.'''
        with tempfile.TemporaryDirectory() as repo:
            _write_record(repo, 'retired', 'CVE-2020-0001', 'from-retired\n')
            self.assertEqual(
                load_uct_record(repo, 'CVE-2020-0001'), 'from-retired\n')

    def test_missing_record_returns_empty_string(self):
        '''No record in either directory returns ''.'''
        with tempfile.TemporaryDirectory() as repo:
            os.makedirs(os.path.join(repo, 'active'))
            self.assertEqual(load_uct_record(repo, 'CVE-2099-9999'), '')

    def test_no_repo_returns_empty_string(self):
        '''Falsy repo path returns '' without touching the filesystem.'''
        self.assertEqual(load_uct_record(None, 'CVE-2023-48795'), '')
        self.assertEqual(load_uct_record('', 'CVE-2023-48795'), '')

    def test_rejects_malformed_cve_id(self):
        '''Non-CVE-shaped id is rejected before any path join.'''
        with tempfile.TemporaryDirectory() as repo:
            self.assertEqual(load_uct_record(repo, 'not-a-cve'), '')

    def test_rejects_path_traversal_attempt(self):
        '''Path-traversal id is rejected, not joined onto the repo path.'''
        with tempfile.TemporaryDirectory() as repo:
            self.assertEqual(
                load_uct_record(repo, '../../etc/passwd'), '')


_OPENSSH_RECORD = '''Candidate: CVE-2023-48795
PublicDate: 2023-12-18
References:
 https://www.cve.org/CVERecord?id=CVE-2023-48795
Description:
 The SSH transport protocol...
Notes:
 someone> see also https://github.com/unrelated/repo/commit/deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
 for background, not a fix for this CVE
Priority: medium

Patches_openssh:
 upstream: https://github.com/openssh/openssh-portable/commit/1edb00c58f8a6875fad6a497aa2bacf37f9e6cd5
upstream_openssh: released (1:9.6p1-1)
noble_openssh: released (1:9.6p1-1)

Patches_dropbear:
 upstream: https://github.com/mkj/dropbear/commit/6e43be5c7b99dbee49dc72b6f989f29fdd7e9356
upstream_dropbear: released
'''

_NO_PATCHES_RECORD = '''Candidate: CVE-2099-0001
References:
 https://www.cve.org/CVERecord?id=CVE-2099-0001
Notes:
 nobody> nothing to see here
Priority: low
'''

_PR_RECORD = '''Candidate: CVE-2024-0001
References:

Patches_foo:
 upstream: https://github.com/test/repo/pull/42
'''


class TestUctSourceExtract(unittest.TestCase):
    '''Test UctSource.extract().'''

    def _source(self, repo):
        source = UctSource()
        source._repo = repo
        return source

    def test_extracts_hash_from_patches_region(self):
        '''upstream: commit URL in a Patches_ block yields a tagged hash.'''
        with tempfile.TemporaryDirectory() as repo:
            _write_record(repo, 'active', 'CVE-2023-48795', _OPENSSH_RECORD)
            source = self._source(repo)
            stats = {'uct_hashes': 0, 'uct_patches': 0}
            hashes, patches, series, refs = source.extract(
                'CVE-2023-48795', stats)

            hash_values = {h['hash'] for h in hashes}
            self.assertIn('1edb00c58f8a6875fad6a497aa2bacf37f9e6cd5', hash_values)
            self.assertIn('6e43be5c7b99dbee49dc72b6f989f29fdd7e9356', hash_values)
            self.assertTrue(all(h['source'] == 'uct' for h in hashes))
            self.assertTrue(all(p['source'] == 'uct' for p in patches))
            self.assertEqual(stats['uct_hashes'], 1)
            self.assertEqual(stats['uct_patches'], 1)
            self.assertTrue(series == [] or isinstance(series, list))
            self.assertTrue(len(refs) > 0)

    def test_notes_section_urls_excluded_from_hashes(self):
        '''A commit URL cited in Notes/before Patches_ never becomes a hash.'''
        with tempfile.TemporaryDirectory() as repo:
            _write_record(repo, 'active', 'CVE-2023-48795', _OPENSSH_RECORD)
            source = self._source(repo)
            stats = {'uct_hashes': 0, 'uct_patches': 0}
            hashes, _, _, refs = source.extract('CVE-2023-48795', stats)

            hash_values = {h['hash'] for h in hashes}
            self.assertNotIn(
                'deadbeefdeadbeefdeadbeefdeadbeefdeadbeef', hash_values)
            # The Notes URL is still captured as a reference, just not a hash.
            self.assertTrue(any('unrelated/repo/commit' in r['url']
                                for r in refs))

    def test_record_with_no_patches_block_returns_empty(self):
        '''No Patches_ block anywhere -> four empty lists.'''
        with tempfile.TemporaryDirectory() as repo:
            _write_record(repo, 'active', 'CVE-2099-0001', _NO_PATCHES_RECORD)
            source = self._source(repo)
            stats = {'uct_hashes': 0, 'uct_patches': 0}
            hashes, patches, series, refs = source.extract(
                'CVE-2099-0001', stats)
            self.assertEqual(hashes, [])
            self.assertEqual(patches, [])
            self.assertEqual(series, [])
            self.assertEqual(stats['uct_hashes'], 0)
            self.assertEqual(stats['uct_patches'], 0)

    def test_pr_url_in_patch_region_lands_in_series_not_hashes(self):
        '''A GitHub PR URL inside Patches_ goes to series, not hashes.'''
        with tempfile.TemporaryDirectory() as repo:
            _write_record(repo, 'active', 'CVE-2024-0001', _PR_RECORD)
            source = self._source(repo)
            stats = {'uct_hashes': 0, 'uct_patches': 0}
            with patch('cve_metadata_extractor.utils.process_pr_url') as mock_pr:
                hashes, _, _, _ = source.extract('CVE-2024-0001', stats)
                mock_pr.assert_called_once()
            self.assertEqual(hashes, [])

    def test_missing_record_returns_empty_without_exception(self):
        '''No record at all -> clean empty result, no exception.'''
        with tempfile.TemporaryDirectory() as repo:
            source = self._source(repo)
            stats = {'uct_hashes': 0, 'uct_patches': 0}
            result = source.extract('CVE-2099-9999', stats)
            self.assertEqual(result, ([], [], [], []))


class TestUctSourceDeduceComponent(unittest.TestCase):
    '''Test UctSource.deduce_component().'''

    def test_returns_first_patches_package(self):
        '''Returns the package name from the first Patches_ block.'''
        with tempfile.TemporaryDirectory() as repo:
            _write_record(repo, 'active', 'CVE-2023-48795', _OPENSSH_RECORD)
            source = UctSource()
            source._repo = repo
            self.assertEqual(
                source.deduce_component('CVE-2023-48795', repo), 'openssh')

    def test_returns_none_when_no_patches_block(self):
        '''Returns None for a record with no Patches_ block.'''
        with tempfile.TemporaryDirectory() as repo:
            _write_record(repo, 'active', 'CVE-2099-0001', _NO_PATCHES_RECORD)
            source = UctSource()
            source._repo = repo
            self.assertIsNone(
                source.deduce_component('CVE-2099-0001', repo))


class TestUctSourceSetup(unittest.TestCase):
    '''Test UctSource.setup() repo-unavailable handling.'''

    def test_repo_unavailable_warns_and_extract_stays_clean(self):
        '''ensure_data_repo() returning None logs a warning; extract() still
        works cleanly with no exception.'''
        args = MagicMock()
        args.uct_dir = '/nonexistent/uct'
        source = UctSource()
        with patch('cve_metadata_extractor.uct.ensure_data_repo',
                   return_value=None):
            with self.assertLogs('root', level='WARNING') as cm:
                source.setup(args, {'uct_url': 'https://example.invalid/uct'})
            self.assertTrue(
                any('unavailable' in m for m in cm.output))

        stats = {'uct_hashes': 0, 'uct_patches': 0}
        self.assertEqual(
            source.extract('CVE-2023-48795', stats), ([], [], [], []))

    def test_is_enabled_default(self):
        '''uct is enabled by default.'''
        args = MagicMock()
        args.no_uct = False
        self.assertTrue(UctSource().is_enabled(args))

    def test_is_disabled_with_flag(self):
        '''uct is disabled with --no-uct.'''
        args = MagicMock()
        args.no_uct = True
        self.assertFalse(UctSource().is_enabled(args))


if __name__ == '__main__':
    unittest.main()
