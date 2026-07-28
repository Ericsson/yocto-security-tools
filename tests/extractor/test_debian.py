# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Tests for Debian source patch extraction.'''
import argparse
import io
import os
import tarfile
import tempfile
from unittest import TestCase, mock

from cve_metadata_extractor.debian import (
    DebianSource,
    _match_patches_to_cve,
    diff_debian_patches,
    extract_debian_source_patches,
    extract_patches_from_tar,
    find_previous_version,
    load_debian_tracker_extended,
    load_dsa_list,
)


def _make_cve_list(entries):
    '''Build a minimal CVE list file content from entry strings.'''
    return '\n'.join(entries) + '\n'


def _make_dsa_list(entries):
    '''Build a minimal DSA list file content.'''
    return '\n'.join(entries) + '\n'


def _make_debian_tar(patches):
    '''Create a .debian.tar.xz in memory with given patches.

    patches: dict {name: content_bytes}
    Returns path to temp file.
    '''
    with tempfile.NamedTemporaryFile(suffix='.debian.tar.xz', delete=False) as tmp:
        with tarfile.open(tmp.name, 'w:xz') as tar:
            # Add series file
            series_content = '\n'.join(patches.keys()).encode()
            info = tarfile.TarInfo(name='debian/patches/series')
            info.size = len(series_content)
            tar.addfile(info, io.BytesIO(series_content))
            # Add patch files
            for name, content in patches.items():
                info = tarfile.TarInfo(name=f'debian/patches/{name}')
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
        return tmp.name


class TestLoadDsaList(TestCase):
    '''Tests for DSA list parsing.'''

    def test_parse_dsa_entry(self):
        content = _make_dsa_list([
            '[01 Jul 2024] DSA-5724-1 openssh - security update',
            '\t{CVE-2024-6387}',
            '\t[bookworm] - openssh 1:9.2p1-2+deb12u3',
        ])
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                         delete=False) as f:
            f.write(content)
            f.flush()
            result = load_dsa_list(f.name)
        os.unlink(f.name)
        self.assertIn('DSA-5724-1', result)
        self.assertEqual(result['DSA-5724-1']['package'], 'openssh')
        self.assertEqual(result['DSA-5724-1']['cves'], ['CVE-2024-6387'])
        self.assertEqual(
            result['DSA-5724-1']['fixes']['bookworm'],
            '1:9.2p1-2+deb12u3')

    def test_missing_file(self):
        self.assertEqual(load_dsa_list('/nonexistent/path'), {})


class TestLoadDebianTrackerExtended(TestCase):
    '''Tests for extended Debian tracker parsing.'''

    def _write_files(self, cve_content, dsa_content=None):
        with tempfile.NamedTemporaryFile(
                mode='w', suffix='.txt', delete=False) as cve_file:
            cve_file.write(cve_content)
            cve_file.flush()
            cve_path = cve_file.name
        dsa_path = None
        if dsa_content:
            with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.txt', delete=False) as dsa_file:
                dsa_file.write(dsa_content)
                dsa_file.flush()
                dsa_path = dsa_file.name
        return cve_path, dsa_path

    def test_fix_from_cve_entry(self):
        '''CVE with [bookworm] fix line directly in CVE entry.'''
        cve = _make_cve_list([
            'CVE-2023-51384 (desc ...)',
            '\t- openssh 1:9.6p1-1',
            '\t[bookworm] - openssh 1:9.2p1-2+deb12u2',
        ])
        cve_path, _ = self._write_files(cve)
        result = load_debian_tracker_extended(cve_path)
        os.unlink(cve_path)
        fix = result['CVE-2023-51384']['fixes']['bookworm']
        self.assertEqual(fix['pkg'], 'openssh')
        self.assertEqual(fix['version'], '1:9.2p1-2+deb12u2')

    def test_fix_from_dsa_lookup(self):
        '''CVE with DSA ref but no [bookworm] line — enriched from DSA.'''
        cve = _make_cve_list([
            'CVE-2024-6387 (desc ...)',
            '\t{DSA-5724-1}',
            '\t- openssh 1:9.7p1-7',
        ])
        dsa = _make_dsa_list([
            '[01 Jul 2024] DSA-5724-1 openssh - security update',
            '\t{CVE-2024-6387}',
            '\t[bookworm] - openssh 1:9.2p1-2+deb12u3',
        ])
        cve_path, dsa_path = self._write_files(cve, dsa)
        result = load_debian_tracker_extended(cve_path, dsa_path)
        os.unlink(cve_path)
        os.unlink(dsa_path)
        fix = result['CVE-2024-6387']['fixes']['bookworm']
        self.assertEqual(fix['pkg'], 'openssh')
        self.assertEqual(fix['version'], '1:9.2p1-2+deb12u3')

    def test_not_affected_skipped(self):
        '''CVE with <not-affected> should not have a fix entry.'''
        cve = _make_cve_list([
            'CVE-2024-6387 (desc ...)',
            '\t[bookworm] - openssh <not-affected> (reason)',
        ])
        cve_path, _ = self._write_files(cve)
        result = load_debian_tracker_extended(cve_path)
        os.unlink(cve_path)
        self.assertEqual(result['CVE-2024-6387']['fixes'], {})

    def test_unfixed_skipped(self):
        '''CVE with <unfixed> should not have a fix entry.'''
        cve = _make_cve_list([
            'CVE-2025-9999 (desc ...)',
            '\t- somepkg <unfixed>',
        ])
        cve_path, _ = self._write_files(cve)
        result = load_debian_tracker_extended(cve_path)
        os.unlink(cve_path)
        self.assertEqual(result['CVE-2025-9999']['fixes'], {})

    def test_no_tracker_entry(self):
        '''CVE not in tracker should not be in result.'''
        cve = _make_cve_list([
            'CVE-2024-0001 (desc ...)',
            '\tNOT-FOR-US: something',
        ])
        cve_path, _ = self._write_files(cve)
        result = load_debian_tracker_extended(cve_path)
        os.unlink(cve_path)
        # Entry exists but has no fixes and no notes
        self.assertEqual(result.get('CVE-2024-0001', {}).get('fixes'), {})

    def test_notes_preserved(self):
        '''NOTE lines should still be parsed.'''
        cve = _make_cve_list([
            'CVE-2024-6387 (desc ...)',
            '\tNOTE: https://example.com/fix',
        ])
        cve_path, _ = self._write_files(cve)
        result = load_debian_tracker_extended(cve_path)
        os.unlink(cve_path)
        self.assertEqual(
            result['CVE-2024-6387']['notes'],
            ['https://example.com/fix'])


class TestFindPreviousVersion(TestCase):
    '''Tests for find_previous_version.'''

    def _mock_versions(self, versions):
        return {'result': [{'version': v} for v in versions]}

    @mock.patch('cve_metadata_extractor.debian._snapshot_get')
    def test_finds_previous_in_series(self, mock_get):
        mock_get.return_value = self._mock_versions([
            '1:9.2p1-2+deb12u3',
            '1:9.2p1-2+deb12u2',
            '1:9.2p1-2+deb12u1',
            '1:9.2p1-2',
        ])
        result = find_previous_version('openssh', '1:9.2p1-2+deb12u3')
        self.assertEqual(result, '1:9.2p1-2+deb12u2')

    @mock.patch('cve_metadata_extractor.debian._snapshot_get')
    def test_falls_back_to_base(self, mock_get):
        mock_get.return_value = self._mock_versions([
            '1:9.2p1-2+deb12u1',
            '1:9.2p1-2',
        ])
        result = find_previous_version('openssh', '1:9.2p1-2+deb12u1')
        self.assertEqual(result, '1:9.2p1-2')

    @mock.patch('cve_metadata_extractor.debian._snapshot_get')
    def test_no_previous_returns_none(self, mock_get):
        mock_get.return_value = self._mock_versions([
            '1:9.2p1-2+deb12u1',
        ])
        result = find_previous_version('openssh', '1:9.2p1-2+deb12u1')
        # Base version not in list either
        self.assertIsNone(result)

    def test_non_debu_version_returns_none(self):
        '''Version without +debNNuX pattern returns None.'''
        with mock.patch('cve_metadata_extractor.debian._snapshot_get'):
            result = find_previous_version('openssh', '1:9.7p1-7')
        self.assertIsNone(result)


class TestPatchDiffExtraction(TestCase):
    '''Tests for patch extraction and diffing.'''

    def test_extract_patches_from_tar(self):
        patches = {
            'fix-a.patch': b'--- a/file\n+++ b/file\n',
            'fix-b.patch': b'--- a/other\n+++ b/other\n',
        }
        tar_path = _make_debian_tar(patches)
        result = extract_patches_from_tar(tar_path)
        os.unlink(tar_path)
        self.assertEqual(set(result.keys()), {'fix-a.patch', 'fix-b.patch'})
        self.assertEqual(result['fix-a.patch'], b'--- a/file\n+++ b/file\n')

    def test_series_file_excluded(self):
        tar_path = _make_debian_tar({'fix.patch': b'content'})
        result = extract_patches_from_tar(tar_path)
        os.unlink(tar_path)
        self.assertNotIn('series', result)

    def test_diff_finds_new_patches(self):
        fixed = {'a.patch': b'a', 'b.patch': b'b', 'c.patch': b'c'}
        previous = {'a.patch': b'a', 'b.patch': b'b'}
        result = diff_debian_patches(fixed, previous)
        self.assertEqual(list(result.keys()), ['c.patch'])

    def test_diff_no_new_patches(self):
        fixed = {'a.patch': b'a'}
        previous = {'a.patch': b'a'}
        result = diff_debian_patches(fixed, previous)
        self.assertEqual(result, {})

    def test_diff_multiple_new_patches(self):
        '''DSA fixing multiple CVEs may add multiple patches.'''
        fixed = {
            'existing.patch': b'x',
            'CVE-2023-48795.patch': b'fix1',
            'CVE-2023-51385.patch': b'fix2',
        }
        previous = {'existing.patch': b'x'}
        result = diff_debian_patches(fixed, previous)
        self.assertEqual(
            sorted(result.keys()),
            ['CVE-2023-48795.patch', 'CVE-2023-51385.patch'])

    def test_cve_named_patch(self):
        '''Patch with CVE in filename is correctly identified.'''
        fixed = {
            'old.patch': b'old',
            'CVE-2023-48795.patch': b'fix content',
        }
        previous = {'old.patch': b'old'}
        result = diff_debian_patches(fixed, previous)
        self.assertIn('CVE-2023-48795.patch', result)

    def test_non_cve_named_patch(self):
        '''Patch without CVE in filename is correctly identified.'''
        fixed = {
            'old.patch': b'old',
            'Disable-async-signal-unsafe-code.patch': b'fix',
        }
        previous = {'old.patch': b'old'}
        result = diff_debian_patches(fixed, previous)
        self.assertIn('Disable-async-signal-unsafe-code.patch', result)


class TestMatchPatchesToCve(TestCase):
    '''Tests for CVE-specific patch filtering.'''

    def test_filters_by_hash_in_content(self):
        patches = {
            'fix-a.patch': b'From abc1234 Mon Sep 17\nSubject: fix a',
            'fix-b.patch': b'From def5678 Mon Sep 17\nSubject: fix b',
        }
        result = _match_patches_to_cve(patches, {'abc1234'})
        self.assertEqual(list(result.keys()), ['fix-a.patch'])

    def test_no_hashes_returns_all(self):
        patches = {'a.patch': b'a', 'b.patch': b'b'}
        result = _match_patches_to_cve(patches, None)
        self.assertEqual(len(result), 2)

    def test_empty_hashes_returns_all(self):
        patches = {'a.patch': b'a', 'b.patch': b'b'}
        result = _match_patches_to_cve(patches, set())
        self.assertEqual(len(result), 2)

    def test_no_match_falls_back_to_all(self):
        patches = {'a.patch': b'content a', 'b.patch': b'content b'}
        result = _match_patches_to_cve(patches, {'zzz9999'})
        self.assertEqual(len(result), 2)

    def test_multiple_hashes_match_multiple_patches(self):
        patches = {
            'fix-a.patch': b'cherry-picked from abc1234',
            'fix-b.patch': b'cherry-picked from def5678',
            'unrelated.patch': b'some other fix',
        }
        result = _match_patches_to_cve(patches, {'abc1234', 'def5678'})
        self.assertEqual(sorted(result.keys()),
                         ['fix-a.patch', 'fix-b.patch'])


class TestExtractDebianSourcePatches(TestCase):
    '''Integration test for the full extraction flow.'''

    @mock.patch('cve_metadata_extractor.debian.find_previous_version')
    @mock.patch('cve_metadata_extractor.debian.download_debian_tar')
    @mock.patch('cve_metadata_extractor.debian.find_debian_tar_url')
    def test_full_flow(self, mock_find_tar, mock_download, mock_prev):
        '''End-to-end: finds new patch between two versions.'''
        prev_tar = _make_debian_tar({'old.patch': b'old'})
        fixed_tar = _make_debian_tar({
            'old.patch': b'old',
            'new-fix.patch': b'new fix content',
        })

        mock_find_tar.side_effect = [
            ('http://example.com/fixed.tar.xz', 'fixed.tar.xz'),
            ('http://example.com/prev.tar.xz', 'prev.tar.xz'),
        ]
        mock_download.side_effect = [fixed_tar, prev_tar]
        mock_prev.return_value = '1:1.0-1+deb12u1'

        with tempfile.TemporaryDirectory() as tmpdir:
            result = extract_debian_source_patches(
                'CVE-2024-1234', 'testpkg', '1:1.0-1+deb12u2', tmpdir)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['name'], 'new-fix.patch')
            self.assertTrue(os.path.exists(result[0]['path']))

        # Cleanup
        os.unlink(prev_tar)
        os.unlink(fixed_tar)

    @mock.patch('cve_metadata_extractor.debian.find_debian_tar_url')
    def test_no_tar_found(self, mock_find_tar):
        '''Gracefully returns empty when no .debian.tar.xz found.'''
        mock_find_tar.return_value = (None, None)
        with tempfile.TemporaryDirectory() as tmpdir:
            result = extract_debian_source_patches(
                'CVE-2024-9999', 'nopkg', '1:1.0-1+deb12u1', tmpdir)
        self.assertEqual(result, [])

    @mock.patch('cve_metadata_extractor.debian.find_previous_version')
    @mock.patch('cve_metadata_extractor.debian.find_debian_tar_url')
    def test_no_previous_version(self, mock_find_tar, mock_prev):
        '''Gracefully returns empty when no previous version found.'''
        mock_find_tar.return_value = (
            'http://example.com/f.tar.xz', 'f.tar.xz')
        mock_prev.return_value = None
        with tempfile.TemporaryDirectory() as tmpdir:
            result = extract_debian_source_patches(
                'CVE-2024-9999', 'pkg', '1:1.0-1+deb12u1', tmpdir)
        self.assertEqual(result, [])

    @mock.patch('cve_metadata_extractor.debian.find_previous_version')
    @mock.patch('cve_metadata_extractor.debian.download_debian_tar')
    @mock.patch('cve_metadata_extractor.debian.find_debian_tar_url')
    def test_subdirectory_patches(self, mock_find_tar, mock_download,
                                  mock_prev):
        '''Patches in subdirs (e.g. upstream/) create parent dirs.'''
        prev_tar = _make_debian_tar({'base.patch': b'base'})
        fixed_tar = _make_debian_tar({
            'base.patch': b'base',
            'upstream/0001-fix.patch': b'fix content',
        })
        mock_find_tar.side_effect = [
            ('http://example.com/fixed.tar.xz', 'fixed.tar.xz'),
            ('http://example.com/prev.tar.xz', 'prev.tar.xz'),
        ]
        mock_download.side_effect = [fixed_tar, prev_tar]
        mock_prev.return_value = '1:1.0-1+deb12u1'

        with tempfile.TemporaryDirectory() as tmpdir:
            result = extract_debian_source_patches(
                'CVE-2024-5555', 'pkg', '1:1.0-1+deb12u2', tmpdir)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]['name'], 'upstream/0001-fix.patch')
            self.assertTrue(os.path.exists(result[0]['path']))

        os.unlink(prev_tar)
        os.unlink(fixed_tar)

    @mock.patch('cve_metadata_extractor.debian.get_snapshot_srcfiles')
    def test_snapshot_404_returns_none(self, mock_srcfiles):
        '''Snapshot API 404 is handled gracefully.'''
        # pylint: disable=import-outside-toplevel
        import requests

        from cve_metadata_extractor.debian import find_debian_tar_url
        mock_srcfiles.side_effect = requests.exceptions.HTTPError('404')
        url, fname = find_debian_tar_url('curl', '7.88.1-10+deb12u10')
        self.assertIsNone(url)
        self.assertIsNone(fname)


class TestDebianSourceEnrichKnownHashes(TestCase):
    '''Hashes embedded in tracker notes feed patch matching.'''

    @mock.patch('cve_metadata_extractor.debian.extract_debian_source_patches')
    def test_note_hashes_reach_known_hashes(self, mock_extract):
        '''Regression: HASH_RE must stay unanchored for note scanning.'''
        source = DebianSource()
        source._extended = {  # pylint: disable=protected-access
            'CVE-2024-1234': {
                'fixes': {'bookworm': {'pkg': 'testpkg', 'version': '1.0-1'}},
                'notes': ['Fixed by commit abc1234def and def5678abc upstream'],
            },
        }
        args = argparse.Namespace(
            download_patches=True, cache='/tmp/cache',
            debian_release='bookworm')
        mock_extract.return_value = []

        source.enrich('CVE-2024-1234', {}, {'hashes': []}, args)

        known_hashes = mock_extract.call_args[1]['known_hashes']
        self.assertEqual(known_hashes, {'abc1234def', 'def5678abc'})
