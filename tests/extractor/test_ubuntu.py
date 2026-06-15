# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Tests for Ubuntu source extractor.'''
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from cve_metadata_extractor.ubuntu import (
    UbuntuSource,
    extract_from_ubuntu_response,
    get_ubuntu_cve,
)


@patch('cve_metadata_extractor.ubuntu.time.sleep')
class TestGetUbuntuCve(unittest.TestCase):
    '''Test Ubuntu API client with caching.'''

    def test_caches_response(self, _mock_sleep):
        '''API response is cached to file.'''
        from shared.json_cache import cache_exists
        with tempfile.TemporaryDirectory() as tmpdir:
            ubuntu_data = {'id': 'CVE-2026-35386', 'patches': {}}
            with patch('cve_metadata_extractor.ubuntu.requests.get') as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = ubuntu_data
                mock_resp.raise_for_status = MagicMock()
                mock_get.return_value = mock_resp

                result = get_ubuntu_cve(tmpdir, 'CVE-2026-35386')
                self.assertEqual(result, ubuntu_data)
                cache_file = os.path.join(tmpdir, 'CVE-2026-35386-ubuntu.json')
                self.assertTrue(cache_exists(cache_file))

    def test_uses_cache_on_second_call(self, _mock_sleep):
        '''Second call reads from cache, no API request.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            ubuntu_data = {'id': 'CVE-2026-35386', 'patches': {}}
            cache_file = os.path.join(tmpdir, 'CVE-2026-35386-ubuntu.json')
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(ubuntu_data, f)

            with patch('cve_metadata_extractor.ubuntu.requests.get') as mock_get:
                result = get_ubuntu_cve(tmpdir, 'CVE-2026-35386')
                self.assertEqual(result, ubuntu_data)
                mock_get.assert_not_called()

    def test_refresh_bypasses_cache(self, _mock_sleep):
        '''refresh=True re-fetches even if cache exists.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = os.path.join(tmpdir, 'CVE-2026-35386-ubuntu.json')
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump({'old': True}, f)

            new_data = {'id': 'CVE-2026-35386', 'refreshed': True}
            with patch('cve_metadata_extractor.ubuntu.requests.get') as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 200
                mock_resp.json.return_value = new_data
                mock_resp.raise_for_status = MagicMock()
                mock_get.return_value = mock_resp

                result = get_ubuntu_cve(tmpdir, 'CVE-2026-35386', refresh=True)
                self.assertEqual(result, new_data)
                mock_get.assert_called_once()

    def test_gives_up_warning_after_retries(self, _mock_sleep):
        '''Logs warning when all retries are exhausted.'''
        import requests as req
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('cve_metadata_extractor.ubuntu.requests.get') as mock_get:
                mock_get.side_effect = req.ConnectionError('timeout')
                with self.assertLogs('root', level='WARNING') as cm:
                    result = get_ubuntu_cve(tmpdir, 'CVE-2026-99999')
                self.assertEqual(result, {})
                self.assertTrue(any('Gave up fetching Ubuntu data' in m
                                    for m in cm.output))

    def test_retries_on_429_then_succeeds(self, _mock_sleep):
        '''429 triggers retry; success on next attempt.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            resp_429 = MagicMock(status_code=429)
            resp_200 = MagicMock(status_code=200)
            resp_200.json.return_value = {'id': 'CVE-2026-1234'}
            resp_200.raise_for_status = MagicMock()

            with patch('cve_metadata_extractor.ubuntu.requests.get',
                       side_effect=[resp_429, resp_200]) as mock_get:
                result = get_ubuntu_cve(tmpdir, 'CVE-2026-1234')
                self.assertEqual(result['id'], 'CVE-2026-1234')
                self.assertEqual(mock_get.call_count, 2)

    def test_404_returns_empty_dict(self, _mock_sleep):
        '''404 response caches and returns empty dict.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('cve_metadata_extractor.ubuntu.requests.get') as mock_get:
                mock_resp = MagicMock()
                mock_resp.status_code = 404
                mock_get.return_value = mock_resp

                result = get_ubuntu_cve(tmpdir, 'CVE-9999-0000')
                self.assertEqual(result, {})
                cache_file = os.path.join(tmpdir, 'CVE-9999-0000-ubuntu.json')
                from shared.json_cache import cache_load
                self.assertEqual(cache_load(cache_file), {})


class TestExtractFromUbuntuResponse(unittest.TestCase):
    '''Test metadata extraction from Ubuntu response.'''

    def test_extract_patch_commit_url(self):
        '''Extract commit hash from patches field.'''
        ubuntu_data = {
            'patches': {
                'openssh': [
                    'upstream: https://github.com/openssh/openssh-portable/commit/76685c9b09a66435cd2ad8373246adf1c53976d3'
                ]
            },
            'references': []
        }
        patch_links, hashes, _, _ = extract_from_ubuntu_response(ubuntu_data)
        self.assertEqual(len(hashes), 1)
        self.assertEqual(hashes[0]['hash'],
                         '76685c9b09a66435cd2ad8373246adf1c53976d3')
        self.assertIn('github.com/openssh/openssh-portable/commit/',
                      hashes[0]['url'])
        self.assertEqual(len(patch_links), 1)

    def test_extract_multiple_packages(self):
        '''Extract patches from multiple packages.'''
        ubuntu_data = {
            'patches': {
                'pkg-a': [
                    'upstream: https://github.com/a/repo/commit/aaaa1111bbbb2222'
                ],
                'pkg-b': [
                    'upstream: https://github.com/b/repo/commit/cccc3333dddd4444'
                ]
            },
            'references': []
        }
        patch_links, hashes, _, _ = extract_from_ubuntu_response(ubuntu_data)
        self.assertEqual(len(hashes), 2)
        hash_values = {h['hash'] for h in hashes}
        self.assertIn('aaaa1111bbbb2222', hash_values)
        self.assertIn('cccc3333dddd4444', hash_values)

    def test_extract_references(self):
        '''Capture reference URLs.'''
        ubuntu_data = {
            'patches': {},
            'references': [
                'https://www.cve.org/CVERecord?id=CVE-2026-35386',
                'https://www.openssh.org/releasenotes.html#10.3p1',
            ]
        }
        _, _, _, references = extract_from_ubuntu_response(ubuntu_data)
        self.assertEqual(len(references), 2)
        self.assertIn('https://www.cve.org/CVERecord?id=CVE-2026-35386',
                      references)

    def test_pr_url_creates_series(self):
        '''PR URLs in patches trigger series extraction.'''
        ubuntu_data = {
            'patches': {
                'pkg': [
                    'upstream: https://github.com/test/repo/pull/42'
                ]
            },
            'references': []
        }
        with patch('cve_metadata_extractor.ubuntu.process_pr_url') as mock_pr:
            extract_from_ubuntu_response(ubuntu_data)
            mock_pr.assert_called_once()

    def test_empty_response(self):
        '''Empty dict returns empty results.'''
        patch_links, hashes, series, refs = extract_from_ubuntu_response({})
        self.assertEqual(patch_links, [])
        self.assertEqual(hashes, [])
        self.assertEqual(series, [])
        self.assertEqual(refs, [])

    def test_empty_patches_list(self):
        '''Package with empty patches list is handled.'''
        ubuntu_data = {
            'patches': {'openssh-ssh1': []},
            'references': []
        }
        patch_links, hashes, _, _ = extract_from_ubuntu_response(ubuntu_data)
        self.assertEqual(patch_links, [])
        self.assertEqual(hashes, [])


class TestUbuntuSource(unittest.TestCase):
    '''Test UbuntuSource class integration.'''

    def test_is_enabled_default(self):
        '''Ubuntu is enabled by default.'''
        args = MagicMock()
        args.no_ubuntu = False
        source = UbuntuSource()
        self.assertTrue(source.is_enabled(args))

    def test_is_disabled_with_flag(self):
        '''Ubuntu is disabled with --no-ubuntu.'''
        args = MagicMock()
        args.no_ubuntu = True
        source = UbuntuSource()
        self.assertFalse(source.is_enabled(args))

    def test_extract_tags_results(self):
        '''Extract returns results tagged with source ubuntu.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            ubuntu_data = {
                'patches': {
                    'openssh': [
                        'upstream: https://github.com/openssh/openssh-portable/commit/abc123def456'
                    ]
                },
                'references': []
            }
            source = UbuntuSource()
            source._cache = tmpdir
            source._refresh = False

            with patch('cve_metadata_extractor.ubuntu.get_ubuntu_cve',
                       return_value=ubuntu_data):
                stats = {'ubuntu_hashes': 0, 'ubuntu_patches': 0}
                hashes, patches, _, _ = source.extract(
                    'CVE-2026-35386', stats)
                self.assertEqual(len(hashes), 1)
                self.assertEqual(hashes[0]['source'], 'ubuntu')
                self.assertEqual(stats['ubuntu_hashes'], 1)

    def test_deduce_component_from_cache(self):
        '''deduce_component reads package name from cached Ubuntu data.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            ubuntu_data = {
                'packages': [
                    {'name': 'openssh', 'source': 'https://...'}
                ]
            }
            cache_file = os.path.join(tmpdir, 'CVE-2026-35386-ubuntu.json')
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(ubuntu_data, f)

            source = UbuntuSource()
            result = source.deduce_component('CVE-2026-35386', tmpdir)
            self.assertEqual(result, 'openssh')

    def test_deduce_component_no_cache(self):
        '''deduce_component returns None when no cache file.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            source = UbuntuSource()
            result = source.deduce_component('CVE-9999-0000', tmpdir)
            self.assertIsNone(result)

    def test_circuit_breaker_aborts_after_threshold(self):
        '''After 3 cumulative failures extract() returns empty and skips.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            source = UbuntuSource()
            source._cache = tmpdir
            source._refresh = False

            stats = {'ubuntu_hashes': 0, 'ubuntu_patches': 0}
            with patch('cve_metadata_extractor.ubuntu.get_ubuntu_cve',
                       side_effect=RuntimeError('network error')):
                for i in range(3):
                    source.extract(f'CVE-2026-000{i}', stats)
            self.assertEqual(source._failures, 3)

            # 4th call must be skipped (no get_ubuntu_cve call)
            with patch('cve_metadata_extractor.ubuntu.get_ubuntu_cve') as mock_get:
                with self.assertLogs('root', level='WARNING') as cm:
                    result = source.extract('CVE-2026-9999', stats)
                mock_get.assert_not_called()
                self.assertEqual(result, ([], [], [], []))
                self.assertTrue(any('Ubuntu source disabled' in m
                                    for m in cm.output))

    def test_circuit_breaker_resets_on_success(self):
        '''A successful extract resets the failure counter.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            source = UbuntuSource()
            source._cache = tmpdir
            source._refresh = False
            source._failures = 2

            stats = {'ubuntu_hashes': 0, 'ubuntu_patches': 0}
            with patch('cve_metadata_extractor.ubuntu.get_ubuntu_cve',
                       return_value={}):
                source.extract('CVE-2026-1111', stats)
            self.assertEqual(source._failures, 0)


if __name__ == '__main__':
    unittest.main()
