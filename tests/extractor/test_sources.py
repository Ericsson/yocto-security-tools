# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Tests for source extractors.'''
import json
import os
import tempfile
import unittest

from cve_metadata_extractor.cvelistv5 import extract_from_cvelistv5
from cve_metadata_extractor.debian import extract_from_debian_tracker
from cve_metadata_extractor.sources import SOURCE_REGISTRY


class TestSourceRegistry(unittest.TestCase):
    '''Test the source registry pattern.'''

    def test_all_sources_registered(self):
        '''All expected sources are in registry.'''
        # Import source modules to trigger registration
        import cve_metadata_extractor.cvelistv5  # noqa: F401
        import cve_metadata_extractor.debian  # noqa: F401
        import cve_metadata_extractor.osv  # noqa: F401
        import cve_metadata_extractor.ubuntu  # noqa: F401
        import cve_metadata_extractor.uct  # noqa: F401
        expected = {'cvelistv5', 'nvd', 'debian', 'osv', 'ubuntu', 'uct'}
        self.assertTrue(expected <= {s.name for s in SOURCE_REGISTRY})


class TestCVEListV5Extractor(unittest.TestCase):
    '''Test CVEListV5 source extractor.'''

    def test_extract_with_patch_reference(self):
        '''Extract patch from CVEListV5 JSON with patch tag.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            cve_data = {
                'containers': {
                    'cna': {
                        'references': [
                            {
                                'url': 'https://github.com/test/repo/commit/abc123def456',
                                'tags': ['patch']
                            }
                        ]
                    }
                }
            }
            cve_file = os.path.join(tmpdir, 'CVE-2024-1234.json')
            with open(cve_file, 'w', encoding='utf-8') as f:
                json.dump(cve_data, f)

            stats = {'cvelistv5_hashes': 0, 'cvelistv5_patches': 0}
            hashes, patches, _, _ = extract_from_cvelistv5(
                'CVE-2024-1234', tmpdir, stats)

            self.assertGreater(len(hashes), 0)
            self.assertEqual(hashes[0]['source'], 'cvelistv5')
            self.assertGreater(len(patches), 0)
            self.assertEqual(stats['cvelistv5_hashes'], 1)
            self.assertEqual(stats['cvelistv5_patches'], 1)

    def test_no_cve_file_returns_empty(self):
        '''Return empty results when CVE file not found.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            stats = {'cvelistv5_hashes': 0, 'cvelistv5_patches': 0}
            hashes, patches, _, _ = extract_from_cvelistv5(
                'CVE-2024-9999', tmpdir, stats)

            self.assertEqual(len(hashes), 0)
            self.assertEqual(len(patches), 0)
            self.assertEqual(stats['cvelistv5_hashes'], 0)


class TestDebianExtractor(unittest.TestCase):
    '''Test Debian tracker source extractor.'''

    def test_extract_from_notes(self):
        '''Extract commit hash from Debian NOTE.'''
        debian_data = {
            'CVE-2024-1234': [
                'Fixed by https://github.com/test/repo/commit/abc123def456'
            ]
        }
        stats = {'debian_hashes': 0, 'debian_patches': 0}
        hashes, _, _, _ = extract_from_debian_tracker(
            'CVE-2024-1234', debian_data, stats)

        self.assertEqual(len(hashes), 1)
        self.assertEqual(hashes[0]['hash'], 'abc123def456')
        self.assertEqual(hashes[0]['source'], 'debian')
        self.assertEqual(stats['debian_hashes'], 1)

    def test_extract_patch_url(self):
        '''Extract .patch URL from Debian NOTE.'''
        debian_data = {
            'CVE-2024-5678': [
                'See https://example.com/fix.patch'
            ]
        }
        stats = {'debian_hashes': 0, 'debian_patches': 0}
        _, patches, _, _ = extract_from_debian_tracker(
            'CVE-2024-5678', debian_data, stats)

        self.assertEqual(len(patches), 1)
        self.assertEqual(patches[0]['url'], 'https://example.com/fix.patch')
        self.assertEqual(patches[0]['source'], 'debian')
        self.assertEqual(stats['debian_patches'], 1)


if __name__ == '__main__':
    unittest.main()
