# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Tests for utility functions.'''
import json
import os
import tempfile
import unittest

from cve_metadata_extractor.cvelistv5 import find_cve_json_file
from cve_metadata_extractor.utils import (
    HASH_RE,
    URL_RE,
    extract_commit_hash,
    normalize_component_name,
    resolve_url_refs,
)


class TestNormalizeComponentName(unittest.TestCase):
    '''Test component name normalization.'''

    def test_removes_native_suffix(self):
        '''Remove -native suffix from component name.'''
        self.assertEqual(normalize_component_name('curl-native'), 'curl')

    def test_preserves_name_without_suffix(self):
        '''Preserve name without -native suffix.'''
        self.assertEqual(normalize_component_name('openssl'), 'openssl')

    def test_handles_empty_string(self):
        '''Handle empty string.'''
        self.assertEqual(normalize_component_name(''), '')

    def test_handles_none(self):
        '''Handle None value.'''
        self.assertIsNone(normalize_component_name(None))


class TestFindHash(unittest.TestCase):
    '''Test hash extraction from URLs.'''

    def test_extracts_short_hash(self):
        '''Extract 7-character hash from URL.'''
        url = 'https://github.com/test/repo/commit/abc1234'
        self.assertEqual(extract_commit_hash(url), 'abc1234')

    def test_extracts_full_hash(self):
        '''Extract 40-character hash from URL.'''
        url = 'https://github.com/test/repo/commit/abc123def456789012345678901234567890abcd'
        self.assertEqual(extract_commit_hash(url), 'abc123def456789012345678901234567890abcd')

    def test_ignores_bugzilla_urls(self):
        '''Ignore hashes in bugzilla URLs.'''
        url = 'https://bugzilla.redhat.com/show_bug.cgi?id=abc123'
        self.assertIsNone(extract_commit_hash(url))

    def test_ignores_numeric_only(self):
        '''Ignore numeric-only strings.'''
        url = 'https://example.com/issue/1234567'
        self.assertIsNone(extract_commit_hash(url))

    def test_returns_none_for_no_hash(self):
        '''Return None when no hash found.'''
        url = 'https://example.com/page'
        self.assertIsNone(extract_commit_hash(url))


class TestFindCVEJsonFile(unittest.TestCase):
    '''Test CVE JSON file discovery.'''

    def test_finds_cve_file(self):
        '''Find CVE JSON file in directory.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            cve_file = os.path.join(tmpdir, 'CVE-2024-1234.json')
            with open(cve_file, 'w', encoding='utf-8') as f:
                json.dump({'id': 'CVE-2024-1234'}, f)

            result = find_cve_json_file('CVE-2024-1234', tmpdir)
            self.assertEqual(result, cve_file)

    def test_finds_cve_in_subdirectory(self):
        '''Find CVE JSON file in subdirectory.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = os.path.join(tmpdir, '2024')
            os.makedirs(subdir)
            cve_file = os.path.join(subdir, 'CVE-2024-5678.json')
            with open(cve_file, 'w', encoding='utf-8') as f:
                json.dump({'id': 'CVE-2024-5678'}, f)

            result = find_cve_json_file('CVE-2024-5678', tmpdir)
            self.assertEqual(result, cve_file)

    def test_returns_none_when_not_found(self):
        '''Return None when CVE file not found.'''
        with tempfile.TemporaryDirectory() as tmpdir:
            result = find_cve_json_file('CVE-2024-9999', tmpdir)
            self.assertIsNone(result)


class TestRegexPatterns(unittest.TestCase):
    '''Test regex patterns.'''

    def test_hash_regex_matches_valid_hashes(self):
        '''HASH_RE matches valid git hashes.'''
        self.assertIsNotNone(HASH_RE.search('abc1234'))
        self.assertIsNotNone(HASH_RE.search('abc123def456789012345678901234567890abcd'))

    def test_hash_regex_requires_minimum_length(self):
        '''HASH_RE requires at least 7 characters.'''
        self.assertIsNone(HASH_RE.search('abc123'))
        self.assertIsNotNone(HASH_RE.search('abc1234'))

    def test_url_regex_matches_http(self):
        '''URL_RE matches http URLs.'''
        match = URL_RE.search('See http://example.com for details')
        self.assertIsNotNone(match)
        self.assertEqual(match.group(0), 'http://example.com')

    def test_url_regex_matches_https(self):
        '''URL_RE matches https URLs.'''
        match = URL_RE.search('See https://example.com/path for details')
        self.assertIsNotNone(match)
        self.assertEqual(match.group(0), 'https://example.com/path')


class TestResolveUrlRefs(unittest.TestCase):
    '''Test resolve_url_refs PR/issue dispatch and hash extraction.'''

    def test_pr_url_appends_to_series(self):
        '''GitHub PR URL is dispatched to process_pr_url, appending to series.'''
        from unittest.mock import patch
        series = []
        with patch('cve_metadata_extractor.utils.process_pr_url') as mock_pr:
            resolve_url_refs('https://github.com/test/repo/pull/42', series)
            mock_pr.assert_called_once_with(
                'https://github.com/test/repo/pull/42', series)

    def test_gitlab_issue_url_appends_to_series(self):
        '''GitLab issue URL is dispatched to process_gitlab_issue_url.'''
        from unittest.mock import patch
        series = []
        url = 'https://gitlab.com/test/repo/-/issues/7'
        with patch(
                'cve_metadata_extractor.utils.process_gitlab_issue_url'
        ) as mock_issue:
            resolve_url_refs(url, series)
            mock_issue.assert_called_once_with(url, series)

    def test_commit_url_returns_hash(self):
        '''Plain commit URL returns the extracted hash.'''
        url = 'https://github.com/test/repo/commit/abc1234'
        self.assertEqual(resolve_url_refs(url, []), 'abc1234')

    def test_non_matching_url_returns_none(self):
        '''URL with no commit hash and no PR/issue returns None.'''
        self.assertIsNone(resolve_url_refs('https://example.com/page', []))


if __name__ == '__main__':
    unittest.main()
