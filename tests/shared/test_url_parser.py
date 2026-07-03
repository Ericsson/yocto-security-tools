# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for shared.url_parser module."""
from unittest.mock import Mock, patch

import pytest

from shared.url_parser import (
    deduce_repo_url,
    extract_commit_hash,
    fetch_github_pr_commits,
    fetch_gitlab_issue_commits,
    parse_fix_url,
)


class TestExtractCommitHash:
    def test_github_commit_url(self):
        url = "https://github.com/openssh/openssh-portable/commit/76685c9b09a66435cd2ad8373246adf1c53976d3"
        assert extract_commit_hash(url) == "76685c9b09a66435cd2ad8373246adf1c53976d3"

    def test_gitlab_commit_url(self):
        url = "https://gitlab.com/project/repo/-/commit/abc1234def5678"
        assert extract_commit_hash(url) == "abc1234def5678"

    def test_short_hash(self):
        url = "https://github.com/owner/repo/commit/abc1234"
        assert extract_commit_hash(url) == "abc1234"

    def test_ignored_bugzilla(self):
        url = "https://bugzilla.redhat.com/show_bug.cgi?id=1234567"
        assert extract_commit_hash(url) is None

    def test_ignored_issues(self):
        url = "https://github.com/owner/repo/issues/1234567"
        assert extract_commit_hash(url) is None

    def test_pure_numeric_ignored(self):
        url = "https://example.com/path/1234567"
        assert extract_commit_hash(url) is None

    def test_no_hash(self):
        url = "https://example.com/no-hash-here"
        assert extract_commit_hash(url) is None


class TestFetchGithubPrCommits:
    @patch('requests.get')
    def test_success(self, mock_get):
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: [{'sha': 'aaa'}, {'sha': 'bbb'}])
        mock_get.return_value.raise_for_status = Mock()

        result = fetch_github_pr_commits(
            "https://github.com/owner/repo/pull/42", token="fake")
        assert result == ['aaa', 'bbb']

    def test_non_pr_url(self):
        result = fetch_github_pr_commits(
            "https://github.com/owner/repo/commit/abc123", token="fake")
        assert result == []

    @patch.dict('os.environ', {}, clear=True)
    def test_no_token(self):
        result = fetch_github_pr_commits(
            "https://github.com/owner/repo/pull/42")
        assert result == []


class TestParseFixUrl:
    def test_commit_url(self):
        url = "https://github.com/openssh/openssh-portable/commit/76685c9b09a66"
        result = parse_fix_url(url)
        assert result['hashes'] == ['76685c9b09a66']
        assert result['hash_details'] == [
            {'hash': '76685c9b09a66', 'url': url, 'source': 'cli'}]
        assert result['series'] == []

    @patch('shared.url_parser.fetch_github_pr_commits')
    def test_pr_url(self, mock_fetch):
        mock_fetch.return_value = ['aaa', 'bbb', 'ccc']
        url = "https://github.com/owner/repo/pull/99"
        result = parse_fix_url(url)
        assert result['hashes'] == ['aaa', 'bbb', 'ccc']
        assert result['series'] == [
            {'pull_url': url, 'commits': ['aaa', 'bbb', 'ccc']}]
        assert len(result['hash_details']) == 3

    @patch('shared.url_parser.fetch_github_pr_commits')
    def test_pr_url_no_commits_raises(self, mock_fetch):
        mock_fetch.return_value = []
        with pytest.raises(ValueError, match="Could not extract commits"):
            parse_fix_url("https://github.com/owner/repo/pull/99")

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError, match="Could not extract commit hash"):
            parse_fix_url("https://example.com/no-hash-here")


class TestFetchGitlabIssueCommits:
    @patch('requests.get')
    def test_success(self, mock_get):
        closed_by_resp = Mock(
            status_code=200,
            json=lambda: [{'iid': 101}])
        closed_by_resp.raise_for_status = Mock()

        commits_resp = Mock(
            status_code=200,
            json=lambda: [{'id': 'sha1'}, {'id': 'sha2'}])
        commits_resp.raise_for_status = Mock()

        mock_get.side_effect = [closed_by_resp, commits_resp]

        result = fetch_gitlab_issue_commits(
            "https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3839")
        assert result == ['sha1', 'sha2']

    def test_invalid_url(self):
        result = fetch_gitlab_issue_commits("https://github.com/owner/repo/issues/42")
        assert result == []

    @patch('requests.get')
    def test_api_failure(self, mock_get):
        from requests.exceptions import Timeout
        mock_get.side_effect = Timeout("timed out")

        result = fetch_gitlab_issue_commits(
            "https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/3839")
        assert result == []

    @patch('requests.get')
    @patch.dict('os.environ', {'GITLAB_TOKEN': 'mytoken'})
    def test_uses_token(self, mock_get):
        closed_by_resp = Mock(
            status_code=200, json=lambda: [])
        closed_by_resp.raise_for_status = Mock()
        mock_get.return_value = closed_by_resp

        fetch_gitlab_issue_commits(
            "https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/1")

        headers = mock_get.call_args[1].get('headers', {})
        assert headers.get('PRIVATE-TOKEN') == 'mytoken'

    @patch('requests.get')
    @patch.dict('os.environ', {}, clear=True)
    def test_no_token(self, mock_get):
        closed_by_resp = Mock(
            status_code=200, json=lambda: [])
        closed_by_resp.raise_for_status = Mock()
        mock_get.return_value = closed_by_resp

        fetch_gitlab_issue_commits(
            "https://gitlab.freedesktop.org/gstreamer/gstreamer/-/issues/1")

        headers = mock_get.call_args[1].get('headers', {})
        assert 'PRIVATE-TOKEN' not in headers


class TestDeduceRepoUrl:
    def test_sourceware_cgit_commit_url(self):
        # Regression: CVE-2026-42250 fix commit lived in the bzip2 source repo,
        # exposed via a /cgit/ URL that previously deduced to None.
        url = ("https://sourceware.org/cgit/bzip2/commit/"
               "?id=35d122a3df8b0cc4082a4d89fdc6ee99f375fe67")
        assert deduce_repo_url(url) == "https://sourceware.org/git/bzip2"

    def test_sourceware_git_path_url(self):
        url = "https://sourceware.org/git/glibc/commit/?id=abc1234"
        assert deduce_repo_url(url) == "https://sourceware.org/git/glibc"

    def test_sourceware_gitweb_p_style(self):
        url = "https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=abc1234"
        assert deduce_repo_url(url) == "https://sourceware.org/git/glibc.git"

    def test_sourceware_lookalike_host_rejected(self):
        url = "https://sourceware.org.evil.com/cgit/bzip2/commit/?id=abc1234"
        assert deduce_repo_url(url) is None

    def test_sourceware_no_repo_path(self):
        url = "https://sourceware.org/bzip2/"
        assert deduce_repo_url(url) is None

    def test_savannah_cgit_still_works(self):
        url = "https://git.savannah.gnu.org/cgit/coreutils.git/commit/?id=abc1234"
        assert deduce_repo_url(url) == "https://git.savannah.gnu.org/git/coreutils.git"

    def test_github_commit_url(self):
        url = "https://github.com/owner/repo/commit/abc1234"
        assert deduce_repo_url(url) == "https://github.com/owner/repo"
