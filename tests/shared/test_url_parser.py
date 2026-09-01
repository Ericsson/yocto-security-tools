# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for shared.url_parser module."""
from unittest.mock import Mock, patch

import pytest

from shared.url_parser import (
    HASH_RE,
    deduce_repo_url,
    extract_commit_hash,
    fetch_github_pr_commits,
    fetch_gitlab_issue_commits,
    parse_fix_urls,
)


class TestHashRe:
    """HASH_RE is shared; it must stay usable for both scanning and matching."""

    def test_findall_extracts_embedded_hashes(self):
        # cve_metadata_extractor.debian scans free-text tracker notes with
        # findall(), so the pattern must not be anchored.
        note = "Fixed upstream in commit abc1234def and later def5678abc"
        assert HASH_RE.findall(note) == ['abc1234def', 'def5678abc']

    def test_fullmatch_rejects_surrounding_text(self):
        assert HASH_RE.fullmatch('abc1234def') is not None
        assert HASH_RE.fullmatch('emr_na-c04497075') is None
        assert HASH_RE.fullmatch('abc1234 and more') is None


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

    def test_cgit_commit_query(self):
        url = ("https://git.busybox.net/busybox/commit/"
               "?id=d417193cf37ca1005830d7e16f5fa7e1d8a44209")
        assert extract_commit_hash(url) == "d417193cf37ca1005830d7e16f5fa7e1d8a44209"

    def test_gitweb_commit_query(self):
        url = ("https://git.samba.org/?p=rsync.git;a=commit;"
               "h=0902b52f6687b1f7952422080d50b93108742e53")
        assert extract_commit_hash(url) == "0902b52f6687b1f7952422080d50b93108742e53"

    def test_fossil_info_url(self):
        url = "https://sqlite.org/src/info/498e3f1cf57f164f"
        assert extract_commit_hash(url) == "498e3f1cf57f164f"

    def test_kernel_stable_shortlink(self):
        # The most common commit reference shape in the CVE feeds by far.
        url = ("https://git.kernel.org/stable/c/"
               "512a01da7134bac8f8b373506011e8aaa3283854")
        assert extract_commit_hash(url) == (
            "512a01da7134bac8f8b373506011e8aaa3283854")

    def test_gitiles_commit_url(self):
        url = ("https://android.googlesource.com/platform/frameworks/base/+/"
               "db86972777c84a386d8a6d2d34879923bdbccdf6")
        assert extract_commit_hash(url) == (
            "db86972777c84a386d8a6d2d34879923bdbccdf6")

    def test_github_pull_request_commit_url(self):
        url = ("https://github.com/FRRouting/frr/pull/19480/commits/"
               "cda5ddac0940562d1dca7cbef34d0ce5b00f160b")
        assert extract_commit_hash(url) == (
            "cda5ddac0940562d1dca7cbef34d0ce5b00f160b")

    def test_gitweb_hash_without_explicit_action(self):
        # Old-style gitweb omits a=commit; h= still denotes the commit.
        url = ("https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;"
               "h=d1458933830456e54223d9fc61f0d9b3a19256f5")
        assert extract_commit_hash(url) == (
            "d1458933830456e54223d9fc61f0d9b3a19256f5")

    def test_gitweb_percent_encoded_separators(self):
        url = ("https://git.ghostscript.com/?p=ghostpdl.git%3B"
               "a=commitdiff%3Bh=3d4cfdc1a44")
        assert extract_commit_hash(url) == "3d4cfdc1a44"

    def test_gitweb_blob_hash_not_treated_as_commit(self):
        url = ("https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=blob;"
               "h=d1458933830456e54223d9fc61f0d9b3a19256f5")
        assert extract_commit_hash(url) is None

    def test_hex_in_repo_name_not_mistaken_for_hash(self):
        # Previously returned 'ec61850', taken from the repository name.
        url = ("https://github.com/mz-automation/libiec61850/commit/"
               "1f52be9ddeae00e69cd43e4cac3cb4f0c880c4f0")
        assert extract_commit_hash(url) == (
            "1f52be9ddeae00e69cd43e4cac3cb4f0c880c4f0")

    def test_commitdiff_path(self):
        url = ("https://git.example.org/repo/commitdiff/"
               "3d4cfdc1a44ee1b4f0b3d3d1d0f6e0e91f28b1a0")
        assert extract_commit_hash(url) == (
            "3d4cfdc1a44ee1b4f0b3d3d1d0f6e0e91f28b1a0")

    # The remaining shapes below were found by diffing this parser against the
    # previous one over the 2024-2025 CVE List V5 reference URLs; each one is a
    # real commit reference that a /commit/-only parser silently dropped.
    def test_cgit_patch_query(self):
        url = ("https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/"
               "linux.git/patch/?id=944d5fe50f3f03daacfea16300e656a1691c4a23")
        assert extract_commit_hash(url) == (
            "944d5fe50f3f03daacfea16300e656a1691c4a23")

    def test_cgit_diff_query(self):
        url = ("https://cgit.ghostscript.com/cgi-bin/cgit.cgi/mupdf.git/diff/"
               "?id=b5c898a30f068b5342e8263a2cd5b9f0be291aac")
        assert extract_commit_hash(url) == (
            "b5c898a30f068b5342e8263a2cd5b9f0be291aac")

    def test_pagure_commit_url(self):
        url = ("https://pagure.io/freeipa/c/"
               "6b9400c135ed16b10057b350cc9ce42aa0e862d4")
        assert extract_commit_hash(url) == (
            "6b9400c135ed16b10057b350cc9ce42aa0e862d4")

    def test_sourceforge_commit_url(self):
        url = ("https://sourceforge.net/p/openipmi/code/ci/"
               "4c129d0540f3578ecc078d8612bbf84b6cd24c87/")
        assert extract_commit_hash(url) == (
            "4c129d0540f3578ecc078d8612bbf84b6cd24c87")

    def test_9front_commit_url(self):
        url = ("https://git.9front.org/plan9front/plan9front/"
               "07aa9bfeef55ca987d411115adcfbbd4390ecf34/commit.html")
        assert extract_commit_hash(url) == (
            "07aa9bfeef55ca987d411115adcfbbd4390ecf34")

    def test_kernel_dance_shortlink(self):
        url = "https://kernel.dance/b1db244ffd041a49ecc9618e8feb6b5c1afcdaa7"
        assert extract_commit_hash(url) == (
            "b1db244ffd041a49ecc9618e8feb6b5c1afcdaa7")

    def test_patch_artifact_named_after_commit(self):
        url = ("https://depot.galaxyproject.org/patch/GX-2024-0001/"
               "022da344a02bafd604402ac8e253e0014f6e2e08.patch")
        assert extract_commit_hash(url) == (
            "022da344a02bafd604402ac8e253e0014f6e2e08")

    def test_file_share_hex_account_id_ignored(self):
        # /c/<hex>/<file> share links must not look like Pagure /c/<hash>.
        url = ("https://1drv.ms/t/c/12406a392c92914b/"
               "EQ5pK82-KmxKht6YgsEzaOsBzrC05Cael1vwpfM9ZxX97Q?e=qEgmtB")
        assert extract_commit_hash(url) is None

    def test_mercurial_revision_ignored(self):
        # Not a Git object; the corrector could not cherry-pick it.
        url = "https://hg.savannah.gnu.org/hgweb/unrtf/rev/a5d3b025a8b1"
        assert extract_commit_hash(url) is None

    def test_compare_range_ignored(self):
        url = ("https://github.com/oxidecomputer/omicron/compare/"
               "01bb875a1b2c3d4...ec069f0a1b2c3d4")
        assert extract_commit_hash(url) is None

    def test_tree_browse_url_ignored(self):
        url = ("https://github.com/Homebrew/brew/tree/"
               "237d1e783f7ee261beaba7d3f6bde22da7148b0a")
        assert extract_commit_hash(url) is None

    def test_gerrit_change_id_ignored(self):
        # A Gerrit Change-Id is not a commit hash.
        url = ("https://gerrit.wikimedia.org/r/q/"
               "I7878f8f7bc067080f80427b90f8d85337f172711")
        assert extract_commit_hash(url) is None

    def test_advisory_uuid_ignored(self):
        url = ("https://www.wordfence.com/threat-intel/vulnerabilities/id/"
               "894b43ed-143d-4c0b-afd1-05fcd6fa5018?source=cve")
        assert extract_commit_hash(url) is None

    @pytest.mark.parametrize("url", [
        ("https://support.hpe.com/hpsc/doc/public/display"
         "?docLocale=en_US&docId=emr_na-c04497075"),
        ("https://support.hpe.com/hpsc/doc/public/display"
         "?docLocale=en_US&docId=emr_na-c04518183"),
        ("https://inbox.sourceware.org/libc-announce/"
         "b11f0003-6ec1-4bd6-b9de-9e38a4efeca3@redhat.com/T/"),
    ])
    def test_non_commit_hex_identifier_ignored(self, url):
        assert extract_commit_hash(url) is None

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


class TestParseFixUrls:
    ACL_URLS = [
        "https://cgit.git.savannah.nongnu.org/cgit/acl.git/commit/"
        "?id=5906d2868ec8d3b08be556153696e6b1122eeeda",
        "https://cgit.git.savannah.nongnu.org/cgit/acl.git/commit/"
        "?id=0071c6d1fea0a8a6270333baa85fb609be325c26",
        "https://cgit.git.savannah.nongnu.org/cgit/acl.git/commit/"
        "?id=170dbd3beff9bd5bdab3f72db1a04bf282f6087c",
    ]

    def test_commit_url(self):
        url = "https://github.com/openssh/openssh-portable/commit/76685c9b09a66"
        result = parse_fix_urls([url])
        assert result['hashes'] == ['76685c9b09a66']
        assert result['hash_details'] == [
            {'hash': '76685c9b09a66', 'url': url, 'source': 'cli'}]
        assert result['series'] == []

    @patch('shared.url_parser.fetch_github_pr_commits')
    def test_pr_url(self, mock_fetch):
        mock_fetch.return_value = ['aaa', 'bbb', 'ccc']
        url = "https://github.com/owner/repo/pull/99"
        result = parse_fix_urls([url])
        assert result['hashes'] == ['aaa', 'bbb', 'ccc']
        assert result['series'] == [
            {'pull_url': url, 'commits': ['aaa', 'bbb', 'ccc']}]
        assert len(result['hash_details']) == 3

    @patch('shared.url_parser.fetch_github_pr_commits')
    def test_pr_url_no_commits_raises(self, mock_fetch):
        mock_fetch.return_value = []
        with pytest.raises(ValueError, match="Could not extract commits"):
            parse_fix_urls(["https://github.com/owner/repo/pull/99"])

    def test_invalid_url_raises(self):
        with pytest.raises(ValueError, match="Could not extract commit hash"):
            parse_fix_urls(["https://example.com/no-hash-here"])

    def test_empty_list_raises(self):
        with pytest.raises(ValueError, match="No fix URLs provided"):
            parse_fix_urls([])

    def test_dependent_commit_chain_preserves_cli_order(self):
        """Three dependent commit URLs become one ordered series (acl case)."""
        result = parse_fix_urls(self.ACL_URLS)
        expected = ['5906d2868ec8d3b08be556153696e6b1122eeeda',
                    '0071c6d1fea0a8a6270333baa85fb609be325c26',
                    '170dbd3beff9bd5bdab3f72db1a04bf282f6087c']
        assert result['hashes'] == expected
        assert result['series'] == [{'pull_url': '', 'commits': expected}]
        assert [d['hash'] for d in result['hash_details']] == expected
        assert all(d['source'] == 'cli' for d in result['hash_details'])
        assert [d['url'] for d in result['hash_details']] == self.ACL_URLS

    def test_reversed_order_is_not_sorted(self):
        """Caller owns ordering — nothing is reordered."""
        result = parse_fix_urls(list(reversed(self.ACL_URLS)))
        assert result['hashes'] == [
            '170dbd3beff9bd5bdab3f72db1a04bf282f6087c',
            '0071c6d1fea0a8a6270333baa85fb609be325c26',
            '5906d2868ec8d3b08be556153696e6b1122eeeda']

    @patch('shared.url_parser.fetch_github_pr_commits')
    def test_mixed_pr_and_commit_urls_merge_inline(self, mock_fetch):
        mock_fetch.return_value = ['aaa1234', 'bbb1234']
        pr_url = "https://github.com/owner/repo/pull/7"
        commit_url = "https://github.com/owner/repo/commit/ccc1234"
        result = parse_fix_urls([pr_url, commit_url])
        assert result['hashes'] == ['aaa1234', 'bbb1234', 'ccc1234']
        assert result['series'] == [
            {'pull_url': pr_url,
             'commits': ['aaa1234', 'bbb1234', 'ccc1234']}]

    def test_duplicate_urls_collapse(self):
        url = "https://github.com/owner/repo/commit/abc1234"
        result = parse_fix_urls([url, url])
        assert result['hashes'] == ['abc1234']
        assert result['hash_details'] == [
            {'hash': 'abc1234', 'url': url, 'source': 'cli'}]

    def test_second_bad_url_raises_naming_it(self):
        good = "https://github.com/owner/repo/commit/abc1234"
        bad = "https://example.com/no-hash-here"
        with pytest.raises(ValueError, match="no-hash-here"):
            parse_fix_urls([good, bad])


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
    def test_busybox_cgit_commit_url(self):
        url = ("https://git.busybox.net/busybox/commit/"
               "?id=3fb6b31c716669e12f75a2accd31bb7685b1a1cb")
        assert deduce_repo_url(url) == "https://git.busybox.net/busybox"

    def test_busybox_cgit_lookalike_host_rejected(self):
        url = "https://git.busybox.net.evil.example/busybox/commit/?id=abc1234"
        assert deduce_repo_url(url) is None

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
        assert deduce_repo_url(url) == "https://https.git.savannah.gnu.org/git/coreutils.git"

    def test_savannah_nongnu_cgit_subdomain(self):
        url = ("https://cgit.git.savannah.nongnu.org/cgit/acl.git/commit/"
               "?id=abc1234")
        assert deduce_repo_url(url) == "https://https.git.savannah.nongnu.org/git/acl.git"

    def test_savannah_nongnu_lookalike_host_rejected(self):
        url = "https://git.savannah.nongnu.org.evil.com/cgit/acl.git/commit/?id=abc1234"
        assert deduce_repo_url(url) is None

    def test_github_commit_url(self):
        url = "https://github.com/owner/repo/commit/abc1234"
        assert deduce_repo_url(url) == "https://github.com/owner/repo"
