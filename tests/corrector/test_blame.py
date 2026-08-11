# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector.blame — diff parsing and git blame logic."""
import subprocess
from pathlib import Path

from cve_corrector.blame import (
    _is_release_tag,
    _tag_to_version_str,
    blame_line_ranges,
    check_vulnerability_origin,
    find_introducing_version,
    is_cve_applicable,
    parse_diff_line_ranges,
)


def _git(repo: Path, *args: str) -> str:
    """Run a git command in the test repo."""
    result = subprocess.run(
        ['git'] + list(args), cwd=repo,
        capture_output=True, text=True, check=True,
        env={
            'GIT_AUTHOR_NAME': 'Test', 'GIT_AUTHOR_EMAIL': 'test@test.com',
            'GIT_COMMITTER_NAME': 'Test', 'GIT_COMMITTER_EMAIL': 'test@test.com',
            'HOME': str(repo), 'GIT_CONFIG_NOSYSTEM': '1',
        })
    return result.stdout.strip()


def _init_repo(tmp_path: Path) -> Path:
    """Create a git repo with an initial commit containing a source file."""
    repo = tmp_path / 'repo'
    repo.mkdir()
    _git(repo, 'init')
    _git(repo, 'config', 'user.email', 'test@test.com')
    _git(repo, 'config', 'user.name', 'Test')
    (repo / 'file.c').write_text('line1\nline2\nline3\nline4\nline5\n')
    _git(repo, 'add', 'file.c')
    _git(repo, 'commit', '-m', 'initial')
    return repo


# --- parse_diff_line_ranges ---

class TestParseDiffLineRanges:
    def test_modified_lines(self, tmp_path):
        repo = _init_repo(tmp_path)
        # Modify lines 2-3
        (repo / 'file.c').write_text('line1\nfixed2\nfixed3\nline4\nline5\n')
        _git(repo, 'add', 'file.c')
        _git(repo, 'commit', '-m', 'fix')
        fix_hash = _git(repo, 'rev-parse', 'HEAD')

        ranges = parse_diff_line_ranges(repo, fix_hash)
        assert 'file.c' in ranges
        assert (2, 3) in ranges['file.c']

    def test_deleted_lines(self, tmp_path):
        repo = _init_repo(tmp_path)
        # Delete lines 3-4
        (repo / 'file.c').write_text('line1\nline2\nline5\n')
        _git(repo, 'add', 'file.c')
        _git(repo, 'commit', '-m', 'delete')
        fix_hash = _git(repo, 'rev-parse', 'HEAD')

        ranges = parse_diff_line_ranges(repo, fix_hash)
        assert 'file.c' in ranges
        # Lines 3-4 were deleted from the old side
        assert (3, 4) in ranges['file.c']

    def test_pure_addition(self, tmp_path):
        repo = _init_repo(tmp_path)
        # Add lines without modifying existing ones
        (repo / 'file.c').write_text(
            'line1\nline2\nline3\nnew_line\nline4\nline5\n')
        _git(repo, 'add', 'file.c')
        _git(repo, 'commit', '-m', 'add')
        fix_hash = _git(repo, 'rev-parse', 'HEAD')

        ranges = parse_diff_line_ranges(repo, fix_hash)
        # Pure additions now capture context lines around insertion point
        assert 'file.c' in ranges
        # Context window should be around line 3 (insertion point)
        start, end = ranges['file.c'][0]
        assert start >= 1
        assert end >= start

    def test_empty_diff(self, tmp_path):
        repo = _init_repo(tmp_path)
        initial_hash = _git(repo, 'rev-parse', 'HEAD')
        # No changes — diff against itself
        ranges = parse_diff_line_ranges(repo, initial_hash)
        assert ranges == {}

    def test_multiple_files(self, tmp_path):
        repo = _init_repo(tmp_path)
        (repo / 'other.c').write_text('a\nb\nc\n')
        _git(repo, 'add', 'other.c')
        _git(repo, 'commit', '-m', 'add other')
        # Modify both files
        (repo / 'file.c').write_text('line1\nchanged\nline3\nline4\nline5\n')
        (repo / 'other.c').write_text('a\nchanged\nc\n')
        _git(repo, 'add', '.')
        _git(repo, 'commit', '-m', 'fix both')
        fix_hash = _git(repo, 'rev-parse', 'HEAD')

        ranges = parse_diff_line_ranges(repo, fix_hash)
        assert 'file.c' in ranges
        assert 'other.c' in ranges

    def test_bad_commit(self, tmp_path):
        repo = _init_repo(tmp_path)
        ranges = parse_diff_line_ranges(repo, 'deadbeef' * 5)
        assert ranges == {}

    def test_binary_file(self, tmp_path):
        repo = _init_repo(tmp_path)
        (repo / 'bin.dat').write_bytes(b'\x00\x01\x02')
        _git(repo, 'add', 'bin.dat')
        _git(repo, 'commit', '-m', 'add binary')
        (repo / 'bin.dat').write_bytes(b'\x00\x01\x03')
        _git(repo, 'add', 'bin.dat')
        _git(repo, 'commit', '-m', 'change binary')
        fix_hash = _git(repo, 'rev-parse', 'HEAD')

        ranges = parse_diff_line_ranges(repo, fix_hash)
        # Binary diffs don't produce unified diff hunks
        assert not ranges.get('bin.dat', [])


# --- blame_line_ranges ---

class TestBlameLineRanges:
    def test_blames_correct_commit(self, tmp_path):
        repo = _init_repo(tmp_path)
        initial_hash = _git(repo, 'rev-parse', 'HEAD')

        commits = blame_line_ranges(repo, {'file.c': [(1, 3)]})
        assert initial_hash in commits

    def test_multiple_introducing_commits(self, tmp_path):
        repo = _init_repo(tmp_path)
        initial_hash = _git(repo, 'rev-parse', 'HEAD')
        # Add more lines in a second commit
        (repo / 'file.c').write_text(
            'line1\nline2\nline3\nline4\nline5\nnew_line\n')
        _git(repo, 'add', 'file.c')
        _git(repo, 'commit', '-m', 'extend')
        second_hash = _git(repo, 'rev-parse', 'HEAD')

        commits = blame_line_ranges(repo, {'file.c': [(1, 6)]})
        assert initial_hash in commits
        assert second_hash in commits

    def test_nonexistent_file(self, tmp_path):
        repo = _init_repo(tmp_path)
        commits = blame_line_ranges(repo, {'nosuch.c': [(1, 3)]})
        assert commits == set()

    def test_empty_ranges(self, tmp_path):
        repo = _init_repo(tmp_path)
        commits = blame_line_ranges(repo, {})
        assert commits == set()

    def test_file_deleted_in_fix(self, tmp_path):
        """Blame on a file that exists at HEAD (pre-fix) should work."""
        repo = _init_repo(tmp_path)
        initial_hash = _git(repo, 'rev-parse', 'HEAD')
        # Blame lines that exist at current HEAD
        commits = blame_line_ranges(repo, {'file.c': [(1, 5)]})
        assert initial_hash in commits

    def test_new_file_blame_failure_logged_as_debug(self, tmp_path, caplog):
        """Blaming a file at a revision before it was added should log at
        debug level (expected, harmless) rather than warning.

        Reproduces the noisy "git blame failed ... no such path" warnings
        seen when a fix commit both modifies existing files and adds new
        ones (e.g. acl's *_at.c variants) — blaming the new file against
        its own parent revision always fails since the path didn't exist
        yet, which is not a genuine error.
        """
        repo = _init_repo(tmp_path)
        # Add a brand-new file in a second commit.
        (repo / 'new_file.c').write_text('a\nb\nc\n')
        _git(repo, 'add', 'new_file.c')
        _git(repo, 'commit', '-m', 'add new file')
        new_hash = _git(repo, 'rev-parse', 'HEAD')

        import logging
        with caplog.at_level(logging.DEBUG):
            commits = blame_line_ranges(
                repo, {'new_file.c': [(1, 3)]},
                file_revisions={'new_file.c': f'{new_hash}~1'})

        assert commits == set()
        warning_records = [r for r in caplog.records if r.levelname == 'WARNING']
        debug_records = [r for r in caplog.records if r.levelname == 'DEBUG']
        assert not warning_records
        assert any('no such path' in r.message for r in debug_records)


# --- _tag_to_version_str ---

class TestTagToVersionStr:
    def test_v_prefix(self):
        assert _tag_to_version_str('v3.7.9') == '3.7.9'

    def test_release_prefix(self):
        assert _tag_to_version_str('release-3.7.9') == '3.7.9'

    def test_name_prefix(self):
        assert _tag_to_version_str('libfoo-3.7.9') == '3.7.9'

    def test_underscore(self):
        assert _tag_to_version_str('release_3_7_9') == '3.7.9'

    def test_plain(self):
        assert _tag_to_version_str('3.7.9') == '3.7.9'

    def test_openssh_patch_tag(self):
        assert _tag_to_version_str('V_9_6_P1') == '9.6p1'
        assert _tag_to_version_str('V_10_3_P1') == '10.3p1'
        assert _tag_to_version_str('V_6_5_P1') == '6.5p1'

    def test_openssh_pre_tag(self):
        assert _tag_to_version_str('V_1_2_PRE15') == '1.2pre15'
        assert _tag_to_version_str('V_1_2_PRE3') == '1.2pre3'


# --- find_introducing_version ---

class TestFindIntroducingVersion:
    def test_with_tagged_repo(self, tmp_path):
        repo = _init_repo(tmp_path)
        _git(repo, 'tag', 'v1.0.0')
        # Second commit
        (repo / 'file.c').write_text('line1\nchanged\nline3\nline4\nline5\n')
        _git(repo, 'add', 'file.c')
        _git(repo, 'commit', '-m', 'change')
        _git(repo, 'tag', 'v2.0.0')
        initial_hash = _git(repo, 'rev-list', '--max-parents=0', 'HEAD')

        version = find_introducing_version(repo, {initial_hash})
        assert version == '1.0.0'

    def test_multiple_commits_returns_earliest(self, tmp_path):
        repo = _init_repo(tmp_path)
        _git(repo, 'tag', 'v1.0.0')
        initial_hash = _git(repo, 'rev-parse', 'HEAD')
        (repo / 'file.c').write_text('line1\nchanged\nline3\nline4\nline5\n')
        _git(repo, 'add', 'file.c')
        _git(repo, 'commit', '-m', 'v2 change')
        _git(repo, 'tag', 'v2.0.0')
        second_hash = _git(repo, 'rev-parse', 'HEAD')

        version = find_introducing_version(repo, {initial_hash, second_hash})
        assert version == '1.0.0'

    def test_no_tags(self, tmp_path):
        repo = _init_repo(tmp_path)
        initial_hash = _git(repo, 'rev-parse', 'HEAD')
        version = find_introducing_version(repo, {initial_hash})
        assert version is None

    def test_empty_commits(self, tmp_path):
        repo = _init_repo(tmp_path)
        assert find_introducing_version(repo, set()) is None

    def test_fallback_to_tag_contains(self, tmp_path):
        """When describe --contains fails, falls back to tag --contains."""
        repo = _init_repo(tmp_path)
        _git(repo, 'tag', 'v1.0.0')
        initial_hash = _git(repo, 'rev-parse', 'HEAD')
        # git describe --contains should work here, but the function
        # should also handle the fallback path
        version = find_introducing_version(repo, {initial_hash})
        assert version is not None


# --- is_cve_applicable ---

class TestIsCveApplicable:
    def test_applicable(self):
        assert is_cve_applicable('1.0.0', '2.0.0') is True

    def test_not_applicable(self):
        assert is_cve_applicable('3.0.0', '2.0.0') is False

    def test_equal_versions(self):
        assert is_cve_applicable('2.0.0', '2.0.0') is True

    def test_rc_suffix(self):
        assert is_cve_applicable('2.0.0-rc1', '2.0.0') is True

    def test_unparseable_introducing(self):
        assert is_cve_applicable('not_a_version!!!', '2.0.0') is None

    def test_unparseable_recipe(self):
        assert is_cve_applicable('1.0.0', 'not_a_version!!!') is None

    def test_complex_versions(self):
        assert is_cve_applicable('3.7.8', '3.7.9') is True
        assert is_cve_applicable('3.7.10', '3.7.9') is False


# --- check_vulnerability_origin ---

class TestCheckVulnerabilityOrigin:
    def test_not_applicable(self, tmp_path):
        """Code introduced in v2.0 but recipe is v1.0 → not applicable."""
        repo = _init_repo(tmp_path)
        _git(repo, 'tag', 'v1.0.0')
        # Replace line2 in v2.0 with vulnerable code
        (repo / 'file.c').write_text(
            'line1\nvulnerable_code\nline3\nline4\nline5\n')
        _git(repo, 'add', 'file.c')
        _git(repo, 'commit', '-m', 'introduce vulnerable code')
        _git(repo, 'tag', 'v2.0.0')
        # Fix the vulnerable code (modify same line)
        (repo / 'file.c').write_text(
            'line1\nfixed_code\nline3\nline4\nline5\n')
        _git(repo, 'add', 'file.c')
        _git(repo, 'commit', '-m', 'fix vulnerability')
        fix_hash = _git(repo, 'rev-parse', 'HEAD')
        # Check from v1.0 perspective — the blamed line was introduced in v2.0
        reason = check_vulnerability_origin(repo, [fix_hash], '1.0.0')
        assert reason is not None
        assert 'not affected' in reason

    def test_applicable(self, tmp_path):
        """Code introduced in v1.0 and recipe is v2.0 → applicable."""
        repo = _init_repo(tmp_path)
        _git(repo, 'tag', 'v1.0.0')
        (repo / 'file.c').write_text('line1\nchanged\nline3\nline4\nline5\n')
        _git(repo, 'add', 'file.c')
        _git(repo, 'commit', '-m', 'more changes')
        _git(repo, 'tag', 'v2.0.0')
        # Fix modifies lines from v1.0
        (repo / 'file.c').write_text('line1\nfixed\nline3\nline4\nline5\n')
        _git(repo, 'add', 'file.c')
        _git(repo, 'commit', '-m', 'fix')
        fix_hash = _git(repo, 'rev-parse', 'HEAD')
        reason = check_vulnerability_origin(repo, [fix_hash], '2.0.0')
        assert reason is None

    def test_no_version(self, tmp_path):
        """No recipe version → skip check, return None."""
        repo = _init_repo(tmp_path)
        assert check_vulnerability_origin(repo, ['abc'], '') is None
        assert check_vulnerability_origin(repo, ['abc'], None) is None

    def test_no_commits(self, tmp_path):
        repo = _init_repo(tmp_path)
        assert check_vulnerability_origin(repo, [], '1.0.0') is None

    def test_no_tags_indeterminate(self, tmp_path):
        """No tags in repo → can't determine version → return None."""
        repo = _init_repo(tmp_path)
        (repo / 'file.c').write_text('line1\nfixed\nline3\nline4\nline5\n')
        _git(repo, 'add', 'file.c')
        _git(repo, 'commit', '-m', 'fix')
        fix_hash = _git(repo, 'rev-parse', 'HEAD')
        assert check_vulnerability_origin(repo, [fix_hash], '1.0.0') is None

    def test_series_commits(self, tmp_path):
        """Series commits are included in the analysis."""
        repo = _init_repo(tmp_path)
        _git(repo, 'tag', 'v1.0.0')
        # Replace line2 with vulnerable code in v2.0
        (repo / 'file.c').write_text(
            'line1\nvulnerable\nline3\nline4\nline5\n')
        _git(repo, 'add', 'file.c')
        _git(repo, 'commit', '-m', 'add vuln')
        _git(repo, 'tag', 'v2.0.0')
        (repo / 'file.c').write_text(
            'line1\nfixed\nline3\nline4\nline5\n')
        _git(repo, 'add', 'file.c')
        _git(repo, 'commit', '-m', 'fix')
        fix_hash = _git(repo, 'rev-parse', 'HEAD')
        series = [{'commits': [fix_hash]}]
        reason = check_vulnerability_origin(repo, [], '1.0.0', series=series)
        assert reason is not None


# --- _is_release_tag ---

class TestIsReleaseTag:
    def test_release_tags(self):
        assert _is_release_tag('v2.42') is True
        assert _is_release_tag('binutils-2_42') is True
        assert _is_release_tag('release-3.7.9') is True
        assert _is_release_tag('libxml2-2.13.0') is True
        assert _is_release_tag('V_9_6_P1') is True

    def test_branchpoint_tags(self):
        assert _is_release_tag('binutils-2_15-branchpoint') is False
        assert _is_release_tag('binutils-2_42-branchpoint') is False
        assert _is_release_tag('foo-branchpoint') is False

    def test_rc_tags(self):
        assert _is_release_tag('v2.42-rc1') is False
        assert _is_release_tag('binutils-2_42-rc3') is False

    def test_alpha_beta_tags(self):
        assert _is_release_tag('v1.0-alpha') is False
        assert _is_release_tag('v1.0-beta2') is False
        assert _is_release_tag('foo-alpha1') is False

    def test_dev_tags(self):
        assert _is_release_tag('v1.0-dev') is False
        assert _is_release_tag('v2.0-snapshot') is False
        assert _is_release_tag('nightly-build') is False

    def test_branch_management_tags(self):
        assert _is_release_tag('binutils-2_15-start') is False
        assert _is_release_tag('foo-base') is False
        assert _is_release_tag('merge-point') is False


class TestFindIntroducingVersionFiltersBranchpoints:
    def test_skips_branchpoint_tag(self, tmp_path):
        """Non-release tags like branchpoint are skipped."""
        repo = _init_repo(tmp_path)
        _git(repo, 'tag', 'binutils-2_15-branchpoint')
        _git(repo, 'tag', 'binutils-2_42')
        initial_hash = _git(repo, 'rev-parse', 'HEAD')

        version = find_introducing_version(repo, {initial_hash})
        # Should pick 2.42, not 2.15-branchpoint
        assert version is not None
        assert 'branchpoint' not in version
        assert '42' in version

    def test_only_branchpoint_tags_returns_none(self, tmp_path):
        """If only non-release tags exist, return None."""
        repo = _init_repo(tmp_path)
        _git(repo, 'tag', 'binutils-2_15-branchpoint')
        _git(repo, 'tag', 'foo-rc1')
        initial_hash = _git(repo, 'rev-parse', 'HEAD')

        version = find_introducing_version(repo, {initial_hash})
        assert version is None
