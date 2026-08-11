# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector.git_ops — pure logic functions."""
from cve_corrector.git_ops import deduce_repo_from_patches, find_exact_tag

# --- find_exact_tag ---

def test_find_exact_tag_standard():
    assert find_exact_tag(["v3.7.8", "v3.7.9", "v3.8.0"], "3.7.9") == "v3.7.9"


def test_find_exact_tag_underscore():
    assert find_exact_tag(["release_3_7_9"], "3.7.9") == "release_3_7_9"


def test_find_exact_tag_no_match():
    assert find_exact_tag(["v1.0", "v2.0"], "3.7.9") is None


def test_find_exact_tag_prefix():
    assert find_exact_tag(["libfoo-3.7.9", "libfoo-3.7.8"], "3.7.9") == "libfoo-3.7.9"


def test_find_exact_tag_empty_list():
    assert find_exact_tag([], "3.7.9") is None


def test_find_exact_tag_mixed_separators():
    """binutils-style: tag uses underscore+dot mix like binutils-2_46.1"""
    tags = ["binutils-2_46.1", "binutils-2_46", "binutils-2_45"]
    assert find_exact_tag(tags, "2.46.1") == "binutils-2_46.1"


def test_find_exact_tag_all_underscore_binutils():
    """binutils-style: tag uses all underscores like binutils-2_46_1"""
    tags = ["binutils-2_46_1", "binutils-2_46", "binutils-2_45"]
    assert find_exact_tag(tags, "2.46.1") == "binutils-2_46_1"


def test_find_exact_tag_does_not_match_branchpoint():
    """branchpoint tags should not match (they contain extra text)."""
    tags = ["binutils-2_46-branchpoint", "binutils-2_46"]
    assert find_exact_tag(tags, "2.46") == "binutils-2_46"


# --- deduce_repo_from_patches ---

def test_deduce_repo_github():
    url = "https://github.com/libarchive/libarchive/commit/a612bf62"
    assert deduce_repo_from_patches([url]) == "https://github.com/libarchive/libarchive"


def test_deduce_repo_sourceware():
    url = "https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;a=commit;h=abc123"
    result = deduce_repo_from_patches([url])
    assert "sourceware.org/git/binutils-gdb.git" in result


def test_deduce_repo_rejects_sourceware_lookalike_host():
    url = "https://sourceware.org.evil.com/git/gitweb.cgi?p=binutils-gdb.git;a=commit;h=abc123"
    assert deduce_repo_from_patches([url]) is None


def test_deduce_repo_savannah_cgit():
    url = "https://git.savannah.gnu.org/cgit/grub.git/commit/?id=abc123"
    result = deduce_repo_from_patches([url])
    assert result == "https://https.git.savannah.gnu.org/git/grub.git"


def test_deduce_repo_savannah_git():
    url = "https://git.savannah.gnu.org/git/grub.git/commit/?id=abc123"
    result = deduce_repo_from_patches([url])
    assert "savannah.gnu.org/git/grub" in result


def test_deduce_repo_rejects_savannah_lookalike_host():
    url = "https://git.savannah.gnu.org.evil.com/cgit/grub.git/commit/?id=abc123"
    assert deduce_repo_from_patches([url]) is None


def test_deduce_repo_gitlab():
    url = "https://gitlab.com/foo/bar/-/commit/abc123"
    assert deduce_repo_from_patches([url]) == "https://gitlab.com/foo/bar"


def test_deduce_repo_skips_bugzilla():
    assert deduce_repo_from_patches(["https://bugzilla.redhat.com/show_bug.cgi?id=123"]) is None


def test_deduce_repo_gitweb_generic():
    url = "https://git.samba.org/?p=rsync.git;a=commit;h=8ad4b5d912fad1df29717dddaa775724da77d299"
    assert deduce_repo_from_patches([url]) == "https://git.samba.org/rsync.git"


def test_deduce_repo_empty_list():
    assert deduce_repo_from_patches([]) is None
