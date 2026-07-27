# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector.workflow — pure helper functions."""
import json

import pytest

from cve_corrector.ptest import compare_ptest_results
from cve_corrector.recipe_ops import sort_cve_lines_in_recipe
from cve_corrector.state import MetadataError, load_cve_metadata
from cve_corrector.workflow import filter_by_skip_sources

# --- compare_ptest_results ---

def test_compare_ptest_same():
    r = "PASSED: 42, FAILED: 3"
    assert compare_ptest_results(r, r) is True


def test_compare_ptest_increased():
    assert compare_ptest_results("PASSED: 42, FAILED: 3",
                                  "PASSED: 41, FAILED: 4") is False


def test_compare_ptest_decreased():
    assert compare_ptest_results("PASSED: 42, FAILED: 3",
                                  "PASSED: 44, FAILED: 1") is True


def test_compare_ptest_missing_counts():
    assert compare_ptest_results("no results", "PASSED: 1, FAILED: 0") is True
    assert compare_ptest_results("PASSED: 1, FAILED: 0", "no results") is True
    assert compare_ptest_results("no results", "no results") is True


# --- sort_cve_lines_in_recipe ---

def testsort_cve_lines_in_recipe(tmp_path):
    recipe = tmp_path / "recipes" / "foo_1.0.bb"
    recipe.parent.mkdir(parents=True)
    recipe.write_text(
        'SRC_URI = "\\\n'
        '    file://base.patch \\\n'
        '    file://CVE-2025-1234-3.patch \\\n'
        '    file://CVE-2025-1234-1.patch \\\n'
        '    file://CVE-2025-1234-2.patch \\\n'
        '"\n'
    )
    sort_cve_lines_in_recipe("CVE-2025-1234", tmp_path)
    content = recipe.read_text()
    idx1 = content.index("CVE-2025-1234-1")
    idx2 = content.index("CVE-2025-1234-2")
    idx3 = content.index("CVE-2025-1234-3")
    assert idx1 < idx2 < idx3


def test_sort_cve_lines_already_sorted(tmp_path):
    recipe = tmp_path / "recipes" / "foo_1.0.bb"
    recipe.parent.mkdir(parents=True)
    original = (
        'SRC_URI = "\\\n'
        '    file://CVE-2025-1234-1.patch \\\n'
        '    file://CVE-2025-1234-2.patch \\\n'
        '"\n'
    )
    recipe.write_text(original)
    sort_cve_lines_in_recipe("CVE-2025-1234", tmp_path)
    assert recipe.read_text() == original


def test_sort_cve_lines_single_patch(tmp_path):
    recipe = tmp_path / "recipes" / "foo_1.0.bb"
    recipe.parent.mkdir(parents=True)
    original = 'SRC_URI = "file://CVE-2025-1234-1.patch"\n'
    recipe.write_text(original)
    sort_cve_lines_in_recipe("CVE-2025-1234", tmp_path)
    assert recipe.read_text() == original


# --- load_cve_metadata ---

def test_load_cve_metadata_valid(tmp_path):
    f = tmp_path / "cve.json"
    data = {"CVE-2025-0001": {"name": "foo"}}
    f.write_text(json.dumps(data))
    assert load_cve_metadata(f) == data


def test_load_cve_metadata_missing_file(tmp_path):
    with pytest.raises(MetadataError):
        load_cve_metadata(tmp_path / "nonexistent.json")


def test_load_cve_metadata_invalid_json(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{invalid json")
    with pytest.raises(MetadataError):
        load_cve_metadata(f)


# --- filter_by_skip_sources ---

def test_skip_sources_empty_is_noop():
    info = {'hashes': ['a'], 'hash_details': [{'hash': 'a', 'source': 'osv'}]}
    assert filter_by_skip_sources(info, []) is info


def test_skip_sources_drops_unique_source():
    """A commit reported only by the skipped source is removed."""
    info = {
        'hashes': ['deb1', 'osv1'],
        'hash_details': [
            {'hash': 'deb1', 'url': 'u1', 'source': 'debian'},
            {'hash': 'osv1', 'url': 'u2', 'source': 'osv'},
        ],
    }
    out = filter_by_skip_sources(info, ['osv'])
    assert out['hashes'] == ['deb1']
    assert [d['hash'] for d in out['hash_details']] == ['deb1']


def test_skip_sources_keeps_corroborated_commit():
    """A commit also reported by a non-skipped source is kept (lenient AND)."""
    info = {
        'hashes': ['shared'],
        'hash_details': [{'hash': 'shared', 'url': 'u', 'source': 'debian, osv'}],
    }
    out = filter_by_skip_sources(info, ['osv'])
    assert out['hashes'] == ['shared']
    assert len(out['hash_details']) == 1


def test_skip_sources_case_insensitive():
    info = {
        'hashes': ['osv1'],
        'hash_details': [{'hash': 'osv1', 'source': 'OSV'}],
    }
    out = filter_by_skip_sources(info, ['osv'])
    assert out['hashes'] == []


def test_skip_sources_repeatable_multiple():
    info = {
        'hashes': ['deb1', 'osv1', 'ubu1'],
        'hash_details': [
            {'hash': 'deb1', 'source': 'debian'},
            {'hash': 'osv1', 'source': 'osv'},
            {'hash': 'ubu1', 'source': 'ubuntu'},
        ],
    }
    out = filter_by_skip_sources(info, ['osv', 'ubuntu'])
    assert out['hashes'] == ['deb1']


def test_skip_sources_unattributed_hash_kept():
    """A hash with no matching hash_details entry cannot be attributed, so kept."""
    info = {
        'hashes': ['bare', 'osv1'],
        'hash_details': [{'hash': 'osv1', 'source': 'osv'}],
    }
    out = filter_by_skip_sources(info, ['osv'])
    assert out['hashes'] == ['bare']


def test_skip_sources_does_not_mutate_input():
    info = {
        'hashes': ['osv1'],
        'hash_details': [{'hash': 'osv1', 'source': 'osv'}],
    }
    filter_by_skip_sources(info, ['osv'])
    assert info['hashes'] == ['osv1']
    assert len(info['hash_details']) == 1


def test_skip_sources_series_untouched():
    """Series carry no source attribution and must be left as-is."""
    info = {
        'hashes': ['osv1'],
        'hash_details': [{'hash': 'osv1', 'source': 'osv'}],
        'series': [{'pull_url': 'https://x/pull/1', 'commits': ['c1']}],
    }
    out = filter_by_skip_sources(info, ['osv'])
    assert out['series'] == info['series']
