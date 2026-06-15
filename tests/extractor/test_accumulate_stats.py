"""Tests for _accumulate_stats used during incremental processing."""

from cve_metadata_extractor.__main__ import _accumulate_stats


class TestAccumulateStats:
    def test_counts_single_source(self):
        stats = {'debian_hashes': 0, 'debian_patches': 0}
        result = {
            'hash_details': [{'hash': 'abc', 'source': 'debian'}],
            'patch_details': [{'url': 'http://x', 'source': 'debian'}],
        }
        _accumulate_stats(result, stats)
        assert stats == {'debian_hashes': 1, 'debian_patches': 1}

    def test_counts_comma_separated_sources(self):
        stats = {
            'bdba_hashes': 0, 'bdba_patches': 0,
            'debian_hashes': 0, 'debian_patches': 0,
        }
        result = {
            'hash_details': [{'hash': 'a', 'source': 'bdba, debian'}],
            'patch_details': [],
        }
        _accumulate_stats(result, stats)
        assert stats['bdba_hashes'] == 1
        assert stats['debian_hashes'] == 1

    def test_ignores_unknown_sources(self):
        stats = {'debian_hashes': 0, 'debian_patches': 0}
        result = {
            'hash_details': [{'hash': 'a', 'source': 'unknown'}],
            'patch_details': [],
        }
        _accumulate_stats(result, stats)
        assert stats == {'debian_hashes': 0, 'debian_patches': 0}

    def test_deduplicates_per_cve(self):
        """Multiple hashes from same source count as 1 CVE with hashes."""
        stats = {'osv_hashes': 0, 'osv_patches': 0}
        result = {
            'hash_details': [
                {'hash': 'a', 'source': 'osv'},
                {'hash': 'b', 'source': 'osv'},
            ],
            'patch_details': [],
        }
        _accumulate_stats(result, stats)
        assert stats['osv_hashes'] == 1

    def test_handles_missing_fields(self):
        stats = {'debian_hashes': 0, 'debian_patches': 0}
        _accumulate_stats({}, stats)
        assert stats == {'debian_hashes': 0, 'debian_patches': 0}
