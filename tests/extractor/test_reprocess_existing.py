# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for ``--reprocess-existing`` in cve_metadata_extractor."""
import json
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _no_extra_plugins(monkeypatch, tmp_path):
    """Prevent extra/ plugins from interfering during these tests."""
    import cve_metadata_extractor.sources as src_mod
    original = list(src_mod.SOURCE_REGISTRY)
    monkeypatch.setenv('CVE_EXTRA_SOURCES_DIR', str(tmp_path / 'empty'))
    yield
    src_mod.SOURCE_REGISTRY[:] = original


def _entry(name='foo', version='1.0', score='7.5', hashes=('old',),
           **extra):
    details = [{'hash': h, 'source': 'oldsrc'} for h in hashes]
    return {
        'name': name, 'version': version, 'cvss3_score': score,
        'hashes': list(hashes), 'hash_details': details,
        'patches': [], 'patch_details': [], 'references': [], **extra,
    }


def _new_result(hash_):
    return {
        'name': 'foo', 'version': '1.0', 'cvss3_score': '7.5',
        'hashes': [hash_],
        'hash_details': [{'hash': hash_, 'source': 'newsrc'}],
        'patches': [], 'patch_details': [], 'references': [],
    }


def _run(monkeypatch, out_file, *extra_argv):
    from cve_metadata_extractor.__main__ import main
    monkeypatch.setattr(
        'sys.argv', ['prog', '--output', str(out_file), *extra_argv])
    main()


@patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', [])
@patch('cve_metadata_extractor.__main__.load_pr_cache')
class TestReprocessExisting:
    def test_flag_is_sufficient_input_and_reruns_stored_cves(
            self, _pr, tmp_path, monkeypatch):
        '''No --cve-id/--yocto-summary: stored CVEs are re-run and merged.'''
        out_file = tmp_path / 'out.json'
        out_file.write_text(json.dumps({'CVE-2025-0001': _entry()}))

        with patch('cve_metadata_extractor.__main__.process_cve',
                   return_value=_new_result('new')) as mock_process:
            _run(monkeypatch, out_file, '--reprocess-existing')

        assert mock_process.call_count == 1
        cve = mock_process.call_args.args[0]
        assert cve['id'] == 'CVE-2025-0001'
        # Stored context is fed back so name/version/score are not lost.
        assert (cve['name'], cve['version'], cve['cvss3 Score']) == (
            'foo', '1.0', '7.5')
        data = json.loads(out_file.read_text())
        assert sorted(data['CVE-2025-0001']['hashes']) == ['new', 'old']

    def test_without_flag_existing_cves_are_skipped(
            self, _pr, tmp_path, monkeypatch):
        '''Control: the pre-existing incremental behavior is unchanged.'''
        out_file = tmp_path / 'out.json'
        out_file.write_text(json.dumps({'CVE-2025-0001': _entry()}))

        with patch('cve_metadata_extractor.__main__.process_cve') as mock_process:
            _run(monkeypatch, out_file, '--cve-id', 'CVE-2025-0001')

        mock_process.assert_not_called()

    def test_explicit_cve_is_added_alongside_stored_ones(
            self, _pr, tmp_path, monkeypatch):
        out_file = tmp_path / 'out.json'
        out_file.write_text(json.dumps({'CVE-2025-0001': _entry()}))

        with patch('cve_metadata_extractor.__main__.process_cve',
                   return_value=_new_result('new')) as mock_process:
            _run(monkeypatch, out_file, '--reprocess-existing',
                 '--cve-id', 'CVE-2025-0002')

        ids = sorted(c.args[0]['id'] for c in mock_process.call_args_list)
        assert ids == ['CVE-2025-0001', 'CVE-2025-0002']
        assert set(json.loads(out_file.read_text())) == {
            'CVE-2025-0001', 'CVE-2025-0002'}

    def test_keys_not_regenerated_are_preserved(
            self, _pr, tmp_path, monkeypatch):
        '''upstream_status etc. must survive when this run did not set them.'''
        out_file = tmp_path / 'out.json'
        status = {'scarthgap': 'merged'}
        out_file.write_text(json.dumps({
            'CVE-2025-0001': _entry(upstream_status=status)}))

        with patch('cve_metadata_extractor.__main__.process_cve',
                   return_value=_new_result('new')):
            _run(monkeypatch, out_file, '--reprocess-existing')

        data = json.loads(out_file.read_text())
        assert data['CVE-2025-0001']['upstream_status'] == status

    @pytest.mark.parametrize('content', [None, '{}', 'not json', '[1]'])
    def test_missing_or_empty_output_is_an_error(
            self, _pr, tmp_path, monkeypatch, content):
        from shared.exit_codes import EXIT_METADATA_ERROR
        out_file = tmp_path / 'out.json'
        if content is not None:
            out_file.write_text(content)

        with patch('cve_metadata_extractor.__main__.process_cve') as mock_process:
            with pytest.raises(SystemExit) as exc:
                _run(monkeypatch, out_file, '--reprocess-existing')

        assert exc.value.code == EXIT_METADATA_ERROR
        mock_process.assert_not_called()
        # The unusable file must not be overwritten.
        if content is not None:
            assert out_file.read_text() == content

    def test_fails_before_source_setup(self, _pr, tmp_path, monkeypatch):
        '''A bad request must not trigger clones/fetches in source.setup().'''
        from cve_metadata_extractor.sources import CveSource

        class Spy(CveSource):
            name = 'spy'
            called = False

            def setup(self, args, cfg):
                Spy.called = True

        with patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', [Spy()]):
            with pytest.raises(SystemExit):
                _run(monkeypatch, tmp_path / 'missing.json',
                     '--reprocess-existing')

        assert Spy.called is False
