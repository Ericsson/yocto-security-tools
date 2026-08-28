# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_metadata_extractor CLI, processing, and cve_sources."""
import json
import os
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _no_extra_plugins(monkeypatch, tmp_path):
    """Prevent extra/ plugins from interfering during these tests."""
    import cve_metadata_extractor.sources as src_mod
    original = list(src_mod.SOURCE_REGISTRY)
    monkeypatch.setenv('CVE_EXTRA_SOURCES_DIR', str(tmp_path / 'empty'))
    yield
    src_mod.SOURCE_REGISTRY[:] = original


class TestParseArguments:
    def test_cve_id_input(self):
        from cve_metadata_extractor.__main__ import parse_arguments
        cfg = {'cache_dir': '/tmp/cache', 'oe_branches': ['scarthgap'],
               'repo_dir': '/tmp/repos'}
        with patch('sys.argv', ['prog', '--cve-id', 'CVE-2025-0001']):
            with patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', []):
                args = parse_arguments(cfg)
        assert args.cve_id == ['CVE-2025-0001']

    def test_multiple_cve_ids(self):
        from cve_metadata_extractor.__main__ import parse_arguments
        cfg = {'cache_dir': '/tmp/c', 'oe_branches': ['scarthgap'],
               'repo_dir': '/tmp/r'}
        with patch('sys.argv', ['prog', '--cve-id', 'CVE-2025-0001', 'CVE-2025-0002']):
            with patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', []):
                args = parse_arguments(cfg)
        assert args.cve_id == ['CVE-2025-0001', 'CVE-2025-0002']

    def test_output_default(self):
        from cve_metadata_extractor.__main__ import parse_arguments
        cfg = {'cache_dir': '/tmp/c', 'oe_branches': ['scarthgap'],
               'repo_dir': '/tmp/r'}
        with patch('sys.argv', ['prog', '--cve-id', 'CVE-1']):
            with patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', []):
                args = parse_arguments(cfg)
        assert args.output == 'cve-metadata.json'

    def test_disable_sources(self):
        from cve_metadata_extractor.__main__ import parse_arguments
        cfg = {'cache_dir': '/tmp/c', 'oe_branches': ['scarthgap'],
               'repo_dir': '/tmp/r'}
        with patch('sys.argv', ['prog', '--cve-id', 'CVE-1',
                                '--no-debian', '--no-osv']):
            with patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', []):
                args = parse_arguments(cfg)
        assert args.no_debian is True
        assert args.no_osv is True

    def test_no_ubuntu_flag_parses_without_error(self):
        '''Deprecated --no-ubuntu still parses; it does not enable ubuntu.'''
        from cve_metadata_extractor.__main__ import parse_arguments
        cfg = {'cache_dir': '/tmp/c', 'oe_branches': ['scarthgap'],
               'repo_dir': '/tmp/r'}
        with patch('sys.argv', ['prog', '--cve-id', 'CVE-1', '--no-ubuntu']):
            with patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', []):
                args = parse_arguments(cfg)
        assert args.no_ubuntu is True
        assert args.ubuntu_api is False

    def test_ubuntu_api_flag(self):
        from cve_metadata_extractor.__main__ import parse_arguments
        cfg = {'cache_dir': '/tmp/c', 'oe_branches': ['scarthgap'],
               'repo_dir': '/tmp/r'}
        with patch('sys.argv', ['prog', '--cve-id', 'CVE-1', '--ubuntu-api']):
            with patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', []):
                args = parse_arguments(cfg)
        assert args.ubuntu_api is True

    def test_no_uct_flag(self):
        from cve_metadata_extractor.__main__ import parse_arguments
        cfg = {'cache_dir': '/tmp/c', 'oe_branches': ['scarthgap'],
               'repo_dir': '/tmp/r'}
        with patch('sys.argv', ['prog', '--cve-id', 'CVE-1', '--no-uct']):
            with patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', []):
                args = parse_arguments(cfg)
        assert args.no_uct is True


class TestUbuntuUctActivation:
    '''Test that uct is active by default and ubuntu (HTTP) is opt-in.'''

    def _active_names(self, extra_argv=None):
        from cve_metadata_extractor.__main__ import parse_arguments
        from cve_metadata_extractor.ubuntu import UbuntuSource
        from cve_metadata_extractor.uct import UctSource
        cfg = {'cache_dir': '/tmp/c', 'oe_branches': ['scarthgap'],
               'repo_dir': '/tmp/r'}
        argv = ['prog', '--cve-id', 'CVE-1'] + (extra_argv or [])
        sources = [UbuntuSource(), UctSource()]
        with patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', sources):
            with patch('sys.argv', argv):
                args = parse_arguments(cfg)
        return {s.name for s in sources if s.is_enabled(args)}, args

    def test_default_has_uct_not_ubuntu(self):
        active, _ = self._active_names()
        assert 'uct' in active
        assert 'ubuntu' not in active

    def test_ubuntu_api_enables_both(self):
        active, _ = self._active_names(['--ubuntu-api'])
        assert 'uct' in active
        assert 'ubuntu' in active

    def test_no_uct_disables_uct(self):
        active, _ = self._active_names(['--no-uct'])
        assert 'uct' not in active
        assert 'ubuntu' not in active

    def test_no_ubuntu_alone_does_not_enable_ubuntu(self):
        active, _ = self._active_names(['--no-ubuntu'])
        assert 'ubuntu' not in active
        assert 'uct' in active

    def test_check_oe_flag(self):
        from cve_metadata_extractor.__main__ import parse_arguments
        cfg = {'cache_dir': '/tmp/c', 'oe_branches': ['scarthgap'],
               'repo_dir': '/tmp/r'}
        with patch('sys.argv', ['prog', '--cve-id', 'CVE-1', '--check-oe']):
            with patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', []):
                args = parse_arguments(cfg)
        assert args.check_oe is True

    def test_checkpoint_interval(self):
        from cve_metadata_extractor.__main__ import parse_arguments
        cfg = {'cache_dir': '/tmp/c', 'oe_branches': ['scarthgap'],
               'repo_dir': '/tmp/r'}
        with patch('sys.argv', [
                'prog', '--cve-id', 'CVE-1',
                '--checkpoint-interval', '0']):
            with patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', []):
                args = parse_arguments(cfg)
        assert args.checkpoint_interval == 0

    @pytest.mark.parametrize('value', ['-1', 'nan', 'inf'])
    def test_checkpoint_interval_rejects_invalid_value(self, value):
        from cve_metadata_extractor.__main__ import parse_arguments
        cfg = {'cache_dir': '/tmp/c', 'oe_branches': ['scarthgap'],
               'repo_dir': '/tmp/r'}
        with patch('sys.argv', [
                'prog', '--cve-id', 'CVE-1',
                '--checkpoint-interval', value]):
            with patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', []):
                with pytest.raises(SystemExit):
                    parse_arguments(cfg)


class TestCfgKeyForFlag:
    def test_simple(self):
        from cve_metadata_extractor.__main__ import _cfg_key_for_flag
        assert _cfg_key_for_flag('--debian-tracker-dir') == 'debian_tracker_dir'

    def test_short_flag(self):
        from cve_metadata_extractor.__main__ import _cfg_key_for_flag
        assert _cfg_key_for_flag('--no-osv') == 'no_osv'


class TestPrintSummary:
    def test_basic_summary(self, capsys):
        from cve_metadata_extractor.__main__ import _print_summary
        results = {
            'CVE-1': {'hashes': ['abc'], 'patches': [], 'cvss3_score': '7.5'},
            'CVE-2': {'hashes': [], 'patches': ['http://p'], 'cvss3_score': None},
        }
        args = MagicMock(check_oe=False, download_patches=False)
        _print_summary(results, {}, args)
        out = capsys.readouterr().out
        assert 'Total CVEs processed: 2' in out
        assert 'CVEs with hashes: 1' in out


class TestMain:
    def test_no_input_exits(self, monkeypatch):
        from cve_metadata_extractor.__main__ import main
        monkeypatch.setattr('sys.argv', ['prog'])
        with patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', []):
            with pytest.raises(SystemExit):
                main()

    def test_plugin_input_source_passes_validation(self, monkeypatch, tmp_path):
        """A plugin with is_input_source=True should pass input validation."""
        from cve_metadata_extractor.sources import CveSource

        class FakeInput(CveSource):
            name = 'fake_ndjson'
            is_input_source = True
            cli_args = [(['--cve-ndjson'], {'help': 'NDJSON file'})]

            def is_enabled(self, args):
                return bool(getattr(args, 'cve_ndjson', None))

        fake = FakeInput()
        out_file = tmp_path / 'out.json'
        ndjson_file = tmp_path / 'input.ndjson'
        ndjson_file.write_text('')
        monkeypatch.setattr('sys.argv', [
            'prog', '--cve-ndjson', str(ndjson_file),
            '--output', str(out_file)])

        with patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', [fake]):
            with patch('cve_metadata_extractor.__main__.load_pr_cache'):
                with patch('cve_metadata_extractor.cve_sources.load_cves_from_sources',
                           return_value=[]):
                    from cve_metadata_extractor.__main__ import main
                    main()
        assert out_file.exists()

    @patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', [])
    @patch('cve_metadata_extractor.__main__.load_pr_cache')
    @patch('cve_metadata_extractor.cve_sources.load_cves_from_sources')
    @patch('cve_metadata_extractor.__main__.process_cve')
    def test_cve_id_flow(self, mock_process, mock_load, mock_pr, tmp_path, monkeypatch):
        mock_load.return_value = [{'id': 'CVE-2025-0001', 'name': 'foo'}]
        mock_process.return_value = {
            'name': 'foo', 'hashes': ['abc123'], 'hash_details': [],
            'patches': [], 'patch_details': [], 'references': [],
            'version': '1.0', 'cvss3_score': None,
        }
        out_file = tmp_path / 'out.json'
        monkeypatch.setattr('sys.argv', [
            'prog', '--cve-id', 'CVE-2025-0001', '--output', str(out_file)])
        from cve_metadata_extractor.__main__ import main
        main()
        data = json.loads(out_file.read_text())
        assert 'CVE-2025-0001' in data

    @patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', [])
    @patch('cve_metadata_extractor.__main__.load_pr_cache')
    @patch('cve_metadata_extractor.cve_sources.load_cves_from_sources')
    @patch('cve_metadata_extractor.__main__.process_cve')
    def test_checkpoints_completed_cves_on_interrupt(
            self, mock_process, mock_load, mock_pr, tmp_path, monkeypatch):
        mock_load.return_value = [
            {'id': 'CVE-2025-0001', 'name': 'foo'},
            {'id': 'CVE-2025-0002', 'name': 'bar'},
        ]
        first_result = {
            'name': 'foo', 'hashes': ['abc123'], 'hash_details': [],
            'patches': [], 'patch_details': [], 'references': [],
            'version': '1.0', 'cvss3_score': None,
        }
        mock_process.side_effect = [first_result, KeyboardInterrupt]
        out_file = tmp_path / 'out.json'
        monkeypatch.setattr('sys.argv', [
            'prog', '--cve-id', 'CVE-2025-0001', 'CVE-2025-0002',
            '--output', str(out_file)])

        from cve_metadata_extractor.__main__ import main
        with pytest.raises(KeyboardInterrupt):
            main()

        assert json.loads(out_file.read_text()) == {
            'CVE-2025-0001': first_result,
        }

    @patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', [])
    @patch('cve_metadata_extractor.__main__.load_pr_cache')
    @patch('cve_metadata_extractor.cve_sources.load_cves_from_sources')
    @patch('cve_metadata_extractor.__main__.process_cve')
    @patch('cve_metadata_extractor.__main__._save_results')
    def test_periodic_checkpoint_after_interval(
            self, mock_save, mock_process, mock_load, mock_pr,
            tmp_path, monkeypatch):
        mock_load.return_value = [
            {'id': 'CVE-2025-0001', 'name': 'foo'},
            {'id': 'CVE-2025-0002', 'name': 'bar'},
        ]
        mock_process.side_effect = [
            {'name': 'foo', 'hashes': [], 'hash_details': [],
             'patches': [], 'patch_details': [], 'references': []},
            {'name': 'bar', 'hashes': [], 'hash_details': [],
             'patches': [], 'patch_details': [], 'references': []},
        ]
        monkeypatch.setattr('sys.argv', [
            'prog', '--cve-id', 'CVE-2025-0001', 'CVE-2025-0002',
            '--output', str(tmp_path / 'out.json'),
            '--checkpoint-interval', '60'])

        from cve_metadata_extractor.__main__ import main
        with patch('cve_metadata_extractor.__main__.time.monotonic',
                   side_effect=[100, 159, 160, 161]):
            main()

        assert mock_save.call_count == 2
        assert set(mock_save.call_args_list[0].args[0]) == {
            'CVE-2025-0001', 'CVE-2025-0002',
        }

    @patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', [])
    @patch('cve_metadata_extractor.__main__.load_pr_cache')
    @patch('cve_metadata_extractor.cve_sources.load_cves_from_sources')
    @patch('cve_metadata_extractor.__main__.process_cve')
    @patch('cve_metadata_extractor.__main__._save_results')
    def test_periodic_checkpoint_throttled_before_interval(
            self, mock_save, mock_process, mock_load, mock_pr,
            tmp_path, monkeypatch):
        mock_load.return_value = [{'id': 'CVE-2025-0001', 'name': 'foo'}]
        mock_process.return_value = {
            'name': 'foo', 'hashes': [], 'hash_details': [],
            'patches': [], 'patch_details': [], 'references': [],
        }
        monkeypatch.setattr('sys.argv', [
            'prog', '--cve-id', 'CVE-2025-0001',
            '--output', str(tmp_path / 'out.json'),
            '--checkpoint-interval', '60'])

        from cve_metadata_extractor.__main__ import main
        with patch('cve_metadata_extractor.__main__.time.monotonic',
                   side_effect=[100, 159]):
            main()

        assert mock_save.call_count == 1

    @patch('cve_metadata_extractor.__main__.SOURCE_REGISTRY', [])
    @patch('cve_metadata_extractor.__main__.load_pr_cache')
    @patch('cve_metadata_extractor.cve_sources.load_cves_from_sources')
    @patch('cve_metadata_extractor.__main__.process_cve')
    @patch('cve_metadata_extractor.__main__._save_results')
    def test_zero_interval_disables_periodic_but_saves_on_interrupt(
            self, mock_save, mock_process, mock_load, mock_pr,
            tmp_path, monkeypatch):
        mock_load.return_value = [
            {'id': 'CVE-2025-0001', 'name': 'foo'},
            {'id': 'CVE-2025-0002', 'name': 'bar'},
        ]
        first_result = {
            'name': 'foo', 'hashes': [], 'hash_details': [],
            'patches': [], 'patch_details': [], 'references': [],
        }
        mock_process.side_effect = [first_result, KeyboardInterrupt]
        monkeypatch.setattr('sys.argv', [
            'prog', '--cve-id', 'CVE-2025-0001', 'CVE-2025-0002',
            '--output', str(tmp_path / 'out.json'),
            '--checkpoint-interval', '0'])

        from cve_metadata_extractor.__main__ import main
        with pytest.raises(KeyboardInterrupt):
            main()

        mock_save.assert_called_once()
        assert mock_save.call_args.args[0] == {
            'CVE-2025-0001': first_result,
        }


class TestSaveResults:
    def test_new_output_respects_umask(self, tmp_path):
        from cve_metadata_extractor.__main__ import _save_results
        out_file = tmp_path / 'out.json'

        old_umask = os.umask(0o022)
        try:
            _save_results({'CVE-NEW': {'hashes': []}}, str(out_file))
        finally:
            os.umask(old_umask)

        assert out_file.stat().st_mode & 0o777 == 0o644

    def test_existing_output_preserves_mode(self, tmp_path):
        from cve_metadata_extractor.__main__ import _save_results
        out_file = tmp_path / 'out.json'
        out_file.write_text('{}')
        out_file.chmod(0o640)

        _save_results({'CVE-NEW': {'hashes': []}}, str(out_file))

        assert out_file.stat().st_mode & 0o777 == 0o640

    def test_failed_write_preserves_existing_output(self, tmp_path):
        from cve_metadata_extractor.__main__ import _save_results
        out_file = tmp_path / 'out.json'
        original = {'CVE-OLD': {'hashes': []}}
        out_file.write_text(json.dumps(original))

        with pytest.raises(TypeError):
            _save_results({'not-json': {object()}}, str(out_file))

        assert json.loads(out_file.read_text()) == original
        assert not list(tmp_path.glob('*.tmp'))

    def test_interrupted_write_preserves_existing_output(self, tmp_path):
        from cve_metadata_extractor.__main__ import _save_results
        out_file = tmp_path / 'out.json'
        original = {'CVE-OLD': {'hashes': []}}
        out_file.write_text(json.dumps(original))

        with patch('cve_metadata_extractor.__main__.json.dump',
                   side_effect=KeyboardInterrupt):
            with pytest.raises(KeyboardInterrupt):
                _save_results({'CVE-NEW': {'hashes': []}}, str(out_file))

        assert json.loads(out_file.read_text()) == original
        assert not list(tmp_path.glob('*.tmp'))


class TestProcessCve:
    def test_basic_processing(self):
        from cve_metadata_extractor.processing import (
            extract_metadata_from_sources,
        )
        source = MagicMock()
        source.extract.return_value = ([{'hash': 'h1', 'source': 'test'}], [], [], [])
        source.enrich.return_value = None
        source.name = 'test'
        source.deduce_component.return_value = None
        _args = MagicMock(check_oe=False, cache='/tmp')
        stats = {}
        metadata = extract_metadata_from_sources('CVE-1', [source], stats)
        assert metadata['hashes'][0]['hash'] == 'h1'

    def test_deduce_component(self):
        from cve_metadata_extractor.processing import deduce_component_name
        source = MagicMock()
        source.deduce_component.return_value = 'deduced-pkg'
        result = deduce_component_name('CVE-1', '/tmp', [source])
        assert result == 'deduced-pkg'


class TestExtractMetadataFromSources:
    def test_deduplicates(self):
        from cve_metadata_extractor.processing import extract_metadata_from_sources
        s1 = MagicMock()
        s1.extract.return_value = (
            [{'hash': 'abc', 'source': 's1'}],
            [{'url': 'http://p', 'source': 's1'}], [], [])
        s2 = MagicMock()
        s2.extract.return_value = (
            [{'hash': 'abc', 'source': 's2'}],
            [], [], [])
        result = extract_metadata_from_sources('CVE-1', [s1, s2], {})
        assert len(result['hashes']) == 1

    def test_series_dedup(self):
        from cve_metadata_extractor.processing import extract_metadata_from_sources
        s1 = MagicMock()
        s1.extract.return_value = (
            [], [], [{'pull_url': 'http://pr/1', 'commits': ['a']}], [])
        s2 = MagicMock()
        s2.extract.return_value = (
            [], [], [{'pull_url': 'http://pr/1', 'commits': ['a']}], [])
        result = extract_metadata_from_sources('CVE-1', [s1, s2], {})
        assert len(result['series']) == 1


def _plugin_active():
    """Check if the elin_sec_bulletin_input plugin has monkey-patched load_cves_from_sources."""
    try:
        from cve_metadata_extractor.cve_sources import load_cves_from_sources
        return 'extended' in getattr(load_cves_from_sources, '__name__', '')
    except Exception:
        return False


@pytest.mark.skipif(_plugin_active(),
                    reason="extra/ plugin monkey-patches load_cves_from_sources")
class TestLoadCvesFromSources:
    """Test the core load_cves_from_sources logic."""

    def test_cve_id_only(self):
        # Import the actual function from the module (not the monkey-patched one)
        from cve_metadata_extractor import cve_sources
        fn = cve_sources.__dict__.get('load_cves_from_sources',
                                       cve_sources.load_cves_from_sources)
        # If monkey-patched, get the original via closure
        if hasattr(fn, '__wrapped__'):
            fn = fn.__wrapped__
        result = cve_sources.load_cves_from_sources(['CVE-2025-0001'], None, None)
        assert any(c['id'] == 'CVE-2025-0001' for c in result)

    def test_yocto_summary(self, tmp_path):
        summary = {'package': [{'name': 'openssl', 'version': '3.0.1',
                                'issue': [{'id': 'CVE-2025-9999',
                                           'status': 'Unpatched'}]}]}
        f = tmp_path / 'summary.json'
        f.write_text(json.dumps(summary))
        from cve_metadata_extractor import cve_sources
        result = cve_sources.load_cves_from_sources(
            None, None, None, yocto_summary=str(f))
        assert any(c['id'] == 'CVE-2025-9999' for c in result)

    def test_filters_linux_kernel(self):
        from cve_metadata_extractor import cve_sources
        result = cve_sources.load_cves_from_sources(
            ['CVE-2025-0001'], 'linux_kernel', None)
        assert len(result) == 0

    def test_merges_cve_id_and_summary(self, tmp_path):
        summary = {'package': [{'name': 'curl', 'version': '8.0',
                                'issue': [{'id': 'CVE-2025-1111',
                                           'status': 'Unpatched'}]}]}
        f = tmp_path / 's.json'
        f.write_text(json.dumps(summary))
        from cve_metadata_extractor import cve_sources
        result = cve_sources.load_cves_from_sources(
            ['CVE-2025-2222'], None, None, yocto_summary=str(f))
        ids = [c['id'] for c in result]
        assert 'CVE-2025-1111' in ids
        assert 'CVE-2025-2222' in ids
