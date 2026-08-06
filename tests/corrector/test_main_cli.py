# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector/__main__.py CLI parsing and flow."""
import json
from unittest.mock import patch

import pytest

from cve_corrector.__main__ import _check_bitbake_env, _get_version, main


class TestGetVersion:
    def test_returns_string(self):
        v = _get_version()
        assert isinstance(v, str)
        assert v  # not empty


class TestCheckBitbakeEnv:
    def test_no_bbpath(self, monkeypatch):
        monkeypatch.delenv('BBPATH', raising=False)
        with pytest.raises(SystemExit):
            _check_bitbake_env()

    def test_no_bitbake_layers(self, monkeypatch):
        monkeypatch.setenv('BBPATH', '/tmp')
        with patch('shutil.which', return_value=None), pytest.raises(SystemExit):
            _check_bitbake_env()


class TestMainCli:
    def test_no_args_exits(self, monkeypatch):
        monkeypatch.setattr('sys.argv', ['cve-corrector'])
        monkeypatch.setenv('BBPATH', '/tmp')
        with patch('shutil.which', return_value='/usr/bin/bitbake-layers'):
            with pytest.raises(SystemExit):
                main()

    def test_dry_run(self, tmp_path, monkeypatch):
        cve_info = tmp_path / 'cve.json'
        cve_info.write_text(json.dumps({
            'CVE-2025-0001': {'name': 'foo', 'hashes': ['abc123'],
                              'hash_details': [{'hash': 'abc123'}]}
        }))
        monkeypatch.setattr('sys.argv', [
            'cve-corrector', '--cve-id', 'CVE-2025-0001',
            '--cve-info', str(cve_info), '--dry-run',
            '--meta-layer', str(tmp_path)])
        # dry-run skips bitbake env check
        main()  # should not raise

    def test_missing_cve_in_metadata(self, tmp_path, monkeypatch):
        cve_info = tmp_path / 'cve.json'
        cve_info.write_text(json.dumps({'CVE-OTHER': {'name': 'bar'}}))
        monkeypatch.setattr('sys.argv', [
            'cve-corrector', '--cve-id', 'CVE-2025-MISSING',
            '--cve-info', str(cve_info), '--dry-run',
            '--meta-layer', str(tmp_path)])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 6  # EXIT_METADATA_ERROR

    def test_continue_without_state(self, monkeypatch):
        monkeypatch.setattr('sys.argv', ['cve-corrector', '--continue'])
        monkeypatch.setenv('BBPATH', '/tmp')
        with patch('shutil.which', return_value='/usr/bin/bitbake-layers'):
            with pytest.raises(SystemExit):
                main()

    def _resumed_state(self, tmp_path, sign_off):
        from cve_corrector.state import WorkflowState
        return WorkflowState(
            workspace_path=tmp_path / 'ws', cve_id='CVE-2025-0001', recipe='foo',
            commit_hash='abc123', hash_details=[], meta_layer=None,
            skip_build=True, skip_ptest=True, sign_off=sign_off)

    def test_continue_preserves_stored_sign_off_when_flag_omitted(self, tmp_path, monkeypatch):
        """--continue without repeating --sign-off must not silently unsign a
        run that opted in on its original invocation."""
        monkeypatch.setattr('sys.argv', ['cve-corrector', '--continue'])
        monkeypatch.setenv('BBPATH', '/tmp')
        state = self._resumed_state(tmp_path, sign_off=True)
        with patch('shutil.which', return_value='/usr/bin/bitbake-layers'), \
             patch('cve_corrector.__main__.continue_from_conflict', return_value=state), \
             patch('cve_corrector.__main__.setup_logging', return_value='log.txt'), \
             patch('cve_corrector.__main__.finish_cve_workflow') as mock_finish:
            main()
        assert mock_finish.call_args[0][0].sign_off is True

    def test_continue_sign_off_flag_overrides_stored_value(self, tmp_path, monkeypatch):
        """Repeating --sign-off on --continue still overrides the stored value."""
        monkeypatch.setattr('sys.argv', ['cve-corrector', '--continue', '--sign-off'])
        monkeypatch.setenv('BBPATH', '/tmp')
        state = self._resumed_state(tmp_path, sign_off=False)
        with patch('shutil.which', return_value='/usr/bin/bitbake-layers'), \
             patch('cve_corrector.__main__.continue_from_conflict', return_value=state), \
             patch('cve_corrector.__main__.setup_logging', return_value='log.txt'), \
             patch('cve_corrector.__main__.finish_cve_workflow') as mock_finish:
            main()
        assert mock_finish.call_args[0][0].sign_off is True

    def test_skip_source_removes_only_matching(self, tmp_path, monkeypatch):
        """--skip-source drops the osv-only commit but keeps the debian one."""
        cve_info = tmp_path / 'cve.json'
        cve_info.write_text(json.dumps({
            'CVE-2025-0001': {
                'name': 'foo',
                'hashes': ['deb1', 'osv1'],
                'hash_details': [
                    {'hash': 'deb1', 'source': 'debian'},
                    {'hash': 'osv1', 'source': 'osv'},
                ],
            }
        }))
        captured = {}
        monkeypatch.setattr('sys.argv', [
            'cve-corrector', '--cve-id', 'CVE-2025-0001',
            '--cve-info', str(cve_info), '--dry-run',
            '--skip-source', 'osv', '--meta-layer', str(tmp_path)])

        real_print = print

        def _capture_print(*a, **k):
            captured.setdefault('lines', []).append(' '.join(str(x) for x in a))
            real_print(*a, **k)

        with patch('builtins.print', _capture_print):
            main()  # should not raise

        joined = '\n'.join(captured['lines'])
        assert 'Commits:    1' in joined

    def test_skip_source_all_removed_is_metadata_error(self, tmp_path, monkeypatch):
        """Skipping the only source leaves no fix commits -> metadata error."""
        cve_info = tmp_path / 'cve.json'
        cve_info.write_text(json.dumps({
            'CVE-2025-0001': {
                'name': 'foo',
                'hashes': ['osv1'],
                'hash_details': [{'hash': 'osv1', 'source': 'osv'}],
            }
        }))
        monkeypatch.setattr('sys.argv', [
            'cve-corrector', '--cve-id', 'CVE-2025-0001',
            '--cve-info', str(cve_info), '--dry-run',
            '--skip-source', 'osv', '--meta-layer', str(tmp_path)])
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 6  # EXIT_METADATA_ERROR


class TestRepeatableFixUrl:
    """--fix-url is repeatable; N>1 values form one dependent chain."""

    ACL_URLS = [
        "https://cgit.git.savannah.nongnu.org/cgit/acl.git/commit/"
        "?id=5906d2868ec8d3b08be556153696e6b1122eeeda",
        "https://cgit.git.savannah.nongnu.org/cgit/acl.git/commit/"
        "?id=0071c6d1fea0a8a6270333baa85fb609be325c26",
        "https://cgit.git.savannah.nongnu.org/cgit/acl.git/commit/"
        "?id=170dbd3beff9bd5bdab3f72db1a04bf282f6087c",
    ]

    def test_single_fix_url_unchanged(self, tmp_path, monkeypatch):
        monkeypatch.setattr('sys.argv', [
            'cve-corrector', '--cve-id', 'CVE-2025-0001',
            '--recipe', 'foo', '--fix-url', self.ACL_URLS[0],
            '--dry-run', '--meta-layer', str(tmp_path)])
        captured = []
        with patch('builtins.print', lambda *a, **k: captured.append(' '.join(map(str, a)))):
            main()
        joined = '\n'.join(captured)
        assert 'Commits:    1' in joined
        assert 'Series:     0' in joined
        assert 'Dependent:' not in joined

    def test_three_fix_urls_form_one_dependent_series(self, tmp_path, monkeypatch):
        argv = ['cve-corrector', '--cve-id', 'CVE-2025-0002',
                '--recipe', 'acl', '--dry-run', '--meta-layer', str(tmp_path)]
        for url in self.ACL_URLS:
            argv += ['--fix-url', url]
        monkeypatch.setattr('sys.argv', argv)

        captured = []
        with patch('builtins.print', lambda *a, **k: captured.append(' '.join(map(str, a)))):
            main()
        joined = '\n'.join(captured)
        assert 'Commits:    3' in joined
        assert 'Series:     1' in joined
        assert 'Dependent:  yes' in joined

    def test_multiple_fix_urls_replace_stale_json_series(self, tmp_path, monkeypatch):
        """N>1 --fix-url values must win over a stale series in --cve-info."""
        cve_info = tmp_path / 'cve.json'
        cve_info.write_text(json.dumps({
            'CVE-2025-0003': {
                'name': 'acl',
                'hashes': ['stale1'],
                'series': [{'pull_url': 'https://old', 'commits': ['stale1']}],
            }
        }))
        argv = ['cve-corrector', '--cve-id', 'CVE-2025-0003',
                '--cve-info', str(cve_info), '--dry-run',
                '--meta-layer', str(tmp_path)]
        for url in self.ACL_URLS:
            argv += ['--fix-url', url]
        monkeypatch.setattr('sys.argv', argv)

        captured = []
        with patch('builtins.print', lambda *a, **k: captured.append(' '.join(map(str, a)))):
            main()
        joined = '\n'.join(captured)
        assert 'Commits:    3' in joined
        assert 'stale1' not in joined

    def test_bad_url_among_many_reports_parser_error(self, tmp_path, monkeypatch, capsys):
        argv = ['cve-corrector', '--cve-id', 'CVE-2025-0004',
                '--recipe', 'acl', '--dry-run', '--meta-layer', str(tmp_path),
                '--fix-url', self.ACL_URLS[0],
                '--fix-url', 'https://example.com/no-hash-here']
        monkeypatch.setattr('sys.argv', argv)
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 2  # argparse.error() exit code
        assert 'no-hash-here' in capsys.readouterr().err

    def test_already_applied_skips_meta_layer_deduction(self, tmp_path, monkeypatch):
        """The SRC_URI already-applied check must run before — and skip —
        the (expensive) meta-layer deduction step."""
        cve_info = tmp_path / 'cve.json'
        cve_info.write_text(json.dumps({
            'CVE-2025-0001': {'name': 'foo', 'hashes': ['abc123'],
                              'hash_details': [{'hash': 'abc123'}]}
        }))
        monkeypatch.setattr('sys.argv', [
            'cve-corrector', '--cve-id', 'CVE-2025-0001',
            '--cve-info', str(cve_info)])
        monkeypatch.setenv('BBPATH', '/tmp')
        with patch('shutil.which', return_value='/usr/bin/bitbake-layers'), \
             patch('cve_corrector.__main__.check_cve_status',
                   return_value=None), \
             patch('cve_corrector.__main__.check_cve_patch_in_src_uri',
                   return_value='CVE-2025-0001.patch') as mock_check, \
             patch('cve_corrector.__main__.deduce_meta_layer_from_recipe') as mock_deduce:
            with pytest.raises(SystemExit) as exc_info:
                main()
        assert exc_info.value.code == 11  # EXIT_ALREADY_APPLIED
        mock_check.assert_called_once_with('foo', 'CVE-2025-0001')
        mock_deduce.assert_not_called()

    def test_cve_status_ignored_skips_meta_layer_deduction(self, tmp_path, monkeypatch):
        """The CVE_STATUS ignored check must run before — and skip — both
        the SRC_URI check and the (expensive) meta-layer deduction step."""
        cve_info = tmp_path / 'cve.json'
        cve_info.write_text(json.dumps({
            'CVE-2025-0001': {'name': 'foo', 'hashes': ['abc123'],
                              'hash_details': [{'hash': 'abc123'}]}
        }))
        monkeypatch.setattr('sys.argv', [
            'cve-corrector', '--cve-id', 'CVE-2025-0001',
            '--cve-info', str(cve_info)])
        monkeypatch.setenv('BBPATH', '/tmp')
        with patch('shutil.which', return_value='/usr/bin/bitbake-layers'), \
             patch('cve_corrector.__main__.check_cve_status',
                   return_value=('Ignored', 'cpe-incorrect: wrong component')
                   ) as mock_status, \
             patch('cve_corrector.__main__.check_cve_patch_in_src_uri') as mock_check, \
             patch('cve_corrector.__main__.deduce_meta_layer_from_recipe') as mock_deduce:
            with pytest.raises(SystemExit) as exc_info:
                main()
        assert exc_info.value.code == 16  # EXIT_IGNORED_BY_STATUS
        mock_status.assert_called_once_with('foo', 'CVE-2025-0001')
        mock_check.assert_not_called()
        mock_deduce.assert_not_called()

    def test_cve_status_patched_skips_meta_layer_deduction(self, tmp_path, monkeypatch):
        """A Patched CVE_STATUS also short-circuits before meta-layer deduction."""
        cve_info = tmp_path / 'cve.json'
        cve_info.write_text(json.dumps({
            'CVE-2025-0001': {'name': 'foo', 'hashes': ['abc123'],
                              'hash_details': [{'hash': 'abc123'}]}
        }))
        monkeypatch.setattr('sys.argv', [
            'cve-corrector', '--cve-id', 'CVE-2025-0001',
            '--cve-info', str(cve_info)])
        monkeypatch.setenv('BBPATH', '/tmp')
        with patch('shutil.which', return_value='/usr/bin/bitbake-layers'), \
             patch('cve_corrector.__main__.check_cve_status',
                   return_value=('Patched', 'fixed-version: fixed externally')), \
             patch('cve_corrector.__main__.deduce_meta_layer_from_recipe') as mock_deduce:
            with pytest.raises(SystemExit) as exc_info:
                main()
        assert exc_info.value.code == 16  # EXIT_IGNORED_BY_STATUS
        mock_deduce.assert_not_called()
