# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Agent-level integration tests for all 17 shell test scenarios.

These tests call process_single_cve() from cve_agent.orchestrator instead of
run_workflow() from cve_corrector.workflow, exercising the full agent
orchestration layer with mocked kiro sessions and approval.
"""
import json
from unittest.mock import patch

from cve_agent import AgentConfig, ResultStatus
from cve_agent.knowledge import KnowledgeBase
from cve_agent.orchestrator import process_single_cve
from cve_agent.session import SessionResult
from tests.helpers import (
    assert_no_patches_removed,
    assert_patch_correctness,
    assert_patch_naming,
    get_src_uri_patches,
    git,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cfg(cve_id, cve_info_path, meta_layer=None, **kwargs):
    defaults = dict(trust_mode=True, skip_ptest=True, skip_cve_applicability=True)
    defaults.update(kwargs)
    return AgentConfig(cve_id=cve_id, cve_info_path=cve_info_path,
                       meta_layer=meta_layer, **defaults)


def _write_cve_json(tmp_path, cve_id, recipe, hashes, series=False):
    """Write a CVE info JSON file and return its path."""
    data = {cve_id: {
        'name': recipe, 'hashes': hashes,
        'hash_details': [{'hash': h, 'url': f'https://example.com/commit/{h}',
                          'source': 'test'} for h in hashes]}}
    if series:
        data[cve_id]['series'] = [{'pull_url': 'https://example.com/pull/1',
                                   'commits': hashes}]
    p = tmp_path / f'{cve_id}.json'
    p.write_text(json.dumps(data))
    return p


def _resolve_conflict_side_effect(context_file, workspace_path, upstream_sha,
                                   cve_info, model, timeout, cve_id,
                                   interactive=False, backend_name="kiro"):
    """Side effect that resolves cherry-pick conflicts."""
    if workspace_path.exists():
        git(workspace_path, 'checkout', '--theirs', '.', check=False)
        git(workspace_path, 'add', '-A', check=False)
        git(workspace_path, '-c', 'core.editor=true', 'cherry-pick', '--continue', check=False)
    return SessionResult(resolved=True, duration=1.0)


def _make_corrector_mock(cve_info_path):
    """Create a run_corrector mock that delegates to the real workflow."""
    import json

    from cve_corrector.state import WorkflowError
    from cve_corrector.workflow import WorkflowConfig, finish_cve_workflow, initialize_cve_workflow

    state_holder = {}

    def _mock_run_corrector(config, continue_mode=False, mark_not_applicable=None):
        if mark_not_applicable:
            return (0, '')
        cve_data = json.loads(config.cve_info_path.read_text())
        wf_config = WorkflowConfig(
            mirror_path=None, mirror_dir=config.mirror_dir,
            meta_layer=config.meta_layer, skip_build=True, clean=config.clean,
            skip_ptest=config.skip_ptest, edit_mode=False,
            skip_cve_applicability=config.skip_cve_applicability)

        if continue_mode:
            if 'state' not in state_holder:
                return (0, '')
            try:
                state_holder['state'].skip_confirm = True
                finish_cve_workflow(state_holder['state'])
                return (0, '')
            except WorkflowError as e:
                return (e.exit_code, '')
            except SystemExit as e:
                return (e.code, '')
        else:
            try:
                state = initialize_cve_workflow(cve_data, config.cve_id, wf_config)
                state.skip_confirm = True
                state_holder['state'] = state
                finish_cve_workflow(state)
                return (0, '')
            except WorkflowError as e:
                return (e.exit_code, '')
            except SystemExit as e:
                return (e.code if e.code else 0, '')

    return _mock_run_corrector


def _run(config, kb, mock_session_rv=None, session_side_effect=None):
    """Run process_single_cve with standard mocks."""
    session_mock_kwargs = {}
    if session_side_effect:
        session_mock_kwargs['side_effect'] = session_side_effect
    else:
        session_mock_kwargs['return_value'] = mock_session_rv or SessionResult(resolved=True, duration=1.0)

    corrector_mock = _make_corrector_mock(config.cve_info_path)

    with patch('cve_agent.orchestrator.run_corrector', side_effect=corrector_mock), \
         patch('cve_agent.orchestrator.request_approval', return_value=('approved', '')), \
         patch('cve_agent.orchestrator.guarded_session', **session_mock_kwargs), \
         patch('cve_agent.__main__._log_result'):
        return process_single_cve(config, kb)


# ---------------------------------------------------------------------------
# Test 1: Multi-patch preserved
# ---------------------------------------------------------------------------

class TestAgentMultiPatchPreserved:
    def test_agent_multi_patch_preserved(self, make_upstream_repo, make_workspace,
                                         make_meta_layer, mock_bitbake_env, tmp_path):
        bare, hashes = make_upstream_repo(
            files={'src/rsync.c': 'void sync() { /* vuln */ }\n'},
            version_tag='v3.2.7',
            fix_commits=[{'files': {'src/rsync.c': 'void sync() { /* fixed */ }\n'},
                          'message': 'Fix path traversal'}])

        ws = make_workspace(bare, 'rsync', 'v3.2.7')
        meta = make_meta_layer('rsync', '3.2.7',
                               existing_patches={'CVE-2024-12087.patch': 'other\n',
                                                 'CVE-2024-12088.patch': 'other2\n'},
                               src_uri_entries=['file://CVE-2024-12087.patch',
                                               'file://CVE-2024-12088.patch'])
        before = get_src_uri_patches(meta, 'rsync')
        mock_bitbake_env(ws, meta, 'rsync', '3.2.7')

        cve_id = 'CVE-2024-12086'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'rsync', hashes)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb)

        assert result.status == ResultStatus.SUCCESS
        assert_patch_naming(meta, cve_id, expect_series=False)
        after = get_src_uri_patches(meta, 'rsync')
        assert_no_patches_removed(before, after)


# ---------------------------------------------------------------------------
# Test 2: Clean cherry-pick
# ---------------------------------------------------------------------------

class TestAgentCleanCherryPick:
    def test_agent_clean_cherry_pick(self, make_upstream_repo, make_workspace,
                                     make_meta_layer, mock_bitbake_env, tmp_path):
        bare, hashes = make_upstream_repo(
            files={'src/archive.c': 'void read() { /* vulnerable */ }\n'},
            version_tag='v3.7.2',
            fix_commits=[{'files': {'src/archive.c': 'void read() { /* fixed */ }\n'},
                          'message': 'Fix buffer overflow'}])

        ws = make_workspace(bare, 'libarchive', 'v3.7.2')
        meta = make_meta_layer('libarchive', '3.7.2',
                               existing_patches={'defconfig.patch': 'existing\n'},
                               src_uri_entries=['file://defconfig.patch'])
        mock_bitbake_env(ws, meta, 'libarchive', '3.7.2')

        cve_id = 'CVE-2025-5915'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'libarchive', hashes)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb)

        assert result.status == ResultStatus.SUCCESS
        assert_patch_correctness(meta, cve_id, expected_files={'src/archive.c'})


# ---------------------------------------------------------------------------
# Test 3: Series naming
# ---------------------------------------------------------------------------

class TestAgentSeries:
    def test_agent_series(self, make_upstream_repo, make_workspace,
                          make_meta_layer, mock_bitbake_env, tmp_path):
        bare, hashes = make_upstream_repo(
            files={'src/parser.c': 'void parse() { /* v1 */ }\n',
                   'src/alloc.c': 'void alloc() { /* v1 */ }\n',
                   'src/bounds.c': 'void check() { /* v1 */ }\n'},
            version_tag='v2.5.0',
            fix_commits=[
                {'files': {'src/parser.c': 'void parse() { /* fix1 */ }\n'},
                 'message': 'Fix parser overflow'},
                {'files': {'src/alloc.c': 'void alloc() { /* fix2 */ }\n'},
                 'message': 'Fix allocator'},
                {'files': {'src/bounds.c': 'void check() { /* fix3 */ }\n'},
                 'message': 'Harden bounds'},
            ])

        ws = make_workspace(bare, 'expat', 'v2.5.0')
        meta = make_meta_layer('expat', '2.5.0')
        mock_bitbake_env(ws, meta, 'expat', '2.5.0')

        cve_id = 'CVE-2026-25210'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'expat', hashes, series=True)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb)

        assert result.status == ResultStatus.SUCCESS
        assert_patch_naming(meta, cve_id, expect_series=True)


# ---------------------------------------------------------------------------
# Test 4: Conflict escalates
# ---------------------------------------------------------------------------

class TestAgentConflictEscalates:
    def test_agent_conflict_escalates(self, make_upstream_repo, make_workspace,
                                      make_meta_layer, mock_bitbake_env, tmp_path):
        bare, hashes = make_upstream_repo(
            files={'src/file.c': 'line1\nline2\nline3\nvulnerable_code\nline5\n'},
            version_tag='v3.1',
            fix_commits=[{'files': {'src/file.c': 'line1\nline2\nline3\nfixed_code\nline5\n'},
                          'message': 'Fix vulnerability'}])

        ws = make_workspace(bare, 're2c', 'v3.1',
                            existing_patch_commits=[
                                {'files': {'src/file.c': 'line1\nline2\nline3\npatched_code\nline5\n'},
                                 'message': 'Existing recipe patch'}])
        meta = make_meta_layer('re2c', '3.1',
                               existing_patches={'0001-Existing-recipe-patch.patch': 'p\n'})
        mock_bitbake_env(ws, meta, 're2c', '3.1')

        cve_id = 'CVE-2026-2903'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 're2c', hashes)
        config = _cfg(cve_id, cve_info_path, meta, max_retries=1)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb, mock_session_rv=SessionResult(resolved=False, duration=1.0))

        assert result.status == ResultStatus.ESCALATED


# ---------------------------------------------------------------------------
# Test 5: Single patch with ptest
# ---------------------------------------------------------------------------

class TestAgentSinglePatchPtest:
    def test_agent_single_patch_ptest(self, make_upstream_repo, make_workspace,
                                      make_meta_layer, mock_bitbake_env, tmp_path):
        bare, hashes = make_upstream_repo(
            files={'src/shell.c': 'void exec() { /* bug */ }\n'},
            version_tag='v1.36.1',
            fix_commits=[{'files': {'src/shell.c': 'void exec() { /* safe */ }\n'},
                          'message': 'Fix use-after-free'}])

        ws = make_workspace(bare, 'busybox', 'v1.36.1')
        meta = make_meta_layer('busybox', '1.36.1',
                               existing_patches={'init.patch': 'p\n'},
                               src_uri_entries=['file://init.patch'])
        mock_bitbake_env(ws, meta, 'busybox', '1.36.1')

        cve_id = 'CVE-2023-42363'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'busybox', hashes)
        config = _cfg(cve_id, cve_info_path, meta, skip_ptest=False)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb)

        assert result.status == ResultStatus.SUCCESS
        assert_patch_correctness(meta, cve_id, expected_files={'src/shell.c'})


# ---------------------------------------------------------------------------
# Test 6: Conflict resolved
# ---------------------------------------------------------------------------

class TestAgentConflictResolved:
    def test_agent_conflict_resolved(self, make_upstream_repo, make_workspace,
                                     make_meta_layer, mock_bitbake_env, tmp_path):
        bare, hashes = make_upstream_repo(
            files={'src/file.c': 'line1\nline2\nline3\nvulnerable\nline5\n'},
            version_tag='v1.36.1',
            fix_commits=[{'files': {'src/file.c': 'line1\nline2\nline3\nfixed\nline5\n'},
                          'message': 'Fix vulnerability'}])

        ws = make_workspace(bare, 'busybox', 'v1.36.1',
                            existing_patch_commits=[
                                {'files': {'src/file.c': 'line1\nline2\nline3\nexisting\nline5\n'},
                                 'message': 'Existing patch'}])
        meta = make_meta_layer('busybox', '1.36.1',
                               existing_patches={'0001-Existing-patch.patch': 'p\n'})
        mock_bitbake_env(ws, meta, 'busybox', '1.36.1')

        cve_id = 'CVE-2026-26157'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'busybox', hashes)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb, session_side_effect=_resolve_conflict_side_effect)

        assert result.status == ResultStatus.CONFLICT_RESOLVED

    def test_agent_conflict_resolved_summary_names_actual_backend(
            self, make_upstream_repo, make_workspace, make_meta_layer,
            mock_bitbake_env, tmp_path):
        """The resolution summary must name whichever backend actually ran,
        not a hardcoded "kiro-cli" — misleading once more than one backend
        exists, since a claude-resolved CVE would be reported as kiro's work.
        """
        bare, hashes = make_upstream_repo(
            files={'src/file.c': 'line1\nline2\nline3\nvulnerable\nline5\n'},
            version_tag='v1.36.1',
            fix_commits=[{'files': {'src/file.c': 'line1\nline2\nline3\nfixed\nline5\n'},
                          'message': 'Fix vulnerability'}])

        ws = make_workspace(bare, 'busybox', 'v1.36.1',
                            existing_patch_commits=[
                                {'files': {'src/file.c': 'line1\nline2\nline3\nexisting\nline5\n'},
                                 'message': 'Existing patch'}])
        meta = make_meta_layer('busybox', '1.36.1',
                               existing_patches={'0001-Existing-patch.patch': 'p\n'})
        mock_bitbake_env(ws, meta, 'busybox', '1.36.1')

        cve_id = 'CVE-2026-26158'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'busybox', hashes)
        config = _cfg(cve_id, cve_info_path, meta, backend='claude')
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb, session_side_effect=_resolve_conflict_side_effect)

        assert result.status == ResultStatus.CONFLICT_RESOLVED
        assert 'claude' in result.resolution_summary.lower()
        assert 'kiro' not in result.resolution_summary.lower()


# ---------------------------------------------------------------------------
# Test 7: Conflict state resume
# ---------------------------------------------------------------------------

class TestAgentConflictStateResume:
    def test_agent_conflict_state_resume(self, make_upstream_repo, make_workspace,
                                         make_meta_layer, mock_bitbake_env, tmp_path):
        bare, hashes = make_upstream_repo(
            files={'src/file.c': 'line1\nline2\nline3\nvulnerable_code\nline5\n'},
            version_tag='v9.4',
            fix_commits=[{'files': {'src/file.c': 'line1\nline2\nline3\nfixed_code\nline5\n'},
                          'message': 'Fix vulnerability'}])

        ws = make_workspace(bare, 'coreutils', 'v9.4',
                            existing_patch_commits=[
                                {'files': {'src/file.c': 'line1\nline2\nline3\npatched_code\nline5\n'},
                                 'message': 'Existing recipe patch'}])
        meta = make_meta_layer('coreutils', '9.4',
                               existing_patches={'0001-Existing-recipe-patch.patch': 'p\n'})
        mock_bitbake_env(ws, meta, 'coreutils', '9.4')

        cve_id = 'CVE-2024-0684'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'coreutils', hashes)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb, session_side_effect=_resolve_conflict_side_effect)

        assert result.status == ResultStatus.CONFLICT_RESOLVED


# ---------------------------------------------------------------------------
# Test 8: Missing autotools
# ---------------------------------------------------------------------------

class TestAgentMissingAutotools:
    def test_agent_missing_autotools(self, make_upstream_repo, make_workspace,
                                     make_meta_layer, mock_bitbake_env, tmp_path):
        bare, hashes = make_upstream_repo(
            files={'src/main.c': 'int main() { /* vuln */ }\n'},
            version_tag='v9.4',
            fix_commits=[{'files': {'src/main.c': 'int main() { /* fixed */ }\n'},
                          'message': 'Fix buffer overflow'}])

        ws = make_workspace(bare, 'coreutils', 'v9.4',
                            existing_patch_commits=[
                                {'files': {'configure': '#!/bin/sh\necho ok\n',
                                           'Makefile.in': 'all:\n\techo build\n'},
                                 'message': 'Add generated autotools files'}])
        meta = make_meta_layer('coreutils', '9.4',
                               existing_patches={'0001-Add-generated-autotools-files.patch': 'p\n'})
        mock_bitbake_env(ws, meta, 'coreutils', '9.4')

        cve_id = 'CVE-2024-0684'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'coreutils', hashes)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb)

        assert result.status == ResultStatus.SUCCESS
        assert_patch_correctness(meta, cve_id, expected_files={'src/main.c'})


# ---------------------------------------------------------------------------
# Test 9: Monorepo strip
# ---------------------------------------------------------------------------

class TestAgentMonorepoStrip:
    def test_agent_monorepo_strip(self, make_upstream_repo, make_workspace,
                                  make_meta_layer, mock_bitbake_env, tmp_path):
        recipe = 'gstreamer1.0-plugins-good'
        prefix = 'subprojects/gst-plugins-good'
        bare, hashes = make_upstream_repo(
            files={'gst/rtpmanager/file.c': 'void process() { /* vuln */ }\n',
                   'meson.build': "project('gst-plugins-good')\n"},
            version_tag='1.24.0',
            fix_commits=[{'files': {'gst/rtpmanager/file.c': 'void process() { /* fixed */ }\n'},
                          'message': 'Fix buffer overflow'}],
            monorepo_prefix=prefix)

        # Create workspace with extracted subproject at root
        import shutil
        ws = tmp_path / 'build' / 'workspace' / 'sources' / recipe
        git(tmp_path, 'clone', str(bare), str(ws))
        git(ws, 'checkout', '-b', 'extract', '1.24.0')
        git(ws, 'branch', '-D', 'main')
        git(ws, 'checkout', '--orphan', 'main')
        for item in ws.iterdir():
            if item.name == '.git':
                continue
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
        (ws / 'gst' / 'rtpmanager').mkdir(parents=True)
        (ws / 'gst' / 'rtpmanager' / 'file.c').write_text('void process() { /* vuln */ }\n')
        (ws / 'meson.build').write_text("project('gst-plugins-good')\n")
        git(ws, 'add', '-A')
        git(ws, 'commit', '-m', 'Extracted subproject')
        git(ws, 'branch', 'devtool-base')
        git(ws, 'checkout', '-b', 'devtool')
        git(ws, 'remote', 'rename', 'origin', 'upstream')
        git(ws, 'fetch', 'upstream', '--tags')

        meta = make_meta_layer(recipe, '1.24.0')
        mock_bitbake_env(ws, meta, recipe, '1.24.0')

        cve_id = 'CVE-2024-47539'
        cve_info_path = _write_cve_json(tmp_path, cve_id, recipe, hashes)
        config = _cfg(cve_id, cve_info_path, meta, mirror_dir=bare.parent)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb)

        assert result.status == ResultStatus.SUCCESS


# ---------------------------------------------------------------------------
# Test 10: SRC_URI conflict escalates
# ---------------------------------------------------------------------------

class TestAgentSrcUriConflictEscalates:
    def test_agent_src_uri_conflict_escalates(self, make_upstream_repo, make_workspace,
                                              make_meta_layer, mock_bitbake_env, tmp_path):
        bare, hashes = make_upstream_repo(
            files={'src/file.c': 'line1\nline2\nline3\nvulnerable_code\nline5\n'},
            version_tag='v2024.2.2',
            fix_commits=[{'files': {'src/file.c': 'line1\nline2\nline3\nfixed_code\nline5\n'},
                          'message': 'Fix vulnerability'}])

        ws = make_workspace(bare, 'python3-certifi', 'v2024.2.2',
                            existing_patch_commits=[
                                {'files': {'src/file.c': 'line1\nline2\nline3\npatched_code\nline5\n'},
                                 'message': 'Existing recipe patch'}])
        meta = make_meta_layer('python3-certifi', '2024.2.2',
                               existing_patches={'0001-Existing-recipe-patch.patch': 'p\n'})
        mock_bitbake_env(ws, meta, 'python3-certifi', '2024.2.2')

        cve_id = 'CVE-2024-39689'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'python3-certifi', hashes)
        config = _cfg(cve_id, cve_info_path, meta, max_retries=1)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb, mock_session_rv=SessionResult(resolved=False, duration=1.0))

        assert result.status == ResultStatus.ESCALATED


# ---------------------------------------------------------------------------
# Test 11: Devtool finish failure
# ---------------------------------------------------------------------------

class TestAgentDevtoolFinishFailure:
    def test_agent_devtool_finish_failure(self, make_upstream_repo, make_workspace,
                                          make_meta_layer, mock_bitbake_env, tmp_path):
        bare, hashes = make_upstream_repo(
            files={'src/ssh.c': 'void connect() { /* vuln */ }\n'},
            version_tag='v9.6p1',
            fix_commits=[{'files': {'src/ssh.c': 'void connect() { /* fixed */ }\n'},
                          'message': 'Fix version comment'}])

        ws = make_workspace(bare, 'openssh', 'v9.6p1')
        meta = make_meta_layer('openssh', '9.6p1')
        mock_bitbake_env(ws, meta, 'openssh', '9.6p1', devtool_finish_fails=True)

        cve_id = 'CVE-2024-39894'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'openssh', hashes)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb)

        assert result.status == ResultStatus.FAILED


# ---------------------------------------------------------------------------
# Test 12: Skip build ptest
# ---------------------------------------------------------------------------

class TestAgentSkipBuildPtest:
    def test_agent_skip_build_ptest(self, make_upstream_repo, make_workspace,
                                    make_meta_layer, mock_bitbake_env, tmp_path):
        bare, hashes = make_upstream_repo(
            files={'src/rtsp.c': 'void serve() { /* vuln */ }\n'},
            version_tag='v1.22.0',
            fix_commits=[{'files': {'src/rtsp.c': 'void serve() { /* ok */ }\n'},
                          'message': 'Fix null deref'}])

        ws = make_workspace(bare, 'gstreamer1.0-rtsp-server', 'v1.22.0')
        meta = make_meta_layer('gstreamer1.0-rtsp-server', '1.22.0')
        mock_bitbake_env(ws, meta, 'gstreamer1.0-rtsp-server', '1.22.0')

        cve_id = 'CVE-2024-44331'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'gstreamer1.0-rtsp-server', hashes)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb)

        assert result.status == ResultStatus.SUCCESS
        assert_patch_correctness(meta, cve_id, expected_files={'src/rtsp.c'})


# ---------------------------------------------------------------------------
# Test 13: Monorepo with build
# ---------------------------------------------------------------------------

class TestAgentMonorepoWithBuild:
    def test_agent_monorepo_with_build(self, make_upstream_repo, make_workspace,
                                       make_meta_layer, mock_bitbake_env, tmp_path):
        recipe = 'gstreamer1.0-rtsp-server'
        prefix = 'subprojects/gst-plugins-bad'
        bare, hashes = make_upstream_repo(
            files={'gst/rtpmanager/file.c': 'void process() { /* vuln */ }\n',
                   'meson.build': "project('gst-rtsp-server')\n"},
            version_tag='1.22.0',
            fix_commits=[{'files': {'gst/rtpmanager/file.c': 'void process() { /* fixed */ }\n'},
                          'message': 'Fix buffer overflow'}],
            monorepo_prefix=prefix)

        import shutil
        ws = tmp_path / 'build' / 'workspace' / 'sources' / recipe
        git(tmp_path, 'clone', str(bare), str(ws))
        git(ws, 'checkout', '-b', 'extract', '1.22.0')
        git(ws, 'branch', '-D', 'main')
        git(ws, 'checkout', '--orphan', 'main')
        for item in ws.iterdir():
            if item.name == '.git':
                continue
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
        (ws / 'gst' / 'rtpmanager').mkdir(parents=True)
        (ws / 'gst' / 'rtpmanager' / 'file.c').write_text('void process() { /* vuln */ }\n')
        (ws / 'meson.build').write_text("project('gst-rtsp-server')\n")
        git(ws, 'add', '-A')
        git(ws, 'commit', '-m', 'Extracted subproject')
        git(ws, 'branch', 'devtool-base')
        git(ws, 'checkout', '-b', 'devtool')
        git(ws, 'remote', 'rename', 'origin', 'upstream')
        git(ws, 'fetch', 'upstream', '--tags')

        meta = make_meta_layer(recipe, '1.22.0')
        mock_bitbake_env(ws, meta, recipe, '1.22.0')

        cve_id = 'CVE-2024-44331'
        cve_info_path = _write_cve_json(tmp_path, cve_id, recipe, hashes)
        config = _cfg(cve_id, cve_info_path, meta, mirror_dir=bare.parent, skip_ptest=False)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb)

        assert result.status == ResultStatus.SUCCESS


# ---------------------------------------------------------------------------
# Test 14: Underscore tag
# ---------------------------------------------------------------------------

class TestAgentUnderscoreTag:
    def test_agent_underscore_tag(self, make_upstream_repo, make_workspace,
                                  make_meta_layer, mock_bitbake_env, tmp_path):
        bare, hashes = make_upstream_repo(
            files={'src/bfd.c': 'void bfd_read() { /* vuln */ }\n'},
            version_tag='binutils-2_42',
            fix_commits=[{'files': {'src/bfd.c': 'void bfd_read() { /* fixed */ }\n'},
                          'message': 'Fix integer overflow'}])

        ws = make_workspace(bare, 'binutils', 'binutils-2_42')
        meta = make_meta_layer('binutils', '2.42')
        mock_bitbake_env(ws, meta, 'binutils', '2.42')

        cve_id = 'CVE-2024-53589'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'binutils', hashes)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb)

        assert result.status == ResultStatus.SUCCESS
        assert_patch_correctness(meta, cve_id, expected_files={'src/bfd.c'})


# ---------------------------------------------------------------------------
# Test 15: Cross-recipe conflict escalates
# ---------------------------------------------------------------------------

class TestAgentCrossRecipeConflictEscalates:
    def test_agent_cross_recipe_conflict_escalates(self, make_upstream_repo, make_workspace,
                                                    make_meta_layer, mock_bitbake_env, tmp_path):
        bare, hashes = make_upstream_repo(
            files={'src/file.c': 'line1\nline2\nline3\nvulnerable_code\nline5\n'},
            version_tag='v2.74.3',
            fix_commits=[{'files': {'src/file.c': 'line1\nline2\nline3\nfixed_code\nline5\n'},
                          'message': 'Fix vulnerability'}])

        ws = make_workspace(bare, 'libsoup-2.4', 'v2.74.3',
                            existing_patch_commits=[
                                {'files': {'src/file.c': 'line1\nline2\nline3\npatched_code\nline5\n'},
                                 'message': 'Existing recipe patch'}])

        # Create meta-layer with two recipes sharing a patch
        meta = tmp_path / 'meta-layer'
        meta.mkdir()
        git(meta, 'init')
        git(meta, 'commit', '--allow-empty', '-m', 'init')
        for rname in ('libsoup-2.4', 'libsoup'):
            rd = meta / 'recipes-core' / rname
            rd.mkdir(parents=True)
            ver = '2.74.3' if '2.4' in rname else '3.4.4'
            (rd / f'{rname}_{ver}.bb').write_text(
                f'SUMMARY = "{rname}"\nSRC_URI = "file://shared.patch"\n')
            (rd / 'shared.patch').write_text('shared\n')
        git(meta, 'add', '-A')
        git(meta, 'commit', '-m', 'Add recipes')

        mock_bitbake_env(ws, meta, 'libsoup-2.4', '2.74.3')

        cve_id = 'CVE-2025-32909'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'libsoup-2.4', hashes)
        config = _cfg(cve_id, cve_info_path, meta, max_retries=1)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb, mock_session_rv=SessionResult(resolved=False, duration=1.0))

        assert result.status == ResultStatus.ESCALATED


# ---------------------------------------------------------------------------
# Test 16: Ignored untracked files
# ---------------------------------------------------------------------------

class TestAgentIgnoredUntracked:
    def test_agent_ignored_untracked(self, make_upstream_repo, make_workspace,
                                     make_meta_layer, mock_bitbake_env, tmp_path):
        bare, hashes = make_upstream_repo(
            files={'src/main.c': 'int main() { /* vuln */ }\n',
                   '.gitignore': 'configure\nautom4te.cache\n'},
            version_tag='v4.9.1',
            fix_commits=[{'files': {'src/main.c': 'int main() { /* fixed */ }\n'},
                          'message': 'Fix overflow'}])

        ws = make_workspace(bare, 'screen', 'v4.9.1',
                            existing_patch_commits=[
                                {'files': {'configure': '#!/bin/sh\necho configured\n'},
                                 'message': 'Add autotools files from tarball'}])
        meta = make_meta_layer('screen', '4.9.1',
                               existing_patches={'0001-Add-autotools-files-from-tarball.patch': 'existing\n'},
                               src_uri_entries=['file://0001-Add-autotools-files-from-tarball.patch'])
        before = get_src_uri_patches(meta, 'screen')
        mock_bitbake_env(ws, meta, 'screen', '4.9.1')

        cve_id = 'CVE-2025-46802'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'screen', hashes)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb)

        assert result.status == ResultStatus.SUCCESS
        after = get_src_uri_patches(meta, 'screen')
        assert_no_patches_removed(before, after)


# ---------------------------------------------------------------------------
# Test 17: Monorepo build verification
# ---------------------------------------------------------------------------

class TestAgentMonorepoBuildVerification:
    def test_agent_monorepo_build_verification(self, make_upstream_repo, make_workspace,
                                               make_meta_layer, mock_bitbake_env, tmp_path):
        recipe = 'gstreamer1.0-plugins-good'
        prefix = 'subprojects/gst-plugins-good'
        bare, hashes = make_upstream_repo(
            files={'gst/rtpmanager/file.c': 'void process() { /* vuln */ }\n',
                   'meson.build': "project('gst-plugins-good')\n"},
            version_tag='1.24.0',
            fix_commits=[{'files': {'gst/rtpmanager/file.c': 'void process() { /* fixed */ }\n'},
                          'message': 'Fix buffer overflow'}],
            monorepo_prefix=prefix)

        import shutil
        ws = tmp_path / 'build' / 'workspace' / 'sources' / recipe
        git(tmp_path, 'clone', str(bare), str(ws))
        git(ws, 'checkout', '-b', 'extract', '1.24.0')
        git(ws, 'branch', '-D', 'main')
        git(ws, 'checkout', '--orphan', 'main')
        for item in ws.iterdir():
            if item.name == '.git':
                continue
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
        (ws / 'gst' / 'rtpmanager').mkdir(parents=True)
        (ws / 'gst' / 'rtpmanager' / 'file.c').write_text('void process() { /* vuln */ }\n')
        (ws / 'meson.build').write_text("project('gst-plugins-good')\n")
        git(ws, 'add', '-A')
        git(ws, 'commit', '-m', 'Extracted subproject')
        git(ws, 'branch', 'devtool-base')
        git(ws, 'checkout', '-b', 'devtool')
        git(ws, 'remote', 'rename', 'origin', 'upstream')
        git(ws, 'fetch', 'upstream', '--tags')

        meta = make_meta_layer(recipe, '1.24.0')
        _build_called = mock_bitbake_env(ws, meta, recipe, '1.24.0')

        cve_id = 'CVE-2024-47539'
        cve_info_path = _write_cve_json(tmp_path, cve_id, recipe, hashes)
        config = _cfg(cve_id, cve_info_path, meta, mirror_dir=bare.parent, skip_ptest=False)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        result = _run(config, kb)

        assert result.status == ResultStatus.SUCCESS
