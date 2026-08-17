# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Regression test: a stale conclusion.json must not override a later fix.

Reproduces the CVE-2026-26158 benchmark bug. ``conclusion.json`` lives in the
persistent agent dir and was never cleared between resolution attempts. When an
early attempt escalated (``needs_human``) and made no changes, but a later
attempt actually *resolved* the conflict without writing a fresh conclusion,
the orchestrator re-read the stale escalation file and reported the CVE as
ESCALATED — silently discarding the good, building resolution.

The fix clears ``conclusion.json`` at the start of every resolution attempt, so
the orchestrator only ever observes the verdict of the session that just ran.
"""
import json
from unittest.mock import MagicMock, patch

from cve_agent import AgentConfig, ResultStatus, get_agent_dir
from cve_agent.knowledge import KnowledgeBase
from cve_agent.orchestrator import process_single_cve
from cve_agent.session import SessionResult
from tests.helpers import git


def _cfg(cve_id, cve_info_path, meta_layer=None, **kwargs):
    defaults = dict(trust_mode=True, skip_ptest=True, skip_cve_applicability=True)
    defaults.update(kwargs)
    return AgentConfig(cve_id=cve_id, cve_info_path=cve_info_path,
                       meta_layer=meta_layer, **defaults)


def _write_cve_json(tmp_path, cve_id, recipe, hashes):
    data = {cve_id: {
        'name': recipe, 'hashes': hashes,
        'hash_details': [{'hash': h, 'url': f'https://example.com/commit/{h}',
                          'source': 'test'} for h in hashes]}}
    p = tmp_path / f'{cve_id}.json'
    p.write_text(json.dumps(data))
    return p


class TestStaleConclusionDoesNotOverrideResolution:
    """An earlier attempt's escalation must not mask a later resolution."""

    def test_escalation_then_resolution_reports_resolved(
            self, make_upstream_repo, make_workspace, make_meta_layer,
            mock_bitbake_env, tmp_path):
        """Attempt 1 escalates (writes needs_human, no code change); attempt 2
        resolves the conflict without writing a conclusion. The run must report
        CONFLICT_RESOLVED, not ESCALATED.
        """
        bare, hashes = make_upstream_repo(
            files={'src/file.c': 'line1\nline2\nvulnerable\nline4\n'},
            version_tag='v1.0',
            fix_commits=[{'files': {'src/file.c': 'line1\nline2\nfixed\nline4\n'},
                          'message': 'Fix vuln'}])

        ws = make_workspace(bare, 'conflictpkg', 'v1.0',
                            existing_patch_commits=[
                                {'files': {'src/file.c':
                                           'line1\nline2\npatched\nline4\n'},
                                 'message': 'Existing patch'}])
        meta = make_meta_layer('conflictpkg', '1.0',
                               existing_patches={'0001-Existing-patch.patch': 'p\n'})
        mock_bitbake_env(ws, meta, 'conflictpkg', '1.0')

        cve_id = 'CVE-2026-26158'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'conflictpkg', hashes)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        approval_mock = MagicMock(return_value=('approved', ''))
        session_calls = [0]

        def _session_side_effect(context_file, workspace_path, upstream_sha,
                                 cve_info, model, timeout, cve_id,
                                 interactive=False, backend_name="kiro",
                                 require_handoff=False):
            session_calls[0] += 1
            agent_dir = get_agent_dir(workspace_path)
            if session_calls[0] == 1:
                # Attempt 1: escalate — write needs_human, make NO code change,
                # leave the conflict unresolved (resolved=False).
                (agent_dir / 'conclusion.json').write_text(json.dumps({
                    "needs_human": True,
                    "reason": "Prerequisite touches files outside allowed scope",
                }), encoding='utf-8')
                return SessionResult(resolved=False, duration=1.0)
            # Attempt 2: actually resolve the conflict, write NO conclusion.
            git(workspace_path, 'checkout', '--theirs', '.', check=False)
            git(workspace_path, 'add', '-A', check=False)
            git(workspace_path, '-c', 'core.editor=true', 'cherry-pick',
                '--continue', check=False)
            return SessionResult(resolved=True, duration=2.0)

        corrector_calls = [0]

        def _mock_corrector(config, continue_mode=False, mark_not_applicable=None):
            if mark_not_applicable:
                return (0, '')
            corrector_calls[0] += 1
            if corrector_calls[0] == 1:
                git(ws, 'checkout', '-B', cve_id, 'v1.0')
                git(ws, 'branch', 'original-version', 'v1.0')
                git(ws, 'cherry-pick', hashes[0], check=False)
                return (1, 'CONFLICT in src/file.c')
            elif continue_mode:
                return (0, '')
            return (0, '')

        with patch('cve_agent.orchestrator.run_corrector',
                   side_effect=_mock_corrector), \
             patch('cve_agent.orchestrator.request_approval', approval_mock), \
             patch('cve_agent.orchestrator.guarded_session',
                   side_effect=_session_side_effect), \
             patch('cve_agent.__main__._log_result'):
            result = process_single_cve(config, kb)

        # The later successful resolution must win over attempt 1's stale
        # escalation. Without the fix this asserts ESCALATED.
        assert result.status == ResultStatus.CONFLICT_RESOLVED
        assert session_calls[0] == 2
        # The good resolution was finalized (approval + --continue ran once).
        approval_mock.assert_called_once()
