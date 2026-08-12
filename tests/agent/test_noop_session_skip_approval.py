# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Test the orchestrator's approval flow for build/ptest resolutions.

Reproduces the double-approval bug: when the AI session doesn't fix the
build error, the orchestrator should skip the approval prompt and retry
rather than asking the human to approve a non-existent fix.

Behaviour:
1. No-op detection: if HEAD is unchanged after a build/ptest session, skip
   approval and retry — there is nothing for the human to review.
2. Real change: show the human the review *before* finalizing (same path as
   conflict resolution). Only on approval does the corrector run --continue
   (build + ptest + devtool finish). This keeps the workspace present for the
   review and never asks the human to approve a change already committed.
   --continue re-verifies the build authoritatively and retries on a
   recoverable failure.
"""
import json
from unittest.mock import MagicMock, patch

from cve_agent import AgentConfig, ResultStatus
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


class TestNoopSessionSkipsApproval:
    """AI session that makes no changes should not trigger approval for build/ptest."""

    def test_build_error_noop_skips_approval_then_fix_succeeds(
            self, make_upstream_repo, make_workspace, make_meta_layer,
            mock_bitbake_env, tmp_path):
        """Simulate: build fails -> AI does nothing -> no approval -> retry ->
        AI fixes -> build verified -> approval shown once.

        This is the exact scenario from the libxml2 cast recording where the
        user was asked to approve twice.
        """
        bare, hashes = make_upstream_repo(
            files={'src/tree.c': 'int lenn, lenp;\n'},
            version_tag='v2.12.10',
            fix_commits=[{'files': {'src/tree.c': 'size_t lenn, lenp;\n'},
                          'message': 'Fix integer overflow'}])

        ws = make_workspace(bare, 'libxml2', 'v2.12.10')
        meta = make_meta_layer('libxml2', '2.12.10')
        mock_bitbake_env(ws, meta, 'libxml2', '2.12.10')

        cve_id = 'CVE-2025-6021'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'libxml2', hashes)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        # Track calls to request_approval
        approval_mock = MagicMock(return_value=('approved', ''))

        session_call_count = [0]

        def _session_side_effect(context_file, workspace_path, upstream_sha,
                                 cve_info, model, timeout, cve_id,
                                 interactive=False, backend_name="kiro"):
            """First call: do nothing (no-op). Second call: amend commit."""
            session_call_count[0] += 1
            if session_call_count[0] == 1:
                # Simulate AI session that talks but doesn't change anything
                return SessionResult(resolved=True, duration=1.0)
            else:
                # Simulate AI session that actually fixes the build error
                # by amending the commit (e.g. adding #include <stdint.h>)
                (workspace_path / 'src' / 'tree.c').write_text(
                    '#include <stdint.h>\nsize_t lenn, lenp;\n')
                git(workspace_path, 'add', '-A', check=False)
                git(workspace_path, 'commit', '--amend', '--no-edit',
                    check=False)
                return SessionResult(resolved=True, duration=2.0)

        corrector_calls = [0]

        def _mock_corrector(config, continue_mode=False, mark_not_applicable=None):
            if mark_not_applicable:
                return (0, '')
            corrector_calls[0] += 1
            if corrector_calls[0] == 1:
                # Initial run: cherry-pick succeeds but build fails (exit 4)
                git(ws, 'checkout', '-B', 'CVE-2025-6021', 'v2.12.10')
                git(ws, 'branch', 'original-version', 'v2.12.10')
                git(ws, 'cherry-pick', hashes[0])
                return (4, 'Build failed for libxml2')
            elif continue_mode:
                # --continue called after AI made changes: build passes
                return (0, '')
            return (0, '')

        with patch('cve_agent.orchestrator.run_corrector',
                   side_effect=_mock_corrector), \
             patch('cve_agent.orchestrator.request_approval', approval_mock), \
             patch('cve_agent.orchestrator.guarded_session',
                   side_effect=_session_side_effect), \
             patch('cve_agent.__main__._log_result'):
            result = process_single_cve(config, kb)

        # The fix should ultimately succeed
        assert result.status == ResultStatus.CONFLICT_RESOLVED

        # Key assertion: approval should only be called ONCE — after the
        # second attempt where the AI actually fixed the build.
        assert approval_mock.call_count == 1

        # AI session was called twice (first no-op, second with fix)
        assert session_call_count[0] == 2

    def test_build_error_workspace_finalized_by_continue_no_crash(
            self, make_upstream_repo, make_workspace, make_meta_layer,
            mock_bitbake_env, tmp_path):
        """--continue finalizes (removes) the workspace on success, without crash.

        The review is shown *before* --continue while the workspace still
        exists, so request_approval is called exactly once and never runs
        against a removed directory (the earlier design showed approval after
        --continue and crashed with FileNotFoundError from `git commit --amend`
        inside a nonexistent cwd). Finalization removing the workspace
        afterwards must not affect the successful outcome.
        """
        bare, hashes = make_upstream_repo(
            files={'src/tree.c': 'int lenn, lenp;\n'},
            version_tag='v2.12.10',
            fix_commits=[{'files': {'src/tree.c': 'size_t lenn, lenp;\n'},
                          'message': 'Fix integer overflow'}])

        ws = make_workspace(bare, 'libxml2', 'v2.12.10')
        meta = make_meta_layer('libxml2', '2.12.10')
        mock_bitbake_env(ws, meta, 'libxml2', '2.12.10')

        cve_id = 'CVE-2025-6023'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'libxml2', hashes)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        approval_mock = MagicMock(return_value=('approved', ''))

        def _session_fix(context_file, workspace_path, upstream_sha,
                         cve_info, model, timeout, cve_id,
                         interactive=False, backend_name="kiro"):
            (workspace_path / 'src' / 'tree.c').write_text(
                '#include <stdint.h>\nsize_t lenn, lenp;\n')
            git(workspace_path, 'add', '-A', check=False)
            git(workspace_path, 'commit', '--amend', '--no-edit', check=False)
            return SessionResult(resolved=True, duration=1.0)

        corrector_calls = [0]

        def _mock_corrector(config, continue_mode=False, mark_not_applicable=None):
            if mark_not_applicable:
                return (0, '')
            corrector_calls[0] += 1
            if corrector_calls[0] == 1:
                git(ws, 'checkout', '-B', 'CVE-2025-6023', 'v2.12.10')
                git(ws, 'branch', 'original-version', 'v2.12.10')
                git(ws, 'cherry-pick', hashes[0])
                return (4, 'Build failed for libxml2')
            elif continue_mode:
                # Simulate devtool finish removing the workspace on success,
                # exactly like the real corrector does after finalizing.
                import shutil
                if ws.exists():
                    shutil.rmtree(ws)
                return (0, '')
            return (0, '')

        with patch('cve_agent.orchestrator.run_corrector',
                   side_effect=_mock_corrector), \
             patch('cve_agent.orchestrator.request_approval', approval_mock), \
             patch('cve_agent.orchestrator.guarded_session',
                   side_effect=_session_fix), \
             patch('cve_agent.__main__._log_result'):
            result = process_single_cve(config, kb)

        # Must not crash, and must report success. The review is shown once,
        # before --continue removes the workspace.
        assert result.status == ResultStatus.CONFLICT_RESOLVED
        approval_mock.assert_called_once()

    def test_build_error_ai_changes_reviewed_each_attempt_until_build_passes(
            self, make_upstream_repo, make_workspace, make_meta_layer,
            mock_bitbake_env, tmp_path):
        """AI makes a real change each attempt -> review shown before each
        finalize; --continue fails twice then passes.

        Each real change is reviewed before finalizing (same as conflict
        resolution). --continue re-verifies the build after approval and, on a
        recoverable failure, the loop retries with a fresh session and a fresh
        review. No-op sessions (unchanged HEAD) would be filtered out earlier
        and never reach approval.
        """
        bare, hashes = make_upstream_repo(
            files={'src/tree.c': 'int lenn, lenp;\n'},
            version_tag='v2.12.10',
            fix_commits=[{'files': {'src/tree.c': 'size_t lenn, lenp;\n'},
                          'message': 'Fix integer overflow'}])

        ws = make_workspace(bare, 'libxml2', 'v2.12.10')
        meta = make_meta_layer('libxml2', '2.12.10')
        mock_bitbake_env(ws, meta, 'libxml2', '2.12.10')

        cve_id = 'CVE-2025-6022'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'libxml2', hashes)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        approval_mock = MagicMock(return_value=('approved', ''))
        session_call_count = [0]

        def _session_side_effect(context_file, workspace_path, upstream_sha,
                                 cve_info, model, timeout, cve_id,
                                 interactive=False, backend_name="kiro"):
            session_call_count[0] += 1
            if session_call_count[0] <= 2:
                # Both first and second attempts: make a change that doesn't
                # fully fix the build
                (workspace_path / 'src' / 'tree.c').write_text(
                    f'// attempt {session_call_count[0]}\nsize_t lenn, lenp;\n')
                git(workspace_path, 'add', '-A', check=False)
                git(workspace_path, 'commit', '--amend', '--no-edit',
                    check=False)
                return SessionResult(resolved=True, duration=1.0)
            else:
                # Third attempt finally fixes it
                (workspace_path / 'src' / 'tree.c').write_text(
                    '#include <stdint.h>\nsize_t lenn, lenp;\n')
                git(workspace_path, 'add', '-A', check=False)
                git(workspace_path, 'commit', '--amend', '--no-edit',
                    check=False)
                return SessionResult(resolved=True, duration=2.0)

        corrector_calls = [0]

        def _mock_corrector(config, continue_mode=False, mark_not_applicable=None):
            if mark_not_applicable:
                return (0, '')
            corrector_calls[0] += 1
            if corrector_calls[0] == 1:
                # Initial: build error
                git(ws, 'checkout', '-B', 'CVE-2025-6022', 'v2.12.10')
                git(ws, 'branch', 'original-version', 'v2.12.10')
                git(ws, 'cherry-pick', hashes[0])
                return (4, 'Build failed')
            elif continue_mode:
                # First two --continue calls fail, third succeeds
                if corrector_calls[0] <= 3:
                    return (4, 'Build still failing')
                return (0, '')
            return (0, '')

        with patch('cve_agent.orchestrator.run_corrector',
                   side_effect=_mock_corrector), \
             patch('cve_agent.orchestrator.request_approval', approval_mock), \
             patch('cve_agent.orchestrator.guarded_session',
                   side_effect=_session_side_effect), \
             patch('cve_agent.__main__._log_result'):
            result = process_single_cve(config, kb)

        assert result.status == ResultStatus.CONFLICT_RESOLVED
        # A real change is reviewed before each finalize attempt: two failed
        # --continue builds then a passing one => three reviews.
        assert approval_mock.call_count == 3
        # AI was called 3 times (first two changes didn't fix build)
        assert session_call_count[0] == 3

    def test_ptest_error_noop_also_skips_approval(
            self, make_upstream_repo, make_workspace, make_meta_layer,
            mock_bitbake_env, tmp_path):
        """Same behavior for ptest failures: no-op sessions skip approval."""
        bare, hashes = make_upstream_repo(
            files={'src/parser.c': 'void parse() { /* vuln */ }\n'},
            version_tag='v1.0',
            fix_commits=[{'files': {'src/parser.c': 'void parse() { /* fixed */ }\n'},
                          'message': 'Fix ptest regression'}])

        ws = make_workspace(bare, 'testpkg', 'v1.0')
        meta = make_meta_layer('testpkg', '1.0')
        mock_bitbake_env(ws, meta, 'testpkg', '1.0')

        cve_id = 'CVE-2025-9999'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'testpkg', hashes)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        approval_mock = MagicMock(return_value=('approved', ''))
        call_count = [0]

        def _session_side_effect(context_file, workspace_path, upstream_sha,
                                 cve_info, model, timeout, cve_id,
                                 interactive=False, backend_name="kiro"):
            call_count[0] += 1
            if call_count[0] == 1:
                return SessionResult(resolved=True, duration=1.0)
            else:
                # Second attempt: amend commit to fix ptest
                (workspace_path / 'src' / 'parser.c').write_text(
                    'void parse() { /* fixed properly */ }\n')
                git(workspace_path, 'add', '-A', check=False)
                git(workspace_path, 'commit', '--amend', '--no-edit',
                    check=False)
                return SessionResult(resolved=True, duration=2.0)

        corrector_calls = [0]

        def _mock_corrector(config, continue_mode=False, mark_not_applicable=None):
            if mark_not_applicable:
                return (0, '')
            corrector_calls[0] += 1
            if corrector_calls[0] == 1:
                # Initial: ptest error (3)
                git(ws, 'checkout', '-B', 'CVE-2025-9999', 'v1.0')
                git(ws, 'branch', 'original-version', 'v1.0')
                git(ws, 'cherry-pick', hashes[0])
                return (3, 'Ptest failed for testpkg')
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

        assert result.status == ResultStatus.CONFLICT_RESOLVED
        assert approval_mock.call_count == 1

    def test_conflict_noop_still_shows_approval(
            self, make_upstream_repo, make_workspace, make_meta_layer,
            mock_bitbake_env, tmp_path):
        """For conflict resolution (exit 1), even unchanged HEAD shows approval.

        Conflicts are different — the AI may have resolved the conflict by
        accepting the existing version verbatim (no net diff from HEAD),
        which is a valid resolution that should still be reviewed. The
        build-verification path only applies to exit codes 3 and 4.
        """
        bare, hashes = make_upstream_repo(
            files={'src/file.c': 'line1\nline2\nvulnerable\nline4\n'},
            version_tag='v1.0',
            fix_commits=[{'files': {'src/file.c': 'line1\nline2\nfixed\nline4\n'},
                          'message': 'Fix vuln'}])

        ws = make_workspace(bare, 'conflictpkg', 'v1.0',
                            existing_patch_commits=[
                                {'files': {'src/file.c': 'line1\nline2\npatched\nline4\n'},
                                 'message': 'Existing patch'}])
        meta = make_meta_layer('conflictpkg', '1.0',
                               existing_patches={'0001-Existing-patch.patch': 'p\n'})
        mock_bitbake_env(ws, meta, 'conflictpkg', '1.0')

        cve_id = 'CVE-2025-8888'
        cve_info_path = _write_cve_json(tmp_path, cve_id, 'conflictpkg', hashes)
        config = _cfg(cve_id, cve_info_path, meta)
        kb = KnowledgeBase(tmp_path / 'kb.json')

        approval_mock = MagicMock(return_value=('approved', ''))

        def _session_resolve(context_file, workspace_path, upstream_sha,
                             cve_info, model, timeout, cve_id,
                             interactive=False, backend_name="kiro"):
            """Session resolves conflict by taking theirs."""
            git(workspace_path, 'checkout', '--theirs', '.', check=False)
            git(workspace_path, 'add', '-A', check=False)
            git(workspace_path, '-c', 'core.editor=true', 'cherry-pick',
                '--continue', check=False)
            return SessionResult(resolved=True, duration=1.0)

        corrector_calls = [0]

        def _mock_corrector(config, continue_mode=False, mark_not_applicable=None):
            if mark_not_applicable:
                return (0, '')
            corrector_calls[0] += 1
            if corrector_calls[0] == 1:
                # Initial: conflict (exit 1)
                git(ws, 'checkout', '-B', 'CVE-2025-8888', 'v1.0')
                git(ws, 'branch', 'original-version', 'v1.0')
                git(ws, 'cherry-pick', hashes[0], check=False)
                # Leave conflict unresolved for AI to handle
                return (1, 'CONFLICT in src/file.c')
            elif continue_mode:
                return (0, '')
            return (0, '')

        with patch('cve_agent.orchestrator.run_corrector',
                   side_effect=_mock_corrector), \
             patch('cve_agent.orchestrator.request_approval', approval_mock), \
             patch('cve_agent.orchestrator.guarded_session',
                   side_effect=_session_resolve), \
             patch('cve_agent.__main__._log_result'):
            result = process_single_cve(config, kb)

        # For conflicts, approval SHOULD be called (no build-verify shortcut)
        assert approval_mock.call_count == 1
        assert result.status == ResultStatus.CONFLICT_RESOLVED
