# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for dependent commit chains declared with repeated --fix-url.

Covers the acl-style case where a CVE is fixed by several dependent upstream
commits that must all be applied, in the order given on the command line.
"""
import json

import pytest

from cve_corrector import cherry_pick as cherry_pick_mod
from cve_corrector import workflow as workflow_mod
from cve_corrector.cherry_pick import apply_series
from cve_corrector.state import EXIT_CONFLICT, ConflictError
from cve_corrector.workflow import WorkflowConfig, _handle_no_clean_apply
from tests.helpers import assert_patch_naming, run_workflow

CHAIN = ['a' * 40, 'b' * 40, 'c' * 40]


class TestApplySeriesRequireAll:
    """apply_series must surface conflict state for a required chain."""

    @staticmethod
    def _fake_git(monkeypatch, tmp_path, failing_hash):
        """Make cherry-pick fail, leaving CHERRY_PICK_HEAD at failing_hash."""
        (tmp_path / '.git').mkdir()
        (tmp_path / '.git' / 'CHERRY_PICK_HEAD').write_text(failing_hash + '\n')

        def fake_run_cmd(cmd, cwd=None, **kwargs):
            # Non-zero only for the batch cherry-pick itself.
            if cmd[:2] == ['git', 'cherry-pick'] and '--abort' not in cmd:
                return 1
            return 0

        monkeypatch.setattr(cherry_pick_mod, 'run_cmd', fake_run_cmd)
        monkeypatch.setattr(cherry_pick_mod, 'is_bad_object',
                            lambda *a, **kw: False)

    def test_conflict_on_first_commit_reports_state(self, tmp_path, monkeypatch):
        """Regression: a chain failing on commit 1 of 3 must not be lost.

        With ``max_applied`` starting at 0, ``len([]) > 0`` was False, so
        best_series stayed None and the caller silently fell back to applying
        a single commit — a partial, wrong fix.
        """
        self._fake_git(monkeypatch, tmp_path, CHAIN[0])
        series = [{'pull_url': '', 'commits': CHAIN}]

        success, last, best = apply_series(tmp_path, series, require_all=True)

        assert success is False
        assert last is None
        assert best is not None, "required chain lost its conflict state"
        assert best['applied_commits'] == []
        assert best['failed_at'] == CHAIN[0]
        assert best['remaining_commits'] == CHAIN[1:]
        assert best['commits'] == CHAIN

    def test_conflict_on_first_commit_without_require_all_unchanged(
            self, tmp_path, monkeypatch):
        """Candidate (PR) series keep their existing fallback behaviour."""
        self._fake_git(monkeypatch, tmp_path, CHAIN[0])
        series = [{'pull_url': 'https://github.com/o/r/pull/1',
                   'commits': CHAIN}]

        success, last, best = apply_series(tmp_path, series)

        assert (success, last, best) == (False, None, None)

    def test_partial_progress_still_reported(self, tmp_path, monkeypatch):
        """A chain failing mid-way reports what was applied."""
        self._fake_git(monkeypatch, tmp_path, CHAIN[1])
        series = [{'pull_url': '', 'commits': CHAIN}]

        _, _, best = apply_series(tmp_path, series, require_all=True)

        assert best['applied_commits'] == [CHAIN[0]]
        assert best['failed_at'] == CHAIN[1]
        assert best['remaining_commits'] == [CHAIN[2]]


class TestHandleNoCleanApply:
    """A required chain never degrades to a single least-conflict commit."""

    def test_require_all_skips_least_conflict(self, monkeypatch, tmp_path):
        calls = []
        monkeypatch.setattr(workflow_mod, 'find_least_conflict_commit',
                            lambda *a, **kw: calls.append(a) or ('x', 0))

        with pytest.raises(ConflictError):
            _handle_no_clean_apply(tmp_path, CHAIN, [], lambda *a: None, 'acl',
                                   require_all_commits=True)

        assert calls == [], "least-conflict pick must not run for a chain"

    def test_without_require_all_uses_least_conflict(self, monkeypatch, tmp_path):
        calls = []
        monkeypatch.setattr(workflow_mod, 'find_least_conflict_commit',
                            lambda *a, **kw: (calls.append(a), (CHAIN[0], 1))[1])
        monkeypatch.setattr(workflow_mod, 'run_cmd', lambda *a, **kw: 0)
        monkeypatch.setattr(workflow_mod, 'has_conflict_state', lambda *a: True)
        monkeypatch.setattr(workflow_mod, 'save_workflow_state', lambda s: None)
        monkeypatch.setattr(workflow_mod, 'print_conflict_instructions',
                            lambda *a, **kw: None)

        with pytest.raises(ConflictError):
            _handle_no_clean_apply(tmp_path, CHAIN, [], lambda *a: None, 'acl')

        assert len(calls) == 1


class TestWorkflowConfigDefault:
    def test_require_all_commits_defaults_false(self):
        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=None,
            skip_build=True, clean=False, skip_ptest=True, edit_mode=False)
        assert config.require_all_commits is False


class TestDependentChainEndToEnd:
    """Full workflow with a three-commit dependent chain."""

    @staticmethod
    def _chain_repo(make_upstream_repo, make_workspace, conflicting=False):
        """Upstream with 3 dependent commits touching the same file."""
        bare, hashes = make_upstream_repo(
            files={'libacl/acl_copy.c': 'v0\nshared\ntail\n'},
            version_tag='v2.3.1',
            fix_commits=[
                {'files': {'libacl/acl_copy.c': 'fix1\nshared\ntail\n'},
                 'message': 'Fix buffer overflow'},
                {'files': {'libacl/acl_copy.c': 'fix1\nshared\nfix2\n'},
                 'message': 'Follow-up: guard length'},
                {'files': {'libacl/acl_copy.c': 'fix1\nfix3\nfix2\n'},
                 'message': 'Follow-up: harden copy'},
            ])
        existing = None
        if conflicting:
            # Recipe patch rewrites the first line the chain depends on.
            existing = [{'files': {'libacl/acl_copy.c': 'distro\nshared\ntail\n'},
                         'message': 'Existing recipe patch'}]
        ws = make_workspace(bare, 'acl', 'v2.3.1',
                            existing_patch_commits=existing)
        return ws, hashes

    @staticmethod
    def _cve_data(cve_id, hashes):
        """Metadata as parse_fix_urls() would build it from 3 --fix-url values."""
        return {cve_id: {
            'name': 'acl',
            'hashes': hashes,
            'hash_details': [
                {'hash': h,
                 'url': 'https://cgit.git.savannah.nongnu.org/cgit/acl.git/'
                        f'commit/?id={h}',
                 'source': 'cli'} for h in hashes],
            'series': [{'pull_url': '', 'commits': hashes}]}}

    def test_all_commits_applied(self, make_upstream_repo, make_workspace,
                                 make_meta_layer, mock_bitbake_env):
        ws, hashes = self._chain_repo(make_upstream_repo, make_workspace)
        meta = make_meta_layer('acl', '2.3.1')
        mock_bitbake_env(ws, meta, 'acl', '2.3.1')

        cve_id = 'CVE-2026-99001'
        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=True, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True,
            require_all_commits=True)

        exit_code = run_workflow(self._cve_data(cve_id, hashes), cve_id, config)

        assert exit_code == 0
        # All three commits produce patches, numbered in application order.
        assert_patch_naming(meta, cve_id, expect_series=True)
        patches = sorted(meta.rglob(f'*{cve_id}*.patch'))
        assert len(patches) == 3
        # Every patch of the chain keeps its CVE tag.
        for patch in patches:
            assert f'CVE: {cve_id}' in patch.read_text()

    def test_conflict_never_falls_back_to_single_commit(
            self, make_upstream_repo, make_workspace, make_meta_layer,
            mock_bitbake_env, monkeypatch):
        ws, hashes = self._chain_repo(make_upstream_repo, make_workspace,
                                      conflicting=True)
        meta = make_meta_layer('acl', '2.3.1')
        mock_bitbake_env(ws, meta, 'acl', '2.3.1')

        single_calls, least_calls = [], []
        monkeypatch.setattr(
            workflow_mod, 'apply_single_commits',
            lambda *a, **kw: (single_calls.append(a), (False, None))[1])
        monkeypatch.setattr(
            workflow_mod, 'find_least_conflict_commit',
            lambda *a, **kw: (least_calls.append(a), (None, float('inf')))[1])

        cve_id = 'CVE-2026-99002'
        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=True, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True,
            require_all_commits=True)

        exit_code = run_workflow(self._cve_data(cve_id, hashes), cve_id, config)

        assert exit_code == EXIT_CONFLICT
        assert single_calls == [], "chain must not fall back to one commit"
        assert least_calls == [], "chain must not pick a least-conflict commit"

        # Conflict state records the whole chain so --continue resumes it.
        state_files = list((ws.parent.parent / 'cve_corrector').glob('*.json'))
        assert state_files, "no state file saved for resume"
        state = json.loads(state_files[0].read_text())
        assert state['series_state']['commits'] == hashes
