# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests that a metadata series' commits are never applied on their own.

``series`` is an ordered chain that ``apply_series`` applies in full, while
``hashes`` are alternatives tried one at a time. Metadata routinely lists the
same commits in both, and ``require_all_commits`` is only set for chains given
on the command line via repeated ``--fix-url`` -- so for a metadata-driven
series the fallback path used to offer each chain member as a standalone
candidate.

Two real shapes make that dangerous:

* setuptools' CVE-2025-47273 -- ``d8390feaa`` extracts a helper and
  ``250a6d179`` adds the guard. Applying the refactor alone builds and tests
  clean while leaving the CVE unfixed.
* binutils' CVE-2025-1153 -- three commits where the third reverts part of the
  first, so applying only the first is worse than applying none.
"""
import pytest

from cve_corrector import workflow as workflow_mod
from cve_corrector.cherry_pick import (
    dependent_chain_commits,
    standalone_candidates,
)
from cve_corrector.state import EXIT_CONFLICT, ConflictError
from cve_corrector.workflow import WorkflowConfig, _handle_no_clean_apply
from tests.helpers import run_workflow

PRE = 'd8390feaa99091d1ba9626bec0e4ba7072fc507a'
FIX = '250a6d17978f9f6ac3ac887091f2d32886fbbb0b'
UNRELATED = '8e4868a036b7fae3208d16cb4e5fe6d63c3752df'


def _series(*commits):
    return [{'pull_url': 'oe_patch:CVE-2025-47273-pre1.patch',
             'commits': list(commits)}]


class TestDependentChainCommits:
    def test_multi_commit_series_is_a_chain(self):
        assert dependent_chain_commits(_series(PRE, FIX)) == {PRE, FIX}

    def test_single_commit_series_is_not_a_chain(self):
        """That commit alone is the whole fix, so it stays a valid fallback."""
        assert dependent_chain_commits(_series(FIX)) == set()

    def test_no_series(self):
        assert dependent_chain_commits(None) == set()
        assert dependent_chain_commits([]) == set()

    def test_several_series_are_all_collected(self):
        both = _series(PRE, FIX) + [{'commits': ['a' * 40, 'b' * 40]}]
        assert dependent_chain_commits(both) == {PRE, FIX, 'a' * 40, 'b' * 40}


class TestStandaloneCandidates:
    def test_chain_members_are_dropped(self):
        """The regression: chain commits must not survive as alternatives."""
        assert standalone_candidates([PRE, FIX, UNRELATED],
                                     _series(PRE, FIX)) == [UNRELATED]

    def test_order_of_survivors_is_preserved(self):
        other = 'f' * 40
        assert standalone_candidates([UNRELATED, PRE, other],
                                     _series(PRE, FIX)) == [UNRELATED, other]

    def test_short_hash_still_matches_a_chain_member(self):
        """Trackers record short shas; a prefix match must still be caught."""
        assert standalone_candidates([PRE[:12], UNRELATED],
                                     _series(PRE, FIX)) == [UNRELATED]

    def test_long_hash_matches_a_short_chain_member(self):
        assert standalone_candidates([PRE], _series(PRE[:12], FIX)) == []

    def test_single_commit_series_is_left_alone(self):
        assert standalone_candidates([FIX], _series(FIX)) == [FIX]

    def test_no_series_passes_hashes_through(self):
        assert standalone_candidates([PRE, FIX], []) == [PRE, FIX]

    def test_empty_hashes(self):
        assert standalone_candidates(None, _series(PRE, FIX)) == []


class TestHandleNoCleanApplyWithChain:
    """With every candidate filtered out, report the chain, not a dead end."""

    def test_chain_only_never_reaches_least_conflict(self, monkeypatch, tmp_path):
        calls = []
        monkeypatch.setattr(workflow_mod, 'find_least_conflict_commit',
                            lambda *a, **kw: calls.append(a) or (PRE, 0))

        with pytest.raises(ConflictError):
            _handle_no_clean_apply(tmp_path, [], _series(PRE, FIX),
                                   lambda *a: None, 'python3-setuptools',
                                   had_chain=True)

        assert calls == [], \
            'a chain member must never be picked as the least-conflict commit'

    def test_surviving_candidate_still_uses_least_conflict(self, monkeypatch,
                                                          tmp_path):
        """Filtering the chain must not disable the fallback altogether."""
        calls = []
        monkeypatch.setattr(workflow_mod, 'find_least_conflict_commit',
                            lambda *a, **kw: (calls.append(a), (UNRELATED, 1))[1])
        monkeypatch.setattr(workflow_mod, 'run_cmd', lambda *a, **kw: 0)
        monkeypatch.setattr(workflow_mod, 'has_conflict_state', lambda *a: True)
        monkeypatch.setattr(workflow_mod, 'save_workflow_state', lambda s: None)
        monkeypatch.setattr(workflow_mod, 'print_conflict_instructions',
                            lambda *a, **kw: None)

        with pytest.raises(ConflictError):
            _handle_no_clean_apply(tmp_path, [UNRELATED], _series(PRE, FIX),
                                   lambda *a: None, 'python3-setuptools',
                                   had_chain=True)

        assert len(calls) == 1
        assert calls[0][1] == [UNRELATED]


class TestChainNeverPartiallyAppliedEndToEnd:
    """The real path: a metadata series whose first commit conflicts.

    ``apply_series`` records a partial result only when at least one commit
    applied (``max_applied = 0`` for a metadata series), so a failure on the
    *first* commit leaves ``best_series`` None and falls straight through to the
    ``hashes`` fallback. That fallback used to apply whichever chain member
    happened to fit -- shipping a recipe that builds and tests clean with only
    half the fix.
    """

    def test_series_failure_does_not_apply_one_chain_commit(
            self, make_upstream_repo, make_workspace, make_meta_layer,
            mock_bitbake_env):
        # Two-commit chain: a "refactor" then a "guard", as in CVE-2025-47273.
        bare, hashes = make_upstream_repo(
            files={'src/helper.c': 'int helper(void) { return 0; }\n',
                   'src/guard.c': 'void check(void) { }\n'},
            version_tag='v1.0',
            fix_commits=[
                {'files': {'src/helper.c': 'int helper(void) { return 1; }\n'},
                 'message': 'Extract helper (prerequisite)'},
                {'files': {'src/guard.c': 'void check(void) { validate(); }\n'},
                 'message': 'Add the guard (the actual fix)'},
            ])
        refactor, guard = hashes

        # A local change to helper.c makes the *first* chain commit conflict,
        # while the second would still apply cleanly on its own.
        ws = make_workspace(
            bare, 'thing', 'v1.0',
            existing_patch_commits=[
                {'files': {'src/helper.c': 'int helper(void) { return 42; }\n'},
                 'message': 'Local divergence'}])
        meta = make_meta_layer('thing', '1.0')
        mock_bitbake_env(ws, meta, 'thing', '1.0')

        cve_id = 'CVE-2025-47273'
        # The chain is recorded correctly *and* duplicated into `hashes`, which
        # is how the enricher and the extractor both leave real entries.
        cve_data = {cve_id: {
            'name': 'thing',
            'hashes': [refactor, guard],
            'series': [{'pull_url': 'oe_patch:CVE-2025-47273-pre1.patch',
                        'commits': [refactor, guard]}],
            'hash_details': [{'hash': refactor, 'url': None, 'source': 'test'}],
        }}
        config = WorkflowConfig(
            mirror_path=None, mirror_dir=None, meta_layer=meta,
            skip_build=True, clean=False, skip_ptest=True,
            edit_mode=False, skip_cve_applicability=True)

        exit_code = run_workflow(cve_data, cve_id, config)

        assert exit_code == EXIT_CONFLICT, (
            f"expected the chain to be reported as a conflict, got "
            f"{exit_code}; a chain commit was applied on its own")
        # Nothing may have been committed to the meta layer: a patch here would
        # be the partial fix.
        patches = list((meta).rglob(f'*{cve_id}*.patch'))
        assert patches == [], \
            f"a partial-fix patch was written: {[p.name for p in patches]}"
