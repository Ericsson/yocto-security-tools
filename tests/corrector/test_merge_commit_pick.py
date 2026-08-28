# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Regression tests: fix commits referenced by a merge SHA.

Many upstream projects land CVE fixes through a GitHub pull request, so the
metadata sources hand cve-corrector the *merge* commit (e.g. setuptools'
CVE-2024-6345 fix 88807c70). ``git cherry-pick <merge>`` refuses to run at all
("is a merge but no -m option was given") and, crucially, leaves **no**
cherry-pick in progress. Before the fix that made the corrector:

* score the merge as "0 conflicts" — the best possible candidate — in
  :func:`find_least_conflict_commit`, and
* report EXIT_CONFLICT from :func:`_handle_no_clean_apply` while the workspace
  was pristine, sending the AI agent (or a human) to resolve a conflict that
  never existed.
"""
import pytest

from cve_corrector.cherry_pick import find_least_conflict_commit
from cve_corrector.git_ops import cherry_pick_command, has_conflict_state, is_merge_commit
from cve_corrector.state import ConflictError, PatchError
from cve_corrector.workflow import _handle_no_clean_apply
from tests.helpers import git, git_hash


@pytest.fixture
def merge_repo(tmp_path):
    """Repo whose fix arrives as a merge commit that conflicts with the base.

    Layout::

        base ── stable   (recipe version: 'shared' line rewritten downstream)
          └──── feature  (upstream fix rewrites the same line)
                   │
        base ──── merge (merge of feature into base = the "fix" SHA)

    Returns:
        Tuple of (repo path, merge commit hash, ordinary commit hash).
    """
    repo = tmp_path / 'src'
    repo.mkdir()
    git(repo, 'init', '-b', 'main')
    target = repo / 'pkg.py'
    target.write_text('header\nvulnerable\nfooter\n')
    git(repo, 'add', '-A')
    git(repo, 'commit', '-m', 'initial')
    base = git_hash(repo)

    # Upstream fix on a feature branch, merged back with a merge commit.
    git(repo, 'checkout', '-b', 'feature')
    target.write_text('header\nfixed upstream\nfooter\n')
    git(repo, 'add', '-A')
    git(repo, 'commit', '-m', 'fix the vulnerability')
    git(repo, 'checkout', 'main')
    git(repo, 'merge', '--no-ff', '-m', 'Merge pull request #1', 'feature')
    merge_sha = git_hash(repo)

    # An ordinary (non-merge) commit for the negative case.
    (repo / 'other.py').write_text('unrelated\n')
    git(repo, 'add', '-A')
    git(repo, 'commit', '-m', 'unrelated change')
    plain_sha = git_hash(repo)

    # The recipe's branch: same line, different content -> guaranteed conflict.
    git(repo, 'checkout', '-b', 'CVE-2024-6345', base)
    git(repo, 'tag', 'original-version')
    target.write_text('header\ndownstream variant\nfooter\n')
    git(repo, 'add', '-A')
    git(repo, 'commit', '-m', 'downstream patch')

    return repo, merge_sha, plain_sha


class TestCherryPickCommand:
    def test_merge_commit_gets_mainline(self, merge_repo):
        repo, merge_sha, _ = merge_repo
        assert is_merge_commit(repo, merge_sha) is True
        assert cherry_pick_command(repo, merge_sha) == [
            'git', 'cherry-pick', '-m', '1', merge_sha]

    def test_plain_commit_unchanged(self, merge_repo):
        repo, _, plain_sha = merge_repo
        assert is_merge_commit(repo, plain_sha) is False
        assert cherry_pick_command(repo, plain_sha) == [
            'git', 'cherry-pick', plain_sha]


class TestFindLeastConflictWithMerge:
    def test_merge_conflicts_are_counted(self, merge_repo):
        """The merge must be scored by its real conflicts, not as a free win."""
        repo, merge_sha, _ = merge_repo
        best, conflicts = find_least_conflict_commit(repo, [merge_sha])
        assert best == merge_sha
        assert conflicts == 1, "expected the conflicting file to be counted"
        # The probe cleans up after itself.
        assert not has_conflict_state(repo)


class TestHandleNoCleanApplyWithMerge:
    def test_conflict_state_exists_for_resolver(self, merge_repo, monkeypatch):
        """EXIT_CONFLICT is only reported with a real conflict in the tree."""
        repo, merge_sha, _ = merge_repo
        monkeypatch.setattr('cve_corrector.workflow.save_workflow_state',
                            lambda state: None)
        monkeypatch.setattr('cve_corrector.workflow.print_conflict_instructions',
                            lambda *a, **kw: None)

        with pytest.raises(ConflictError):
            _handle_no_clean_apply(repo, [merge_sha], [], lambda *a: None,
                                   'python3-setuptools')

        assert has_conflict_state(repo), (
            "the resolver was sent to a workspace with no conflict")
        unmerged = git(repo, 'ls-files', '-u').stdout
        assert 'pkg.py' in unmerged

    def test_unapplicable_commit_is_not_a_conflict(self, merge_repo, monkeypatch):
        """No conflict state -> PatchError, not a bogus EXIT_CONFLICT."""
        repo, merge_sha, _ = merge_repo
        # Simulate a commit that git refuses outright: least-conflict picks it,
        # but the pick leaves the tree pristine.
        monkeypatch.setattr('cve_corrector.workflow.find_least_conflict_commit',
                            lambda *a, **kw: (merge_sha, 0))
        monkeypatch.setattr('cve_corrector.workflow.cherry_pick_command',
                            lambda ws, sha: ['git', 'status'])
        monkeypatch.setattr('cve_corrector.workflow.save_workflow_state',
                            lambda state: None)

        with pytest.raises(PatchError):
            _handle_no_clean_apply(repo, [merge_sha], [], lambda *a: None,
                                   'python3-setuptools')
        assert not has_conflict_state(repo)
