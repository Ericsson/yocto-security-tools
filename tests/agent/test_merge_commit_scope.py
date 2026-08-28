# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Regression tests for the AI session's file scope (Allowed Files).

``git show --name-only`` prints nothing for a merge commit, so when a CVE fix
is referenced by a pull-request merge SHA (e.g. setuptools' CVE-2024-6345 fix
88807c70) the scope used to come out **empty**. The session then started with
an empty Allowed Files list, the pre-commit guard rejected every write, and the
model could do nothing but escalate — after a paid session.
"""
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cve_agent import AgentConfig, ResultStatus
from cve_agent.git import compute_allowed_files, upstream_changed_files
from cve_agent.orchestrator import _run_single_resolution_attempt
from tests.helpers import git, git_hash


@pytest.fixture
def merge_workspace(tmp_path):
    """Workspace whose upstream fix SHA is a merge commit.

    Returns:
        Tuple of (workspace path, merge commit hash).
    """
    ws = tmp_path / 'build' / 'workspace' / 'sources' / 'python3-setuptools'
    ws.mkdir(parents=True)
    git(ws, 'init', '-b', 'main')
    (ws / 'package_index.py').write_text('vulnerable\n')
    git(ws, 'add', '-A')
    git(ws, 'commit', '-m', 'initial')
    base = git_hash(ws)

    git(ws, 'checkout', '-b', 'feature')
    (ws / 'package_index.py').write_text('fixed\n')
    (ws / 'test_packageindex.py').write_text('test\n')
    git(ws, 'add', '-A')
    git(ws, 'commit', '-m', 'fix vcs url handling')
    git(ws, 'checkout', 'main')
    git(ws, 'merge', '--no-ff', '-m', 'Merge pull request #4332', 'feature')
    merge_sha = git_hash(ws)

    git(ws, 'checkout', '-b', 'CVE-2024-6345', base)
    git(ws, 'tag', 'original-version')
    return ws, merge_sha


class TestMergeCommitScope:
    def test_upstream_changed_files_sees_merge(self, merge_workspace):
        ws, merge_sha = merge_workspace
        assert upstream_changed_files(ws, merge_sha) == {
            'package_index.py', 'test_packageindex.py'}

    def test_allowed_files_not_empty_for_merge(self, merge_workspace):
        """A merge SHA must still yield a usable file scope."""
        ws, merge_sha = merge_workspace
        allowed = compute_allowed_files({'hashes': [merge_sha]}, ws)
        assert 'package_index.py' in allowed

    def test_unknown_sha_falls_back_to_empty(self, merge_workspace):
        """Nothing to derive a scope from -> empty, so callers can bail out."""
        ws, _ = merge_workspace
        assert compute_allowed_files({'hashes': ['0' * 40]}, ws) == set()


class TestEmptyFileScopeEscalates:
    """An empty scope must escalate instead of paying for a doomed session."""

    @patch('cve_agent.orchestrator.guarded_session')
    @patch('cve_agent.orchestrator.build_context')
    @patch('cve_agent.orchestrator.compute_allowed_files', return_value=set())
    def test_no_session_started(self, mock_allowed, mock_context, mock_session,
                                tmp_path):
        config = AgentConfig(cve_id='CVE-2024-6345',
                             cve_info_path=Path('/tmp/c.json'))
        outcome = _run_single_resolution_attempt(
            config, tmp_path, 1, {'hashes': ['abc123']}, MagicMock(), 1,
            time.monotonic())

        assert outcome.result is not None
        assert outcome.result.status == ResultStatus.ESCALATED
        assert 'file scope' in outcome.result.resolution_summary
        mock_session.assert_not_called()
        mock_context.assert_not_called()
