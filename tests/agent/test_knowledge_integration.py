# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_agent knowledge base integration — pattern lifecycle."""
import threading
from pathlib import Path
from unittest.mock import patch

from cve_agent import AgentConfig
from cve_agent.context import _gather_knowledge
from cve_agent.knowledge import (
    KnowledgeBase,
    create_pattern,
    gather_pattern_details,
    save_knowledge_pattern,
)


def _cfg(**kwargs):
    defaults = dict(cve_id='CVE-2025-0001', cve_info_path=Path('/tmp/c.json'))
    defaults.update(kwargs)
    return AgentConfig(**defaults)


class TestSavePattern:
    def test_trust_mode_auto_saves(self, tmp_path):
        kb = KnowledgeBase(tmp_path / 'kb.json')
        cfg = _cfg(trust_mode=True)
        save_knowledge_pattern(cfg, kb, 'summary', 'abc123', 'busybox')
        assert len(kb.list_patterns()) == 1

    @patch('builtins.input', return_value='n')
    def test_user_declines_save(self, _, tmp_path):
        kb = KnowledgeBase(tmp_path / 'kb.json')
        cfg = _cfg(trust_mode=False)
        save_knowledge_pattern(cfg, kb, 'summary', 'abc123', 'busybox')
        assert len(kb.list_patterns()) == 0

    @patch('builtins.input', return_value='')
    def test_accept_default_saves_full_pattern(self, _, tmp_path):
        kb = KnowledgeBase(tmp_path / 'kb.json')
        cfg = _cfg(trust_mode=False)
        save_knowledge_pattern(cfg, kb, 'summary', 'abc123', 'busybox',
                               details={'affected_files': ['a.c'],
                                        'per_file_changes': {'a.c': 'adapted'},
                                        'diff_stat': '+1 -1',
                                        'commit_message': 'Fix CVE'})
        patterns = kb.list_patterns()
        assert len(patterns) == 1
        p = patterns[0]
        assert p.upstream_sha == 'abc123'
        assert p.affected_files == ['a.c']
        assert p.per_file_changes == {'a.c': 'adapted'}
        assert p.diff_stat == '+1 -1'
        assert p.commit_message == 'Fix CVE'


class TestGatherPatternDetails:
    @patch('cve_agent.knowledge.run_git_stdout')
    @patch('cve_agent.knowledge.get_changed_files')
    def test_fields_populated(self, mock_files, mock_git):
        mock_files.side_effect = [{'a.c', 'b.c'}, {'a.c', 'c.c'}]
        mock_git.side_effect = [
            'a.c | 2 +-',  # stat for a.c
            'diff stat output',  # overall diff stat
            'Fix buffer overflow',  # commit message
        ]
        result = gather_pattern_details(Path('/ws'), 'abc123')
        assert 'affected_files' in result
        assert 'per_file_changes' in result
        assert 'diff_stat' in result
        assert 'commit_message' in result
        assert 'a.c' in result['per_file_changes']
        assert 'c.c' in result['per_file_changes']
        assert result['per_file_changes']['c.c'] == 'omitted from backport'


class TestSimilarPatternInContext:
    @patch('cve_agent.context._get_conflicted_files', return_value=['a.c'])
    def test_pattern_included_in_context(self, _, tmp_path):
        kb = KnowledgeBase(tmp_path / 'kb.json')
        kb.add_pattern(create_pattern(
            'auto', 'busybox', '*', 'adapted API', 'CVE-2025-0001',
            upstream_sha='abc123', affected_files=['a.c']))
        result = _gather_knowledge(kb, 'busybox', Path('/ws'))
        assert 'CVE-2025-0001' in result
        assert 'adapted API' in result


class TestConcurrentAccess:
    def test_concurrent_writes_safe(self, tmp_path):
        path = tmp_path / 'kb.json'
        errors = []
        lock = threading.Lock()

        def writer(thread_id):
            try:
                kb = KnowledgeBase(path=path)
                for i in range(5):
                    with lock:
                        kb.add_pattern(create_pattern(
                            'auto', f'recipe-{thread_id}', '*',
                            f'fix-{i}', f'CVE-{thread_id}-{i}'))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        kb = KnowledgeBase(path=path)
        patterns = kb.list_patterns()
        assert len(patterns) == 20  # 4 threads * 5 patterns
