# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for per-CVE credit aggregation in the orchestrator."""
from pathlib import Path
from unittest.mock import patch

from cve_agent import AgentConfig, CveResult, ResultStatus
from cve_agent.knowledge import KnowledgeBase
from cve_agent.orchestrator import (
    _AcceptedSuggestion,
    _accumulate_credits,
    process_single_cve,
)


def _cfg(**kwargs):
    defaults = dict(cve_id="CVE-2025-0001", cve_info_path=Path("/tmp/c.json"),
                    trust_mode=True)
    defaults.update(kwargs)
    return AgentConfig(**defaults)


def test_accumulate_credits_sums_run_over_run(tmp_path):
    cfg = _cfg()
    with patch("cve_agent.orchestrator._agent_dir_for", return_value=tmp_path), \
         patch("cve_agent.session.sum_session_credits",
               return_value=(2.14, "credits")):
        total, unit = _accumulate_credits(cfg, 5.86, "credits")
    assert total == 8.0
    assert unit == "credits"


def test_accumulate_credits_none_when_no_workspace():
    cfg = _cfg()
    with patch("cve_agent.orchestrator._agent_dir_for", return_value=None):
        assert _accumulate_credits(cfg, None, None) == (None, None)


def test_agent_dir_for_resolves_without_workspace(tmp_path, monkeypatch):
    """The agent dir must resolve from BBPATH + recipe even after devtool
    finish has removed the source workspace (the success path)."""
    from cve_agent.orchestrator import _agent_dir_for
    monkeypatch.setenv("BBPATH", str(tmp_path))
    cfg = _cfg()
    with patch("cve_agent.orchestrator._resolve_cve_data",
               return_value={"CVE-2025-0001": {"name": "busybox"}}):
        agent_dir = _agent_dir_for(cfg)
    assert agent_dir == tmp_path / "workspace" / "cve_agent" / "busybox"
    # No source workspace exists — resolution still succeeds.
    assert not (tmp_path / "workspace" / "sources").exists()


def test_accumulate_credits_no_session_cost_keeps_running(tmp_path):
    cfg = _cfg()
    with patch("cve_agent.orchestrator._agent_dir_for", return_value=tmp_path), \
         patch("cve_agent.session.sum_session_credits",
               return_value=(None, None)):
        assert _accumulate_credits(cfg, 5.86, "credits") == (5.86, "credits")


def test_process_single_cve_sets_total_credits():
    cfg = _cfg()
    kb = KnowledgeBase()
    result = CveResult(cve_id="CVE-2025-0001", status=ResultStatus.SUCCESS)
    with patch("cve_agent.orchestrator._run_cve_pipeline", return_value=result), \
         patch("cve_agent.orchestrator._accumulate_credits",
               return_value=(5.86, "credits")):
        out = process_single_cve(cfg, kb)
    assert out.total_credits == 5.86
    assert out.credits_unit == "credits"


def test_process_single_cve_sums_credits_across_chain_reruns():
    """A re-run triggered by an accepted suggestion accumulates the earlier
    run's credits (read before the clean=True wipe) plus the final run's."""
    cfg = _cfg()
    kb = KnowledgeBase()
    final = CveResult(cve_id="CVE-2025-0001",
                      status=ResultStatus.CONFLICT_RESOLVED)

    pipeline_calls = [
        _AcceptedSuggestion(["url-a", "url-b"], ["b" * 40]),
        final,
    ]

    def fake_pipeline(config, knowledge_base, start_time):
        outcome = pipeline_calls.pop(0)
        if isinstance(outcome, _AcceptedSuggestion):
            raise outcome
        return outcome

    # Each _accumulate_credits call adds 3.0 to the running total.
    def fake_accumulate(config, running_total, running_unit):
        base = running_total or 0.0
        return base + 3.0, "credits"

    with patch("cve_agent.orchestrator._run_cve_pipeline",
               side_effect=fake_pipeline), \
         patch("cve_agent.orchestrator._accumulate_credits",
               side_effect=fake_accumulate):
        out = process_single_cve(cfg, kb)

    assert out.status == ResultStatus.CONFLICT_RESOLVED
    assert out.total_credits == 6.0
    assert out.credits_unit == "credits"
