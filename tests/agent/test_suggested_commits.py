# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the agent 'suggest commit -> accept -> re-run with extended guard'
workflow (orchestrator escalation with ``suggested_commits``)."""
import json

import pytest

from cve_agent import AgentConfig, ResultStatus, get_agent_dir
from cve_agent import orchestrator as orch

# A realistic busybox cgit fix URL + its 40-char commit SHA.
FIX_URL = "https://git.busybox.net/busybox/commit/archival?id=3fb6b31c716669e12f75a2accd31bb7685b1a1cb"
FIX_HASH = "3fb6b31c716669e12f75a2accd31bb7685b1a1cb"
# A plausible sibling commit (different 40-char hex hash, same repo).
SUGGESTED_HASH = "8c24af9dcabcdef0123456789abcdef012345678"
SUGGESTED_URL = "https://git.busybox.net/busybox/commit/testsuite?id=" + SUGGESTED_HASH


def _cve_info():
    return {
        "name": "busybox",
        "version": "1.36.1",
        "hashes": [FIX_HASH],
        "patches": [FIX_URL],
        "hash_details": [{"hash": FIX_HASH, "url": FIX_URL, "source": "debian"}],
    }


def _make_workspace(tmp_path):
    """Build a devtool-style workspace path so get_agent_dir resolves."""
    ws = tmp_path / "build" / "workspace" / "sources" / "busybox"
    ws.mkdir(parents=True)
    return ws


def _write_conclusion(ws, payload):
    agent_dir = get_agent_dir(ws)
    (agent_dir / "conclusion.json").write_text(json.dumps(payload),
                                               encoding="utf-8")


# --- _read_escalation --------------------------------------------------------

def test_read_escalation_with_suggested_commits(tmp_path):
    ws = _make_workspace(tmp_path)
    _write_conclusion(ws, {
        "needs_human": True,
        "reason": "needs testsuite fixup",
        "suggested_commits": [SUGGESTED_HASH, "  "],  # blank entry is dropped
    })
    esc = orch._read_escalation(ws)
    assert esc is not None
    assert esc.reason == "needs testsuite fixup"
    assert esc.suggested_commits == [SUGGESTED_HASH]


def test_read_escalation_without_suggested_commits(tmp_path):
    ws = _make_workspace(tmp_path)
    _write_conclusion(ws, {"needs_human": True, "reason": "structural change"})
    esc = orch._read_escalation(ws)
    assert esc is not None
    assert esc.suggested_commits == []


def test_read_escalation_ignores_non_list_suggested(tmp_path):
    ws = _make_workspace(tmp_path)
    _write_conclusion(ws, {
        "needs_human": True, "reason": "x", "suggested_commits": "not-a-list"})
    esc = orch._read_escalation(ws)
    assert esc is not None and esc.suggested_commits == []


def test_read_escalation_absent_when_not_needs_human(tmp_path):
    ws = _make_workspace(tmp_path)
    _write_conclusion(ws, {"not_applicable": True, "reason": "n/a"})
    assert orch._read_escalation(ws) is None


def test_read_escalation_missing_file(tmp_path):
    ws = _make_workspace(tmp_path)
    assert orch._read_escalation(ws) is None


# --- _original_fix_url -------------------------------------------------------

def test_original_fix_url_prefers_patches():
    assert orch._original_fix_url(_cve_info()) == FIX_URL


def test_original_fix_url_falls_back_to_hash_details():
    info = {"hash_details": [{"hash": FIX_HASH, "url": FIX_URL}]}
    assert orch._original_fix_url(info) == FIX_URL


def test_original_fix_url_none_when_unresolvable():
    info = {"patches": ["https://example.com/advisory/GHSA-xxxx"]}
    assert orch._original_fix_url(info) is None


# --- _normalize_suggestion ---------------------------------------------------

def test_normalize_suggestion_url():
    url, h = orch._normalize_suggestion(SUGGESTED_URL, FIX_URL, FIX_HASH)
    assert url == SUGGESTED_URL
    assert h == SUGGESTED_HASH


def test_normalize_suggestion_bare_sha_builds_sibling_url():
    url, h = orch._normalize_suggestion(SUGGESTED_HASH, FIX_URL, FIX_HASH)
    assert h == SUGGESTED_HASH
    # Sibling URL reuses the fix URL template with the hash substituted.
    assert url == FIX_URL.replace(FIX_HASH, SUGGESTED_HASH)


def test_normalize_suggestion_bare_sha_without_template_fails():
    # ref_hash not present in ref_url -> cannot build a sibling URL.
    url, h = orch._normalize_suggestion(SUGGESTED_HASH, "https://x/commit/abc", "deadbeef")
    assert (url, h) == (None, None)


def test_normalize_suggestion_garbage():
    assert orch._normalize_suggestion("not a commit", FIX_URL, FIX_HASH) == (None, None)


def test_normalize_suggestion_non_commit_url():
    assert orch._normalize_suggestion(
        "https://example.com/blob/main/x.c", FIX_URL, FIX_HASH) == (None, None)


# --- _build_extended_chain ---------------------------------------------------

def test_build_extended_chain_with_sha():
    chain, new_hashes = orch._build_extended_chain(_cve_info(), [SUGGESTED_HASH])
    assert chain == [FIX_URL, FIX_URL.replace(FIX_HASH, SUGGESTED_HASH)]
    assert new_hashes == [SUGGESTED_HASH]


def test_build_extended_chain_with_url():
    chain, new_hashes = orch._build_extended_chain(_cve_info(), [SUGGESTED_URL])
    assert chain == [FIX_URL, SUGGESTED_URL]
    assert new_hashes == [SUGGESTED_HASH]


def test_build_extended_chain_dedupes_existing():
    # Suggesting the fix commit itself yields no genuinely new commit.
    chain, new_hashes = orch._build_extended_chain(_cve_info(), [FIX_HASH])
    assert chain == [] and new_hashes == []


def test_build_extended_chain_no_original_url():
    info = {"hashes": [FIX_HASH], "patches": ["https://example.com/advisory"]}
    chain, new_hashes = orch._build_extended_chain(info, [SUGGESTED_HASH])
    assert chain == [] and new_hashes == []


def test_build_extended_chain_skips_unresolvable():
    chain, new_hashes = orch._build_extended_chain(
        _cve_info(), ["garbage", SUGGESTED_HASH])
    assert new_hashes == [SUGGESTED_HASH]
    assert chain == [FIX_URL, FIX_URL.replace(FIX_HASH, SUGGESTED_HASH)]


# --- _accept_suggestion ------------------------------------------------------

def _cfg(**kw):
    return AgentConfig(cve_id="CVE-2026-26157", **kw)


def test_accept_suggestion_trust_auto_accepts():
    assert orch._accept_suggestion(_cfg(trust_mode=True), [SUGGESTED_HASH]) is True


def test_accept_suggestion_interactive_yes(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "y")
    assert orch._accept_suggestion(
        _cfg(interactive=True), [SUGGESTED_HASH]) is True


def test_accept_suggestion_interactive_no(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *_: "n")
    assert orch._accept_suggestion(
        _cfg(interactive=True), [SUGGESTED_HASH]) is False


def test_accept_suggestion_non_interactive_declines():
    # No trust, not interactive -> cannot safely widen scope.
    assert orch._accept_suggestion(_cfg(), [SUGGESTED_HASH]) is False


# --- _handle_escalation ------------------------------------------------------

def test_handle_escalation_no_suggestion_returns_escalated():
    esc = orch._Escalation(reason="structural change", suggested_commits=[])
    result = orch._handle_escalation(_cfg(trust_mode=True), _cve_info(), esc, 1, 0.0)
    assert result.status is ResultStatus.ESCALATED
    assert result.resolution_summary == "structural change"


def test_handle_escalation_trust_raises_accepted_suggestion():
    esc = orch._Escalation(reason="needs fixup", suggested_commits=[SUGGESTED_HASH])
    with pytest.raises(orch._AcceptedSuggestion) as excinfo:
        orch._handle_escalation(_cfg(trust_mode=True), _cve_info(), esc, 1, 0.0)
    assert excinfo.value.new_hashes == [SUGGESTED_HASH]
    assert excinfo.value.fix_urls == [FIX_URL, FIX_URL.replace(FIX_HASH, SUGGESTED_HASH)]


def test_handle_escalation_declined_returns_escalated():
    esc = orch._Escalation(reason="needs fixup", suggested_commits=[SUGGESTED_HASH])
    # Not trust, not interactive -> declined -> ESCALATED (no raise).
    result = orch._handle_escalation(_cfg(), _cve_info(), esc, 1, 0.0)
    assert result.status is ResultStatus.ESCALATED


def test_handle_escalation_unresolvable_suggestion_escalates():
    esc = orch._Escalation(reason="needs fixup", suggested_commits=["garbage"])
    result = orch._handle_escalation(_cfg(trust_mode=True), _cve_info(), esc, 1, 0.0)
    assert result.status is ResultStatus.ESCALATED


# --- process_single_cve re-run loop -----------------------------------------

def test_rerun_loop_extends_chain_then_succeeds(monkeypatch):
    """First pipeline run accepts a suggestion; second run succeeds with the
    extended fix-url chain threaded into the config."""
    seen_configs = []

    def fake_pipeline(config, kb, start_time):
        seen_configs.append(config)
        if len(seen_configs) == 1:
            raise orch._AcceptedSuggestion(
                [FIX_URL, SUGGESTED_URL], [SUGGESTED_HASH])
        return orch._make_result(
            config.cve_id, ResultStatus.CONFLICT_RESOLVED, 0, start_time, "ok")

    monkeypatch.setattr(orch, "_run_cve_pipeline", fake_pipeline)
    result = orch.process_single_cve(_cfg(trust_mode=True), None)

    assert result.status is ResultStatus.CONFLICT_RESOLVED
    assert len(seen_configs) == 2
    # Re-run config carries the extended chain and forces a clean cherry-pick.
    assert seen_configs[1].fix_urls == [FIX_URL, SUGGESTED_URL]
    assert seen_configs[1].clean is True


def test_rerun_loop_caps_extensions(monkeypatch):
    """A pipeline that keeps suggesting new commits is stopped at the cap."""
    calls = {"n": 0}

    def fake_pipeline(config, kb, start_time):
        calls["n"] += 1
        # Always suggest a genuinely-new hash.
        new = f"{calls['n']:040x}"
        raise orch._AcceptedSuggestion([FIX_URL, SUGGESTED_URL], [new])

    monkeypatch.setattr(orch, "_run_cve_pipeline", fake_pipeline)
    result = orch.process_single_cve(_cfg(trust_mode=True), None)

    assert result.status is ResultStatus.ESCALATED
    # Initial run + _MAX_CHAIN_EXTENSIONS re-runs.
    assert calls["n"] == orch._MAX_CHAIN_EXTENSIONS + 1


def test_rerun_loop_stops_on_repeated_suggestion(monkeypatch):
    """Re-suggesting an already-accepted commit does not loop forever."""
    calls = {"n": 0}

    def fake_pipeline(config, kb, start_time):
        calls["n"] += 1
        raise orch._AcceptedSuggestion([FIX_URL, SUGGESTED_URL], [SUGGESTED_HASH])

    monkeypatch.setattr(orch, "_run_cve_pipeline", fake_pipeline)
    result = orch.process_single_cve(_cfg(trust_mode=True), None)

    assert result.status is ResultStatus.ESCALATED
    # First run accepts (extends once); second run's repeat has no new hash.
    assert calls["n"] == 2
