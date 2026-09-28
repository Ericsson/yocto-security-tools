# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for shared.paths — XDG base directory resolution.

Regression coverage for the CVE_TOOLS_DATA_DIR / global-config coupling
bug: cve_agent/setup.py's STABLE_AGENT_INSTRUCTIONS (referenced from the
machine-global ~/.kiro/agents/*.json prompt) must NOT follow a per-run
CVE_TOOLS_DATA_DIR override the way data_dir() does, or every CI/benchmark
run that sets it leaves the global agent config pointing at a throwaway
temp directory -- breaking any other kiro-cli invocation on the host once
that directory is gone (``Error: File URI not found: ...``).
"""
from pathlib import Path

from shared.paths import cache_dir, data_dir, user_data_dir


class TestDataDir:
    def test_honors_cve_tools_data_dir_override(self, monkeypatch, tmp_path):
        monkeypatch.setenv("CVE_TOOLS_DATA_DIR", str(tmp_path))
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        assert data_dir() == tmp_path / "yocto-security-tools"

    def test_falls_back_to_xdg_data_home(self, monkeypatch, tmp_path):
        monkeypatch.delenv("CVE_TOOLS_DATA_DIR", raising=False)
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        assert data_dir() == tmp_path / "yocto-security-tools"

    def test_falls_back_to_home_local_share(self, monkeypatch):
        monkeypatch.delenv("CVE_TOOLS_DATA_DIR", raising=False)
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        assert data_dir() == Path.home() / ".local" / "share" / "yocto-security-tools"


class TestUserDataDir:
    def test_ignores_cve_tools_data_dir_override(self, monkeypatch, tmp_path):
        # This is the bug this function exists to fix: a per-run
        # CVE_TOOLS_DATA_DIR (e.g. a benchmark's mktemp -d artifact root)
        # must not affect a path referenced from global host state.
        monkeypatch.setenv("CVE_TOOLS_DATA_DIR", str(tmp_path))
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        assert user_data_dir() == Path.home() / ".local" / "share" / "yocto-security-tools"

    def test_still_honors_xdg_data_home(self, monkeypatch, tmp_path):
        monkeypatch.delenv("CVE_TOOLS_DATA_DIR", raising=False)
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        assert user_data_dir() == tmp_path / "yocto-security-tools"

    def test_diverges_from_data_dir_when_override_is_set(self, monkeypatch, tmp_path):
        monkeypatch.setenv("CVE_TOOLS_DATA_DIR", str(tmp_path))
        monkeypatch.delenv("XDG_DATA_HOME", raising=False)
        assert user_data_dir() != data_dir()

    def test_matches_data_dir_when_no_override_is_set(self, monkeypatch, tmp_path):
        monkeypatch.delenv("CVE_TOOLS_DATA_DIR", raising=False)
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
        assert user_data_dir() == data_dir()


class TestCacheDir:
    def test_honors_cve_tools_cache_dir_override(self, monkeypatch, tmp_path):
        monkeypatch.setenv("CVE_TOOLS_CACHE_DIR", str(tmp_path))
        monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
        assert cache_dir() == tmp_path / "yocto-security-tools"
