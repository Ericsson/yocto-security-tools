# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the oe-init-build-env lookup in tests/integration/test_common.sh.

``oe-init-build-env`` computes ``OEROOT=$(dirname "$THIS_SCRIPT")``, so it
always sits at the root of the OE checkout itself — ``$OE_DIR/oe-init-build-env``
— in every supported layout:

- poky (scarthgap and older): ``<proj>/poky/oe-init-build-env``
- standalone openembedded-core (whinlatter, wrynose — poky has no such branch,
  so these releases must be built from an oe-core checkout):
  ``<proj>/openembedded-core/oe-init-build-env``

Rather than driving a real Yocto build, these tests source ``test_common.sh``
against synthetic checkouts whose ``oe-init-build-env`` is a stub that records
that it ran and exports BBPATH — exactly the contract the real script fulfils.
"""
import os
import subprocess
from pathlib import Path

import pytest

_COMMON_SH = Path(__file__).resolve().parent / "test_common.sh"

_STUB_INIT = """#!/bin/sh
# Stub oe-init-build-env: records the OEROOT it would resolve to, then exports
# BBPATH like the real script does via scripts/oe-buildenv-internal.
# $0 is the *parent* shell when sourced, so use $BASH_SOURCE — the same
# THIS_SCRIPT dance the real oe-init-build-env performs.
if [ -n "$BASH_SOURCE" ]; then THIS_SCRIPT="$BASH_SOURCE"; else THIS_SCRIPT="$0"; fi
(cd "$(dirname "$THIS_SCRIPT")" && pwd) > "$MARKER_FILE"
BBPATH="$1"
export BBPATH
"""


def _make_checkout(root: Path, name: str, with_init: bool = True) -> Path:
    """Create a synthetic OE checkout: meta/conf marker + oe-init-build-env."""
    checkout = root / name
    (checkout / "meta" / "conf").mkdir(parents=True)
    if with_init:
        init = checkout / "oe-init-build-env"
        init.write_text(_STUB_INIT, encoding="utf-8")
        init.chmod(0o755)
    return checkout


def _source_build_env(tmp_path: Path, oe_dir: Path | None, build_dir: Path,
                      marker: Path) -> subprocess.CompletedProcess:
    """Source test_common.sh and run source_build_env() in a clean shell."""
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "BUILD_DIR": str(build_dir),
        "MARKER_FILE": str(marker),
    }
    if oe_dir is not None:
        env["OE_DIR"] = str(oe_dir)
    # BBPATH deliberately unset: that is what triggers the lookup under test.
    script = f'set -u; . "{_COMMON_SH}"; source_build_env; echo "BBPATH=$BBPATH"'
    return subprocess.run(["bash", "-c", script], env=env, capture_output=True,
                          text=True, check=False)


@pytest.fixture
def build_dir(tmp_path):
    d = tmp_path / "build"
    d.mkdir()
    return d


def test_finds_init_in_poky_checkout(tmp_path, build_dir):
    """poky layout: oe-init-build-env lives at $OE_DIR/oe-init-build-env."""
    poky = _make_checkout(tmp_path, "poky")
    marker = tmp_path / "ran"

    result = _source_build_env(tmp_path, poky, build_dir, marker)

    assert result.returncode == 0, result.stdout + result.stderr
    assert marker.is_file(), "oe-init-build-env was never sourced"
    assert marker.read_text(encoding="utf-8").strip() == str(poky)
    assert f"BBPATH={build_dir}" in result.stdout


def test_finds_init_in_standalone_oe_core_checkout(tmp_path, build_dir):
    """oe-core layout (wrynose has no poky branch): same $OE_DIR/ location."""
    oe_core = _make_checkout(tmp_path, "openembedded-core")
    marker = tmp_path / "ran"

    result = _source_build_env(tmp_path, oe_core, build_dir, marker)

    assert result.returncode == 0, result.stdout + result.stderr
    assert marker.is_file(), "oe-init-build-env was never sourced"
    assert marker.read_text(encoding="utf-8").strip() == str(oe_core)
    assert f"BBPATH={build_dir}" in result.stdout


def test_autodetects_oe_dir_from_build_dir(tmp_path, build_dir):
    """With OE_DIR unset, the poky checkout beside build/ is autodetected and
    its oe-init-build-env is still found."""
    poky = _make_checkout(tmp_path, "poky")
    marker = tmp_path / "ran"

    result = _source_build_env(tmp_path, None, build_dir, marker)

    assert result.returncode == 0, result.stdout + result.stderr
    assert marker.read_text(encoding="utf-8").strip() == str(poky)


def test_superproject_layout_still_works(tmp_path, build_dir):
    """Regression guard: a checkout whose oe-init-build-env sits one level
    above OE_DIR keeps working via the existing fallback."""
    oe_core = _make_checkout(tmp_path, "openembedded-core", with_init=False)
    init = tmp_path / "oe-init-build-env"
    init.write_text(_STUB_INIT, encoding="utf-8")
    init.chmod(0o755)
    marker = tmp_path / "ran"

    result = _source_build_env(tmp_path, oe_core, build_dir, marker)

    assert result.returncode == 0, result.stdout + result.stderr
    assert marker.read_text(encoding="utf-8").strip() == str(tmp_path)


def test_missing_init_still_fails_loudly(tmp_path, build_dir):
    """No oe-init-build-env anywhere: the script must die, not continue."""
    oe_core = _make_checkout(tmp_path, "openembedded-core", with_init=False)
    marker = tmp_path / "ran"

    result = _source_build_env(tmp_path, oe_core, build_dir, marker)

    assert result.returncode != 0
    assert "Cannot find oe-init-build-env" in result.stdout + result.stderr
    assert not marker.exists()
