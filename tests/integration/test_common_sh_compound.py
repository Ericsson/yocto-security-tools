# SPDX-License-Identifier: MIT
"""Tests for ``<cve-id>+<recipe>`` roster keys in test_common.sh.

discover_cves_from_layers keys a second recipe patched for the same CVE as
``<cve-id>+<recipe>``. The harness passed that key verbatim as ``--cve-id``
(which cve_agent rejects) and as the patch search string, so all such
entries were skipped as NOTFOUND. These tests source ``test_common.sh`` in a
clean shell against a synthetic git checkout.
"""
import json
import os
import subprocess
from pathlib import Path

_COMMON_SH = Path(__file__).resolve().parent / "test_common.sh"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=repo, check=True,
                          capture_output=True, text=True).stdout.strip()


def _run(tmp_path: Path, oe_dir: Path, body: str, **extra: str) -> str:
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "OE_DIR": str(oe_dir),
        "BUILD_DIR": str(tmp_path / "build"),
        "META_OE_LAYERS": "",
        **extra,
    }
    script = f'set -u; . "{_COMMON_SH}"; {body}'
    result = subprocess.run(["bash", "-c", script], env=env, check=True,
                            capture_output=True, text=True)
    return result.stdout


def test_resolve_cve_run_args_rekeys_compound_entry(tmp_path):
    oe_dir = tmp_path / "oe"
    (oe_dir / "meta" / "conf").mkdir(parents=True)
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    metadata = tmp_path / "meta.json"
    entry = {"name": "krb5", "hashes": ["a" * 40]}
    metadata.write_text(json.dumps({"CVE-2024-3596": {"name": "hostapd"},
                                    "CVE-2024-3596+krb5": entry}))

    out = _run(tmp_path, oe_dir,
               'resolve_cve_run_args CVE-2024-3596+krb5; '
               'echo "$CVE_RUN_ID $CVE_RUN_INFO"; '
               'resolve_cve_run_args CVE-2024-3596; '
               'echo "$CVE_RUN_ID $CVE_RUN_INFO"',
               CVE_METADATA=str(metadata), LOG_DIR=str(log_dir))

    compound, plain = out.splitlines()
    run_id, info = compound.split()
    assert run_id == "CVE-2024-3596"
    assert json.loads(Path(info).read_text()) == {"CVE-2024-3596": entry}
    assert plain == f"CVE-2024-3596 {metadata}"


def test_compare_skips_untouched_sibling_recipe_patch(tmp_path):
    """Only the regenerated patch is compared, not the other recipe's original."""
    oe_dir = tmp_path / "oe"
    recipes = oe_dir / "meta" / "recipes-graphics"
    for pn in ("xwayland", "xserver-xorg"):
        (recipes / pn).mkdir(parents=True)
        (recipes / pn / "CVE-2026-33999.patch").write_text(
            f"--- a/{pn}.c\n+++ b/{pn}.c\n@@ -1 +1 @@\n-old\n+new\n")
    (oe_dir / "meta" / "conf").mkdir(parents=True)
    _git(oe_dir, "init", "-q")
    _git(oe_dir, "config", "user.email", "t@example.com")
    _git(oe_dir, "config", "user.name", "T")
    _git(oe_dir, "add", "-A")
    _git(oe_dir, "commit", "-q", "-m", "base")
    # The harness's removal commit for the compound key.
    (recipes / "xwayland" / "CVE-2026-33999.patch").unlink()
    _git(oe_dir, "commit", "-q", "-am",
         "test: remove CVE-2026-33999+xwayland for testing")
    # The corrector's regenerated patch.
    (recipes / "xwayland" / "CVE-2026-33999.patch").write_text(
        "--- a/xwayland.c\n+++ b/xwayland.c\n@@ -1 +1 @@\n-old\n+new\n")
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    (log_dir / "full_CVE-2026-33999+xwayland_CVE-2026-33999.patch").write_text(
        "--- a/xwayland.c\n+++ b/xwayland.c\n@@ -1 +1 @@\n-old\n+new\n")

    out = _run(tmp_path, oe_dir,
               f'compare_patches_detailed "CVE-2026-33999+xwayland" "{log_dir}" meta')

    assert "DIFF_PATCHES:1>1" in out
    assert "DIFF_CHANGES:0" in out
