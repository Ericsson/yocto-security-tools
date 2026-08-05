# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for cve_corrector.bitbake_ops — file-based operations."""
from unittest.mock import MagicMock, patch

from cve_corrector.bitbake_ops import check_cve_patch_in_src_uri, check_cve_status, find_mirror_repo


def test_find_mirror_repo_bare(tmp_path):
    (tmp_path / "libarchive.git").mkdir()
    assert find_mirror_repo(tmp_path, "libarchive") == tmp_path / "libarchive.git"


def test_find_mirror_repo_plain(tmp_path):
    (tmp_path / "libarchive").mkdir()
    assert find_mirror_repo(tmp_path, "libarchive") == tmp_path / "libarchive"


def test_find_mirror_repo_missing(tmp_path):
    assert find_mirror_repo(tmp_path, "nonexistent") is None


def test_update_recipe_patch(tmp_path):
    from cve_corrector.recipe_ops import update_recipe_patch
    recipe_dir = tmp_path / "recipes-foo" / "foo"
    recipe_dir.mkdir(parents=True)
    bb = recipe_dir / "foo_1.0.bb"
    bb.write_text('SRC_URI = "file://old-name.patch"\n')
    update_recipe_patch("foo", "new-name.patch", "old-name.patch", tmp_path)
    assert "new-name.patch" in bb.read_text()
    assert "old-name.patch" not in bb.read_text()


def test_update_recipe_patch_no_match(tmp_path, capsys):
    from unittest.mock import MagicMock
    from unittest.mock import patch as mock_patch

    from cve_corrector.recipe_ops import update_recipe_patch
    recipe_dir = tmp_path / "recipes-foo" / "foo"
    recipe_dir.mkdir(parents=True)
    bb = recipe_dir / "foo_1.0.bb"
    bb.write_text('SRC_URI = "file://other.patch"\n')
    with mock_patch("cve_corrector.recipe_ops.run_cmd_capture",
                    return_value=MagicMock(stdout="")):
        update_recipe_patch("foo", "new.patch", "missing.patch", meta_layer=tmp_path)
    assert "Warning" in capsys.readouterr().out

def test_snapshot_src_uri(tmp_path):
    """snapshot_src_uri returns file:// basenames from the recipe."""
    from cve_corrector.recipe_ops import snapshot_src_uri
    recipe_dir = tmp_path / "recipes-core" / "busybox"
    recipe_dir.mkdir(parents=True)
    recipe = recipe_dir / "busybox_1.36.1.bb"
    recipe.write_text(
        'SRC_URI = "file://defconfig \\\n'
        '           file://mdev.cfg \\\n'
        '           file://patch.patch \\\n'
        '           "\n'
    )
    entries = snapshot_src_uri(tmp_path, "busybox")
    assert entries == {"defconfig", "mdev.cfg", "patch.patch"}


def test_remove_bbappend_leaks(tmp_path):
    """remove_bbappend_leaks strips non-patch entries added by devtool."""
    from cve_corrector.recipe_ops import remove_bbappend_leaks
    recipe_dir = tmp_path / "recipes-core" / "busybox"
    recipe_dir.mkdir(parents=True)
    recipe = recipe_dir / "busybox_1.36.1.bb"
    recipe.write_text(
        'SRC_URI = "file://defconfig \\\n'
        '           file://mdev.cfg \\\n'
        '           file://lspci.cfg \\\n'
        '           file://nsenter.cfg \\\n'
        '           file://new-fix.patch \\\n'
        '           "\n'
    )
    original = {"defconfig", "mdev.cfg"}
    remove_bbappend_leaks(tmp_path, "busybox", original)
    text = recipe.read_text()
    assert "defconfig" in text
    assert "mdev.cfg" in text
    assert "new-fix.patch" in text  # new patch kept
    assert "lspci.cfg" not in text  # bbappend leak removed
    assert "nsenter.cfg" not in text  # bbappend leak removed


def test_remove_bbappend_leaks_no_leaks(tmp_path):
    """remove_bbappend_leaks is a no-op when nothing leaked."""
    from cve_corrector.recipe_ops import remove_bbappend_leaks
    recipe_dir = tmp_path / "recipes-core" / "busybox"
    recipe_dir.mkdir(parents=True)
    recipe = recipe_dir / "busybox_1.36.1.bb"
    original_text = 'SRC_URI = "file://defconfig \\\n           file://fix.patch \\\n           "\n'
    recipe.write_text(original_text)
    remove_bbappend_leaks(tmp_path, "busybox", {"defconfig"})
    assert recipe.read_text() == original_text


def test_append_src_uri_entries_not_confused_by_sha256sum(tmp_path):
    """_append_src_uri_entries inserts before closing quote, not near SRC_URI[sha256sum]."""
    from cve_corrector.recipe_ops import _append_src_uri_entries
    recipe_dir = tmp_path / "recipes-extended" / "libarchive"
    recipe_dir.mkdir(parents=True)
    recipe = recipe_dir / "libarchive_3.7.9.bb"
    recipe.write_text(
        'SRC_URI = "http://libarchive.org/downloads/libarchive-${PV}.tar.gz \\\n'
        '           file://configurehack.patch \\\n'
        '           "\n'
        'UPSTREAM_CHECK_URI = "http://libarchive.org/"\n'
        '\n'
        'SRC_URI[sha256sum] = "aa90732c5a6bdda52fda2ad468ac98d75be981c15dde263d7b5cf6af66fd009f"\n'
        '\n'
        'inherit autotools update-alternatives pkgconfig\n'
    )
    _append_src_uri_entries(recipe, ["CVE-2026-4424-1.patch", "CVE-2026-4424-2.patch"])
    content = recipe.read_text()
    # Patches must be inside SRC_URI block (before the closing quote)
    lines = content.splitlines()
    closing_quote_idx = next(i for i, l in enumerate(lines) if l.strip() == '"')
    sha256_idx = next(i for i, l in enumerate(lines) if 'sha256sum' in l)
    patch_indices = [i for i, l in enumerate(lines) if 'CVE-2026-4424' in l]
    for idx in patch_indices:
        assert idx < closing_quote_idx, f"Patch at line {idx} should be before closing quote at {closing_quote_idx}"
        assert idx < sha256_idx, f"Patch at line {idx} should be before sha256sum at {sha256_idx}"


def test_append_src_uri_entries_override_style(tmp_path):
    """_append_src_uri_entries handles SRC_URI:append override syntax."""
    from cve_corrector.recipe_ops import _append_src_uri_entries
    recipe_dir = tmp_path / "recipes-core" / "openssl"
    recipe_dir.mkdir(parents=True)
    recipe = recipe_dir / "openssl_3.1.4.bb"
    recipe.write_text(
        'SUMMARY = "Secure Sockets Layer"\n'
        'SRC_URI:append:class-target = " \\\n'
        '    file://existing.patch \\\n'
        '    "\n'
    )
    _append_src_uri_entries(recipe, ["CVE-2026-1234.patch"])
    content = recipe.read_text()
    assert "CVE-2026-1234.patch" in content
    assert content.index("CVE-2026-1234.patch") < content.rindex('"')


def test_find_recipe_file_exact_match(tmp_path):
    """_find_recipe_file does not match busybox-utils when looking for busybox."""
    from cve_corrector.recipe_ops import _find_recipe_file
    recipe_dir = tmp_path / "recipes-core" / "busybox"
    recipe_dir.mkdir(parents=True)
    (recipe_dir / "busybox_1.36.1.bb").write_text('SUMMARY = "busybox"\n')
    (recipe_dir / "busybox-utils_1.36.1.bb").write_text('SUMMARY = "utils"\n')
    result = _find_recipe_file(tmp_path, "busybox")
    assert result is not None
    assert result.name == "busybox_1.36.1.bb"


def test_find_recipe_file_prefers_bbappend(tmp_path):
    """_find_recipe_file prefers .bbappend over .bb."""
    from cve_corrector.recipe_ops import _find_recipe_file
    recipe_dir = tmp_path / "recipes-core" / "openssl"
    recipe_dir.mkdir(parents=True)
    (recipe_dir / "openssl_3.1.4.bb").write_text('SUMMARY = "ssl"\n')
    (recipe_dir / "openssl_3.1.4.bbappend").write_text('# append\n')
    result = _find_recipe_file(tmp_path, "openssl")
    assert result is not None
    assert result.suffix == ".bbappend"


class TestCheckCveStatus:
    """Tests for check_cve_status — CVE_STATUS pre-flight check."""

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_ignored_reason_maps_to_ignored(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="not-applicable-platform: Windows only\n")
        result = check_cve_status("wpa-supplicant", "CVE-2024-5290")
        assert result == ("Ignored", "not-applicable-platform: Windows only")
        mock_run.assert_called_once_with([
            'bitbake-getvar', 'CVE_STATUS', '-f', 'CVE-2024-5290',
            '-r', 'wpa-supplicant', '--value', '--ignore-undefined'])

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_cpe_incorrect_maps_to_ignored(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="cpe-incorrect: wrong component\n")
        result = check_cve_status("foo", "CVE-2016-10642")
        assert result == ("Ignored", "cpe-incorrect: wrong component")

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_fixed_version_maps_to_patched(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="fixed-version: fixed externally\n")
        result = check_cve_status("curl", "CVE-2025-5025")
        assert result == ("Patched", "fixed-version: fixed externally")

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_unpatched_reason_maps_to_unpatched(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="vulnerable-investigating: under review\n")
        result = check_cve_status("foo", "CVE-2025-0001")
        assert result == ("Unpatched", "vulnerable-investigating: under review")

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_no_status_returns_none(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="\n")
        assert check_cve_status("foo", "CVE-2025-0001") is None

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_command_failure_returns_none(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert check_cve_status("foo", "CVE-2025-0001") is None

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_reason_without_description_is_handled(self, mock_run):
        """CVE_STATUS may be set without a ': description' suffix."""
        mock_run.return_value = MagicMock(returncode=0, stdout="ignored\n")
        result = check_cve_status("foo", "CVE-2025-0001")
        assert result == ("Ignored", "ignored")

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_case_insensitive_reason_matching(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="Not-Applicable-Config: disabled feature\n")
        result = check_cve_status("foo", "CVE-2025-0001")
        assert result == ("Ignored", "Not-Applicable-Config: disabled feature")


    """Tests for check_cve_patch_in_src_uri — pre-flight already-applied check."""

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_finds_matching_patch(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='SRC_URI="file://CVE-2024-1234.patch file://defconfig"\n')
        result = check_cve_patch_in_src_uri("busybox", "CVE-2024-1234")
        assert result == "CVE-2024-1234.patch"
        mock_run.assert_called_once_with(
            ['bitbake-getvar', 'SRC_URI', '-r', 'busybox'])

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_case_insensitive_match(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='SRC_URI="file://cve-2024-1234.patch"\n')
        result = check_cve_patch_in_src_uri("busybox", "CVE-2024-1234")
        assert result == "cve-2024-1234.patch"

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_ignores_subdir_prefix_and_params(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='SRC_URI="file://patches/CVE-2024-1234.patch;striplevel=1"\n')
        result = check_cve_patch_in_src_uri("busybox", "CVE-2024-1234")
        assert result == "CVE-2024-1234.patch"

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_no_match_returns_none(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='SRC_URI="file://other-fix.patch file://defconfig"\n')
        assert check_cve_patch_in_src_uri("busybox", "CVE-2024-1234") is None

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_does_not_match_different_cve(self, mock_run):
        """A patch for a different CVE must not be treated as a match."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='SRC_URI="file://CVE-2024-99999.patch"\n')
        assert check_cve_patch_in_src_uri("busybox", "CVE-2024-1234") is None

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_bitbake_getvar_failure_returns_none(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert check_cve_patch_in_src_uri("busybox", "CVE-2024-1234") is None


class TestCheckCveStatusCpeScope:
    """CVE_STATUS entries scoped with ``cpe:<vendor>:<product>:`` apply only to
    recipes whose CVE_PRODUCT matches, per oe-core's ``decode_cve_status()`` and
    ``has_cve_product_match()`` (meta/lib/oe/cve_check.py).

    Such entries are typically set distro-wide (e.g. oe-core's own
    ``cve-extra-exclusions.inc``), so ``bitbake-getvar CVE_STATUS -r <recipe>``
    returns the value from *every* recipe's datastore — the ``cpe:`` segment is
    the only thing limiting which recipe it applies to.
    """

    @staticmethod
    def _mock_getvar(cve_status: str, cve_product: str):
        """Answer the CVE_STATUS query then the CVE_PRODUCT query."""
        return [
            MagicMock(returncode=0, stdout=cve_status + "\n"),
            MagicMock(returncode=0, stdout=cve_product + "\n"),
        ]

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_scoped_entry_does_not_apply_to_unrelated_recipe(self, mock_run):
        """A distro-wide entry scoped to selinux must not suppress zstd's CVE.

        Reproduces the real downstream case: iotgw sets this entry in a distro
        .inc, so it is visible from zstd's datastore even though the scope names
        selinux_project:selinux.
        """
        mock_run.side_effect = self._mock_getvar(
            "cpe-incorrect: cpe:selinux_project:selinux:Red Hat selinux-policy "
            "RPM flaw, not SELinux upstream; CPE collision",
            "zstd")
        assert check_cve_status("zstd", "CVE-2015-3170") is None
        assert mock_run.call_args_list[1][0][0] == [
            'bitbake-getvar', 'CVE_PRODUCT', '-r', 'zstd', '--value']

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_scoped_entry_applies_to_matching_recipe(self, mock_run):
        """The same entry must still be honoured for the recipe it scopes to.

        meta-selinux's selinux_common.inc sets
        ``CVE_PRODUCT ?= "selinux_project:selinux"``, the vendor-qualified form
        the scope names.
        """
        raw = ("cpe-incorrect: cpe:selinux_project:selinux:Red Hat "
               "selinux-policy RPM flaw, not SELinux upstream; CPE collision")
        mock_run.side_effect = self._mock_getvar(raw, "selinux_project:selinux")
        assert check_cve_status("libselinux", "CVE-2015-3170") == ("Ignored", raw)

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_wildcard_scope_applies_to_every_recipe(self, mock_run):
        raw = "fixed-version: cpe:*:*:applies everywhere"
        mock_run.side_effect = self._mock_getvar(raw, "zstd")
        assert check_cve_status("zstd", "CVE-2025-0001") == ("Patched", raw)

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_entry_without_cpe_segment_is_honoured(self, mock_run):
        """No cpe: segment means vendor/product "*" — applies to all recipes.

        CVE_PRODUCT is not queried at all in this case.
        """
        mock_run.return_value = MagicMock(
            returncode=0, stdout="ignored: no scope, applies to this recipe\n")
        result = check_cve_status("zstd", "CVE-2025-0001")
        assert result == ("Ignored", "ignored: no scope, applies to this recipe")
        mock_run.assert_called_once_with([
            'bitbake-getvar', 'CVE_STATUS', '-f', 'CVE-2025-0001',
            '-r', 'zstd', '--value', '--ignore-undefined'])

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_vendor_wildcard_matches_named_product_only(self, mock_run):
        raw = "ignored: cpe:*:glibc:only the glibc CPE is affected"
        mock_run.side_effect = self._mock_getvar(raw, "glibc")
        assert check_cve_status("glibc", "CVE-2010-4756") == ("Ignored", raw)

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_vendor_wildcard_does_not_match_other_product(self, mock_run):
        mock_run.side_effect = self._mock_getvar(
            "ignored: cpe:*:glibc:only the glibc CPE is affected", "curl")
        assert check_cve_status("curl", "CVE-2010-4756") is None

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_named_vendor_scope_does_not_match_bare_cve_product(self, mock_run):
        """A scope naming a vendor requires CVE_PRODUCT to name it too.

        oe-core's has_cve_product_match() only wildcards the CVE_STATUS side, so
        a bare ``CVE_PRODUCT = "selinux"`` is outside a
        ``cpe:selinux_project:selinux:`` scope. Pinned here because it is the
        one place these semantics are counter-intuitive.
        """
        mock_run.side_effect = self._mock_getvar(
            "ignored: cpe:selinux_project:selinux:scoped", "selinux")
        assert check_cve_status("some-recipe", "CVE-2015-3170") is None

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_cve_product_vendor_qualified_entry_rejects_other_vendor(self, mock_run):
        mock_run.side_effect = self._mock_getvar(
            "ignored: cpe:selinux_project:selinux:scoped", "otherproject:selinux")
        assert check_cve_status("libselinux", "CVE-2015-3170") is None

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_any_of_several_cve_products_may_match(self, mock_run):
        """CVE_PRODUCT is a space-separated list; one match is enough."""
        raw = "ignored: cpe:*:openssl:scoped"
        mock_run.side_effect = self._mock_getvar(raw, "openssl-native openssl")
        assert check_cve_status("openssl", "CVE-2025-0001") == ("Ignored", raw)

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_malformed_cpe_segment_is_honoured(self, mock_run):
        """oe-core warns and leaves vendor/product unset for a truncated cpe:
        segment, so the entry keeps applying to every recipe."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="ignored: cpe:vendor-only\n")
        assert check_cve_status("zstd", "CVE-2025-0001") == (
            "Ignored", "ignored: cpe:vendor-only")

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_scope_without_description_still_matched(self, mock_run):
        """``detail: cpe:vendor:product:`` with an empty description."""
        raw = "ignored: cpe:*:zstd:"
        mock_run.side_effect = self._mock_getvar(raw, "zstd")
        assert check_cve_status("zstd", "CVE-2025-0001") == ("Ignored", raw)

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_recipe_name_is_not_used_as_a_product_fallback(self, mock_run):
        """A failed CVE_PRODUCT query must not fall back to the recipe name.

        The recipe name is frequently not the CPE product — zstd is scanned as
        "zstandard" — so substituting it would invent a match oe-core would not
        make, silently skipping the CVE. That is the very failure this scope
        check exists to prevent, so an undeterminable product reports no status.
        """
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="ignored: cpe:*:zstd:scoped\n"),
            MagicMock(returncode=1, stdout=""),
        ]
        assert check_cve_status("zstd", "CVE-2025-0001") is None

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_empty_cve_product_matches_nothing(self, mock_run):
        """oe-core excludes recipes with an empty CVE_PRODUCT from CVE
        checking, so no scope can match one."""
        mock_run.side_effect = self._mock_getvar("ignored: cpe:*:zstd:scoped", "")
        assert check_cve_status("zstd", "CVE-2025-0001") is None

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_scope_is_matched_against_cve_product_not_recipe_name(self, mock_run):
        """zstd's real CVE_PRODUCT is "zstandard" (measured on a live build):
        a scope naming the *recipe* does not apply to it..."""
        mock_run.side_effect = self._mock_getvar(
            "ignored: cpe:*:zstd:names the recipe, not the product", "zstandard")
        assert check_cve_status("zstd", "CVE-2025-0001") is None

    @patch("cve_corrector.bitbake_ops.run_cmd_capture")
    def test_scope_naming_the_real_product_applies(self, mock_run):
        """...while a scope naming the product it is actually scanned as does."""
        raw = "ignored: cpe:*:zstandard:names the real CPE product"
        mock_run.side_effect = self._mock_getvar(raw, "zstandard")
        assert check_cve_status("zstd", "CVE-2025-0001") == ("Ignored", raw)
