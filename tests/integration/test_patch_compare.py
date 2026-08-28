# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Tests for the patch comparison in tests/integration/test_utils.py.

``compare_patches_detailed`` decides how close a generated backport is to the
reference patch carried in the OE layer. It used to compare the two as *sets of
+/- lines*, which reported differences that are not differences at all — a
context line whose leading space had been stripped in the reference patch, or a
``git format-patch`` signature written ``--`` instead of ``-- ``, both showed up
as divergence, while the real comparison drowned in whitespace noise. The
comparison now runs ``interdiff`` over the two patch bodies, so only genuine
code differences are reported.

``test_utils.py`` is a script (invoked by ``test_common.sh``), not an importable
package module, so it is loaded here by path.
"""
import importlib.util
import shutil
from pathlib import Path

import pytest

from tests.benchmark.bench_lib import (
    ONE_SIDED_MARKER,
    classify_diff_bucket,
    scope_diff_to_common_files,
)

_SPEC = importlib.util.spec_from_file_location(
    "integration_test_utils", Path(__file__).resolve().parent / "test_utils.py"
)
assert _SPEC and _SPEC.loader  # noqa: S101
test_utils = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(test_utils)

requires_interdiff = pytest.mark.skipif(
    shutil.which("interdiff") is None,
    reason="patchutils (interdiff) not installed",
)

# A reference patch as actually carried in oe-core for less CVE-2024-32487:
# whitespace-damaged (tab-indented context lines lost their leading space) and
# signed off with '--' rather than '-- '.
DAMAGED_REFERENCE = """From 007521ac3c95bc76e3d59c6dbfe75d06c8075c33 Mon Sep 17 00:00:00 2001
From: Mark Nudelman <markn@example.com>
Subject: [PATCH] Fix bug when viewing a file whose name contains a newline.

CVE: CVE-2024-32487

Upstream-Status: Backport [https://example.com/commit/007521ac]

Signed-off-by: Reference Author <ref@example.com>
---
 filename.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/filename.c b/filename.c
index a8726dc..c4b35b1 100644
--- a/filename.c
+++ b/filename.c
@@ -133,6 +133,10 @@ static int metachar(char c)
\treturn (strchr(metachars(), c) != NULL);
 }

+static int must_quote(char c)
+{
+\treturn (c == '\\n');
+}
 /*
  * Insert a backslash before each metacharacter in a string.
  */
--
2.40.0
"""

# The same fix as a well-formed patch: intact context lines, different commit
# metadata, a '-- ' signature, and the hunk shifted by two lines.
WELLFORMED_GENERATED = """From abcdef1234567890 Mon Sep 17 00:00:00 2001
From: CVE Corrector <cve@example.com>
Subject: [PATCH] Fix bug when viewing a file whose name contains a newline.

CVE: CVE-2024-32487

Upstream-Status: Backport [https://example.com/commit/007521ac]

Signed-off-by: CVE Corrector <cve@example.com>
---
 filename.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/filename.c b/filename.c
index a8726dc..c4b35b1 100644
--- a/filename.c
+++ b/filename.c
@@ -135,6 +135,10 @@ static int metachar(char c)
 \treturn (strchr(metachars(), c) != NULL);
 }
\x20
+static int must_quote(char c)
+{
+\treturn (c == '\\n');
+}
 /*
  * Insert a backslash before each metacharacter in a string.
  */
--\x20
2.45.2
"""

SECOND_FILE_PATCH = """diff --git a/other.c b/other.c
index 1111111..2222222 100644
--- a/other.c
+++ b/other.c
@@ -10,3 +10,4 @@ int foo(void)
 \tint a = 1;
 \tint b = 2;
+\tint c = 3;
 \treturn a + b;
"""


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    return str(path)


def _compare(tmp_path, old_text, new_text, old_name="reference.patch",
             new_name="generated.patch"):
    """Run compare_patches_detailed and return (changes, report, diff_patch)."""
    old = _write(tmp_path, old_name, old_text)
    new = _write(tmp_path, new_name, new_text)
    diff_file = tmp_path / "CVE-2024-32487_differences.txt"
    changes = test_utils.compare_patches_detailed([old], [new], str(diff_file))
    diff_patch = tmp_path / "CVE-2024-32487_differences_diff.patch"
    return (changes, diff_file.read_text(),
            diff_patch.read_text() if diff_patch.exists() else "")


class TestMarkerContract:
    def test_marker_matches_bench_lib(self):
        assert test_utils.ONE_SIDED_MARKER == ONE_SIDED_MARKER


class TestStripDiffPrefix:
    def test_strips_b_prefix(self):
        assert test_utils._strip_diff_prefix("b/filename.c") == "filename.c"

    def test_strips_a_prefix(self):
        assert test_utils._strip_diff_prefix("a/filename.c") == "filename.c"

    def test_keeps_path_starting_with_b(self):
        # str.lstrip('b/') would turn this into 'in/x.c'.
        assert test_utils._strip_diff_prefix("b/bin/x.c") == "bin/x.c"

    def test_leaves_unprefixed_path(self):
        assert test_utils._strip_diff_prefix("filename.c") == "filename.c"


class TestExtractDiffBody:
    def test_drops_mail_metadata_and_signature(self, tmp_path):
        body = test_utils._extract_diff_body(
            _write(tmp_path, "p.patch", WELLFORMED_GENERATED))
        assert body.startswith("diff --git a/filename.c b/filename.c")
        assert "Signed-off-by" not in body
        assert "2.45.2" not in body
        assert body.rstrip().endswith("  */")

    def test_keeps_damaged_context_lines(self, tmp_path):
        body = test_utils._extract_diff_body(
            _write(tmp_path, "p.patch", DAMAGED_REFERENCE))
        assert "\treturn (strchr(metachars(), c) != NULL);" in body
        assert "2.40.0" not in body

    def test_missing_file_returns_empty(self, tmp_path):
        assert test_utils._extract_diff_body(str(tmp_path / "nope.patch")) == ""


class TestFilesTouched:
    def test_extracts_path_without_mangling(self, tmp_path):
        patch = SECOND_FILE_PATCH.replace("a/other.c", "a/bin/other.c").replace(
            "b/other.c", "b/bin/other.c")
        files = test_utils._extract_files_touched(
            _write(tmp_path, "p.patch", patch))
        assert files == {"bin/other.c"}


@requires_interdiff
class TestInterdiffComparison:
    def test_equivalent_patches_report_no_differences(self, tmp_path):
        """The regression: same fix, damaged reference, shifted hunk offsets.

        The line-set comparison reported one bogus differing line (the '--'
        signature); interdiff reports none.
        """
        changes, report, diff_patch = _compare(
            tmp_path, DAMAGED_REFERENCE, WELLFORMED_GENERATED)
        assert changes == 0
        assert "Comparison: interdiff (patchutils)" in report
        assert "Patches are equivalent." in report
        assert diff_patch.strip() == ""
        assert classify_diff_bucket(report) == "identical"

    def test_real_code_difference_is_reported(self, tmp_path):
        generated = WELLFORMED_GENERATED.replace(
            "return (c == '\\n');", "return (c == '\\n' || c == '\\r');")
        changes, report, diff_patch = _compare(
            tmp_path, DAMAGED_REFERENCE, generated)
        assert changes == 2  # one line removed, one added
        assert "Patches are equivalent." not in report
        assert "Adaptation delta" in report
        assert "+\treturn (c == '\\n' || c == '\\r');" in diff_patch
        assert classify_diff_bucket(report) == "minor"

    def test_one_sided_file_is_separated_from_the_common_delta(self, tmp_path):
        generated = WELLFORMED_GENERATED.replace(
            "-- \n2.45.2\n", SECOND_FILE_PATCH)
        changes, report, diff_patch = _compare(
            tmp_path, DAMAGED_REFERENCE, generated)
        assert "  Extra in generated:   other.c" in report
        assert classify_diff_bucket(report) == "partial"
        assert ONE_SIDED_MARKER in diff_patch
        # other.c only exists on the generated side, so it must not count as
        # part of the judgeable (common-file) delta -- which here is empty,
        # because filename.c is treated identically by both patches.
        assert "other.c" in diff_patch.split(ONE_SIDED_MARKER)[1]
        assert scope_diff_to_common_files(diff_patch) == ""
        assert changes > 0

    def test_common_delta_survives_scoping_when_a_file_is_one_sided(self, tmp_path):
        generated = WELLFORMED_GENERATED.replace(
            "-- \n2.45.2\n", SECOND_FILE_PATCH).replace(
            "return (c == '\\n');", "return (c == '\\n' || c == '\\r');")
        _, report, diff_patch = _compare(tmp_path, DAMAGED_REFERENCE, generated)
        scoped = scope_diff_to_common_files(diff_patch)
        assert "filename.c" in scoped
        assert "other.c" not in scoped
        assert classify_diff_bucket(report) == "partial"


class TestLineSetFallback:
    """Without patchutils the harness must still produce its legacy report."""

    @pytest.fixture(autouse=True)
    def _no_interdiff(self, monkeypatch):
        monkeypatch.setattr(test_utils, "generate_interdiff", lambda *a, **kw: None)

    def test_uses_legacy_report_format(self, tmp_path):
        changes, report, _ = _compare(
            tmp_path, DAMAGED_REFERENCE, WELLFORMED_GENERATED)
        assert "Comparison: line-set fallback (interdiff unavailable)" in report
        assert "Files touched - original: 1, generated: 1" in report
        assert changes == 0
        assert "Patches are equivalent." in report

    def test_signature_without_trailing_space_no_longer_counts(self, tmp_path):
        """A '--' signature used to be read as a removed diff line.

        oe-core's less CVE-2024-32487.patch ends '--' rather than '-- ', which
        made the reference and the generated patch differ by exactly one
        phantom line.
        """
        reference = DAMAGED_REFERENCE.replace("\n--\n2.40.0\n", "\n-- \n2.40.0\n")
        changes, _, _ = _compare(tmp_path, DAMAGED_REFERENCE, WELLFORMED_GENERATED)
        changes_both_spaced, _, _ = _compare(
            tmp_path, reference, WELLFORMED_GENERATED)
        assert changes == changes_both_spaced == 0

    def test_real_difference_is_still_detected(self, tmp_path):
        generated = WELLFORMED_GENERATED.replace(
            "return (c == '\\n');", "return (c == '\\n' || c == '\\r');")
        changes, report, _ = _compare(tmp_path, DAMAGED_REFERENCE, generated)
        assert changes == 2
        assert "--- Only in original ---" in report
        assert "+++ Only in generated +++" in report
