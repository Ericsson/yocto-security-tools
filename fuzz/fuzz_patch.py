# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Fuzz the format-patch text helpers that parse upstream patch content."""
import sys

import atheris

with atheris.instrument_imports():
    from shared.patch import annotate_patch_text, cherry_picked_sha, extract_patch_subject


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    cve_id = fdp.ConsumeUnicodeNoSurrogates(32)
    url = fdp.ConsumeUnicodeNoSurrogates(256)
    include_cve_tag = fdp.ConsumeBool()
    patch_text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())

    extract_patch_subject(patch_text)
    cherry_picked_sha(patch_text)

    try:
        annotated = annotate_patch_text(patch_text, cve_id, url, include_cve_tag)
    except ValueError:
        # Documented: raised when the patch has no '---' separator.
        return
    # Annotation only inserts metadata; it must never drop patch content.
    if len(annotated) < len(patch_text):
        raise AssertionError("annotate_patch_text shrank the patch")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
