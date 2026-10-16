# Copyright (C) 2026 Triet Hoang <triet.hoang.dev@gmail.com>
# SPDX-License-Identifier: MIT
"""Patch metadata and format-patch helpers shared for CVE tools."""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile

from shared import TEXT_ENCODING
from shared.git_runner import run_capture


def annotate_patch_text(patch_text: str, cve_id: str, original_url: str,
                        include_cve_tag: bool = True,
                        sign_off_identity: tuple[str, str] | None = None) -> str:
    """Add CVE and Upstream-Status metadata before a format-patch separator."""
    lines = patch_text.splitlines(keepends=True)
    insert_index = next(
        (index for index, line in enumerate(lines)
         if line.rstrip("\n\r") == "---"),
        None,
    )
    header = "".join(lines if insert_index is None else lines[:insert_index])
    has_upstream = "Upstream-Status:" in header
    has_cve = f"CVE: {cve_id}" in header
    metadata_present = has_upstream and (has_cve or not include_cve_tag)

    own_signoff_line = None
    has_own_signoff = False
    if sign_off_identity is not None:
        author, email = sign_off_identity
        own_signoff_line = f"Signed-off-by: {author} <{email}>"
        has_own_signoff = own_signoff_line in header

    if metadata_present and (sign_off_identity is None or has_own_signoff):
        return patch_text

    if insert_index is None:
        raise ValueError("No line containing '---' found in patch")

    if metadata_present:
        block = f"\n{own_signoff_line}\n"
    else:
        cve_line = f"CVE: {cve_id}\n" if include_cve_tag else ""
        block = "\n" + cve_line + f"Upstream-Status: Backport [{original_url}]\n"
        if sign_off_identity is not None:
            block += f"\n{own_signoff_line}\n"

    return "".join(lines[:insert_index]) + block + "".join(lines[insert_index:])


def modify_patch(patch_file: Path, cve_id: str, original_url: str,
                 include_cve_tag: bool = True,
                 sign_off_identity: tuple[str, str] | None = None) -> None:
    """Annotate a patch file, replacing it only after the update is complete."""
    text = patch_file.read_text(encoding=TEXT_ENCODING)
    updated = annotate_patch_text(
        text, cve_id, original_url, include_cve_tag, sign_off_identity)
    if updated == text:
        return

    with NamedTemporaryFile("w", delete=False, encoding=TEXT_ENCODING) as tmp:
        tmp.write(updated)
        tmp_path = tmp.name

    try:
        shutil.move(tmp_path, str(patch_file))
    except Exception:
        os.unlink(tmp_path)
        raise


def extract_patch_subject(patch_text: str) -> str:
    """Extract the unwrapped subject from a format-patch message."""
    parts: list[str] = []
    capturing = False
    for line in patch_text.splitlines():
        if not capturing:
            if line.startswith("Subject:"):
                parts.append(line[len("Subject:"):].strip())
                capturing = True
            continue
        if line[:1] in (" ", "\t") and line.strip():
            parts.append(line.strip())
        else:
            break
    subject = " ".join(parts)
    subject = re.sub(r"^\[PATCH[^\]]*\]\s*", "", subject)
    return subject.strip()


def normalize_subject(subject: str) -> str:
    """Collapse whitespace and lowercase a subject for robust comparison."""
    return " ".join(subject.split()).lower()


def git_commit_subject(workspace_path: Path, commit_hash: str) -> str | None:
    """Return a commit subject, or None if its workspace or commit is unavailable."""
    if not commit_hash or not workspace_path.exists():
        return None
    result = run_capture(
        ["git", "log", "-1", "--format=%s", commit_hash], cwd=workspace_path)
    if result.returncode != 0:
        return None
    subject = result.stdout.strip()
    return subject or None


def cherry_picked_sha(patch_text: str) -> str | None:
    """Extract the upstream SHA from a ``(cherry picked from commit ...)`` line."""
    match = re.search(r"cherry picked from commit ([0-9a-f]{7,40})", patch_text)
    return match.group(1) if match else None
