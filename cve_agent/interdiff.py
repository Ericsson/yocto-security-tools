# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Optional interdiff (patchutils) integration.

Computes a diff-of-diffs between the upstream patch and the backported
patch so reviewers and the AI backend see only the adaptation delta,
instead of two unrelated full patches. Purely additive: when the
``interdiff`` binary (from the ``patchutils`` system package) is not
installed, callers must fall back to their existing behavior unchanged.

Note: ``interdiff`` aligns hunks by matching surrounding context lines.
When the recipe's base file has diverged significantly from the upstream
commit's base (e.g. missing refactors, different function signatures),
context lines won't line up well and the output can be nearly as large
as the full backport diff — this is expected behavior for distant
patches, not a bug. Treat a large interdiff as a signal that the two
patches don't align well and warrant closer manual review.
"""
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional


def generate_interdiff(upstream_patch: str, backport_patch: str) -> Optional[str]:
    """Compute the diff-of-diffs between an upstream patch and its backport.

    Pure helper: takes the two already-computed patch texts and shells out
    to the ``interdiff`` binary. Returns ``None`` whenever a concise delta
    cannot be produced (binary missing, empty input, non-zero exit, or any
    subprocess/OS failure) so callers can silently fall back to their
    current behavior.

    Args:
        upstream_patch: Full diff text of the original upstream commit.
        backport_patch: Full diff text of the backported change.

    Returns:
        The interdiff output (adaptation delta) on success, or ``None``.
    """
    if not shutil.which('interdiff'):
        return None
    if not upstream_patch.strip() or not backport_patch.strip():
        return None

    old_path: Optional[str] = None
    new_path: Optional[str] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.patch', delete=False, encoding='utf-8'
        ) as old_file:
            old_file.write(_ensure_trailing_newline(upstream_patch))
            old_path = old_file.name
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.patch', delete=False, encoding='utf-8'
        ) as new_file:
            new_file.write(_ensure_trailing_newline(backport_patch))
            new_path = new_file.name

        result = subprocess.run(
            ['interdiff', old_path, new_path],
            capture_output=True, text=True, check=False
        )
        if result.returncode != 0 or not result.stdout.strip():
            return None
        return result.stdout
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        for path in (old_path, new_path):
            if path:
                Path(path).unlink(missing_ok=True)


def _ensure_trailing_newline(patch_text: str) -> str:
    """Ensure a unified diff ends with exactly one trailing newline.

    Callers typically source patch text from helpers (e.g.
    ``run_git_stdout``) that strip trailing whitespace for display
    purposes. A unified diff whose final hunk line lacks a trailing
    newline is invalid input for ``interdiff``'s parser and produces
    corrupted output (stray control characters, spurious
    ``\\ No newline at end of file`` markers). Normalize before writing
    to the temp files passed to the ``interdiff`` binary.

    Args:
        patch_text: Patch text, possibly missing a trailing newline.

    Returns:
        Patch text guaranteed to end with exactly one ``\\n``.
    """
    return patch_text if patch_text.endswith('\n') else patch_text + '\n'
