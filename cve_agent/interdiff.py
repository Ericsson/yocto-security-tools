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

Inputs are normalized before being handed to the binary: whitespace-damaged
context lines are repaired (see :func:`repair_whitespace_damage`) and a
trailing newline is guaranteed, because ``interdiff`` rejects or mangles
both cases.
"""
import re
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from shared import TEXT_ENCODING, TEXT_ERRORS

# Unified-diff hunk header: '@@ -<old_start>[,<old_len>] +<new_start>[,<new_len>] @@'.
# A missing length field means 1 (unified-diff convention).
_HUNK_HEADER_RE = re.compile(r'^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@')


@dataclass(frozen=True)
class InterdiffArtifacts:
    """Persisted inputs/outputs of an ``interdiff`` run.

    Returned by :func:`generate_interdiff` when ``keep_files_dir`` is
    given, so callers that log the interdiff output (e.g. the review
    diff file) can also record the exact patch files and command used,
    letting a reviewer reproduce the delta outside the tool.

    Attributes:
        output: The interdiff output (adaptation delta).
        command: The exact argv used to invoke ``interdiff``, already
            shell-quoted and joined into a single copy-pasteable string.
        old_patch_path: Path to the persisted upstream ("old") patch file.
        new_patch_path: Path to the persisted backport ("new") patch file.
    """
    output: str
    command: str
    old_patch_path: Path
    new_patch_path: Path


def generate_interdiff(
    upstream_patch: str, backport_patch: str,
    keep_files_dir: Optional[Path] = None,
    allow_empty: bool = False,
) -> Optional[str]:
    """Compute the diff-of-diffs between an upstream patch and its backport.

    Pure helper: takes the two already-computed patch texts and shells out
    to the ``interdiff`` binary. Returns ``None`` whenever a concise delta
    cannot be produced (binary missing, empty input, non-zero exit, or any
    subprocess/OS failure) so callers can silently fall back to their
    current behavior.

    Args:
        upstream_patch: Full diff text of the original upstream commit.
        backport_patch: Full diff text of the backported change.
        keep_files_dir: If given, persist the two patch files fed to
            ``interdiff`` in this directory instead of a temp dir, and
            use ``generate_interdiff_artifacts`` under the hood so the
            reproduction command is available. Prefer calling
            :func:`generate_interdiff_artifacts` directly when the
            command/paths are also needed by the caller.
        allow_empty: Treat an empty ``interdiff`` output as a successful
            result (the two patches are equivalent) instead of ``None``.
            Callers that only display a delta want the default; callers
            that compare two patches need to tell "equivalent" apart from
            "could not compare".

    Returns:
        The interdiff output (adaptation delta) on success, or ``None``.
    """
    artifacts = generate_interdiff_artifacts(
        upstream_patch, backport_patch, keep_files_dir=keep_files_dir,
        allow_empty=allow_empty,
    )
    return artifacts.output if artifacts else None


def generate_interdiff_artifacts(
    upstream_patch: str, backport_patch: str,
    keep_files_dir: Optional[Path] = None,
    allow_empty: bool = False,
) -> Optional[InterdiffArtifacts]:
    """Compute the diff-of-diffs and optionally persist inputs/command.

    Same computation as :func:`generate_interdiff`, but returns the
    output alongside the exact ``interdiff`` command and the paths of
    the two patch files it was run against. When ``keep_files_dir`` is
    ``None`` (default), the patch files are written to a temp dir and
    removed before returning — matching the original pure-helper
    behavior — but the paths in the returned artifacts will no longer
    exist on disk. Pass ``keep_files_dir`` to persist them for later
    inspection or standalone reproduction.

    Args:
        upstream_patch: Full diff text of the original upstream commit.
        backport_patch: Full diff text of the backported change.
        keep_files_dir: Directory to persist the ``old.patch`` /
            ``new.patch`` files into. Created if missing. When omitted,
            the files are written to a temp dir and deleted afterwards.
        allow_empty: Treat an empty ``interdiff`` output (exit 0, no
            delta — i.e. the two patches are equivalent) as success,
            returning artifacts whose ``output`` is empty.

    Returns:
        :class:`InterdiffArtifacts` on success, or ``None`` whenever a
        concise delta cannot be produced (binary missing, empty input,
        non-zero exit, or any subprocess/OS failure).
    """
    if not shutil.which('interdiff'):
        return None
    if not upstream_patch.strip() or not backport_patch.strip():
        return None

    persist = keep_files_dir is not None
    old_path: Optional[Path] = None
    new_path: Optional[Path] = None
    try:
        if persist:
            assert keep_files_dir is not None
            keep_files_dir.mkdir(parents=True, exist_ok=True)
            old_path = keep_files_dir / 'upstream.patch'
            new_path = keep_files_dir / 'backport.patch'
            old_path.write_text(_normalize_for_interdiff(upstream_patch), encoding='utf-8')
            new_path.write_text(_normalize_for_interdiff(backport_patch), encoding='utf-8')
        else:
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.patch', delete=False, encoding='utf-8'
            ) as old_file:
                old_file.write(_normalize_for_interdiff(upstream_patch))
                old_path = Path(old_file.name)
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.patch', delete=False, encoding='utf-8'
            ) as new_file:
                new_file.write(_normalize_for_interdiff(backport_patch))
                new_path = Path(new_file.name)

        argv = ['interdiff', str(old_path), str(new_path)]
        result = subprocess.run(
            argv, capture_output=True,
            encoding=TEXT_ENCODING, errors=TEXT_ERRORS, check=False
        )
        if result.returncode != 0:
            return None
        if not result.stdout.strip() and not allow_empty:
            return None
        return InterdiffArtifacts(
            output=result.stdout,
            command=shlex.join(argv),
            old_patch_path=old_path,
            new_patch_path=new_path,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        if not persist:
            for path in (old_path, new_path):
                if path:
                    path.unlink(missing_ok=True)


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


def repair_whitespace_damage(patch_text: str) -> str:
    """Restore the leading space on whitespace-damaged context lines.

    ``interdiff`` rejects a patch outright ("Whitespace damage detected in
    input", exit 1) when a hunk's context line has lost its leading space —
    a common form of damage in patches that travelled through mail clients
    or editors that strip leading/trailing whitespace. Patches carried in
    OE layers are sometimes damaged this way, so repair before feeding
    ``interdiff`` instead of losing the comparison entirely.

    Hunk boundaries are tracked from each ``@@`` header's declared old/new
    line counts, so only lines genuinely inside a hunk body are touched:
    patch metadata, the ``--``/version signature of a ``git format-patch``
    mail, and anything between hunks passes through verbatim. A well-formed
    patch is returned unchanged, and the function is idempotent.

    Args:
        patch_text: Patch text, possibly whitespace-damaged.

    Returns:
        The patch text with a leading space restored on every damaged
        context line.
    """
    out: list[str] = []
    old_left = new_left = 0
    in_hunk = False

    lines = patch_text.split('\n')
    last = len(lines) - 1
    for idx, raw_line in enumerate(lines):
        line = raw_line
        # The empty string after a trailing newline is not part of any hunk;
        # never re-prefix it (a patch with inconsistent @@ counts would
        # otherwise gain a stray ' ' at EOF).
        if idx == last and line == '':
            out.append(line)
            continue
        if in_hunk:
            if line.startswith('\\'):
                # '\ No newline at end of file' belongs to the preceding
                # line and counts toward neither side's line budget.
                out.append(line)
                continue
            if line.startswith('+'):
                new_left -= 1
            elif line.startswith('-'):
                old_left -= 1
            elif line.startswith(' '):
                old_left -= 1
                new_left -= 1
            else:
                # Damaged context line: the leading space was stripped. An
                # emptied blank line is the common case, but any content
                # can lose it.
                line = ' ' + line
                old_left -= 1
                new_left -= 1
            out.append(line)
            if old_left <= 0 and new_left <= 0:
                in_hunk = False
            continue

        match = _HUNK_HEADER_RE.match(line)
        if match:
            old_left = int(match.group(1)) if match.group(1) is not None else 1
            new_left = int(match.group(2)) if match.group(2) is not None else 1
            # A hunk with no body on either side (both counts zero) has
            # nothing to repair; don't enter the body-consuming state.
            in_hunk = old_left > 0 or new_left > 0
        out.append(line)

    return '\n'.join(out)


def _normalize_for_interdiff(patch_text: str) -> str:
    """Make ``patch_text`` safe to feed to the ``interdiff`` binary.

    Applies both preprocessing steps ``interdiff`` needs: repairing
    whitespace-damaged context lines (which it rejects outright) and
    guaranteeing a trailing newline (whose absence corrupts its output).

    Args:
        patch_text: Raw patch text.

    Returns:
        Normalized patch text.
    """
    return _ensure_trailing_newline(repair_whitespace_damage(patch_text))
