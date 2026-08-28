#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Test utilities for cve_corrector integration test harness."""
import difflib
import glob
import os
import re
import shutil
import sys

# Run as a script from tests/integration/ by test_common.sh, so the repo root
# is not on sys.path — add it to reuse cve_agent's interdiff wrapper instead of
# reimplementing patch comparison here.
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))))

from cve_agent.interdiff import generate_interdiff  # noqa: E402

# Unified-diff hunk header: '@@ -<old_start>[,<old_len>] +<new_start>[,<new_len>] @@'.
# A missing length field means 1 (unified-diff convention).
_HUNK_HEADER_RE = re.compile(r'^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@')


def _fix_src_uri(content):
    """Fix SRC_URI formatting after patch line removal."""
    content = re.sub(r'\s*\\\s*"(\s*)$', r'"\1', content, flags=re.MULTILINE)
    content = re.sub(r'\\\s*\\\s*$', r'\\', content, flags=re.MULTILINE)
    content = re.sub(r'SRC_URI\s*[+:]?=\s*"\s*"\s*\n', '', content)
    content = re.sub(r'SRC_URI\s*[+:]?=\s*"\s*\\\n\s*"\s*\n', '', content)
    return content


def remove_cve_from_file(path, cve_id):
    """Remove CVE reference from a recipe file."""
    cve_lower = cve_id.lower().replace('cve-', '')
    cve_pattern = re.compile(
        rf'\s*file://[^\s"]*[Cc][Vv][Ee]-?{re.escape(cve_lower)}[^\s"]*',
        re.IGNORECASE)

    with open(path) as f:
        original = f.read()
    if cve_id.lower().replace('cve-', '') not in original.lower():
        return False

    lines = original.split('\n')
    out = []
    in_src_uri_block = False
    src_uri_has_content = False

    for line in lines:
        if re.match(r'^\s*SRC_URI\s*\+?=\s*"', line):
            in_src_uri_block = True
            src_uri_has_content = False

        if (re.search(rf'[Cc][Vv][Ee]-?{re.escape(cve_lower)}', line, re.IGNORECASE)
                and 'file://' in line):
            cleaned = cve_pattern.sub('', line)
            rest = cleaned.strip().rstrip('\\').strip().strip('"').strip()
            rest = re.sub(r'^SRC_URI\s*\+?=\s*', '', rest).strip('"').strip()
            if rest:
                out.append(cleaned)
                src_uri_has_content = True
            else:
                if line.rstrip().endswith('"'):
                    if out and out[-1].rstrip().endswith('\\'):
                        out[-1] = out[-1].rstrip().rstrip('\\').rstrip() + '"'
                    in_src_uri_block = False
        elif in_src_uri_block and re.match(r'^\s*"\s*$', line):
            if src_uri_has_content:
                out.append(line)
            in_src_uri_block = False
        else:
            if not in_src_uri_block or line.strip():
                if in_src_uri_block:
                    rest = line.strip().rstrip('\\').strip().strip('"').strip()
                    if rest:
                        src_uri_has_content = True
                out.append(line)
            if (in_src_uri_block and line.rstrip().endswith('"')
                    and not line.rstrip().endswith('\\"')):
                in_src_uri_block = False

    result = _fix_src_uri('\n'.join(out))

    if result != original:
        with open(path, 'w') as f:
            f.write(result)
        return True
    return False


def remove_single_patch(path, patch_filename):
    """Remove only the specified patch from SRC_URI, keeping all others."""
    try:
        with open(path) as f:
            content = f.read()
        if patch_filename not in content:
            return False

        lines = content.split('\n')
        new_lines = []
        removed = False
        removed_closing_quote = False
        removed_opener = False
        in_src_uri = False
        last_kept_src_uri_idx = -1

        for line in lines:
            if re.match(r'^\s*SRC_URI\s*[+:]?=', line):
                in_src_uri = True

            if in_src_uri and 'file://' in line and patch_filename in line:
                removed = True
                if re.match(r'^\s*SRC_URI\s*[+:]?=', line):
                    removed_opener = True
                if (line.rstrip().endswith('"')
                        and not line.rstrip().endswith('\\"')):
                    removed_closing_quote = True
                    in_src_uri = False
                continue

            if removed_opener and in_src_uri and re.match(r'^\s*"\s*$', line):
                removed_opener = False
                in_src_uri = False
                continue

            new_lines.append(line)

            if in_src_uri:
                last_kept_src_uri_idx = len(new_lines) - 1
                if (line.rstrip().endswith('"')
                        and not line.rstrip().endswith('\\"')):
                    in_src_uri = False

        if not removed:
            return False

        if removed_closing_quote and last_kept_src_uri_idx >= 0:
            stripped = new_lines[last_kept_src_uri_idx].rstrip()
            if stripped.endswith('\\'):
                new_lines[last_kept_src_uri_idx] = (
                    stripped.rstrip('\\').rstrip() + '"')
            elif not stripped.endswith('"'):
                new_lines[last_kept_src_uri_idx] = stripped + '"'

        new_content = _fix_src_uri('\n'.join(new_lines))

        with open(path, 'w') as f:
            f.write(new_content)
        return True
    except Exception:
        return False


def remove_patches_from_position(path, patch_filename):
    """Remove a patch and all subsequent patches from SRC_URI."""
    try:
        with open(path) as f:
            content = f.read()
        if patch_filename not in content:
            return []

        lines = content.split('\n')
        removed = []
        in_src_uri = False
        found_target = False
        new_lines = []
        removed_closing_quote = False
        removed_opener = False
        last_kept_src_uri_idx = -1

        for line in lines:
            if re.match(r'^\s*SRC_URI\s*[+:]?=', line):
                in_src_uri = True

            if in_src_uri and 'file://' in line and patch_filename in line:
                found_target = True

            if (found_target and in_src_uri and 'file://' in line
                    and '.patch' in line):
                m = re.search(r'file://([^\s"\\]+)', line)
                if m:
                    removed.append(m.group(1))
                if re.match(r'^\s*SRC_URI\s*[+:]?=', line):
                    removed_opener = True
                if (line.rstrip().endswith('"')
                        and not line.rstrip().endswith('\\"')):
                    removed_closing_quote = True
                    in_src_uri = False
                    found_target = False
                continue

            if (removed_opener and found_target and in_src_uri
                    and re.match(r'^\s*"\s*$', line)):
                removed_opener = False
                in_src_uri = False
                found_target = False
                continue

            new_lines.append(line)

            if in_src_uri:
                last_kept_src_uri_idx = len(new_lines) - 1
                if (line.rstrip().endswith('"')
                        and not line.rstrip().endswith('\\"')):
                    in_src_uri = False
                    found_target = False

        if not removed:
            return []

        if removed_closing_quote and last_kept_src_uri_idx >= 0:
            stripped = new_lines[last_kept_src_uri_idx].rstrip()
            if stripped.endswith('\\'):
                new_lines[last_kept_src_uri_idx] = (
                    stripped.rstrip('\\').rstrip() + '"')
            elif not stripped.endswith('"'):
                new_lines[last_kept_src_uri_idx] = stripped + '"'

        new_content = _fix_src_uri('\n'.join(new_lines))

        with open(path, 'w') as f:
            f.write(new_content)
        return removed
    except Exception:
        return []


def _validate_src_uri(path):
    """Validate SRC_URI blocks are well-formed."""
    with open(path) as f:
        lines = f.read().split('\n')
    in_src_uri = False
    block_start = 0
    for i, line in enumerate(lines, 1):
        if re.match(r'^\s*SRC_URI\s*[+:]?=\s*"', line):
            in_src_uri = True
            block_start = i
            if line.rstrip().endswith('"') and line.count('"') >= 2:
                in_src_uri = False
                continue
        if in_src_uri:
            stripped = line.strip()
            if stripped == '':
                print(f"SRC_URI_ERROR:{path}:{i}: empty line inside SRC_URI "
                      f"(started line {block_start})")
            if stripped.endswith('"') and not stripped.endswith('\\"'):
                in_src_uri = False
                continue
            if stripped and not stripped.endswith('\\'):
                print(f"SRC_URI_ERROR:{path}:{i}: missing trailing backslash: "
                      f"{stripped[:80]}")
    if in_src_uri:
        print(f"SRC_URI_ERROR:{path}: unclosed SRC_URI "
              f"(started line {block_start})")


def remove_cve_patch(oe_dir, cve_id, log_dir, prefix=None):
    """Remove a CVE patch and its recipe references."""
    os.chdir(oe_dir)
    cve_lower = cve_id.lower().replace('cve-', '')
    modified_recipes = set()
    file_prefix = f"{prefix}_" if prefix else ""

    patch_files = []
    for f in glob.glob('meta/**/*.patch', recursive=True):
        if re.search(rf'[Cc][Vv][Ee]-?{re.escape(cve_lower)}', f, re.IGNORECASE):
            patch_files.append(f)

    if not patch_files:
        for f in glob.glob('meta/**/*.patch', recursive=True):
            try:
                with open(f) as pf:
                    content = pf.read(4096)
                    if re.search(rf'^CVE:.*{re.escape(cve_id)}', content,
                                 re.MULTILINE | re.IGNORECASE):
                        patch_files.append(f)
            except Exception:
                pass

    if patch_files:
        all_removed_files = set()
        for patch_file in patch_files:
            patch_path = os.path.abspath(patch_file)
            if not os.path.exists(patch_path):
                continue
            patch_filename = os.path.basename(patch_file)
            shutil.copy(patch_path, os.path.join(
                log_dir, f"{file_prefix}{cve_id}_{patch_filename}"))
            print(f"PATCH:{patch_path}")
            os.remove(patch_path)

            for pattern in ['meta/**/*.bb', 'meta/**/*.inc',
                            'meta/**/*.bbappend']:
                for path in glob.glob(pattern, recursive=True):
                    removed_patches = remove_patches_from_position(
                        path, patch_filename)
                    if removed_patches:
                        print(f"RECIPE:{os.path.abspath(path)}")
                        modified_recipes.add(os.path.abspath(path))
                        for extra in removed_patches[1:]:
                            extra_path = os.path.join(
                                os.path.dirname(patch_path), extra)
                            if os.path.exists(extra_path):
                                os.remove(extra_path)
                                print(f"REMOVED_SUBSEQUENT:{extra_path}")
                            all_removed_files.add(extra)

        if all_removed_files:
            for pattern in ['meta/**/*.bb', 'meta/**/*.inc',
                            'meta/**/*.bbappend']:
                for path in glob.glob(pattern, recursive=True):
                    try:
                        with open(path) as f:
                            content = f.read()
                    except Exception:
                        continue
                    changed = False
                    for fname in all_removed_files:
                        if fname not in content:
                            continue
                        removed = remove_patches_from_position(path, fname)
                        if removed:
                            changed = True
                            with open(path) as f:
                                content = f.read()
                    if changed:
                        abs_path = os.path.abspath(path)
                        if abs_path not in modified_recipes:
                            print(f"RECIPE:{abs_path}")
                            modified_recipes.add(abs_path)

    modified_any = False
    for pattern in ['meta/**/*.bb', 'meta/**/*.inc', 'meta/**/*.bbappend']:
        for path in glob.glob(pattern, recursive=True):
            if remove_cve_from_file(path, cve_id):
                print(f"RECIPE:{os.path.abspath(path)}")
                modified_recipes.add(os.path.abspath(path))
                modified_any = True

    if not patch_files and not modified_any:
        print("NOTFOUND")

    for path in modified_recipes:
        _validate_src_uri(path)


def _extract_diff_lines(patch_file):
    """Extract meaningful +/- lines from a patch, ignoring metadata."""
    try:
        with open(patch_file) as f:
            content = f.read()
    except Exception:
        return []
    lines = []
    in_diff = False
    for line in content.split('\n'):
        if line.startswith(('diff --git', '---', '+++')):
            in_diff = True
            continue
        if line.startswith('@@'):
            in_diff = True
            continue
        if re.match(
            r'^(From |Subject:|Date:|Signed-off-by:|CVE:|Upstream-Status:'
            r'|index |new file|deleted file|-- ?$|\d+\.\d+\.\d+)', line):
            continue
        if in_diff and (line.startswith('+') or line.startswith('-')):
            lines.append(line.rstrip())
    return lines


def _extract_files_touched(patch_file):
    """Extract set of files modified by a patch."""
    files = set()
    try:
        with open(patch_file) as f:
            for line in f:
                if line.startswith('diff --git'):
                    parts = line.split()
                    if len(parts) >= 4:
                        files.add(_strip_diff_prefix(parts[3]))
    except Exception:
        pass
    return files


def _extract_diff_content_by_file(patch_file):
    """Extract per-file diff hunks from a patch. Returns {filepath: [lines]}."""
    result = {}
    current_file = None
    try:
        with open(patch_file) as f:
            content = f.read()
    except Exception:
        return result
    for line in content.split('\n'):
        if line.startswith('diff --git'):
            parts = line.split()
            current_file = _strip_diff_prefix(parts[3]) if len(parts) >= 4 else None
            if current_file:
                result.setdefault(current_file, [])
            continue
        if re.match(
            r'^(From |Subject:|Date:|Signed-off-by:|CVE:|Upstream-Status:'
            r'|index |new file|deleted file|-- ?$|\d+\.\d+\.\d+)', line):
            continue
        if current_file is not None:
            result.setdefault(current_file, []).append(line)
    return result


def compare_patches(old_patch, new_patch):
    """Compare two patches and count meaningful changes."""
    old_lines = set(_extract_diff_lines(old_patch))
    new_lines = set(_extract_diff_lines(new_patch))
    changes = len(new_lines - old_lines) + len(old_lines - new_lines)
    print(f"DIFF_CHANGES:{changes}")


# --- interdiff-based comparison ---------------------------------------------

# Separates the judgeable part of a differences_diff.patch (the delta on files
# touched by BOTH patch sets) from the one-sided blocks, which say nothing
# about how the shared code was adapted. tests/benchmark/bench_lib.py's
# scope_diff_to_common_files() truncates at this marker.
ONE_SIDED_MARKER = '=== files touched by only one side (not comparable) ==='

_DIFF_META_PREFIXES = (
    'diff --git ', 'diff -u ', '--- ', '+++ ', 'index ', 'new file mode',
    'deleted file mode', 'old mode ', 'new mode ', 'similarity index ',
    'rename from ', 'rename to ', 'copy from ', 'copy to ',
    'GIT binary patch', 'Binary files ',
)


def _strip_diff_prefix(path):
    """Strip a unified-diff ``a/``/``b/`` path prefix.

    ``str.lstrip('b/')`` cannot be used here: it strips a *character set*, so
    ``b/bin/x.c`` would become ``in/x.c``.
    """
    for prefix in ('a/', 'b/'):
        if path.startswith(prefix):
            return path[len(prefix):]
    return path


def _diff_header_path(header_line):
    """Extract the file path from a ``--- ``/``+++ `` unified-diff header."""
    path = header_line.split(' ', 1)[1] if ' ' in header_line else ''
    path = path.split('\t')[0].strip()
    return _strip_diff_prefix(path)


def _extract_diff_body(patch_file):
    """Extract just the unified-diff body of a patch file.

    Drops everything ``interdiff`` has no use for and that differs between an
    upstream patch and its backport for uninteresting reasons: the mail
    headers, commit message, diffstat, and the trailing ``--``/version
    signature of a ``git format-patch`` mail. Hunk bodies are delimited using
    the line counts declared in each ``@@`` header, so a removed source line
    that happens to look like patch metadata is preserved.

    Args:
        patch_file: Path to a patch file.

    Returns:
        The concatenated diff body, or ``''`` when the file has none.
    """
    try:
        with open(patch_file, errors='replace') as f:
            content = f.read()
    except Exception:
        return ''

    body = []
    in_diff = False
    in_hunk = False
    old_left = new_left = 0
    for line in content.split('\n'):
        if in_hunk:
            if line.startswith('diff --git '):
                in_hunk = False  # hunk counts lied; resync on the next file
            else:
                body.append(line)
                if line.startswith('\\'):
                    continue
                if line.startswith('+'):
                    new_left -= 1
                elif line.startswith('-'):
                    old_left -= 1
                else:  # context line, possibly whitespace-damaged
                    old_left -= 1
                    new_left -= 1
                if old_left <= 0 and new_left <= 0:
                    in_hunk = False
                continue
        if line.startswith(_DIFF_META_PREFIXES):
            in_diff = True
            body.append(line)
            continue
        if in_diff:
            match = _HUNK_HEADER_RE.match(line)
            if match:
                old_left = int(match.group(1)) if match.group(1) is not None else 1
                new_left = int(match.group(2)) if match.group(2) is not None else 1
                in_hunk = old_left > 0 or new_left > 0
                body.append(line)
                continue
            # Between file blocks: the signature, the next mail's headers, ...
            in_diff = False
    return '\n'.join(body)


def _split_interdiff_blocks(delta_text):
    """Split ``interdiff`` output into per-file blocks.

    Args:
        delta_text: Raw ``interdiff`` stdout.

    Returns:
        List of ``(filename, block_text)`` pairs in output order. The
        rationale lines ``interdiff`` prints ahead of a block (``reverted:``,
        ``only in patch2:``, ``unchanged:``, ``diff -u ...``) are kept with
        the block they introduce.
    """
    lines = delta_text.split('\n')
    blocks = []
    pending = []
    current = None
    i = 0
    while i < len(lines):
        line = lines[i]
        if (line.startswith('--- ') and i + 1 < len(lines)
                and lines[i + 1].startswith('+++ ')):
            if current:
                blocks.append(current)
            fname = (_diff_header_path(lines[i + 1]) or _diff_header_path(line))
            if fname == 'dev/null':
                fname = _diff_header_path(line)
            current = (fname, pending + [line, lines[i + 1]])
            pending = []
            i += 2
            continue
        if current is not None and (line.startswith(('@@', ' ', '+', '-', '\\'))
                                    or line == ''):
            current[1].append(line)
        else:
            pending.append(line)
        i += 1
    if current:
        blocks.append(current)
    return [(fname, '\n'.join(block).rstrip('\n') + '\n') for fname, block in blocks]


def _count_delta_lines(delta_text):
    """Count added/removed lines in a unified diff, ignoring file headers."""
    n = 0
    for line in delta_text.splitlines():
        if line.startswith(('+++ ', '--- ')):
            continue
        if line.startswith(('+', '-')):
            n += 1
    return n


def _interdiff_delta(old_patches, new_patches):
    """Compute the adaptation delta between two patch sets via ``interdiff``.

    Both sides are reduced to their diff bodies and concatenated, so a patch
    series is compared as a single combined change. Note that when two patches
    on the same side touch the same file, that file appears twice in the
    combined input — the same flattening the line-set comparison does.

    Args:
        old_patches: Reference (original) patch file paths.
        new_patches: Generated patch file paths.

    Returns:
        The ``interdiff`` output (``''`` when the two sides are equivalent),
        or ``None`` when no delta could be computed — the ``interdiff`` binary
        is missing (``patchutils`` not installed) or it failed to parse the
        input — so callers fall back to the line-set comparison.
    """
    old_body = '\n'.join(_extract_diff_body(p) for p in sorted(old_patches))
    new_body = '\n'.join(_extract_diff_body(p) for p in sorted(new_patches))
    if not old_body.strip() or not new_body.strip():
        return None
    return generate_interdiff(old_body, new_body, allow_empty=True)


def compare_patches_detailed(old_patches, new_patches, diff_file):
    """Compare original vs generated patches, write differences to diff_file.

    Uses ``interdiff`` (patchutils) to compute the real adaptation delta
    between the two patch sets: the diff of what each set does to the source
    tree. That ignores everything a line-set comparison trips over — commit
    metadata, hunk offsets, reordered hunks, and the ``git format-patch``
    signature — and reports only genuine code differences. When ``interdiff``
    is unavailable or cannot parse the input, falls back to the historical
    line-set comparison.

    Writes two files (``<...>_differences.txt`` and ``<...>_differences_diff.patch``)
    and prints the ``DIFF_CHANGES``/``DIFF_PATCHES``/``DIFF_FILES`` lines the
    shell harness greps for.

    Args:
        old_patches: Reference (original) patch file paths.
        new_patches: Generated patch file paths.
        diff_file: Path of the differences report to write.

    Returns:
        The number of differing lines.
    """
    old_files = set()
    for p in old_patches:
        old_files |= _extract_files_touched(p)
    new_files = set()
    for p in new_patches:
        new_files |= _extract_files_touched(p)
    missing_in_generated = sorted(old_files - new_files)
    extra_in_generated = sorted(new_files - old_files)

    delta = _interdiff_delta(old_patches, new_patches)
    if delta is None:
        changes = _write_lineset_report(
            old_patches, new_patches, diff_file,
            old_files, new_files, missing_in_generated, extra_in_generated)
    else:
        changes = _write_interdiff_report(
            old_patches, new_patches, diff_file, delta,
            old_files, new_files, missing_in_generated, extra_in_generated)

    print(f"DIFF_CHANGES:{changes}")
    print(f"DIFF_PATCHES:{len(old_patches)}>{len(new_patches)}")
    files_status = f"{len(old_files)}>{len(new_files)}"
    if missing_in_generated:
        files_status += f" -{len(missing_in_generated)}"
    if extra_in_generated:
        files_status += f" +{len(extra_in_generated)}"
    print(f"DIFF_FILES:{files_status}")
    return changes


def _write_report_header(f, old_patches, new_patches, method,
                         old_files, new_files,
                         missing_in_generated, extra_in_generated, changes):
    """Write the machine-parsed header of a differences report.

    The exact wording of these lines is a contract with
    ``tests/benchmark/bench_lib.py`` (``classify_diff_bucket``,
    ``_common_file_count``) and ``generate_differences_report.py``; do not
    reword them without updating both.
    """
    f.write(f"Original patches ({len(old_patches)}): "
            f"{', '.join(os.path.basename(p) for p in sorted(old_patches))}\n")
    f.write(f"Generated patches ({len(new_patches)}): "
            f"{', '.join(os.path.basename(p) for p in sorted(new_patches))}\n")
    if len(old_patches) != len(new_patches):
        f.write(f"WARNING: patch count differs "
                f"({len(old_patches)} original vs {len(new_patches)} generated)\n")
    f.write(f"Comparison: {method}\n")
    f.write(f"\nFiles touched - original: {len(old_files)}, "
            f"generated: {len(new_files)}\n")
    if missing_in_generated:
        f.write(f"  Missing in generated: "
                f"{', '.join(missing_in_generated)}\n")
    if extra_in_generated:
        f.write(f"  Extra in generated:   "
                f"{', '.join(extra_in_generated)}\n")
    f.write(f"\nDifferences: {changes} lines\n\n")


def _write_interdiff_report(old_patches, new_patches, diff_file, delta,
                            old_files, new_files,
                            missing_in_generated, extra_in_generated):
    """Write the differences report and diff patch from an interdiff delta."""
    common_files = old_files & new_files
    common_blocks = []
    one_sided_blocks = []
    for fname, block in _split_interdiff_blocks(delta):
        # A file absent from one side cannot show how the shared code was
        # adapted, so keep it out of the judgeable part of the delta. Files
        # neither side declared via 'diff --git' (e.g. a patch using bare
        # '---'/'+++' headers) are treated as common rather than dropped.
        if fname in common_files or not (old_files or new_files):
            common_blocks.append(block)
        else:
            one_sided_blocks.append(block)

    changes = _count_delta_lines(delta)
    with open(diff_file, 'w') as f:
        _write_report_header(f, old_patches, new_patches,
                             'interdiff (patchutils)',
                             old_files, new_files,
                             missing_in_generated, extra_in_generated, changes)
        if not delta.strip() and not missing_in_generated and not extra_in_generated:
            f.write("Patches are equivalent.\n")
        else:
            f.write("--- Adaptation delta (interdiff: original -> generated) ---\n")
            f.write(delta if delta.endswith('\n') else delta + '\n')

    diff_patch_file = diff_file.rsplit('.', 1)[0] + '_diff.patch'
    with open(diff_patch_file, 'w') as f:
        for block in common_blocks:
            f.write(block)
            f.write('\n')
        if one_sided_blocks:
            f.write(f"{ONE_SIDED_MARKER}\n")
            for block in one_sided_blocks:
                f.write(block)
                f.write('\n')
    return changes


def _write_lineset_report(old_patches, new_patches, diff_file,
                          old_files, new_files,
                          missing_in_generated, extra_in_generated):
    """Compare patch sets as sets of +/- lines (no ``interdiff`` available).

    Kept as a fallback for hosts without ``patchutils``. It is deliberately
    crude: identical changes reported at different hunk offsets compare equal,
    but any whitespace or context difference shows up as a divergence.
    """
    old_lines = []
    for p in sorted(old_patches):
        old_lines.extend(_extract_diff_lines(p))
    new_lines = []
    for p in sorted(new_patches):
        new_lines.extend(_extract_diff_lines(p))

    old_set = set(old_lines)
    new_set = set(new_lines)
    only_in_original = sorted(old_set - new_set)
    only_in_generated = sorted(new_set - old_set)
    changes = len(only_in_original) + len(only_in_generated)

    with open(diff_file, 'w') as f:
        _write_report_header(f, old_patches, new_patches,
                             'line-set fallback (interdiff unavailable)',
                             old_files, new_files,
                             missing_in_generated, extra_in_generated, changes)
        if only_in_original:
            f.write("--- Only in original ---\n")
            for line in only_in_original:
                f.write(line + '\n')
            f.write('\n')
        if only_in_generated:
            f.write("+++ Only in generated +++\n")
            for line in only_in_generated:
                f.write(line + '\n')
        if not only_in_original and not only_in_generated:
            f.write("Patches are equivalent.\n")

    # Write unified-diff-style file per source file
    diff_patch_file = diff_file.rsplit('.', 1)[0] + '_diff.patch'
    old_by_file = {}
    for p in sorted(old_patches):
        for fname, flines in _extract_diff_content_by_file(p).items():
            old_by_file.setdefault(fname, []).extend(flines)
    new_by_file = {}
    for p in sorted(new_patches):
        for fname, flines in _extract_diff_content_by_file(p).items():
            new_by_file.setdefault(fname, []).extend(flines)

    all_files = sorted(set(old_by_file) | set(new_by_file))
    with open(diff_patch_file, 'w') as f:
        for fname in all_files:
            old_content = old_by_file.get(fname, [])
            new_content = new_by_file.get(fname, [])
            if old_content == new_content:
                continue
            diff = difflib.unified_diff(
                old_content, new_content,
                fromfile=f'a/{fname} (original)',
                tofile=f'b/{fname} (generated)',
                lineterm='',
            )
            for line in diff:
                f.write(line + '\n')
            f.write('\n')
        for fname in missing_in_generated:
            if fname not in old_by_file:
                continue
            f.write(f"--- a/{fname} (original)\n")
            f.write("+++ /dev/null (missing in generated)\n")
            for line in old_by_file[fname]:
                f.write(f"-{line}\n")
            f.write('\n')
        for fname in extra_in_generated:
            if fname not in new_by_file:
                continue
            f.write("--- /dev/null (not in original)\n")
            f.write(f"+++ b/{fname} (extra in generated)\n")
            for line in new_by_file[fname]:
                f.write(f"+{line}\n")
            f.write('\n')
    return changes


MIRROR_MAP = {
    'gstreamer1.0-plugins-good': 'gst-plugins-good',
    'gstreamer1.0-plugins-base': 'gst-plugins-base',
    'gstreamer1.0-plugins-bad': 'gst-plugins-bad',
    'gstreamer1.0': 'gstreamer',
    'wpa-supplicant': 'hostap',
    'libsoup-2.4': 'libsoup',
    'glib-2.0': 'glib',
    'libsndfile1': 'libsndfile',
    'qemu-system': 'qemu',
    'go-runtime': 'go',
    'xserver-xorg': 'xserver',
    'python3-certifi': 'certifi',
    'python3-zipp': 'zipp',
    'python3-urllib3': 'urllib3',
    'python3-xmltodict': 'xmltodict',
    'python3': 'cpython',
    'python': 'cpython',
    'grub': 'grub2',
    'wpa_supplicant': 'hostap',
    'international_components_for_unicode': 'icu',
    'sqlite': 'sqlite3',
    'libpam': 'linux-pam',
    'gstreamer1.0-rtsp-server': 'gst-plugins-bad',
    'python3-cryptography': 'cryptography',
    'python3-pip': 'pip',
    'python3-pyasn1': 'pyasn1',
    'python3-pyopenssl': 'pyopenssl',
    'python3-wheel': 'wheel',
    'rust-llvm': 'llvm-project',
    'vim-tiny': 'vim',
}

SKIP_RECIPES = {'linux-dummy', 'network_security_services', 'rust-llvm'}


def list_cves(metadata_path, min_year):
    """List CVEs with hashes from metadata, filtered by year."""
    import json
    with open(metadata_path) as fh:
        data = json.load(fh)
    for cve_id in sorted(data.keys()):
        entry = data[cve_id]
        if entry.get('hashes'):
            match = re.search(r'CVE-(\d{4})-', cve_id)
            if match and int(match.group(1)) >= min_year:
                recipe = entry.get('name', 'unknown')
                if recipe not in SKIP_RECIPES:
                    print(f"{cve_id}:{recipe}")


def check_mirrors(metadata_path, mirror_dir, min_year, components=None):
    """Check for missing mirrors and print missing CVE:recipe pairs."""
    import json
    with open(metadata_path) as fh:
        data = json.load(fh)

    def find_mirror(recipe):
        for name in [recipe, MIRROR_MAP.get(recipe, recipe)]:
            if (os.path.exists(os.path.join(mirror_dir, name))
                    or os.path.exists(os.path.join(mirror_dir, name + '.git'))):
                return True
        return False

    missing = {}
    for cve_id in sorted(data.keys()):
        entry = data[cve_id]
        if entry.get('hashes'):
            match = re.search(r'CVE-(\d{4})-', cve_id)
            if match and int(match.group(1)) >= min_year:
                recipe = entry.get('name', '')
                if components and recipe not in components:
                    continue
                if (recipe and recipe not in SKIP_RECIPES
                        and not find_mirror(recipe)):
                    missing.setdefault(recipe, []).append(cve_id)
    for recipe, cves in sorted(missing.items()):
        print(f"{recipe}: {len(cves)} CVEs")
    if missing:
        print(f"Total: {len(missing)} missing mirrors")


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: test_utils.py <command> [args...]")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == 'remove_cve':
        prefix = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else None
        remove_cve_patch(sys.argv[2], sys.argv[3], sys.argv[4], prefix=prefix)
    elif cmd == 'compare':
        compare_patches(sys.argv[2], sys.argv[3])
    elif cmd == 'compare_detailed':
        args = sys.argv[2:]
        diff_file = args[0]
        rest = args[1:]
        sep = rest.index('--')
        old_patches = rest[:sep]
        new_patches = rest[sep + 1:]
        compare_patches_detailed(old_patches, new_patches, diff_file)
    elif cmd == 'list_cves':
        list_cves(sys.argv[2], int(sys.argv[3]))
    elif cmd == 'check_mirrors':
        components = sys.argv[5].split(',') if len(sys.argv) > 5 else None
        check_mirrors(sys.argv[2], sys.argv[3], int(sys.argv[4]), components)
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
