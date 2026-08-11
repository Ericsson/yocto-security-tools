# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Recipe file manipulation for CVE corrector.

Handles SRC_URI editing, patch references, bbappend management,
and CVE_STATUS line operations in Yocto recipe files.
"""
import re
from pathlib import Path
from typing import Optional

from .utils import logger, run_cmd_capture


def _find_recipe_file(meta_layer: Optional[Path], recipe: str) -> Optional[Path]:
    """Find the .bbappend or .bb file for a recipe in the meta-layer.

    Uses exact recipe name matching (recipe_version or recipe_%) to avoid
    false matches (e.g. 'busybox-utils' when looking for 'busybox').
    Prefers .bbappend over .bb.
    """
    if not meta_layer:
        return None

    def _is_exact_match(path: Path) -> bool:
        """Check filename matches recipe exactly (not a prefix of another recipe)."""
        stem = path.stem  # e.g. 'busybox_1.36.1' or 'busybox_%'
        # Must be recipe_version, recipe_%, or just recipe
        if stem == recipe:
            return True
        return stem.startswith(recipe + '_') or stem.startswith(recipe + '%')

    for pattern in (f'**/{recipe}*.bbappend', f'**/{recipe}*.bb',
                    f'**/{recipe}*.inc'):
        matches = [m for m in sorted(meta_layer.glob(pattern)) if _is_exact_match(m)]
        if matches:
            return matches[0]
    return None


def _get_src_uri_files(recipe_file: Path) -> set[str]:
    """Extract file:// basenames from a recipe's SRC_URI."""
    file_re = re.compile(r'file://([^\s;"\}]+)')
    return {m.group(1) for m in file_re.finditer(recipe_file.read_text(encoding='utf-8'))}


def snapshot_src_uri(meta_layer: Optional[Path], recipe: str) -> set[str]:
    """Snapshot file:// entries in the recipe before devtool finish.

    Returns:
        Set of filenames in SRC_URI before devtool modifies the recipe.
    """
    recipe_file = _find_recipe_file(meta_layer, recipe)
    if not recipe_file:
        return set()
    return _get_src_uri_files(recipe_file)


def update_recipe_patch(recipe: str, new_patch_name: str, original_patch_name: str,
                        meta_layer: Optional[Path] = None) -> None:
    """Update bbappend or bb file to reference the CVE patch."""
    if not original_patch_name:
        print("Warning: No patch name provided, skipping recipe update")
        return

    patch_found = False
    recipe_files = []

    if meta_layer and meta_layer.exists():
        for pattern in ('**/*.bbappend', '**/*.bb', '**/*.inc'):
            for f in meta_layer.glob(pattern):
                try:
                    if original_patch_name in f.read_text(encoding='utf-8', errors='ignore'):
                        recipe_files.append(f)
                except OSError:
                    pass

    if not recipe_files:
        result = run_cmd_capture(['bitbake-layers', 'show-recipes', '-f', recipe])
        for line in result.stdout.splitlines():
            if (line.startswith('/') and recipe in line and
                    ('.bb' in line or '.bbappend' in line)):
                recipe_files.append(Path(line.strip()))

        result = run_cmd_capture(['bitbake-layers', 'show-appends', recipe])
        for line in result.stdout.splitlines():
            if line.strip().endswith('.bbappend'):
                recipe_files.append(Path(line.strip()))

    for recipe_file in recipe_files:
        if not recipe_file.exists():
            continue
        with open(recipe_file, encoding='utf-8') as fh:
            content = fh.read()
        if original_patch_name in content:
            content = content.replace(original_patch_name, new_patch_name)
            with open(recipe_file, 'w', encoding='utf-8') as fh:
                fh.write(content)
            print(f"Updated {recipe_file}")
            patch_found = True
            break

    if not patch_found:
        print(f"Warning: Could not find patch reference {original_patch_name}")


def _append_src_uri_entries(recipe_file: Path, patch_names: list[str]) -> None:
    """Insert new file:// entries before the closing quote of the SRC_URI block.

    Handles standard forms and override-style syntax:
    - SRC_URI = "..."
    - SRC_URI += "..."
    - SRC_URI .= "..."
    - SRC_URI:append = "..."
    - SRC_URI:append:class-target = "..."

    Entries already present in the file's SRC_URI are skipped, so callers
    that don't track what they already merged in (e.g. via
    ``restore_bbappend_extras``) don't end up with a duplicate ``file://``
    line for the same patch.
    """
    existing = _get_src_uri_files(recipe_file)
    patch_names = [name for name in patch_names if name not in existing]
    if not patch_names:
        return

    lines = recipe_file.read_text(encoding='utf-8').splitlines()
    insert_at = None

    # Match all SRC_URI assignment forms including override syntax
    src_uri_re = re.compile(
        r'^\s*SRC_URI\s*'
        r'(?::\w[\w-]*)*'  # optional override suffixes like :append:class-target
        r'\s*(?:\+|\.|\?)?='  # assignment operators: =, +=, .=, ?=
    )
    # A plain SRC_URI assignment, with no override suffix at all. This is
    # the block new file:// entries should be spliced into. Override-suffixed
    # forms (e.g. SRC_URI:append:class-target = "...") are usually a distinct,
    # narrowly-scoped line (e.g. machine/class specific) and must not be
    # confused with the recipe's main patch list, or new entries would get
    # spliced in front of an unrelated line's closing quote, producing a
    # bare, malformed continuation line that breaks bitbake parsing.
    base_src_uri_re = re.compile(r'^\s*SRC_URI\s*(?:\+|\.|\?)?=')

    src_uri_start = None
    for i, line in enumerate(lines):
        if base_src_uri_re.match(line):
            src_uri_start = i
            break
    if src_uri_start is None:
        # No plain SRC_URI assignment — fall back to the first override form
        # (e.g. a bbappend whose only SRC_URI line is ``SRC_URI:append``).
        for i, line in enumerate(lines):
            if src_uri_re.match(line):
                src_uri_start = i
                break
    if src_uri_start is not None:
        # Scan forward from SRC_URI to find the closing line
        for i in range(src_uri_start, len(lines)):
            stripped = lines[i].rstrip()
            if not stripped.endswith('\\'):
                # This is the last line of SRC_URI block
                # Insert before the closing quote
                if stripped.endswith('"'):
                    insert_at = i
                break
    if insert_at is not None:
        if insert_at == src_uri_start:
            # Single-line assignment (e.g. SRC_URI = "file://a.patch") with
            # no line continuation — splice the new entries inside its
            # closing quote instead of inserting a bare line before it,
            # which would leave the opening line's quote unterminated.
            line = lines[insert_at]
            quote_open = line.index('"')
            quote_close = line.rfind('"')
            var_part = line[:quote_open + 1]  # e.g. 'SRC_URI = "'
            existing_content = line[quote_open + 1:quote_close].strip()
            new_block = [f'{var_part} \\']
            if existing_content:
                new_block.append(f'           {existing_content} \\')
            for name in patch_names:
                new_block.append(f'           file://{name} \\')
            new_block.append('           "')
            lines[insert_at:insert_at + 1] = new_block
        else:
            indent = ''
            for j in range(insert_at - 1, -1, -1):
                if 'file://' in lines[j]:
                    indent = lines[j][:lines[j].index('file://')]
                    break
            new_lines = [f'{indent}file://{name} \\' for name in patch_names]
            lines[insert_at:insert_at] = new_lines
    else:
        lines.append('')
        if len(patch_names) == 1:
            lines.append(f'SRC_URI += "file://{patch_names[0]}"')
        else:
            lines.append('SRC_URI += " \\')
            for name in patch_names:
                lines.append(f'            file://{name} \\')
            lines.append('            "')
    recipe_file.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def _split_src_uri_line(cve_id: str, meta_layer: Path) -> None:
    """Split single-line SRC_URI with multiple file:// entries onto separate lines."""
    for recipe_file in (*meta_layer.glob('**/*.bb'),
                        *meta_layer.glob('**/*.bbappend')):
        try:
            content = recipe_file.read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError):
            continue
        if f'file://{cve_id}' not in content:
            continue
        lines = content.splitlines(keepends=True)
        new_lines = []
        changed = False
        for line in lines:
            if 'file://' in line and line.count('file://') > 1:
                stripped = line.rstrip('\n')
                quote_start = stripped.find('"')
                quote_end = stripped.rfind('"')
                if quote_start < 0 or quote_start >= quote_end - 1:
                    new_lines.append(line)
                    continue
                prefix = stripped[:quote_start]
                entries = stripped[quote_start + 1:quote_end].split()
                pad = ' ' * 4
                new_lines.append(f'{prefix}" \\\n')
                for entry in entries:
                    new_lines.append(f'{pad}{entry} \\\n')
                new_lines.append(f'{pad}"\n')
                changed = True
            else:
                new_lines.append(line)
        if changed:
            recipe_file.write_text(''.join(new_lines), encoding='utf-8')
            logger.info("Split SRC_URI onto separate lines in %s", recipe_file.name)
        return


def sort_cve_lines_in_recipe(cve_id: str, meta_layer: Path) -> None:
    """Ensure CVE patch series lines in SRC_URI are in ascending order."""
    for recipe_file in (*meta_layer.glob('**/*.bb'),
                        *meta_layer.glob('**/*.bbappend')):
        try:
            content = recipe_file.read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError):
            continue
        if f'file://{cve_id}-' not in content:
            continue
        lines = content.splitlines(keepends=True)
        indices = [i for i, line in enumerate(lines) if f'file://{cve_id}-' in line]
        if len(indices) < 2:
            return
        extracted = [lines[i] for i in indices]
        if extracted == sorted(extracted):
            return
        for i, idx in enumerate(sorted(indices)):
            lines[idx] = sorted(extracted)[i]
        recipe_file.write_text(''.join(lines), encoding='utf-8')
        logger.info("Reordered CVE patch entries in %s", recipe_file.name)
        return


def save_bbappend_extras(meta_layer: Optional[Path], recipe: str) -> list[str]:
    """Save SRC_URI and CVE_STATUS lines from existing bbappend before devtool overwrites it."""
    recipe_file = _find_recipe_file(meta_layer, recipe)
    if not recipe_file or not recipe_file.exists():
        return []

    src_uri_re = re.compile(
        r'^\s*SRC_URI\s*(?::\w[\w-]*)*\s*(?:\+|\.|\?)?='
    )
    extras: list[str] = []
    in_src_uri = False
    for line in recipe_file.read_text(encoding='utf-8').splitlines():
        stripped = line.strip()
        if stripped.startswith('CVE_STATUS['):
            extras.append(line)
        elif src_uri_re.match(line) and '+=' in line:
            in_src_uri = True
        if in_src_uri:
            extras.append(line)
            if not stripped.endswith('\\'):
                in_src_uri = False

    return extras


def restore_bbappend_extras(meta_layer: Optional[Path], recipe: str,
                            saved_lines: list[str]) -> None:
    """Merge previously saved SRC_URI entries and CVE_STATUS lines back into the bbappend."""
    if not saved_lines:
        return

    recipe_file = _find_recipe_file(meta_layer, recipe)
    if not recipe_file or not recipe_file.exists():
        return

    content = recipe_file.read_text(encoding='utf-8')
    existing_patches = _get_src_uri_files(recipe_file)

    old_patches: list[str] = []
    cve_status_lines: list[str] = []

    for line in saved_lines:
        stripped = line.strip()
        if stripped.startswith('CVE_STATUS['):
            cve_match = re.search(r'CVE_STATUS\[(CVE-\S+)\]', stripped)
            if cve_match and cve_match.group(1) not in content:
                cve_status_lines.append(line)
        elif 'file://' in stripped:
            for patch in re.findall(r'file://(\S+)', stripped):
                name = patch.rstrip('"\\').rstrip()
                if name not in existing_patches:
                    old_patches.append(name)

    if not old_patches and not cve_status_lines:
        return

    if old_patches:
        lines = content.splitlines()
        src_start = None
        for i, line in enumerate(lines):
            if 'SRC_URI' in line and '+=' in line:
                src_start = i
                break

        if src_start is not None:
            src_end = src_start
            while src_end < len(lines) - 1 and lines[src_end].rstrip().endswith('\\'):
                src_end += 1
            new_patch_names = re.findall(r'file://(\S+)',
                                         '\n'.join(lines[src_start:src_end + 1]))
            new_patch_names = [p.rstrip('"\\').rstrip() for p in new_patch_names]

            all_patches = old_patches + new_patch_names
            rebuilt = ['SRC_URI += " \\']
            for name in all_patches:
                rebuilt.append(f'            file://{name} \\')
            rebuilt.append('            "')

            lines[src_start:src_end + 1] = rebuilt
            content = '\n'.join(lines) + '\n'

    if cve_status_lines:
        if not content.endswith('\n'):
            content += '\n'
        content += '\n'.join(cve_status_lines) + '\n'

    recipe_file.write_text(content, encoding='utf-8')
    logger.info("Restored %s SRC_URI + "
                "%s CVE_STATUS line(s) to %s", len(old_patches),
                len(cve_status_lines), recipe_file.name)


def remove_bbappend_leaks(meta_layer: Optional[Path], recipe: str,
                          original_entries: set[str]) -> None:
    """Remove SRC_URI entries that devtool finish leaked from bbappends."""
    recipe_file = _find_recipe_file(meta_layer, recipe)
    if not recipe_file:
        return
    lines = recipe_file.read_text(encoding='utf-8').splitlines()
    file_re = re.compile(r'file://([^\s;"\}]+)')

    drop: set[int] = set()
    for i, line in enumerate(lines):
        m = file_re.search(line)
        if not m:
            continue
        fname = m.group(1)
        if fname in original_entries:
            continue
        if fname.endswith(('.patch', '.diff')):
            continue
        drop.add(i)

    if not drop:
        return

    new_lines = []
    for i, line in enumerate(lines):
        if i in drop:
            logger.info("Removing bbappend-leaked SRC_URI entry: %s", line.strip())
            continue
        new_lines.append(line)

    recipe_file.write_text('\n'.join(new_lines) + '\n', encoding='utf-8')
