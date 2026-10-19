# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Recipe file manipulation for CVE corrector.

Handles SRC_URI editing, patch references, bbappend management,
and CVE_STATUS line operations in Yocto recipe files.
"""
import fnmatch
import re
import shutil
from pathlib import Path

from .utils import logger, run_cmd_capture

# A kirkstone CVE_CHECK_IGNORE assignment (any operator or override).
_CVE_CHECK_IGNORE_RE = re.compile(r'^\s*CVE_CHECK_IGNORE\b')


def _matches_recipe(path: Path, recipe: str) -> bool:
    """Check a recipe/bbappend filename belongs exactly to ``recipe``.

    Matches ``recipe``, ``recipe_<version>`` or ``recipe%`` stems, so
    'busybox-utils' is not taken for 'busybox'.
    """
    stem = path.stem  # e.g. 'busybox_1.36.1' or 'busybox_%'
    if stem == recipe:
        return True
    return stem.startswith(recipe + '_') or stem.startswith(recipe + '%')


def _find_recipe_file(meta_layer: Path | None, recipe: str) -> Path | None:
    """Find the .bbappend or .bb file for a recipe in the meta-layer.

    Uses exact recipe name matching (recipe_version or recipe_%) to avoid
    false matches (e.g. 'busybox-utils' when looking for 'busybox').
    Prefers .bbappend over .bb.
    """
    if not meta_layer:
        return None

    for pattern in (f'**/{recipe}*.bbappend', f'**/{recipe}*.bb',
                    f'**/{recipe}*.inc'):
        matches = [m for m in sorted(meta_layer.glob(pattern)) if _matches_recipe(m, recipe)]
        if matches:
            return matches[0]
    return None


def _get_src_uri_files(recipe_file: Path) -> set[str]:
    """Extract file:// basenames from a recipe's SRC_URI."""
    file_re = re.compile(r'file://([^\s;"\}]+)')
    return {m.group(1) for m in file_re.finditer(recipe_file.read_text(encoding='utf-8'))}


def snapshot_src_uri(meta_layer: Path | None, recipe: str) -> set[str]:
    """Snapshot file:// entries in the recipe before devtool finish.

    Returns:
        Set of filenames in SRC_URI before devtool modifies the recipe.
    """
    recipe_file = _find_recipe_file(meta_layer, recipe)
    if not recipe_file:
        return set()
    return _get_src_uri_files(recipe_file)


def update_recipe_patch(recipe: str, new_patch_name: str, original_patch_name: str,
                        meta_layer: Path | None = None) -> None:
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

    When the recipe file has no plain SRC_URI assignment, sibling ``.inc``
    files in the same directory are checked for the main SRC_URI block.
    If only scoped override forms exist (e.g. ``SRC_URI:append:class-nativesdk``),
    a new ``SRC_URI:append`` line is appended rather than inserting into
    the scoped override (which would limit the patch to that class/machine).

    Entries already present in the file's SRC_URI are skipped, so callers
    that don't track what they already merged in (e.g. via
    ``restore_bbappend_extras``) don't end up with a duplicate ``file://``
    line for the same patch.
    """
    existing = _get_src_uri_files(recipe_file)
    patch_names = [name for name in patch_names if name not in existing]
    if not patch_names:
        return

    target_file = recipe_file
    lines = target_file.read_text(encoding='utf-8').splitlines()
    insert_at = None

    # A plain SRC_URI assignment, with no override suffix at all. This is
    # the block new file:// entries should be spliced into. Override-suffixed
    # forms (e.g. SRC_URI:append:class-target = "...") are usually a distinct,
    # narrowly-scoped line (e.g. machine/class specific) and must not be
    # confused with the recipe's main patch list, or new entries would get
    # spliced in front of an unrelated line's closing quote, producing a
    # bare, malformed continuation line that breaks bitbake parsing.
    base_src_uri_re = re.compile(r'^\s*SRC_URI\s*(?:\+|\.|\?)?=')

    # An unscoped override — SRC_URI:append or SRC_URI:prepend with no
    # further class/machine suffix. Safe to insert into since it applies
    # globally.
    unscoped_override_re = re.compile(
        r'^\s*SRC_URI:(append|prepend)\s*(?:\+|\.|\?)?='
    )

    src_uri_start = _find_base_src_uri_line(lines, base_src_uri_re)

    if src_uri_start is None:
        # No plain SRC_URI in the .bb — check sibling .inc files
        inc_file = _find_inc_with_base_src_uri(recipe_file, base_src_uri_re)
        if inc_file:
            target_file = inc_file
            # Also check .inc doesn't already have these patches
            inc_existing = _get_src_uri_files(inc_file)
            patch_names = [name for name in patch_names if name not in inc_existing]
            if not patch_names:
                return
            lines = inc_file.read_text(encoding='utf-8').splitlines()
            src_uri_start = _find_base_src_uri_line(lines, base_src_uri_re)

    if src_uri_start is None:
        # Still no plain SRC_URI — try unscoped override (SRC_URI:append = ...)
        for i, line in enumerate(lines):
            if unscoped_override_re.match(line):
                src_uri_start = i
                break

    if src_uri_start is None:
        # Only scoped overrides remain — do NOT insert into them.
        # Append a new SRC_URI:append line to the original recipe file.
        _append_new_src_uri_append(recipe_file, patch_names)
        return

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
        # No closing quote found — append as a new block
        _append_new_src_uri_append(target_file, patch_names)
        return
    target_file.write_text('\n'.join(lines) + '\n', encoding='utf-8')


def _find_base_src_uri_line(lines: list[str], base_src_uri_re: re.Pattern) -> int | None:
    """Find the first line matching a plain SRC_URI assignment."""
    for i, line in enumerate(lines):
        if base_src_uri_re.match(line):
            return i
    return None


def _find_inc_with_base_src_uri(recipe_file: Path,
                                base_src_uri_re: re.Pattern) -> Path | None:
    """Find a sibling .inc file that contains the main SRC_URI block.

    Searches the same directory as recipe_file for .inc files and returns
    the first one that has a plain SRC_URI assignment.
    """
    recipe_dir = recipe_file.parent
    recipe_stem = recipe_file.stem.split('_')[0]  # e.g. 'binutils' from 'binutils_2.46'
    # Prefer .inc files whose name matches the recipe base name
    inc_files = sorted(
        recipe_dir.glob('*.inc'),
        key=lambda p: (0 if p.stem.startswith(recipe_stem) else 1, p.name),
    )
    for inc in inc_files:
        try:
            content = inc.read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError):
            continue
        for line in content.splitlines():
            if base_src_uri_re.match(line):
                return inc
    return None


def _append_new_src_uri_append(recipe_file: Path, patch_names: list[str]) -> None:
    """Append a new SRC_URI:append line with the given patches to the file."""
    lines = recipe_file.read_text(encoding='utf-8').splitlines()
    lines.append('')
    if len(patch_names) == 1:
        lines.append(f'SRC_URI:append = " file://{patch_names[0]}"')
    else:
        lines.append('SRC_URI:append = " \\')
        for name in patch_names:
            lines.append(f'           file://{name} \\')
        lines.append('           "')
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


def save_bbappend_extras(meta_layer: Path | None, recipe: str) -> list[str]:
    """Save SRC_URI and CVE status lines from existing bbappend before devtool overwrites it.

    CVE status lines are ``CVE_STATUS[...]`` and, on kirkstone,
    ``CVE_CHECK_IGNORE`` assignments together with the ``# CVE-...`` reason
    comment directly above them.
    """
    recipe_file = _find_recipe_file(meta_layer, recipe)
    if not recipe_file or not recipe_file.exists():
        return []

    src_uri_re = re.compile(
        r'^\s*SRC_URI\s*(?::\w[\w-]*)*\s*(?:\+|\.|\?)?='
    )
    extras: list[str] = []
    in_block = False
    prev_line = ''
    for line in recipe_file.read_text(encoding='utf-8').splitlines():
        stripped = line.strip()
        if stripped.startswith('CVE_STATUS['):
            extras.append(line)
        elif _CVE_CHECK_IGNORE_RE.match(line):
            if prev_line.strip().startswith('# CVE-'):
                extras.append(prev_line)
            in_block = True
        elif src_uri_re.match(line) and '+=' in line:
            in_block = True
        if in_block:
            extras.append(line)
            if not stripped.endswith('\\'):
                in_block = False
        prev_line = line

    return extras


def restore_bbappend_extras(meta_layer: Path | None, recipe: str,
                            saved_lines: list[str]) -> None:
    """Merge previously saved SRC_URI entries and CVE status lines back into the bbappend."""
    if not saved_lines:
        return

    recipe_file = _find_recipe_file(meta_layer, recipe)
    if not recipe_file or not recipe_file.exists():
        return

    content = recipe_file.read_text(encoding='utf-8')
    existing_patches = _get_src_uri_files(recipe_file)

    old_patches: list[str] = []
    cve_status_lines: list[str] = []
    # Reason comment and CVE_CHECK_IGNORE statement being collected (kirkstone).
    ignore_block: list[str] = []

    for line in saved_lines:
        stripped = line.strip()
        if ignore_block or stripped.startswith('# CVE-') or _CVE_CHECK_IGNORE_RE.match(line):
            ignore_block.append(line)
            if stripped.startswith('#') or stripped.endswith('\\'):
                continue
            ids = re.findall(r'CVE-\d{4}-\d+', ' '.join(
                ln for ln in ignore_block if not ln.strip().startswith('#')))
            if any(cve not in content for cve in ids):
                cve_status_lines.extend(ignore_block)
            ignore_block = []
        elif stripped.startswith('CVE_STATUS['):
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
                "%s CVE status line(s) to %s", len(old_patches),
                len(cve_status_lines), recipe_file.name)


def remove_bbappend_leaks(meta_layer: Path | None, recipe: str,
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


# ---------------------------------------------------------------------------
# bbappend placement for layers devtool cannot lay out correctly
# ---------------------------------------------------------------------------
#
# ``devtool finish`` / ``devtool update-recipe -a`` place a bbappend at
# ``<layer>/<path of recipe in its own layer>/<recipe>_%.bbappend``. That is
# wrong for layers such as meta-lts-collab, which keep bbappends under
# per-upstream-layer subdirectories pulled in via BBFILES_DYNAMIC
# (``meta-core/recipes-support/curl/curl_7.82.0.bbappend``). The helpers
# below find where the bbappend belongs and move devtool's output there.

def recipe_bbappends(meta_layer: Path | None, recipe: str) -> set[Path]:
    """Return every bbappend for ``recipe`` in the meta-layer."""
    if not meta_layer:
        return set()
    return {p for p in meta_layer.rglob(f'{recipe}*.bbappend') if _matches_recipe(p, recipe)}


def _conf_words(text: str, var: str) -> list[str]:
    """Collect the words of every ``VAR = / += / ?= / .= "..."`` in conf text."""
    words: list[str] = []
    pattern = rf'^\s*{re.escape(var)}\s*(?:\+|\.|\?)?=\s*"([^"]*)"'
    for match in re.finditer(pattern, text, re.MULTILINE):
        words += [w for w in match.group(1).split() if w != '\\']
    return words


def _layer_root(path: Path) -> Path | None:
    """Return the closest parent directory holding ``conf/layer.conf``."""
    for parent in path.parents:
        if (parent / 'conf' / 'layer.conf').is_file():
            return parent
    return None


def _dynamic_bbappend_dir(meta_layer: Path, recipe: str) -> Path | None:
    """Work out the bbappend directory from the layer's BBFILES_DYNAMIC.

    Matches the recipe's own layer collection (e.g. ``core``) against
    ``BBFILES_DYNAMIC`` entries like
    ``core:${LAYERDIR}/meta-core/*/*/*.bbappend`` and returns
    ``<layer>/meta-core/<recipe's path in its own layer>``.

    Returns:
        The directory, or None when the layer has no matching
        BBFILES_DYNAMIC entry or the recipe's location is unknown.
    """
    layer_conf = meta_layer / 'conf' / 'layer.conf'
    if not layer_conf.is_file():
        return None
    dynamic = _conf_words(layer_conf.read_text(encoding='utf-8'), 'BBFILES_DYNAMIC')
    if not dynamic:
        return None

    result = run_cmd_capture(['bitbake-getvar', 'FILE', '-r', recipe, '--value'])
    lines = result.stdout.strip().splitlines() if result.returncode == 0 else []
    if not lines:
        return None
    recipe_file = Path(lines[-1].strip())
    origin = _layer_root(recipe_file)
    if not origin:
        return None
    collections = _conf_words(
        (origin / 'conf' / 'layer.conf').read_text(encoding='utf-8'), 'BBFILE_COLLECTIONS')
    rel_dir = recipe_file.parent.relative_to(origin)

    for entry in dynamic:
        collection, sep, pattern = entry.partition(':')
        if not sep or collection not in collections or not pattern.endswith('.bbappend'):
            continue
        pattern = pattern.replace('${LAYERDIR}', str(meta_layer))
        try:
            parts = Path(pattern).relative_to(meta_layer).parts
        except ValueError:
            continue
        prefix: list[str] = []
        for part in parts:
            if any(c in part for c in '*?['):
                break
            prefix.append(part)
        candidate = meta_layer.joinpath(*prefix) / rel_dir
        if fnmatch.fnmatchcase(str(candidate / f'{recipe}_%.bbappend'), pattern):
            return candidate
    return None


def resolve_bbappend_dir(meta_layer: Path | None, recipe: str,
                         override: Path | None = None) -> Path | None:
    """Return the directory the recipe's bbappend must live in.

    In order: ``override`` (``--bbappend-dir``), the directory of an
    existing bbappend for the recipe, then the layer's BBFILES_DYNAMIC
    layout. Call before devtool writes anything to the layer.

    Returns:
        The directory, or None to keep devtool's own placement.
    """
    if not meta_layer:
        return None
    if override:
        return override
    existing = sorted(recipe_bbappends(meta_layer, recipe))
    if existing:
        return existing[0].parent
    return _dynamic_bbappend_dir(meta_layer, recipe)


def _files_subdir(bbappend: Path, recipe: str) -> str | None:
    """Return the ``${THISDIR}/<subdir>`` from a bbappend's FILESEXTRAPATHS."""
    match = re.search(r'FILESEXTRAPATHS\S*\s*:?=\s*"\$\{THISDIR\}/([^:"]+)',
                      bbappend.read_text(encoding='utf-8'))
    if not match:
        return None
    return match.group(1).replace('${PN}', recipe).replace('${BPN}', recipe)


def _merge_bbappend(meta_layer: Path, stray: Path, target: Path, recipe: str) -> None:
    """Move a devtool-written bbappend's patches and SRC_URI into ``target``."""
    stray_files = stray.parent / (_files_subdir(stray, recipe) or recipe)

    entries: list[str] = []
    new_lines: list[str] = []
    in_src_uri = False
    for line in stray.read_text(encoding='utf-8').splitlines():
        stripped = line.strip()
        in_src_uri = in_src_uri or bool(re.match(r'^\s*SRC_URI\b', line))
        if in_src_uri:
            entries += re.findall(r'file://([^\s"\\]+)', line)
            in_src_uri = stripped.endswith('\\')
        elif stripped and not stripped.startswith('FILESEXTRAPATHS'):
            new_lines.append(line)

    target.parent.mkdir(parents=True, exist_ok=True)
    content = target.read_text(encoding='utf-8') if target.exists() else ''
    subdir = _files_subdir(target, recipe) if content else None
    if subdir is None:
        subdir = 'files'
        content = f'FILESEXTRAPATHS:prepend := "${{THISDIR}}/{subdir}:"\n\n' + content
    # Entries go into the target's existing SRC_URI, or a new block if it has none.
    to_append = entries
    if entries and not re.search(r'^\s*SRC_URI\b', content, re.MULTILINE):
        new_lines.insert(0, 'SRC_URI += "\\\n'
                         + ''.join(f'    file://{e} \\\n' for e in entries) + '"')
        to_append = []
    if new_lines:
        if content and not content.endswith('\n'):
            content += '\n'
        content += '\n'.join(new_lines) + '\n'
    target.write_text(content, encoding='utf-8')
    _append_src_uri_entries(target, to_append)

    target_files = target.parent / subdir
    for entry in entries:
        name = entry.split(';')[0]
        src = stray_files / name
        if src.exists():
            dest = target_files / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src), str(dest))

    stray.unlink()
    if stray_files.is_dir() and not any(p.is_file() for p in stray_files.rglob('*')):
        shutil.rmtree(stray_files)
    # Prune directories left empty, up to (not including) the layer root.
    for parent in stray.parents:
        if parent == meta_layer or not parent.is_dir() or any(parent.iterdir()):
            break
        parent.rmdir()
    logger.info("Moved %s into %s", stray.name, target)


def relocate_new_bbappends(meta_layer: Path | None, recipe: str,
                           target_dir: Path | None, pre_existing: set[Path]) -> None:
    """Fold bbappends devtool just created elsewhere into ``target_dir``.

    Only bbappends absent from ``pre_existing`` and outside ``target_dir``
    are touched, so layers where devtool's placement is already right are
    left unchanged.
    """
    if not meta_layer or not target_dir:
        return
    for stray in sorted(recipe_bbappends(meta_layer, recipe) - pre_existing):
        if stray.parent == target_dir:
            continue
        targets = sorted(p for p in target_dir.glob(f'{recipe}*.bbappend')
                         if _matches_recipe(p, recipe))
        target = targets[0] if targets else target_dir / stray.name
        _merge_bbappend(meta_layer, stray, target, recipe)
