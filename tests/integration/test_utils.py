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
            r'|index |new file|deleted file|-- $|\d+\.\d+\.\d+)', line):
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
                        files.add(parts[3].lstrip('b/'))
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
            current_file = parts[3].lstrip('b/') if len(parts) >= 4 else None
            if current_file:
                result.setdefault(current_file, [])
            continue
        if re.match(
            r'^(From |Subject:|Date:|Signed-off-by:|CVE:|Upstream-Status:'
            r'|index |new file|deleted file|-- $|\d+\.\d+\.\d+)', line):
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


def compare_patches_detailed(old_patches, new_patches, diff_file):
    """Compare original vs generated patches, write differences to diff_file."""
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

    old_files = set()
    for p in old_patches:
        old_files |= _extract_files_touched(p)
    new_files = set()
    for p in new_patches:
        new_files |= _extract_files_touched(p)
    missing_in_generated = sorted(old_files - new_files)
    extra_in_generated = sorted(new_files - old_files)

    with open(diff_file, 'w') as f:
        f.write(f"Original patches ({len(old_patches)}): "
                f"{', '.join(os.path.basename(p) for p in sorted(old_patches))}\n")
        f.write(f"Generated patches ({len(new_patches)}): "
                f"{', '.join(os.path.basename(p) for p in sorted(new_patches))}\n")
        if len(old_patches) != len(new_patches):
            f.write(f"WARNING: patch count differs "
                    f"({len(old_patches)} original vs {len(new_patches)} generated)\n")
        f.write(f"\nFiles touched - original: {len(old_files)}, "
                f"generated: {len(new_files)}\n")
        if missing_in_generated:
            f.write(f"  Missing in generated: "
                    f"{', '.join(missing_in_generated)}\n")
        if extra_in_generated:
            f.write(f"  Extra in generated:   "
                    f"{', '.join(extra_in_generated)}\n")
        f.write(f"\nDifferences: {changes} lines\n\n")
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

    print(f"DIFF_CHANGES:{changes}")
    print(f"DIFF_PATCHES:{len(old_patches)}>{len(new_patches)}")
    files_status = f"{len(old_files)}>{len(new_files)}"
    if missing_in_generated:
        files_status += f" -{len(missing_in_generated)}"
    if extra_in_generated:
        files_status += f" +{len(extra_in_generated)}"
    print(f"DIFF_FILES:{files_status}")
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
