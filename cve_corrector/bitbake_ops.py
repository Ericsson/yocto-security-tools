# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Bitbake build environment and devtool operations for CVE corrector."""
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Optional

from .state import EXIT_METADATA_ERROR
from .utils import run_cmd_capture


def get_build_path() -> Path:
    """Get build path from BBPATH environment variable."""
    bbpath = os.environ.get('BBPATH', '')
    if not bbpath:
        print("BBPATH environment variable not set", file=sys.stderr)
        sys.exit(EXIT_METADATA_ERROR)
    return Path(bbpath.split(':')[0])


def get_state_dir() -> Path:
    """Get state directory path."""
    build_path = get_build_path()
    state_dir = build_path / 'workspace' / 'cve_corrector'
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir


def cleanup_workspace(bbpath: str, full: bool = False) -> None:
    """Remove devtool workspace layer from bblayers.conf and optionally delete build output.

    Args:
        bbpath: BBPATH value (colon-separated).
        full: If True, also remove tmp/tmp-glibc directories (destructive).
    """
    build_path = Path(bbpath.split(':')[0])
    workspace_path = build_path / 'workspace'

    if workspace_path.exists():
        print(f"Removing workspace directory: {workspace_path}")
        try:
            shutil.rmtree(workspace_path)
        except OSError as e:
            print(f"Warning: Failed to remove workspace: {e}", file=sys.stderr)

    if full:
        for tmp_dir in ['tmp', 'tmp-glibc']:
            tmp_path = build_path / tmp_dir
            if tmp_path.exists():
                print(f"Removing {tmp_dir} directory: {tmp_path}")
                try:
                    shutil.rmtree(tmp_path)
                except OSError as e:
                    print(f"Warning: Failed to remove {tmp_dir}: {e}", file=sys.stderr)

    bblayers_conf = build_path / 'conf' / 'bblayers.conf'
    if bblayers_conf.exists():
        try:
            content = bblayers_conf.read_text()
            lines = content.splitlines(keepends=True)
            new_lines = [
                line for line in lines
                if not (line.strip() and '/workspace' in line and
                        not line.strip().startswith('#'))
            ]
            if len(new_lines) != len(lines):
                bblayers_conf.write_text(''.join(new_lines))
                print(f"Removed workspace layer from {bblayers_conf}")
        except OSError as e:
            print(f"Warning: Failed to update bblayers.conf: {e}", file=sys.stderr)


_MIRROR_ALIASES = {
    'glib-2.0': 'glib',
    'go-runtime': 'go',
    'grub': 'grub2',
    'gstreamer1.0': 'gstreamer',
    'gstreamer1.0-plugins-bad': 'gst-plugins-bad',
    'gstreamer1.0-plugins-base': 'gst-plugins-base',
    'gstreamer1.0-plugins-good': 'gst-plugins-good',
    'gstreamer1.0-rtsp-server': 'gst-plugins-bad',
    'international_components_for_unicode': 'icu',
    'libpam': 'linux-pam',
    'libsndfile1': 'libsndfile',
    'libsoup-2.4': 'libsoup',
    'python3': 'cpython',
    'python3-certifi': 'certifi',
    'python3-urllib3': 'urllib3',
    'python3-xmltodict': 'xmltodict',
    'python3-zipp': 'zipp',
    'python': 'cpython',
    'qemu-system': 'qemu',
    'sqlite': 'sqlite3',
    'wpa-supplicant': 'hostap',
    'wpa_supplicant': 'hostap',
    'xserver-xorg': 'xserver',
}


def find_mirror_repo(mirror_dir: Path, recipe_name: str,
                     hash_details: Optional[list[dict]] = None) -> Optional[Path]:
    """Locate the mirror repository."""
    names = [recipe_name, _MIRROR_ALIASES.get(recipe_name, recipe_name)]
    if hash_details:
        for d in hash_details:
            url = d.get('url', '')
            parts = url.replace('/commit/', '/').replace('/pull/', '/').split('/')
            for i, part in enumerate(parts):
                if part in ('github.com', 'gitlab.com') and i + 2 < len(parts):
                    names.append(parts[i + 2])
                    break
    for name in dict.fromkeys(names):
        for candidate in [mirror_dir / name, mirror_dir / f"{name}.git"]:
            if candidate.exists():
                return candidate
    return None


def deduce_meta_layer_from_recipe(recipe: str) -> Optional[Path]:
    """Deduce meta-layer path from recipe using bitbake-layers."""
    result = run_cmd_capture(['bitbake-layers', 'show-recipes', '-f', recipe])
    for line in result.stdout.splitlines():
        if line.startswith('/') and recipe in line and '.bb' in line:
            recipe_path = Path(line.strip())
            for parent in recipe_path.parents:
                if parent.name.startswith('meta') or parent.name == 'openembedded-core':
                    return parent
    return None


def get_layerseries_corename() -> Optional[str]:
    """Get the release corename from ``LAYERSERIES_CORENAMES``.

    Used as the ``git format-patch --subject-prefix`` when exporting a patch
    for mailing-list submission, e.g. ``scarthgap][PATCH``, so reviewers can
    immediately tell which stable branch the patch targets (see the Yocto
    Project submit-changes guide). ``LAYERSERIES_CORENAMES`` may list more
    than one corename (space-separated) for compatibility; the last one is
    the current release name.

    Returns:
        The current release corename (e.g. ``"scarthgap"``), or None if it
        cannot be determined (missing BBPATH, bitbake-getvar failure, etc).
    """
    result = run_cmd_capture(['bitbake-getvar', 'LAYERSERIES_CORENAMES', '--value'])
    if result.returncode != 0:
        return None
    corenames = result.stdout.strip().split()
    return corenames[-1] if corenames else None


def get_recipe_src_uri_git(recipe: str) -> Optional[str]:
    """Extract git repository URL from recipe's SRC_URI.

    Returns the first git:// or https:// repo URL found in SRC_URI,
    or None if the recipe uses tarballs.
    """
    result = run_cmd_capture(['bitbake-getvar', 'SRC_URI', '-r', recipe])
    for line in result.stdout.splitlines():
        if line.startswith('SRC_URI='):
            src_uri = line.split('=', 1)[1].strip('"')
            for entry in src_uri.split():
                if entry.startswith('git://') or entry.startswith('gitsm://'):
                    # Convert git:// to https:// for fetch
                    url = entry.split(';')[0]
                    url = re.sub(r'^gitsm?://', 'https://', url)
                    return url
                if entry.startswith(('https://', 'http://')) and '.git' in entry.split(';')[0]:
                    return entry.split(';')[0]
    return None


def get_upstream_check_uri(recipe: str) -> Optional[str]:
    """Get UPSTREAM_CHECK_URI from recipe if it points to a git repository.

    Only returns the URI if it looks like a cloneable git repo URL
    (not a releases page, tarball directory, or web page).
    """
    result = run_cmd_capture(['bitbake-getvar', 'UPSTREAM_CHECK_URI', '-r', recipe])
    for line in result.stdout.splitlines():
        if line.startswith('UPSTREAM_CHECK_URI='):
            uri = line.split('=', 1)[1].strip('"').strip()
            if not uri:
                return None
            # Skip release pages, download directories, and web pages
            skip = ('/releases', '/downloads', '/tags', '/archive',
                    'ftp.', 'download.', '.html', '.php')
            if any(s in uri for s in skip):
                return None
            # Must end in .git or be a known git forge path
            if uri.endswith('.git'):
                return uri
            # GitHub/GitLab repo root (no subpath beyond org/repo)
            for forge in ('github.com/', 'gitlab.com/', 'gitlab.'):
                if forge in uri:
                    # e.g. https://github.com/org/repo — valid
                    # e.g. https://github.com/org/repo/releases — skipped above
                    parts = uri.rstrip('/').split('/')
                    if forge.startswith('github') or forge.startswith('gitlab'):
                        idx = next((i for i, p in enumerate(parts) if forge.rstrip('/') in p), -1)
                        if idx >= 0 and len(parts) == idx + 3:
                            return uri
    return None


def resolve_meta_layer(meta_layer: Path) -> Path:
    """Resolve meta-layer to absolute path using bblayers.conf."""
    if meta_layer.is_absolute() and meta_layer.exists():
        return meta_layer

    bbpath = os.environ.get('BBPATH', '')
    if not bbpath:
        return meta_layer

    bblayers_conf = Path(bbpath.split(':')[0]) / 'conf' / 'bblayers.conf'
    if not bblayers_conf.exists():
        return meta_layer

    content = bblayers_conf.read_text()
    layer_name = meta_layer.name if meta_layer.is_dir() else Path(meta_layer).name

    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith('#') and layer_name in line:
            match = re.search(r'([^\s]+' + re.escape(layer_name) + r'[^\s]*)', line)
            if match:
                path_str = match.group(1).strip('\\').strip()
                resolved = Path(path_str)
                if resolved.exists():
                    return resolved

    return meta_layer
