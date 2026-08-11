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


def _is_workspace_layer_line(line: str, workspace_path: Path) -> bool:
    """Check whether a bblayers.conf line is the devtool workspace layer.

    Matches only the exact devtool workspace layer path, not any path that
    merely contains a ``workspace`` component. A substring test on
    ``/workspace`` would strip every layer in the file whenever the build
    tree itself lives under a directory called ``workspace`` (e.g.
    ``/home/user/workspace/build/...``), silently emptying ``BBLAYERS``.

    Args:
        line: A single raw line from ``bblayers.conf``.
        workspace_path: Absolute path of the devtool workspace layer.

    Returns:
        True if the line declares the devtool workspace layer.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        return False
    # Layer entries inside the BBLAYERS list carry a trailing line
    # continuation backslash; drop it before comparing.
    entry = stripped.removesuffix('\\').strip()
    if not entry.startswith('/'):
        return False
    return Path(entry) == workspace_path


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
                if not _is_workspace_layer_line(line, workspace_path)
            ]
            if len(new_lines) != len(lines):
                bblayers_conf.write_text(''.join(new_lines))
                print(f"Removed workspace layer from {bblayers_conf}")
        except OSError as e:
            print(f"Warning: Failed to update bblayers.conf: {e}", file=sys.stderr)


def rewrite_url_for_premirror(upstream_url: str, premirror_base: str) -> str:
    """Rewrite an upstream git URL into a premirror URL.

    Strips the protocol scheme and ``.git`` suffix, joins host and path
    components with dots, and appends the result to *premirror_base*.

    Examples:
        >>> rewrite_url_for_premirror(
        ...     'https://sourceware.org/git/binutils-gdb',
        ...     'https://git.example.com/mirror')
        'https://git.example.com/mirror/sourceware.org.git.binutils-gdb'
        >>> rewrite_url_for_premirror(
        ...     'git://git.savannah.gnu.org/grub.git',
        ...     'https://git.example.com/mirror/')
        'https://git.example.com/mirror/git.savannah.gnu.org.grub'

    Args:
        upstream_url: Original upstream git URL (https, git, or http).
        premirror_base: Base URL to prepend (trailing slash is handled).

    Returns:
        The rewritten premirror URL.
    """
    # Strip protocol scheme
    url = upstream_url
    for prefix in ('https://', 'http://', 'git://'):
        if url.startswith(prefix):
            url = url[len(prefix):]
            break

    # Strip trailing .git suffix
    url = url.removesuffix('.git')

    # Strip trailing slash
    url = url.rstrip('/')

    # Join host + path with dots: split on '/' and rejoin with '.'
    parts = url.split('/')
    mirror_name = '.'.join(parts)

    # Ensure base has no trailing slash, then join
    base = premirror_base.rstrip('/')
    return f"{base}/{mirror_name}"


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
    """Deduce meta-layer path from recipe using bitbake-layers.

    Returns the layer directory containing the recipe, or None if it cannot
    be determined. On failure, diagnostics are written to stderr: silently
    returning None makes the caller report a generic "Could not deduce
    meta-layer", which is indistinguishable from (and has in practice been
    confused with) a broken bitbake environment, a parse error, or an
    unreachable fetch mirror.
    """
    cmd = ['bitbake-layers', 'show-recipes', '-f', recipe]
    result = run_cmd_capture(cmd)
    for line in result.stdout.splitlines():
        if line.startswith('/') and recipe in line and '.bb' in line:
            recipe_path = Path(line.strip())
            for parent in recipe_path.parents:
                if parent.name.startswith('meta') or parent.name == 'openembedded-core':
                    return parent

    print(f"deduce_meta_layer_from_recipe: no layer found for {recipe!r}",
          file=sys.stderr)
    print(f"  command: {' '.join(cmd)} (exit {result.returncode})",
          file=sys.stderr)
    if result.returncode != 0:
        print("  bitbake-layers failed — the environment or metadata is "
              "broken, this is not a missing recipe", file=sys.stderr)
    elif not result.stdout.strip():
        print("  bitbake-layers succeeded but produced no output",
              file=sys.stderr)
    else:
        print("  bitbake-layers produced output, but no line matched "
              f"'/...{recipe}....bb' — recipe may not exist in any "
              "configured layer", file=sys.stderr)
    for stream_name, stream in (('stdout', result.stdout),
                                ('stderr', result.stderr)):
        tail = (stream or '').strip().splitlines()[-25:]
        if tail:
            print(f"  --- {stream_name} (last {len(tail)} lines) ---",
                  file=sys.stderr)
            for line in tail:
                print(f"  {line}", file=sys.stderr)
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


def check_cve_patch_in_src_uri(recipe: str, cve_id: str) -> Optional[str]:
    """Check whether a CVE patch file is already listed in the recipe's SRC_URI.

    Runs ``bitbake-getvar SRC_URI -r <recipe>`` and looks for a
    ``file://<CVE_ID>.patch`` entry (case-insensitive), which is the
    Yocto/OE convention for CVE fix patches (e.g. ``CVE-2024-1234.patch``).

    Args:
        recipe: Recipe name to query.
        cve_id: CVE identifier to look for (e.g. ``"CVE-2024-1234"``).

    Returns:
        The matching patch filename (e.g. ``"CVE-2024-1234.patch"``) if
        found in SRC_URI, or None if not found or SRC_URI could not be
        determined.
    """
    result = run_cmd_capture(['bitbake-getvar', 'SRC_URI', '-r', recipe])
    if result.returncode != 0:
        return None

    src_uri = ''
    for line in result.stdout.splitlines():
        if line.startswith('SRC_URI='):
            src_uri = line.split('=', 1)[1].strip('"')
            break

    pattern = re.compile(rf'{re.escape(cve_id)}\.patch', re.IGNORECASE)
    for entry in src_uri.split():
        if not entry.startswith('file://'):
            continue
        filename = entry[len('file://'):].split(';')[0]
        filename = Path(filename).name
        if pattern.fullmatch(filename):
            return filename
    return None


# Maps CVE_STATUS reason keywords to their final CVE_CHECK_STATUSMAP state.
# Mirrors the default mapping in oe-core's meta/conf/cve-check-map.conf.
# Reasons not listed here are treated as "Unpatched" (e.g. "unpatched",
# "vulnerable-investigating") and do not block backporting.
_CVE_STATUS_IGNORED_REASONS = frozenset({
    'ignored', 'cpe-incorrect', 'disputed', 'not-applicable-config',
    'not-applicable-platform', 'upstream-wontfix',
})
_CVE_STATUS_PATCHED_REASONS = frozenset({
    'patched', 'backported-patch', 'cpe-stable-backport', 'fixed-version',
})


def _decode_cve_status_cpe(raw_value: str) -> tuple[str, str]:
    """Extract the ``cpe:`` scope from a CVE_STATUS value.

    Mirrors ``decode_cve_status()`` in oe-core's ``meta/lib/oe/cve_check.py``.
    The grammar is ``<detail>: cpe:<vendor>:<product>:<description>``, where
    vendor and product are both mandatory when ``cpe:`` is present. Anything
    else (no ``cpe:`` segment, or a malformed one, which oe-core warns about
    and then ignores) leaves the scope unrestricted.

    Args:
        raw_value: The full CVE_STATUS value.

    Returns:
        A ``(vendor, product)`` tuple, each ``"*"`` when unrestricted.
    """
    parts = raw_value.split(':', 4)
    if len(parts) >= 4 and parts[1].strip() == 'cpe':
        return parts[2].strip(), parts[3].strip()
    return '*', '*'


def get_cve_product(recipe: str) -> Optional[str]:
    """Get the recipe's CVE_PRODUCT — the CPE product(s) it is scanned as.

    The recipe name is deliberately *not* used as a fallback: it is often not
    the CPE product (zstd is scanned as ``zstandard``, tcpdump as
    ``tcpdump:tcpdump``), so substituting it could invent a scope match that
    oe-core would not make.

    Args:
        recipe: Recipe name to query.

    Returns:
        The CVE_PRODUCT value, a space-separated list whose entries are
        either ``<product>`` or ``<vendor>:<product>``. An empty string is
        returned as-is — oe-core excludes such recipes from CVE checking, so
        no scope matches. Returns None if the product could not be
        determined.
    """
    result = run_cmd_capture(['bitbake-getvar', 'CVE_PRODUCT', '-r', recipe, '--value'])
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _has_cve_product_match(vendor: str, product: str, cve_products: str) -> bool:
    """Check a CVE_STATUS ``cpe:`` scope against a recipe's CVE_PRODUCT.

    Mirrors ``has_cve_product_match()`` in oe-core's
    ``meta/lib/oe/cve_check.py``: a ``"*"`` on the CVE_STATUS side matches
    anything, and CVE_PRODUCT entries may be ``<vendor>:<product>`` pairs.

    Args:
        vendor: Vendor from the CVE_STATUS ``cpe:`` scope.
        product: Product from the CVE_STATUS ``cpe:`` scope.
        cve_products: The recipe's CVE_PRODUCT value.

    Returns:
        True if any CVE_PRODUCT entry falls within the scope.
    """
    for entry in cve_products.split():
        entry_vendor = '*'
        entry_product = entry
        if ':' in entry:
            entry_vendor, entry_product = entry.split(':', 1)

        if ((entry_vendor == vendor or vendor == '*')
                and (entry_product == product or product == '*')):
            return True
    return False


def check_cve_status(recipe: str, cve_id: str) -> Optional[tuple[str, str]]:
    """Check the recipe's existing CVE_STATUS flag for this CVE.

    Runs ``bitbake-getvar CVE_STATUS -f <cve_id> -r <recipe> --value`` and,
    if set, maps the "reason: description" value to the final CVE state
    (``Patched``, ``Unpatched``, or ``Ignored``) using the same reason
    keywords as oe-core's ``cve-check-map.conf``.

    A CVE_STATUS value may carry a ``cpe:<vendor>:<product>:`` scope that
    limits it to matching recipes. Such entries are typically set distro-wide
    (oe-core's own ``cve-extra-exclusions.inc`` is entirely scoped this way),
    which makes the varflag visible from *every* recipe's datastore —
    ``bitbake-getvar`` returns it regardless of the scope. A scope that does
    not match this recipe's CVE_PRODUCT is therefore treated as no status
    being set, exactly as oe-core's cve-check does.

    Args:
        recipe: Recipe name to query.
        cve_id: CVE identifier to look for (e.g. ``"CVE-2024-1234"``).

    Returns:
        A ``(state, raw_value)`` tuple where ``state`` is one of
        ``"Patched"``, ``"Unpatched"``, or ``"Ignored"``, and ``raw_value``
        is the full ``CVE_STATUS`` value as set in the recipe. Returns
        None if CVE_STATUS is not set for this CVE, does not apply to this
        recipe, or if either it or the recipe's CVE_PRODUCT could not be
        determined.
    """
    result = run_cmd_capture([
        'bitbake-getvar', 'CVE_STATUS', '-f', cve_id, '-r', recipe,
        '--value', '--ignore-undefined'])
    if result.returncode != 0:
        return None

    raw_value = result.stdout.strip()
    if not raw_value:
        return None

    vendor, product = _decode_cve_status_cpe(raw_value)
    if (vendor, product) != ('*', '*'):
        cve_products = get_cve_product(recipe)
        # An undeterminable CVE_PRODUCT means the scope cannot be evaluated.
        # Report no status rather than guess: honouring an entry that may not
        # apply skips the CVE silently, which is the failure this scope check
        # exists to prevent.
        if cve_products is None or not _has_cve_product_match(vendor, product, cve_products):
            return None

    reason = raw_value.split(':', 1)[0].strip().lower()
    if reason in _CVE_STATUS_IGNORED_REASONS:
        state = 'Ignored'
    elif reason in _CVE_STATUS_PATCHED_REASONS:
        state = 'Patched'
    else:
        state = 'Unpatched'
    return state, raw_value


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
