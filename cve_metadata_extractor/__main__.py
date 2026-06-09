# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
'''Extract CVE metadata for known_affected CVEs.

This is the CLI entry point for the cve_metadata_extractor package.
Run with: python3 -m cve_metadata_extractor [options]
'''
import argparse
import json
import logging
import os
import sys

# Import source modules so they register themselves in SOURCE_REGISTRY.
from . import cvelistv5 as _cvelistv5  # noqa: F401
from . import debian as _debian  # noqa: F401
from . import load_cves_from_sources, load_pr_cache, process_cve
from . import osv as _osv  # noqa: F401
from . import ubuntu as _ubuntu  # noqa: F401
from .config import load_config
from .sources import SOURCE_REGISTRY
from .utils import PR_CACHE


def _get_version() -> str:
    from importlib.metadata import PackageNotFoundError, version
    try:
        return version('yocto-security-tools')
    except PackageNotFoundError:
        return 'dev'


def parse_arguments(cfg):
    '''Parse command line arguments.

    Args:
        cfg: Default configuration dict from config.json.
    '''
    parser = argparse.ArgumentParser(
        description='Extract CVE metadata for known_affected CVEs')
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {_get_version()}')

    # --- Input sources ---
    input_group = parser.add_argument_group('input sources (at least one required)')
    input_group.add_argument('--yocto-summary',
                       help='Path to Yocto cve-summary.json or sbom-cve-check output')
    input_group.add_argument('--cve-id', nargs='+',
                       help='One or more CVE IDs to process')
    input_group.add_argument('--cve-component-name',
                       help='Component name (used with --cve-id)')
    input_group.add_argument('--cve-component-version',
                       help='Component version (used with --cve-id)')
    input_group.add_argument('--historical', action='store_true',
                       help='Include backported-patch CVEs')

    # --- Output ---
    output_group = parser.add_argument_group('output')
    output_group.add_argument('--output', default='cve-metadata.json',
                       help='Output JSON file (default: %(default)s)')
    output_group.add_argument('--cache', default=cfg['cache_dir'],
                       help='Cache directory (default: %(default)s)')
    output_group.add_argument('--refresh', action='store_true',
                       help='Skip cache and fetch fresh data')
    output_group.add_argument('--download-patches', action='store_true',
                       help='Download .patch files and extract Debian source patches')

    # --- OE integration ---
    oe_group = parser.add_argument_group('OpenEmbedded integration')
    oe_group.add_argument('--check-oe', action='store_true',
                       help='Check CVE fix status in OpenEmbedded branches')
    oe_group.add_argument('--oe-branch', action='append',
                       default=list(cfg['oe_branches']),
                       help='OE branch to check (default: %(default)s)')
    oe_group.add_argument('--oe-token', help='OpenEmbedded API token (or set OPENEMBEDDED_TOKEN)')
    oe_group.add_argument('--repo-dir', default=cfg['repo_dir'],
                       help='Git repositories directory (default: %(default)s)')

    # --- Source control ---
    source_group = parser.add_argument_group('data sources (disable with --no-*)')
    source_group.add_argument('--no-debian', action='store_true',
                       help='Disable Debian security-tracker')
    source_group.add_argument('--no-cvelistv5', action='store_true',
                       help='Disable CVEListV5')
    source_group.add_argument('--no-nvd', action='store_true',
                       help='Disable NVD')
    source_group.add_argument('--no-osv', action='store_true',
                       help='Disable OSV')
    source_group.add_argument('--no-ubuntu', action='store_true',
                       help='Disable Ubuntu tracker')

    # --- Source directories (advanced) ---
    dirs_group = parser.add_argument_group('data source directories (advanced)')
    dirs_group.add_argument('--debian-tracker-dir',
                       default=cfg.get('debian_tracker_dir'),
                       help='Debian security-tracker clone (default: %(default)s)')
    dirs_group.add_argument('--debian-release',
                       default=cfg.get('debian_release', 'bookworm'),
                       help='Debian release for source patches (default: %(default)s)')
    dirs_group.add_argument('--cvelistv5-dir',
                       default=cfg.get('cvelistv5_dir'),
                       help='CVEListV5 clone (default: %(default)s)')
    dirs_group.add_argument('--nvd-dir',
                       default=cfg.get('nvd_dir'),
                       help='NVD data clone (default: %(default)s)')

    # Register CLI args from plugins (extra/ directory)
    # Built-in source args are already added above; only add new ones from plugins
    _builtin_flags = {
        '--debian-tracker-dir', '--no-debian', '--download-patches',
        '--debian-release', '--cvelistv5-dir', '--no-cvelistv5',
        '--nvd-dir', '--no-nvd', '--no-osv', '--no-ubuntu',
    }
    plugin_group = None
    for source in SOURCE_REGISTRY:
        for flags, kwargs in source.cli_args:
            if flags[0] in _builtin_flags:
                continue
            if plugin_group is None:
                plugin_group = parser.add_argument_group('plugin sources')
            kw = dict(kwargs)
            default_key = _cfg_key_for_flag(flags[0])
            if default_key and default_key in cfg and 'default' not in kw:
                kw['default'] = cfg[default_key]
            if 'help' in kw and '{default}' in kw['help']:
                kw['help'] = kw['help'].format(default=kw.get('default', ''))
            plugin_group.add_argument(*flags, **kw)

    return parser.parse_args()


def _cfg_key_for_flag(flag):
    '''Map a CLI flag like --debian-tracker-dir to config key debian_tracker_dir.'''
    return flag.lstrip('-').replace('-', '_')


def _print_summary(results, stats, args):
    '''Print summary statistics after processing.'''
    total_hashes = sum(len(r['hashes']) for r in results.values())
    total_patches = sum(len(r['patches']) for r in results.values())
    cves_with_hashes = sum(1 for r in results.values() if r['hashes'])
    cves_with_patches = sum(1 for r in results.values() if r['patches'])
    cves_without_metadata = sum(1 for r in results.values()
                                if not r['hashes'] and not r['patches'])
    cves_with_pr_series = sum(1 for r in results.values() if r.get('series'))

    print("\nSUMMARY:")
    print(f"  Total CVEs processed: {len(results)}")
    print(f"  CVEs with hashes: {cves_with_hashes}")
    print(f"  CVEs with patches: {cves_with_patches}")
    print(f"  CVEs without any metadata: {cves_without_metadata}")
    print(f"  CVEs with PR series: {cves_with_pr_series}")
    print(f"  GitHub PRs fetched: {len(PR_CACHE)}")
    print(f"  Total hashes found: {total_hashes}")
    print(f"  Total patches found: {total_patches}")

    if args.check_oe:
        for branch in args.oe_branch:
            branch_fixed = sum(
                1 for r in results.values()
                if r.get('upstream_status', {}).get(branch) and
                'merged' in r['upstream_status'][branch])
            print(f"  {branch} fixes found: {branch_fixed}")

    print("\nBy source:")
    for source in SOURCE_REGISTRY:
        if not source.name:
            continue
        h = stats.get(f'{source.name}_hashes', 0)
        p = stats.get(f'{source.name}_patches', 0)
        print(f"  {source.name:<12} - CVEs with hashes: {h}, "
              f"CVEs with patches: {p}")

    if args.download_patches:
        deb_src_cves = sum(1 for r in results.values()
                           if r.get('debian_source_patches'))
        deb_src_total = sum(len(r['debian_source_patches'])
                            for r in results.values()
                            if r.get('debian_source_patches'))
        print(f"  Debian source patches: {deb_src_cves} CVEs, "
              f"{deb_src_total} total patches")

    # CVSS score distribution
    buckets = {i: {'total': 0, 'with_hashes': 0, 'with_patches': 0,
                   'with_deb_patches': 0}
               for i in range(11)}
    unscored = 0
    for r in results.values():
        try:
            bucket = min(int(float(r.get('cvss3_score'))), 10)
        except (TypeError, ValueError):
            unscored += 1
            continue
        buckets[bucket]['total'] += 1
        if r.get('hashes'):
            buckets[bucket]['with_hashes'] += 1
        if r.get('patches'):
            buckets[bucket]['with_patches'] += 1
        if r.get('debian_source_patches'):
            buckets[bucket]['with_deb_patches'] += 1

    print("\nBy CVSS score:")
    print(f"  {'Score':<6} {'Total':<7} {'w/Hashes':<10} "
          f"{'w/Patches':<11} {'w/Deb Patches'}")
    for i in range(11):
        b = buckets[i]
        if b['total']:
            print(f"  {i:<6} {b['total']:<7} {b['with_hashes']:<10} "
                  f"{b['with_patches']:<11} {b['with_deb_patches']}")
    if unscored:
        print(f"  {'N/A':<6} {unscored}")

    if args.download_patches:
        downloaded = sum(1 for r in results.values()
                         if r.get('downloaded_patches'))
        if downloaded:
            print(f"\nDownloaded patches for {downloaded} CVEs to: "
                  f"{os.path.abspath(args.cache)}")
        deb_cves = sum(1 for r in results.values()
                       if r.get('debian_source_patches'))
        deb_total = sum(len(r['debian_source_patches'])
                        for r in results.values()
                        if r.get('debian_source_patches'))
        if deb_cves:
            print(f"\nDebian source patches: {deb_total} patches "
                  f"extracted for {deb_cves} CVEs "
                  f"to: {os.path.abspath(args.cache)}")


def main():
    '''Main function.'''
    cfg = load_config()
    args = parse_arguments(cfg)

    logging.basicConfig(format='[%(filename)s:%(lineno)d] %(message)s',
                       level=logging.INFO)

    # Check if at least one input source is provided (built-in or plugin)
    has_builtin_input = any([args.cve_id, args.yocto_summary])
    has_plugin_input = any(
        s.is_input_source and s.is_enabled(args)
        for s in SOURCE_REGISTRY
    )
    if not has_builtin_input and not has_plugin_input:
        print("ERROR: At least one input source required "
              "(--yocto-summary or --cve-id)",
              file=sys.stderr)
        from shared.exit_codes import EXIT_METADATA_ERROR
        sys.exit(EXIT_METADATA_ERROR)

    load_pr_cache()

    # Warn early if GITHUB_TOKEN is missing (needed for PR metadata)
    if not os.getenv('GITHUB_TOKEN'):
        print("WARNING: GITHUB_TOKEN not set. GitHub pull request metadata "
              "(commit series) will not be available.", file=sys.stderr)

    # Setup all sources (auth, clone repos, load data)
    for source in SOURCE_REGISTRY:
        source.setup(args, cfg)

    # Determine which sources are active
    active_sources = [s for s in SOURCE_REGISTRY if s.is_enabled(args) and s.name]
    print(f"Active sources: {', '.join(s.name for s in active_sources)}")

    # Initialize stats from active sources
    stats = {f'{s.name}_{k}': 0
             for s in SOURCE_REGISTRY if s.name for k in ('hashes', 'patches')}

    # OE token
    oe_token = args.oe_token or os.getenv('OPENEMBEDDED_TOKEN')
    if args.check_oe and oe_token and not os.path.isdir(args.repo_dir):
        os.makedirs(args.repo_dir)

    known_affected = load_cves_from_sources(
        args.cve_id,
        args.cve_component_name, args.cve_component_version,
        args.historical, args.yocto_summary
    )
    print(f"Found {len(known_affected)} CVEs to process")

    results = {}
    for idx, cve in enumerate(known_affected, 1):
        result = process_cve(
            cve, idx, len(known_affected), args,
            active_sources, stats, oe_token)
        if result:
            results[cve['id']] = result

    print(f"\nSaving results to {args.output}...")
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    _print_summary(results, stats, args)


if __name__ == '__main__':
    main()
