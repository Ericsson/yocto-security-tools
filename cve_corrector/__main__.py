#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Automated CVE patching tool for Yocto recipes.

Automates the process of backporting CVE fixes to Yocto recipes by:
- Cherry-picking upstream CVE fix commits onto recipe version tags
- Verifying pre-patch build integrity before applying fixes
- Running ptests before and after patching to verify no regressions
- Generating properly formatted patches with CVE tags and metadata
- Integrating patches into meta-layers with git commits
- Supporting resume workflow for manual conflict resolution

Exit codes (canonical definitions in cve_corrector/state.py):
- 0:  Success
- 1:  Conflict detected (manual resolution required)
- 2:  Checkout/version error
- 3:  Ptest error (post-patch)
- 4:  Build error (post-patch)
- 5:  Patch generation/application error
- 6:  Metadata/configuration error
- 7:  Git operation error
- 8:  Pre-existing ptest failure (recipe tests already broken)
- 9:  Devtool error
- 10: Pre-existing build failure (recipe already broken before patching)
- 11: CVE fix already present in source tree
- 12: Vulnerable code not present in recipe version (not applicable)
- 16: Recipe's CVE_STATUS marks this CVE as Ignored or already Patched
"""
import argparse
import os
import shutil
import signal
import sys
from pathlib import Path
from typing import Optional

from . import (
    EXIT_ALREADY_APPLIED,
    EXIT_IGNORED_BY_STATUS,
    EXIT_METADATA_ERROR,
    WorkflowConfig,
    continue_from_conflict,
    deduce_meta_layer_from_recipe,
    find_mirror_repo,
    finish_cve_workflow,
    initialize_cve_workflow,
    load_cve_metadata,
    resolve_meta_layer,
)
from .bitbake_ops import (
    check_cve_patch_in_src_uri,
    check_cve_status,
    cleanup_workspace,
    get_build_path,
)
from .state import WorkflowError
from .utils import logger, setup_logging


def _get_version() -> str:
    from importlib.metadata import PackageNotFoundError, version
    try:
        return version('yocto-security-tools')
    except PackageNotFoundError:
        return 'dev'


def _check_bitbake_env() -> None:
    """Verify the Yocto/BitBake build environment is sourced."""
    if not os.environ.get('BBPATH'):
        print("Error: BBPATH not set — source the Yocto build environment "
              "first (e.g. 'source oe-init-build-env')", file=sys.stderr)
        sys.exit(EXIT_METADATA_ERROR)
    if not shutil.which('bitbake-layers'):
        print("Error: 'bitbake-layers' not found in PATH — source the Yocto "
              "build environment first", file=sys.stderr)
        sys.exit(EXIT_METADATA_ERROR)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Correct CVEs in Yocto recipes using devtool"
    )
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {_get_version()}')

    # --- Input ---
    input_group = parser.add_argument_group('input')
    input_group.add_argument('--cve-id',
                        help='CVE identifier (e.g., CVE-2024-1234)')
    input_group.add_argument('--cve-info', type=Path,
                        help='JSON file with CVE metadata (e.g., cve-metadata.json)')
    input_group.add_argument('--fix-url', action='append', default=[],
                        metavar='URL', dest='fix_urls',
                        help='URL of fix commit or pull request (repeatable). '
                             'Two or more URLs are applied as one dependent '
                             'series, in the order given, and all of them must '
                             'apply — a partial application is reported as a '
                             'conflict.')
    input_group.add_argument('--recipe',
                        help='Recipe name (required with --fix-url without --cve-info)')
    input_group.add_argument('--skip-source', action='append', default=[],
                        metavar='SOURCE', dest='skip_sources',
                        help='Ignore fix commits from this source (repeatable). '
                             'Commits also reported by a non-skipped source are kept.')
    input_group.add_argument(
        '--mainline-parent', type=int, metavar='N',
        help='Explicit 1-based direct parent for a selected merge fix commit')

    # --- Workflow mode ---
    mode_group = parser.add_argument_group('workflow mode')
    mode_group.add_argument('--continue', dest='continue_mode', action='store_true',
                        help='Continue after manual conflict resolution')
    mode_group.add_argument('--edit', action='store_true',
                        help='Stop after applying patch for manual editing')
    mode_group.add_argument('--manual', action='store_true',
                        help='Set up environment only; user applies patches manually')
    mode_group.add_argument('--dry-run', action='store_true',
                        help='Validate inputs and show what would be done without changes')
    mode_group.add_argument('--mark-not-applicable', metavar='REASON',
                        help='Write CVE_STATUS entry instead of patching')

    # --- Output ---
    output_group = parser.add_argument_group('output')
    output_group.add_argument('--meta-layer', type=Path,
                        help='Destination meta-layer for devtool finish')
    output_group.add_argument('--bbappend', action='store_true',
                        help='Create a bbappend instead of modifying the original recipe')

    # --- Build control ---
    build_group = parser.add_argument_group('build control')
    build_group.add_argument('--skip-build', action='store_true',
                        help='Skip devtool build step')
    build_group.add_argument('--skip-ptest', action='store_true',
                        help='Skip ptest execution')
    build_group.add_argument('--skip-cve-applicability', action='store_true',
                        help='Skip git-blame based CVE applicability check')
    build_group.add_argument('--clean', action='store_true',
                        help='Clean up workspace and start fresh')

    # --- Environment ---
    env_group = parser.add_argument_group('environment')
    env_group.add_argument('--mirror-dir', type=Path,
                        help='Directory containing bare repository mirrors')
    env_group.add_argument('--premirror', type=str,
                        help='Base URL for premirror. The upstream git URL is '
                             'rewritten by stripping protocol and .git suffix, '
                             'joining components with dots, and appending to this '
                             'base (e.g. https://host/path → <base>/host.path.repo)')

    env_group.add_argument('--yes', '-y', action='store_true',
                        help='Skip confirmation prompts')
    env_group.add_argument('--sign-off', action='store_true', default=None,
                        help='Add a Signed-off-by trailer to generated patches and '
                             'commits, using the git identity resolved from '
                             '`git config`. Off by default — only a human who has '
                             'reviewed the change can certify the DCO. With '
                             '--continue, omitting this flag preserves the choice '
                             'made on the original run; passing it again overrides.')
    env_group.add_argument('--verbose', '-v', action='store_true',
                        help='Show verbose output (live command execution)')

    args = parser.parse_args()

    if not args.dry_run:
        _check_bitbake_env()

    if args.continue_mode:
        try:
            state = continue_from_conflict()
            state.skip_confirm = args.yes
            # Only override the persisted choice when --sign-off is repeated;
            # omitting it on --continue must not silently unsign a run that
            # opted in on its original invocation.
            if args.sign_off is not None:
                state.sign_off = args.sign_off
            log_file = setup_logging(state.cve_id, get_build_path(), args.verbose)
            logger.info("Resuming %s for %s...", state.cve_id, state.recipe)
            logger.info("Log file: %s", log_file)
            finish_cve_workflow(state)
        except WorkflowError as e:
            logger.error(str(e))
            sys.exit(e.exit_code)
        return

    if not args.cve_id:
        parser.error('--cve-id is required (unless using --continue)')

    if args.fix_urls:
        from shared.url_parser import parse_fix_urls
        if not args.cve_info and not args.recipe:
            parser.error('--recipe is required when using --fix-url without --cve-info')
        try:
            url_metadata = parse_fix_urls(args.fix_urls)
        except ValueError as err:
            parser.error(str(err))
        if args.cve_info:
            cve_data = load_cve_metadata(args.cve_info)
            if args.cve_id not in cve_data:
                cve_data[args.cve_id] = {'name': args.recipe or ''}
            cve_data[args.cve_id]['hashes'] = url_metadata['hashes']
            cve_data[args.cve_id]['hash_details'] = url_metadata['hash_details']
            # A multi-URL chain is authoritative: replace any series from the
            # JSON so a stale PR series cannot compete with the explicit chain.
            if url_metadata['series'] or len(args.fix_urls) > 1:
                cve_data[args.cve_id]['series'] = url_metadata['series']
        else:
            cve_data = {args.cve_id: {'name': args.recipe, **url_metadata}}
    else:
        if not args.cve_info:
            parser.error('--cve-info is required (unless using --fix-url or --continue)')
        cve_data = load_cve_metadata(args.cve_info)

    if args.cve_id not in cve_data:
        print(f"CVE {args.cve_id} not found", file=sys.stderr)
        sys.exit(EXIT_METADATA_ERROR)

    cve_info = cve_data[args.cve_id]
    metadata_mainline = cve_info.get('mainline_parent')
    mainline_parent = (args.mainline_parent
                       if args.mainline_parent is not None
                       else metadata_mainline)
    if (mainline_parent is not None
            and (isinstance(mainline_parent, bool)
                 or not isinstance(mainline_parent, int)
                 or mainline_parent < 1)):
        parser.error('mainline parent must be a positive integer')
    recipe_name = cve_info.get('name') or args.recipe
    if not recipe_name:
        print("Recipe name not found", file=sys.stderr)
        sys.exit(EXIT_METADATA_ERROR)
    cve_info['name'] = recipe_name
    if args.skip_sources:
        from . import filter_by_skip_sources
        cve_info = filter_by_skip_sources(cve_info, args.skip_sources)
        cve_data[args.cve_id] = cve_info
    if not cve_info.get('hashes') and not cve_info.get('series'):
        print(f"CVE {args.cve_id} missing fix commits or series", file=sys.stderr)
        sys.exit(EXIT_METADATA_ERROR)

    if args.clean:
        cleanup_workspace(str(get_build_path()))

    # Fail fast if the recipe's CVE_STATUS already marks this CVE as
    # Ignored or Patched (a human decision recorded in the recipe) — skip
    # meta-layer deduction and the rest of the workflow entirely.
    if not args.mark_not_applicable and not args.dry_run:
        cve_status = check_cve_status(recipe_name, args.cve_id)
        if cve_status:
            status_state, raw_value = cve_status
            if status_state in ('Ignored', 'Patched'):
                print(f"CVE {args.cve_id}: CVE_STATUS marks recipe as "
                      f"{status_state} — {raw_value}")
                sys.exit(EXIT_IGNORED_BY_STATUS)

    # Fail fast if the CVE patch is already listed in the recipe's SRC_URI
    # (e.g. CVE-2024-1234.patch) — skip meta-layer deduction and the rest of
    # the workflow entirely, since none of it is needed in that case.
    if not args.mark_not_applicable and not args.dry_run:
        existing_patch = check_cve_patch_in_src_uri(recipe_name, args.cve_id)
        if existing_patch:
            print(f"CVE {args.cve_id}: already patched in recipe SRC_URI — "
                  f"{existing_patch}")
            sys.exit(EXIT_ALREADY_APPLIED)

    meta_layer: Optional[Path]
    if args.meta_layer:
        meta_layer = resolve_meta_layer(args.meta_layer)
    elif args.dry_run:
        meta_layer = None
    else:
        print(f"\n=== Deducing meta-layer from recipe {recipe_name} ===")
        meta_layer = deduce_meta_layer_from_recipe(recipe_name)
        if not meta_layer:
            print("Could not deduce meta-layer, please provide --meta-layer",
                  file=sys.stderr)
            sys.exit(EXIT_METADATA_ERROR)
    if meta_layer:
        print(f"Using meta-layer: {meta_layer}")
        if not meta_layer.is_dir():
            print(f"Meta-layer directory does not exist: {meta_layer}",
                  file=sys.stderr)
            sys.exit(EXIT_METADATA_ERROR)

    if args.mark_not_applicable:
        from .meta_layer import write_cve_status
        ok = write_cve_status(meta_layer, recipe_name, args.cve_id,
                              args.mark_not_applicable,
                              skip_confirm=args.yes,
                              sign_off=bool(args.sign_off))
        sys.exit(0 if ok else EXIT_METADATA_ERROR)

    mirror_path = None
    if args.mirror_dir:
        if not args.mirror_dir.is_dir():
            print(f"Error: --mirror-dir '{args.mirror_dir}' is not a valid directory",
                  file=sys.stderr)
            sys.exit(EXIT_METADATA_ERROR)
        hash_details = cve_data[args.cve_id].get('hash_details', [])
        mirror_path = find_mirror_repo(args.mirror_dir, recipe_name, hash_details)
        if mirror_path:
            print(f"Found mirror: {mirror_path}")
        else:
            print(f"No mirror found for '{recipe_name}', will deduce from hash details")

    # Two or more --fix-url values declare an ordered dependent chain: every
    # commit must apply or the run stops at a conflict (no single-commit
    # fallback, no least-conflict pick).
    require_all_commits = len(args.fix_urls) > 1

    if args.dry_run:
        hashes = cve_info.get('hashes', [])
        series = cve_info.get('series', [])
        print(f"\n=== Dry Run: {args.cve_id} ===")
        print(f"Recipe:     {recipe_name}")
        print(f"Meta-layer: {meta_layer}")
        print(f"Commits:    {len(hashes)}")
        print(f"Series:     {len(series)}")
        if require_all_commits:
            print(f"Dependent:  yes — all {len(hashes)} commit(s) must apply, in this order")
        if hashes:
            for h in hashes[:5]:
                print(f"  - {h[:12]}")
            if len(hashes) > 5:
                print(f"  ... and {len(hashes) - 5} more")
        print(f"Skip build: {args.skip_build}")
        print(f"Skip ptest: {args.skip_ptest}")
        print(f"Bbappend:   {args.bbappend}")
        print("\nNo changes made (dry-run mode).")
        return

    log_file = setup_logging(args.cve_id, get_build_path(), args.verbose)
    logger.info("Processing %s", args.cve_id)
    logger.info("Log file: %s", log_file)

    def _on_interrupt(signum, frame):
        print("\n\nInterrupted by user (Ctrl+C). Workflow state preserved.")
        print("Resume with: cve-corrector --continue")
        logger.info("Interrupted by user")
        sys.exit(EXIT_METADATA_ERROR)

    signal.signal(signal.SIGINT, _on_interrupt)

    try:
        state = initialize_cve_workflow(
            cve_data, args.cve_id, WorkflowConfig(
                mirror_path=mirror_path, mirror_dir=args.mirror_dir,
                meta_layer=meta_layer,
                skip_build=args.skip_build, clean=args.clean,
                skip_ptest=args.skip_ptest, edit_mode=args.edit,
                manual_mode=args.manual, bbappend=args.bbappend,
                skip_cve_applicability=args.skip_cve_applicability,
                skip_confirm=args.yes,
                require_all_commits=require_all_commits,
                sign_off=bool(args.sign_off),
                premirror=args.premirror,
                mainline_parent=mainline_parent))
        state.skip_confirm = args.yes

        finish_cve_workflow(state)
        logger.info("Log file: %s", log_file)
    except WorkflowError as e:
        logger.error(str(e))
        sys.exit(e.exit_code)


if __name__ == '__main__':
    main()
