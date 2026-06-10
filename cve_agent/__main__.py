#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""CVE Backporting Agent — CLI entry point and batch processing.

Run with: python3 -m cve_agent [options]
"""
import argparse
import dataclasses
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from shared.paths import data_dir

from . import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_SESSION_TIMEOUT,
    EXIT_AGENT_ERROR,
    EXIT_TRUST_DECLINED,
    AgentConfig,
    CveResult,
    ResultStatus,
)
from .corrector import get_workspace_path, load_cve_metadata
from .git import run_git_stdout
from .knowledge import KnowledgeBase
from .orchestrator import process_single_cve
from .setup import ensure_agents

logger = __import__('logging').getLogger(__name__)


def _get_version() -> str:
    from importlib.metadata import PackageNotFoundError, version
    try:
        return version('yocto-security-tools')
    except PackageNotFoundError:
        return 'dev'


# --- Trust Mode Warning ---

def _show_trust_warning() -> bool:
    """Display trust mode warning and require explicit confirmation."""
    print(
        "\n\u26a0\ufe0f  WARNING: --trust mode enabled. The agent will operate "
        "without human review.\n\n"
        "This is NOT recommended. Automated conflict resolution may:\n"
        "  - Introduce subtle bugs that change fix semantics\n"
        "  - Miss context that requires human judgment\n"
        "  - Produce patches that pass build/ptest but are logically "
        "incorrect\n\n"
        "Human review of conflict resolutions is strongly recommended.\n"
    )
    response = input("Continue in trust mode? [y/N]: ").strip().lower()
    return response == 'y'


# --- Logging ---

def _log_result(config: AgentConfig, result: CveResult,
                workspace_path: Optional[Path] = None) -> None:
    """Append result entry to the CVE agent log file."""
    bbpath = os.environ.get('BBPATH', '')
    if not bbpath:
        return
    build_ws = Path(bbpath.split(':')[0]) / 'workspace' / 'cve_agent'
    build_ws.mkdir(parents=True, exist_ok=True)
    log_file = build_ws / 'cve_agent.log'

    lines = [
        f"[{datetime.now(timezone.utc).isoformat()}] "
        f"{result.cve_id} | {result.status.value} | "
        f"{result.duration:.1f}s | retries={result.retries} | "
        f"{result.resolution_summary}"
    ]

    ws_path = workspace_path
    if ws_path is None:
        try:
            cve_data = load_cve_metadata(config.cve_info_path)
            ws_path = get_workspace_path(config, cve_data)
        except Exception:
            logger.debug("Could not resolve workspace for %s", result.cve_id, exc_info=True)

    try:
        if ws_path:
            diff_stat = run_git_stdout(['diff', '--stat', 'original-version..HEAD'], ws_path)
            if diff_stat:
                lines.append(f"  diff-stat: {diff_stat}")
            diff = run_git_stdout(['diff', 'original-version..HEAD'], ws_path)
            if diff:
                if len(diff) > 50_000:
                    diff = diff[:50_000] + "\n... (truncated, >50KB)"
                lines.append(f"  diff:\n{diff}")
    except Exception:
        logger.debug("Failed to capture diff for %s", result.cve_id, exc_info=True)

    with open(log_file, 'a', encoding='utf-8') as log_fh:
        log_fh.write('\n'.join(lines) + '\n\n')


# --- Batch Processing ---

def _process_batch(cve_list: list[str], config_template: AgentConfig,
                   knowledge_base: KnowledgeBase) -> list[CveResult]:
    """Process a list of CVEs sequentially."""
    results: list[CveResult] = []
    total = len(cve_list)

    for idx, cve_id in enumerate(cve_list, 1):
        print(f"\n[{idx}/{total}] {cve_id}")
        config = dataclasses.replace(config_template, cve_id=cve_id)

        result = process_single_cve(config, knowledge_base)
        _log_result(config, result)
        results.append(result)
        print(f"  Result: {result.status.value} — {result.resolution_summary}")

        if result.status in (ResultStatus.FAILED, ResultStatus.ESCALATED) and not config_template.trust_mode:
            response = input(
                "Skip and continue to next CVE? [Y/n]: "
            ).strip().lower()
            if response in ('n', 'no'):
                break

    return results


def _print_batch_summary(results: list[CveResult]) -> None:
    """Print a summary of batch processing results."""
    print(f"\n{'=' * 60}")
    print("BATCH SUMMARY")
    print(f"{'=' * 60}")
    print(f"Total CVEs processed: {len(results)}")

    counts: dict[str, int] = {}
    for result in results:
        counts[result.status.value] = counts.get(result.status.value, 0) + 1

    for status, count in sorted(counts.items()):
        print(f"  {status}: {count}")

    print("\nPer-CVE results:")
    for result in results:
        retries_info = f" ({result.retries} retries)" if result.retries else ""
        print(f"  {result.cve_id}: {result.status.value}{retries_info}")

    print(f"{'=' * 60}")


def _save_results(results: list[CveResult]) -> None:
    """Save detailed results to a timestamped file."""
    results_dir = data_dir() / 'results'
    results_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    filepath = results_dir / f"backport_agent_results_{timestamp}.txt"
    with open(filepath, 'w', encoding='utf-8') as file:
        file.write(f"CVE Agent Results - {timestamp}\n")
        file.write("=" * 60 + "\n\n")
        for result in results:
            file.write(
                f"{result.cve_id}: {result.status.value} "
                f"(retries={result.retries}, "
                f"duration={result.duration:.1f}s)\n"
                f"  {result.resolution_summary}\n\n"
            )
    print(f"Results saved to: {filepath}")


# --- Signal Handling ---

def _sigint_handler(results: list[CveResult]):
    """Return a SIGINT handler that saves partial results on interrupt."""
    def handler(signum, frame) -> None:
        print("\n\nInterrupted by user (Ctrl+C).")
        if results:
            _print_batch_summary(results)
            _save_results(results)
            print(f"\nPartial progress saved ({len(results)} CVEs completed).")
        else:
            print("No results to save.")
        sys.exit(EXIT_AGENT_ERROR)
    return handler


# --- CLI Entry Point ---

def _parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="CVE Backporting Agent - AI-assisted CVE fix orchestration"
    )
    parser.add_argument('--version', action='version',
                        version=f'%(prog)s {_get_version()}')

    # --- Input ---
    input_group = parser.add_argument_group('input')
    cve_group = input_group.add_mutually_exclusive_group(required=True)
    cve_group.add_argument('--cve-id', help='Single CVE identifier')
    cve_group.add_argument('--cve-list', type=Path,
                           help='File with CVE IDs, one per line')
    input_group.add_argument('--cve-info', type=Path,
                        help='JSON file with CVE metadata')
    input_group.add_argument('--fix-url',
                        help='URL of fix commit or pull request')
    input_group.add_argument('--recipe',
                        help='Recipe name (required with --fix-url without --cve-info)')

    # --- AI session ---
    ai_group = parser.add_argument_group('AI session')
    ai_group.add_argument('--backend', default='kiro',
                        help='AI backend to use (default: %(default)s)')
    ai_group.add_argument('--model', default='claude-sonnet-4.6',
                        help='Model for AI sessions (default: %(default)s)')
    ai_group.add_argument('--max-retries', type=int, default=DEFAULT_MAX_RETRIES,
                        help='Max resolution attempts (default: %(default)s)')
    ai_group.add_argument('--session-timeout', type=int,
                        default=DEFAULT_SESSION_TIMEOUT,
                        help='Timeout per session in seconds (default: %(default)s)')
    ai_group.add_argument('--trust', action='store_true',
                        help='Skip human review (NOT recommended)')
    ai_group.add_argument('--interactive', action='store_true',
                        help='Enable interactive mode')

    # --- Build control ---
    build_group = parser.add_argument_group('build control')
    build_group.add_argument('--skip-ptest', action='store_true',
                        help='Skip ptest execution')
    build_group.add_argument('--skip-cve-applicability', action='store_true',
                        help='Skip git-blame based CVE applicability check')
    build_group.add_argument('--clean', action='store_true',
                        help='Clean workspace before starting')

    # --- Output ---
    output_group = parser.add_argument_group('output')
    output_group.add_argument('--meta-layer', type=Path,
                        help='Destination meta-layer for devtool finish')
    output_group.add_argument('--bbappend', action='store_true',
                        help='Create a bbappend instead of modifying the original recipe')

    # --- Environment ---
    env_group = parser.add_argument_group('environment')
    env_group.add_argument('--mirror-dir', type=Path,
                        help='Directory with bare repository mirrors')

    return parser.parse_args()


def _read_cve_list(cve_list_path: Path) -> list[str]:
    """Read CVE IDs from a file, one per line."""
    if not cve_list_path.exists():
        print(f"Error: CVE list file not found: {cve_list_path}",
              file=sys.stderr)
        sys.exit(EXIT_AGENT_ERROR)

    lines = cve_list_path.read_text(encoding='utf-8').splitlines()
    return [line.strip() for line in lines if line.strip()]


def _config_from_args(args: argparse.Namespace,
                      cve_id: Optional[str] = None) -> AgentConfig:
    """Create an AgentConfig from parsed CLI arguments."""
    return AgentConfig(
        cve_id=cve_id if cve_id is not None else (args.cve_id or ""),
        cve_info_path=args.cve_info,
        trust_mode=args.trust,
        max_retries=args.max_retries,
        mirror_dir=args.mirror_dir,
        meta_layer=args.meta_layer,
        skip_ptest=args.skip_ptest,
        clean=args.clean,
        model=args.model,
        session_timeout=args.session_timeout,
        bbappend=args.bbappend,
        skip_cve_applicability=args.skip_cve_applicability,
        interactive=args.interactive,
        fix_url=args.fix_url,
        recipe=args.recipe,
        backend=args.backend,
    )


def main() -> None:
    """Main entry point for the CVE agent."""
    results: list[CveResult] = []
    signal.signal(signal.SIGINT, _sigint_handler(results))
    args = _parse_args()

    if not args.cve_info and not args.fix_url:
        print("Error: --cve-info or --fix-url is required", file=sys.stderr)
        sys.exit(EXIT_AGENT_ERROR)
    if args.fix_url and not args.cve_info and not args.recipe:
        print("Error: --recipe is required when using --fix-url without "
              "--cve-info", file=sys.stderr)
        sys.exit(EXIT_AGENT_ERROR)

    if args.backend == 'kiro':
        ensure_agents(interactive=not args.trust)

    if args.trust and not _show_trust_warning():
        print("Trust mode declined. Exiting.")
        sys.exit(EXIT_TRUST_DECLINED)

    knowledge_base = KnowledgeBase()

    if args.cve_id:
        from .corrector import validate_cve_id
        if not validate_cve_id(args.cve_id):
            print(f"Invalid CVE ID format: {args.cve_id}", file=sys.stderr)
            sys.exit(EXIT_AGENT_ERROR)
        config = _config_from_args(args, args.cve_id)
        result = process_single_cve(config, knowledge_base)
        print(f"\n\u2713 {result.cve_id}: {result.status.value}")
        _log_result(config, result)
        if result.resolution_summary:
            print(f"  {result.resolution_summary}")
        if result.status not in (ResultStatus.SUCCESS,
                                 ResultStatus.CONFLICT_RESOLVED,
                                 ResultStatus.SKIPPED):
            sys.exit(EXIT_AGENT_ERROR)
    else:
        cve_list = _read_cve_list(args.cve_list)
        config_template = _config_from_args(args)
        results = _process_batch(cve_list, config_template, knowledge_base)
        _print_batch_summary(results)
        _save_results(results)
        failed = sum(
            1 for r in results
            if r.status in (ResultStatus.FAILED, ResultStatus.ESCALATED)
        )
        if failed:
            sys.exit(EXIT_AGENT_ERROR)


if __name__ == '__main__':
    main()
