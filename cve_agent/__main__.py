#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""CVE Backporting Agent — CLI entry point and batch processing.

Run with: python3 -m cve_agent [options]
"""
import argparse
import dataclasses
import json
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, cast

from shared.paths import data_dir

from . import (
    DEFAULT_MAX_RETRIES,
    DEFAULT_SESSION_TIMEOUT,
    EXIT_AGENT_ERROR,
    EXIT_TRUST_DECLINED,
    AgentConfig,
    CveResult,
    WorkflowStatus,
)
from .backend import (
    AIBackend,
    BackendRuntimeUnavailableError,
    get_backend,
    resolve_backend_selector,
)
from .corrector import get_workspace_path, load_cve_metadata
from .git import run_git_stdout
from .knowledge import KnowledgeBase
from .orchestrator import process_single_cve
from .setup import ensure_agents

logger = __import__('logging').getLogger(__name__)


def _command_succeeded(result: CveResult) -> bool:
    """Accept completed work or a trusted host decision to skip it."""
    return (
        result.outcome is not None
        and result.outcome.workflow_status in {
            WorkflowStatus.COMPLETED,
            WorkflowStatus.SKIPPED,
        }
    )


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

def _credits(result: CveResult, sep: str = " | ") -> str:
    """Render a CVE's total backend cost as ``<sep>credits=<amount> <unit>``,
    or ``''`` when the backend reported no cost, so callers can append it
    unconditionally. ``sep`` is ``" | "`` for log/summary lines and ``", "``
    for the saved-results parenthesized form.
    """
    if result.total_credits is None:
        return ""
    unit = result.credits_unit or "credits"
    return f"{sep}credits={result.total_credits:.2f} {unit}"


def _log_result(config: AgentConfig, result: CveResult,
                workspace_path: Optional[Path] = None) -> None:
    """Append result entry to the CVE agent log file."""
    bbpath = os.environ.get('BBPATH', '')
    if not bbpath:
        return
    build_ws = Path(bbpath.split(':')[0]) / 'workspace' / 'cve_agent'
    build_ws.mkdir(parents=True, exist_ok=True)
    log_file = build_ws / 'cve_agent.log'

    assert result.outcome is not None
    lines = [
        f"[{datetime.now(timezone.utc).isoformat()}] "
        f"{result.cve_id} | {result.outcome.summary_state} | "
        f"{result.duration:.1f}s | retries={result.retries}"
        f"{_credits(result)} | "
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

    result_file = build_ws / f"{result.cve_id}.result.json"
    temporary = result_file.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(result.to_dict(), sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(result_file)


# --- Batch Processing ---

def _process_batch(cve_list: list[str], config_template: AgentConfig,
                   knowledge_base: Optional[KnowledgeBase]) -> list[CveResult]:
    """Process a list of CVEs sequentially."""
    results: list[CveResult] = []
    total = len(cve_list)

    for idx, cve_id in enumerate(cve_list, 1):
        print(f"\n[{idx}/{total}] {cve_id}")
        config = dataclasses.replace(config_template, cve_id=cve_id)

        result = process_single_cve(config, knowledge_base)
        _log_result(config, result)
        results.append(result)
        assert result.outcome is not None
        print(f"  Result: {result.outcome.summary_state} — {result.resolution_summary}"
              f"{_credits(result)}")

        if not _command_succeeded(result) and not config_template.trust_mode:
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
        assert result.outcome is not None
        state = result.outcome.summary_state
        counts[state] = counts.get(state, 0) + 1

    for status, count in sorted(counts.items()):
        print(f"  {status}: {count}")

    print("\nPer-CVE results:")
    for result in results:
        retries_info = f" ({result.retries} retries)" if result.retries else ""
        assert result.outcome is not None
        print(f"  {result.cve_id}: {result.outcome.summary_state}{retries_info}"
              f"{_credits(result)}")

    costs = [r.total_credits for r in results if r.total_credits is not None]
    if costs:
        unit = next(r.credits_unit for r in results
                    if r.total_credits is not None) or "credits"
        print(f"\nTotal {unit}: {sum(costs):.2f}")

    print(f"{'=' * 60}")


def _save_results(results: list[CveResult]) -> None:
    """Save detailed results to a timestamped file."""
    results_dir = data_dir() / 'results'
    results_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    filepath = results_dir / f"backport_agent_results_{timestamp}.txt"
    json_filepath = results_dir / f"backport_agent_results_{timestamp}.json"
    with open(filepath, 'w', encoding='utf-8') as file:
        file.write(f"CVE Agent Results - {timestamp}\n")
        file.write("=" * 60 + "\n\n")
        for result in results:
            assert result.outcome is not None
            file.write(
                f"{result.cve_id}: {result.outcome.summary_state} "
                f"(retries={result.retries}, "
                f"duration={result.duration:.1f}s"
                f"{_credits(result, ', ')})\n"
                f"  {result.resolution_summary}\n\n"
            )
    json_filepath.write_text(
        json.dumps({
            "schema_version": 2,
            "results": [result.to_dict() for result in results],
        }, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"Results saved to: {filepath}")
    print(f"Machine-readable results saved to: {json_filepath}")


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
        description="CVE Backporting Agent - AI-assisted CVE fix orchestration",
        epilog=(
            "Native OpenAI-compatible sessions print their mandatory transcript "
            "path after each run. See docs/openai-compatible-backend.md."
        ),
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

    # --- AI session ---
    ai_group = parser.add_argument_group('AI session')
    ai_group.add_argument('--backend', default='kiro',
                        help='AI backend: kiro, claude, or openai (native Chat '
                             'Completions); use openai-<profile> for a named '
                             'profile. Profiles load '
                             'openai-<profile>.cfg from the repository etc/ '
                             'directory or absolute CVE_AGENT_OPENAI_CONFIG_DIR '
                             '(default: %(default)s)')
    ai_group.add_argument('--model',
                        help='Model for AI sessions; the claude backend also '
                             'accepts aliases like sonnet/opus. Kiro and Claude '
                             'default to claude-sonnet-5; plain OpenAI requires '
                             'this option or CVE_AGENT_OPENAI_MODEL, while a '
                             'named profile may supply it.')
    ai_group.add_argument('--max-retries', type=int, default=DEFAULT_MAX_RETRIES,
                        help='Max resolution attempts (default: %(default)s)')
    ai_group.add_argument('--session-timeout', type=int,
                        default=DEFAULT_SESSION_TIMEOUT,
                        help='Timeout per session in seconds (default: %(default)s)')
    ai_group.add_argument('--trust', action='store_true',
                        help='Skip human review (NOT recommended). Cannot be '
                             'combined with --sign-off.')
    ai_group.add_argument('--no-knowledge', action='store_true',
                        help='Disable the knowledge base for this run: no '
                             'similar-pattern lookups, and no pattern is '
                             'saved on success.')
    ai_group.add_argument('-i', '--interactive', action='store_true',
                        help='Enable interactive mode (human-in-the-loop). '
                             'The native openai backend prompts before side '
                             'effects. Omit for non-interactive/CI use (default).')

    # --- Native OpenAI-compatible backend ---
    openai_group = parser.add_argument_group(
        'OpenAI-compatible backend',
        'Direct non-streaming /chat/completions client; no external agent CLI.')
    openai_group.add_argument('--openai-base-url',
                        help='OpenAI-compatible API root (CLI overrides '
                             'CVE_AGENT_OPENAI_BASE_URL and OPENAI_BASE_URL; '
                             'default: http://127.0.0.1:11434/v1)')
    openai_group.add_argument('--openai-api-key-env', metavar='NAME',
                        help='Name of an environment variable containing the '
                             'API key (CVE_AGENT_OPENAI_API_KEY_ENV; default '
                             'name: OPENAI_API_KEY); never pass the key itself')
    openai_group.add_argument('--openai-max-steps', type=int,
                        help='Maximum model turns per session '
                             '(CVE_AGENT_OPENAI_MAX_STEPS; default: 20)')
    openai_group.add_argument('--openai-max-tool-calls', type=int,
                        help='Maximum total tool calls per session '
                             '(CVE_AGENT_OPENAI_MAX_TOOL_CALLS; default: 100)')
    openai_group.add_argument('--openai-max-output-tokens', type=int,
                        help='Maximum output tokens requested per response '
                             '(CVE_AGENT_OPENAI_MAX_OUTPUT_TOKENS; default: 8192)')
    openai_group.add_argument('--openai-connect-timeout', type=int,
                        help='Endpoint connection timeout in seconds '
                             '(CVE_AGENT_OPENAI_CONNECT_TIMEOUT; default: 10)')
    openai_group.add_argument('--openai-request-timeout', type=int,
                        help='Per-request timeout in seconds '
                             '(CVE_AGENT_OPENAI_REQUEST_TIMEOUT; default: 120)')
    openai_group.add_argument('--openai-temperature', type=float,
                        help='Portable Chat Completions temperature (0 through 2; '
                             'CVE_AGENT_OPENAI_TEMPERATURE)')
    openai_group.add_argument('--openai-top-p', type=float,
                        help='Portable Chat Completions top_p (greater than 0 '
                             'through 1; CVE_AGENT_OPENAI_TOP_P)')
    openai_group.add_argument('--openai-reasoning-effort',
                        choices=('none', 'low', 'medium', 'high', 'max'),
                        help='Portable reasoning effort '
                             '(CVE_AGENT_OPENAI_REASONING_EFFORT)')
    openai_group.add_argument('--openai-allow-remote', action='store_true',
                        default=None, dest='openai_allow_remote_endpoint',
                        help='Explicitly allow a non-loopback endpoint '
                             '(or CVE_AGENT_OPENAI_ALLOW_REMOTE=true)')
    openai_group.add_argument('--openai-allow-insecure-remote-http',
                        action='store_true', default=None,
                        help='Allow HTTP to a non-loopback endpoint; requires '
                             '--openai-allow-remote and exposes inference data '
                             'in transit (or set CVE_AGENT_OPENAI_ALLOW_INSECURE_REMOTE_HTTP=true)')

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
    env_group.add_argument('--sign-off', action='store_true',
                        help='Pass --sign-off through to cve-corrector, adding a '
                             'Signed-off-by trailer to generated patches and '
                             'commits using the git identity resolved from '
                             '`git config`. Off by default — only a human who has '
                             'reviewed the change can certify the DCO. Cannot be '
                             'combined with --trust.')

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
        fix_urls=args.fix_urls,
        recipe=args.recipe,
        backend=args.backend,
        backend_profile=getattr(args, "backend_profile", None),
        backend_selector=getattr(args, "backend_selector", args.backend),
        skip_sources=args.skip_sources,
        sign_off=args.sign_off,
        no_knowledge=args.no_knowledge,
    )


def _configure_backend(args: argparse.Namespace) -> AIBackend:
    """Resolve generic model defaults and backend-specific configuration."""
    selection = resolve_backend_selector(args.backend)
    args.backend_selector = selection.selector
    args.backend = selection.backend
    args.backend_profile = selection.profile
    backend = get_backend(selection.backend)
    if selection.backend == "openai":
        backend.configure(vars(args), os.environ)
        args.model = cast(Any, backend).config.model
    else:
        args.model = backend.resolve_model(args.model, os.environ)
        backend.configure(vars(args), os.environ)
    return backend


def main() -> None:
    """Main entry point for the CVE agent."""
    results: list[CveResult] = []
    signal.signal(signal.SIGINT, _sigint_handler(results))
    args = _parse_args()

    if args.trust and args.sign_off:
        print("Error: --trust and --sign-off cannot be combined — --trust "
              "skips human review of AI-generated changes, so --sign-off "
              "would certify a DCO that nobody actually reviewed. Drop one "
              "of the two flags.", file=sys.stderr)
        sys.exit(EXIT_AGENT_ERROR)

    if not args.cve_info and not args.fix_urls:
        print("Error: --cve-info or --fix-url is required", file=sys.stderr)
        sys.exit(EXIT_AGENT_ERROR)
    if args.fix_urls and not args.cve_info and not args.recipe:
        print("Error: --recipe is required when using --fix-url without "
              "--cve-info", file=sys.stderr)
        sys.exit(EXIT_AGENT_ERROR)

    try:
        backend = _configure_backend(args)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(EXIT_AGENT_ERROR)

    if backend.name == 'kiro':
        ensure_agents(interactive=not args.trust)
    else:
        if not backend.is_available():
            print(f"Error: backend '{args.backend}' prerequisites not met — "
                  "is the required CLI installed and on PATH?", file=sys.stderr)
            sys.exit(EXIT_AGENT_ERROR)
        try:
            backend.setup(interactive=not args.trust)
        except BackendRuntimeUnavailableError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(EXIT_AGENT_ERROR)

    if args.trust and not _show_trust_warning():
        print("Trust mode declined. Exiting.")
        sys.exit(EXIT_TRUST_DECLINED)

    knowledge_base = None if args.no_knowledge else KnowledgeBase()

    if args.cve_id:
        from .corrector import validate_cve_id
        if not validate_cve_id(args.cve_id):
            print(f"Invalid CVE ID format: {args.cve_id}", file=sys.stderr)
            sys.exit(EXIT_AGENT_ERROR)
        config = _config_from_args(args, args.cve_id)
        result = process_single_cve(config, knowledge_base)
        assert result.outcome is not None
        print(f"\n{result.cve_id}: {result.outcome.summary_state}")
        _log_result(config, result)
        if result.resolution_summary:
            print(f"  {result.resolution_summary}")
        if result.total_credits is not None:
            print(f"  credits: {result.total_credits:.2f} "
                  f"{result.credits_unit or 'credits'}")
        if not _command_succeeded(result):
            sys.exit(EXIT_AGENT_ERROR)
    else:
        cve_list = _read_cve_list(args.cve_list)
        config_template = _config_from_args(args)
        results = _process_batch(cve_list, config_template, knowledge_base)
        _print_batch_summary(results)
        _save_results(results)
        failed = sum(
            1 for r in results
            if not _command_succeeded(r)
        )
        if failed:
            sys.exit(EXIT_AGENT_ERROR)


if __name__ == '__main__':
    main()
