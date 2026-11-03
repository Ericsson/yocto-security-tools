#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Compare two models' bulk ``test_cve_corrector.sh`` campaigns end to end.

Three steps, each resumable and safe to rerun:

``seed``
    Start model B's results directory from model A's, keeping only the rows
    the model cannot influence (direct success, skipped, failed before the AI
    was involved) together with their logs, reference copies and artifacts.
    Every CVE that needed the agent is left out, so resuming the harness on
    the new directory makes model B attempt all of them itself::

        AGENT_BACKEND=kiro AGENT_MODEL=<model-b> \\
            ./test_cve_corrector.sh --agent-only --resume <run-b>

    The seeded CVE IDs are written to ``<run-b>/seeded-from.txt``; ``plot``
    reads it to tell rows copied from A apart from real attempts by B.

``judge``
    Rate every patch of one or more runs with one or more judge models
    (review-required and ``AGENT_RESOLVED`` rows) through
    ``tests/benchmark/judge_campaign.py``. Each judge writes to its own
    ``<run>/judge-<model>/judge_results.csv``, so no copies of a run are needed.

``plot``
    Draw the outcome comparison, the majority-of-judges verdict comparison
    and one judge-agreement chart per run into an output directory.

Example, comparing a local model with Claude Opus 5.5 under three judges::

    ./compare_campaigns.py seed test-results/qwen test-results/opus
    # ... run the harness on test-results/opus (above) ...
    ./compare_campaigns.py judge test-results/qwen test-results/opus \\
        -j claude-opus-5.5 -j claude-sonnet-5.5 -j claude-opus-4.6
    ./compare_campaigns.py plot -a "Qwen3.8-27B=test-results/qwen" \\
        -b "Claude Opus 5.5=test-results/opus" \\
        -j claude-opus-5.5 -j claude-sonnet-5.5 -j claude-opus-4.6 -o test-results/plots
"""

from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOLS_DIR = REPO_ROOT / 'tools'
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(TOOLS_DIR))

from plot_corrector_results import (  # noqa: E402
    FAMILY_DIRECT_SUCCESS,
    FAMILY_PREEXISTING_FAILED,
    FAMILY_SKIPPED,
    classify_family,
)

#: Outcome families whose result does not depend on the AI model.
MODEL_INDEPENDENT_FAMILIES = (FAMILY_DIRECT_SUCCESS, FAMILY_SKIPPED, FAMILY_PREEXISTING_FAILED)
#: Statuses whose patches are judged: the review-required ones and the
#: agent-resolved ones that passed the security gate.
JUDGED_STATUSES = ('SECURITY_REVIEW_REQUIRED', 'WORKFLOW_COMPLETED_UNVERIFIED', 'AGENT_RESOLVED')
SEED_LIST = 'seeded-from.txt'
DEFAULT_MODE = 'full'


def judge_dir(run_dir: Path, judge_model: str) -> Path:
    """Return the directory one judge model's verdicts for a run live in."""
    if not judge_model or '/' in judge_model or judge_model.startswith('.'):
        raise SystemExit(f'error: unusable judge model name: {judge_model!r}')
    return run_dir / f'judge-{judge_model}'


def read_rows(csv_path: Path) -> tuple[list[str], list[dict[str, str]]]:
    """Return the header and rows of a results CSV."""
    if not csv_path.is_file():
        raise SystemExit(f'error: no such file: {csv_path}')
    with csv_path.open(newline='', encoding='utf-8') as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def is_model_independent(status: str) -> bool:
    """Whether a row's outcome would be the same under any AI model."""
    return classify_family(status) in MODEL_INDEPENDENT_FAMILIES


def cve_files(run_dir: Path, cve_id: str, mode: str) -> list[Path]:
    """Return the per-CVE logs, patches and artifact directory of a run."""
    patterns = (f'{cve_id}_*.log', f'{cve_id}_*.txt', f'{cve_id}_*.patch',
                f'{mode}_{cve_id}_*.patch', f'{mode}_agent_{cve_id}_*.patch',
                f'{cve_id}_{mode}_artifacts')
    found: dict[str, Path] = {}
    for pattern in patterns:
        for path in run_dir.glob(pattern):
            found[path.name] = path
    return [found[name] for name in sorted(found)]


def seed(source: Path, target: Path, mode: str = DEFAULT_MODE,
         log: Callable[[str], None] = print) -> list[str]:
    """Create ``target`` with the model-independent rows of ``source``.

    Returns:
        The seeded CVE IDs, in the source CSV's order.

    Raises:
        SystemExit: If ``target`` already holds a results CSV, so an existing
            run is never overwritten.
    """
    csv_name = f'results_{mode}.csv'
    header, rows = read_rows(source / csv_name)
    if (target / csv_name).exists():
        raise SystemExit(f'error: {target / csv_name} already exists; refusing to overwrite')
    target.mkdir(parents=True, exist_ok=True)
    kept = [row for row in rows if is_model_independent(row['status'])]
    copied = 0
    for row in kept:
        for path in cve_files(source, row['cve_id'], mode):
            dest = target / path.name
            if dest.exists():
                continue
            if path.is_dir():
                shutil.copytree(path, dest, symlinks=True)
            else:
                shutil.copy2(path, dest)
            copied += 1
    with (target / csv_name).open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=header)
        writer.writeheader()
        writer.writerows(kept)
    seeded = [row['cve_id'] for row in kept]
    (target / SEED_LIST).write_text(
        f'# Rows copied unchanged from {source.resolve()}\n' + ''.join(f'{c}\n' for c in seeded),
        encoding='utf-8')
    log(f'Seeded {len(kept)} of {len(rows)} rows ({copied} files/dirs) into {target}; '
        f'{len(rows) - len(kept)} CVEs are left for the new model to attempt.')
    return seeded


def read_cve_list(path: Path) -> set[str]:
    """Read a CVE list file: one ID per line, ``#`` comments allowed."""
    if not path.is_file():
        return set()
    return {line.strip() for line in path.read_text(encoding='utf-8').splitlines()
            if line.strip() and not line.lstrip().startswith('#')}


def judge(runs: Sequence[Path], judge_models: Sequence[str], *, mode: str = DEFAULT_MODE,
          backend: str = 'kiro', dry_run: bool = False, limit: int | None = None,
          judge_fn: Callable | None = None,
          log: Callable[[str], None] = print) -> dict[tuple[str, str], dict]:
    """Rate every judged-status row of each run with each judge model.

    Returns:
        ``{(run, judge_model): verdict_counts}``.
    """
    from tests.benchmark import judge_campaign

    results = {}
    for run_dir in runs:
        for model in judge_models:
            log(f'== {run_dir.name} / {model}')
            counts = judge_campaign.run(
                run_dir.resolve(), csv_name=f'results_{mode}.csv', judge_model=model,
                backend=backend, limit=limit, dry_run=dry_run, statuses=JUDGED_STATUSES,
                out_dir=judge_dir(run_dir.resolve(), model), log=log,
                judge=judge_fn or judge_campaign.judge_diff)
            log('   verdicts: ' + ', '.join(f'{k}={v}' for k, v in sorted(counts.items())))
            results[(str(run_dir), model)] = dict(counts)
    return results


def parse_named_run(spec: str) -> tuple[str, Path]:
    """Parse ``NAME=RESULTS_DIR``."""
    name, sep, path = spec.partition('=')
    if not sep or not name or not path:
        raise SystemExit(f'error: expected NAME=RESULTS_DIR, got {spec!r}')
    return name, Path(path)


def judge_csv(run_dir: Path, model: str) -> Path:
    """Return a judge's ``judge_results.csv`` for a run, which must exist."""
    path = judge_dir(run_dir, model) / 'judge_results.csv'
    if not path.is_file():
        raise SystemExit(f'error: {path} not found; run the "judge" step first')
    return path


def attempted_by_both(run_a: Path, run_b: Path, mode: str = DEFAULT_MODE) -> set[str]:
    """CVEs both runs attempted themselves, i.e. neither copied from the other."""
    _, rows_a = read_rows(run_a / f'results_{mode}.csv')
    _, rows_b = read_rows(run_b / f'results_{mode}.csv')
    seeded = read_cve_list(run_a / SEED_LIST) | read_cve_list(run_b / SEED_LIST)
    return ({r['cve_id'] for r in rows_a} & {r['cve_id'] for r in rows_b}) - seeded


def plot_commands(model_a: tuple[str, Path], model_b: tuple[str, Path],
                  judge_models: Sequence[str], out_dir: Path, attempted_file: Path,
                  mode: str = DEFAULT_MODE) -> list[list[str]]:
    """Build the argv of every chart the ``plot`` step draws."""
    (name_a, run_a), (name_b, run_b) = model_a, model_b
    py = sys.executable
    spec_a, spec_b = f'{name_a}={run_a}', f'{name_b}={run_b}'
    commands = [[py, str(TOOLS_DIR / 'plot_model_outcome_comparison.py'), '--model-a', spec_a,
                 '--model-b', spec_b, '--mode', mode, '-o', str(out_dir / 'outcomes.png')]]
    if judge_models:
        judged = [py, str(TOOLS_DIR / 'plot_model_judge_comparison.py'), '--model-a', spec_a,
                  '--model-b', spec_b, '--csv', f'results_{mode}.csv',
                  '--attempted', str(attempted_file), '-o', str(out_dir / 'judge_comparison.png')]
        for model in judge_models:
            judged += ['--judge', f'{model}={judge_csv(run_a, model)},{judge_csv(run_b, model)}']
        commands.append(judged)
    if len(judge_models) > 1:
        for name, run_dir in (model_a, model_b):
            slug = ''.join(c if c.isalnum() or c in '.-' else '_' for c in name)
            commands.append(
                [py, str(TOOLS_DIR / 'plot_judge_agreement.py'),
                 *(f'{m}={judge_csv(run_dir, m)}' for m in judge_models),
                 '--title', f'Judge agreement, {name}',
                 '-o', str(out_dir / f'judge_agreement_{slug}.png')])
    return commands


def plot(model_a: tuple[str, Path], model_b: tuple[str, Path], judge_models: Sequence[str],
         out_dir: Path, mode: str = DEFAULT_MODE,
         runner: Callable[[list[str]], int] | None = None) -> None:
    """Draw every comparison chart into ``out_dir``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    attempted_file = out_dir / 'attempted-by-both.txt'
    both = attempted_by_both(model_a[1], model_b[1], mode)
    attempted_file.write_text(''.join(f'{c}\n' for c in sorted(both)), encoding='utf-8')
    run = runner or (lambda argv: subprocess.run(argv, check=False).returncode)
    for argv in plot_commands(model_a, model_b, judge_models, out_dir, attempted_file, mode):
        if run(argv) != 0:
            raise SystemExit(f'error: {Path(argv[1]).name} failed')


def main(argv: Sequence[str] | None = None) -> None:
    """Entry point."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--mode', default=DEFAULT_MODE,
                        help=f'Harness mode whose results_<mode>.csv to use (default: {DEFAULT_MODE})')
    sub = parser.add_subparsers(dest='command', required=True)

    p_seed = sub.add_parser('seed', help="Start model B's run from model A's model-independent rows")
    p_seed.add_argument('source', type=Path, help="Model A's results directory")
    p_seed.add_argument('target', type=Path, help="New results directory for model B")

    p_judge = sub.add_parser('judge', help='Rate every patch of each run with each judge model')
    p_judge.add_argument('runs', nargs='+', type=Path, help='Results directories')
    p_judge.add_argument('-j', '--judge-model', action='append', required=True, dest='judges',
                         help='Judge model; repeatable')
    p_judge.add_argument('--judge-backend', default='kiro',
                         help='kiro (default), openai, or openai-<profile>')
    p_judge.add_argument('--limit', type=int, help='At most this many judge rows per run/judge')
    p_judge.add_argument('--dry-run', action='store_true',
                         help='Bucket only: no judge call, nothing written')

    p_plot = sub.add_parser('plot', help='Draw the comparison charts')
    p_plot.add_argument('-a', '--model-a', required=True, metavar='NAME=RESULTS_DIR')
    p_plot.add_argument('-b', '--model-b', required=True, metavar='NAME=RESULTS_DIR')
    p_plot.add_argument('-j', '--judge-model', action='append', default=[], dest='judges',
                        help='Judge whose verdicts to plot; repeatable (none: outcomes only)')
    p_plot.add_argument('-o', '--output-dir', type=Path, required=True)

    args = parser.parse_args(argv)
    if args.command == 'seed':
        seed(args.source, args.target, args.mode)
        print('Next: AGENT_BACKEND=<backend> AGENT_MODEL=<model> '
              f'./test_cve_corrector.sh --agent-only --resume {args.target.resolve()}')
    elif args.command == 'judge':
        judge(args.runs, args.judges, mode=args.mode, backend=args.judge_backend,
              dry_run=args.dry_run, limit=args.limit)
    else:
        plot(parse_named_run(args.model_a), parse_named_run(args.model_b), args.judges,
             args.output_dir, args.mode)


if __name__ == '__main__':
    main()
