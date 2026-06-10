# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Common utilities for CVE corrector."""
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from shared import build_git_env
from shared.git_runner import is_git_cmd
from shared.git_runner import run_capture as _shared_run_capture

# Module-level config — set by setup_logging(), used by run_cmd()
_verbose = True
_log_file: Optional[Path] = None

logger = logging.getLogger('cve_corrector')


def setup_logging(cve_id: str, build_path: Path, verbose: bool) -> Path:
    """Set up logging with file and console handlers.

    Returns:
        Path to the log file
    """
    global _verbose, _log_file  # pylint: disable=global-statement

    _verbose = verbose

    log_dir = build_path / 'workspace' / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    _log_file = log_dir / f'cve_corrector_{cve_id}_{timestamp}.log'

    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    file_handler = logging.FileHandler(_log_file, mode='a')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'))
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(console_handler)

    return _log_file


def run_cmd(cmd: list[str], cwd: Optional[Path] = None,
            timeout: Optional[int] = None) -> int:
    """Execute command with output directed based on verbose setting.

    Args:
        cmd: Command and arguments to execute.
        cwd: Working directory for the command.
        timeout: Timeout in seconds. None means no timeout.

    Returns:
        Exit code from the command, or -1 on timeout.
    """
    cmd_str = ' '.join(str(c) for c in cmd)
    logger.info("Running: %s", cmd_str)

    env = build_git_env() if is_git_cmd(cmd) else None

    try:
        if _verbose or not _log_file:
            return subprocess.run(cmd, cwd=cwd, env=env,
                                  timeout=timeout, check=False).returncode

        _log_file.parent.mkdir(parents=True, exist_ok=True)
        with open(_log_file, 'a', encoding='utf-8') as log:
            log.write(f'\n=== Running: {cmd_str} ===\n')
            result = subprocess.run(
                cmd, cwd=cwd, stdout=log, stderr=log,
                env=env, timeout=timeout, check=False).returncode
            log.write(f'=== Exit code: {result} ===\n\n')
            return result
    except subprocess.TimeoutExpired:
        logger.error("Command timed out after %ds: %s", timeout, cmd_str)
        if _log_file:
            with open(_log_file, 'a', encoding='utf-8') as log:
                log.write(f'=== TIMEOUT after {timeout}s ===\n\n')
        return -1


def run_cmd_capture(cmd: list[str], cwd: Optional[Path] = None) -> subprocess.CompletedProcess:
    """Execute command and capture output."""
    return _shared_run_capture(cmd, cwd)
