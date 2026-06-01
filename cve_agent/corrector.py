# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Corrector invocation and CVE metadata helpers."""
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

from . import CORRECTOR_CMD, AgentConfig


def validate_cve_id(cve_id: str) -> bool:
    """Check if cve_id matches CVE-YYYY-NNNN+ format."""
    return bool(re.match(r'^CVE-\d{4}-\d{4,}$', cve_id))


def validate_recipe_name(name: str) -> bool:
    """Check if recipe name contains only valid characters."""
    return bool(re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._+-]*$', name))


def run_corrector(config: AgentConfig, continue_mode: bool = False,
                  mark_not_applicable: Optional[str] = None) -> tuple[int, str]:
    """Run cve_corrector and return its exit code and captured output."""
    cmd = list(CORRECTOR_CMD)

    if mark_not_applicable:
        cmd += [
            '--cve-id', config.cve_id,
            '--cve-info', str(config.cve_info_path or ''),
            '--mark-not-applicable', mark_not_applicable,
            '--yes',
        ]
        if config.meta_layer:
            cmd += ['--meta-layer', str(config.meta_layer)]
    elif continue_mode:
        cmd += ['--continue', '--yes']
    else:
        cmd += [
            '--cve-id', config.cve_id,
            '--yes',
        ]
        if config.cve_info_path:
            cmd += ['--cve-info', str(config.cve_info_path)]
        if config.fix_url:
            cmd += ['--fix-url', config.fix_url]
        if config.recipe:
            cmd += ['--recipe', config.recipe]
        if config.clean:
            cmd.append('--clean')
        if config.mirror_dir:
            cmd += ['--mirror-dir', str(config.mirror_dir)]
        if config.meta_layer:
            cmd += ['--meta-layer', str(config.meta_layer)]
        if config.skip_ptest:
            cmd.append('--skip-ptest')
        if config.bbappend:
            cmd.append('--bbappend')
        if config.skip_cve_applicability:
            cmd.append('--skip-cve-applicability')

    output_lines = []
    with subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    ) as process:
        if process.stdout:
            for line in process.stdout:
                sys.stdout.write(line)
                sys.stdout.flush()
                output_lines.append(line)
        process.wait()
    return process.returncode, ''.join(output_lines)


def load_cve_metadata(cve_info_path: Optional[Path]) -> dict:
    """Load CVE metadata from JSON file.

    Raises:
        FileNotFoundError: If the metadata file does not exist.
        ValueError: If the file contains invalid JSON.
    """
    import json

    if cve_info_path is None:
        raise FileNotFoundError("No CVE metadata path provided")
    resolved = Path(cve_info_path).resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"CVE metadata file not found: {resolved}")
    try:
        with open(resolved, encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as err:
        raise ValueError(f"Invalid JSON in {resolved}: {err}") from err


def get_workspace_path(config: AgentConfig, cve_data: dict) -> Optional[Path]:
    """Determine workspace path from CVE metadata and environment."""
    cve_info = cve_data.get(config.cve_id, {})
    recipe = cve_info.get('name')
    if not recipe:
        print("Could not determine recipe name from CVE metadata",
              file=sys.stderr)
        return None

    if not validate_recipe_name(recipe):
        print(f"Error: recipe name '{recipe}' contains invalid characters",
              file=sys.stderr)
        return None

    bbpath = os.environ.get('BBPATH', '')
    if not bbpath:
        print("BBPATH not set — source the Yocto build environment first",
              file=sys.stderr)
        return None

    build_path = Path(bbpath.split(':')[0])
    workspace = build_path / 'workspace' / 'sources' / recipe
    if not workspace.exists():
        print(f"Workspace not found: {workspace}", file=sys.stderr)
        return None
    return workspace
