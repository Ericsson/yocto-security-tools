# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Shared test helpers for cve_corrector scenario tests.

Import this module from test files for assertion helpers and utilities.
"""
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def git(cwd, *args, check=True):
    """Run a git command and return CompletedProcess."""
    env = {**os.environ, 'GIT_AUTHOR_NAME': 'Test', 'GIT_AUTHOR_EMAIL': 'test@test.com',
           'GIT_COMMITTER_NAME': 'Test', 'GIT_COMMITTER_EMAIL': 'test@test.com',
           'GIT_TERMINAL_PROMPT': '0'}
    return subprocess.run(['git'] + list(args), cwd=cwd, capture_output=True,
                          text=True, check=check, env=env)


def git_hash(cwd, ref='HEAD'):
    """Get commit hash for a ref."""
    return git(cwd, 'rev-parse', ref).stdout.strip()


# ---------------------------------------------------------------------------
# devtool finish simulation
# ---------------------------------------------------------------------------

def devtool_finish_sim(workspace_path: Path, meta_layer: Path, recipe: str) -> int:
    """Simulate devtool finish: extract patches from workspace to meta-layer."""
    with tempfile.TemporaryDirectory() as patch_dir:
        env = {**os.environ, 'GIT_AUTHOR_NAME': 'Test', 'GIT_AUTHOR_EMAIL': 'test@test.com',
               'GIT_COMMITTER_NAME': 'Test', 'GIT_COMMITTER_EMAIL': 'test@test.com'}
        result = subprocess.run(
            ['git', 'format-patch', 'devtool-base..devtool', '-o', patch_dir],
            cwd=workspace_path, capture_output=True, text=True, check=False, env=env)
        if result.returncode != 0:
            return 1

        patches = sorted(Path(patch_dir).glob('*.patch'))
        if not patches:
            return 0

        # Find recipe dir in meta-layer
        recipe_dir = None
        for d in meta_layer.rglob(f'{recipe}_*.bb'):
            recipe_dir = d.parent
            break
        if not recipe_dir:
            recipe_dir = meta_layer / 'recipes-core' / recipe
            recipe_dir.mkdir(parents=True, exist_ok=True)

        # Copy patches (leave untracked)
        patch_names = []
        for p in patches:
            dest = recipe_dir / p.name
            shutil.copy2(p, dest)
            patch_names.append(p.name)

        # Update SRC_URI in recipe .bb
        bb_file = next(meta_layer.glob(f'**/{recipe}_*.bb'), None)
        if bb_file:
            content = bb_file.read_text()
            for pname in patch_names:
                if f'file://{pname}' not in content:
                    content = content.rstrip()
                    if content.endswith('"'):
                        content = content[:-1] + f' \\\n           file://{pname} \\\n           "'
                    else:
                        content += f'\nSRC_URI += "file://{pname}"\n'
            bb_file.write_text(content + '\n' if not content.endswith('\n') else content)

    return 0


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

def assert_patch_naming(meta_layer: Path, cve_id: str, expect_series: bool):
    """Assert CVE patches follow naming convention."""
    patches = sorted(meta_layer.rglob(f'*{cve_id}*.patch'))
    assert patches, f"No patches found for {cve_id}"

    if not expect_series:
        assert len(patches) == 1, f"Expected 1 patch, found {len(patches)}: {[p.name for p in patches]}"
        assert patches[0].name == f'{cve_id}.patch', f"Expected {cve_id}.patch, got {patches[0].name}"
    else:
        assert len(patches) >= 2, f"Expected series (>=2), found {len(patches)}"
        for idx, p in enumerate(patches, 1):
            expected = f'{cve_id}-{idx}.patch'
            assert p.name == expected, f"Expected {expected}, got {p.name}"


def assert_no_patches_removed(before_set: set, after_set: set):
    """Assert no pre-existing patches were removed."""
    removed = before_set - after_set
    assert not removed, f"Patches removed: {removed}"


def assert_patch_correctness(meta_layer: Path, cve_id: str,
                             expected_files: set, expected_adds: set | None = None):
    """Assert generated patches touch expected files and contain expected additions."""
    patches = sorted(meta_layer.rglob(f'*{cve_id}*.patch'))
    assert patches, f"No patches found for {cve_id}"

    files_touched = set()
    additions = set()
    for p in patches:
        for line in p.read_text().splitlines():
            if line.startswith('diff --git'):
                parts = line.split()
                if len(parts) >= 4:
                    files_touched.add(parts[3].lstrip('b/'))
            elif line.startswith('+') and not line.startswith('+++'):
                if not re.match(r'^\+(From |Date:|Subject:|Signed-off-by:|CVE:|Upstream-Status:|index )', line):
                    additions.add(line)

    assert expected_files <= files_touched, (
        f"Missing files: {expected_files - files_touched}")
    if expected_adds:
        assert expected_adds <= additions, (
            f"Missing additions: {expected_adds - additions}")


def get_src_uri_patches(meta_layer: Path, recipe: str) -> set:
    """Extract file://...patch entries from recipe files."""
    patches = set()
    for pattern in (f'**/{recipe}*.bb', f'**/{recipe}*.bbappend', f'**/{recipe}*.inc'):
        for f in meta_layer.glob(pattern):
            for match in re.finditer(r'file://([^\s"\\]+\.patch)', f.read_text()):
                patches.add(match.group(1))
    return patches


def run_workflow(cve_data, cve_id, config):
    """Run initialize + finish workflow, return exit code."""
    from cve_corrector.state import WorkflowError
    from cve_corrector.workflow import finish_cve_workflow, initialize_cve_workflow
    try:
        state = initialize_cve_workflow(cve_data, cve_id, config)
        state.skip_confirm = True
        finish_cve_workflow(state)
        return 0
    except WorkflowError as e:
        return e.exit_code
    except SystemExit as e:
        return e.code
