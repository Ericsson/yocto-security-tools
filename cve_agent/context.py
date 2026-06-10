# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Context builder for kiro-cli sessions.

Gathers comprehensive context about conflicts, build errors, or test failures
and writes a structured context.md file for Claude to consume.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .knowledge import KnowledgeBase

from . import (
    AGENT_INSTRUCTIONS,
    EXIT_BUILD_ERROR,
    EXIT_CONFLICT,
    EXIT_PTEST_ERROR,
    get_agent_dir,
    get_build_dir,
)
from .git import get_all_upstream_shas, get_upstream_sha, run_git_stdout


def build_context(workspace_path: Path, exit_code: int, cve_id: str,
                  cve_info: dict, knowledge_base: KnowledgeBase | None = None,
                  model: str = "", backend: str = "") -> Path:
    """Build a context file for kiro-cli with all relevant information.

    Args:
        workspace_path: Path to the devtool workspace source directory.
        exit_code: Exit code from cve_corrector.py that triggered this phase.
        cve_id: CVE identifier being processed.
        cve_info: Metadata dict for this CVE from the JSON file.
        knowledge_base: Optional KnowledgeBase instance for similar patterns.
        model: Model name for the Assisted-by commit trailer.
        backend: Backend name for the Assisted-by commit trailer.

    Returns:
        Path to the generated context.md file.
    """
    agent_dir = get_agent_dir(workspace_path)
    context_file = agent_dir / 'context.md'
    recipe = cve_info.get('name', 'unknown')

    sections = [
        _build_header(cve_id, recipe, exit_code, workspace_path, cve_info,
                      model, backend),
        _build_phase_instructions(),
        _gather_context_for_exit_code(workspace_path, exit_code, cve_info),
    ]

    similar_patterns = _gather_knowledge(knowledge_base, recipe, workspace_path)
    if similar_patterns:
        sections.append(similar_patterns)

    # Include human feedback from previous review if present
    feedback_file = agent_dir / 'human_feedback.txt'
    if feedback_file.exists():
        feedback = feedback_file.read_text(encoding='utf-8').strip()
        if feedback:
            sections.append(
                f"## Human Feedback (from previous review)\n\n"
                f"The reviewer requested the following changes:\n\n"
                f"> {feedback}\n\n"
                f"Apply ONLY these requested changes to the current code in "
                f"the workspace. Do not redo the entire resolution."
            )
        feedback_file.unlink()

    context_file.write_text('\n\n'.join(sections), encoding='utf-8')
    return context_file


def _build_header(cve_id: str, recipe: str, exit_code: int,
                  workspace_path: Path, cve_info: dict,
                  model: str = "", backend: str = "") -> str:
    """Build the context file header with CVE and workspace info.

    Args:
        cve_id: CVE identifier.
        recipe: Recipe name.
        exit_code: Exit code from cve_corrector.
        workspace_path: Path to workspace.
        cve_info: CVE metadata dict (used to resolve upstream SHA).
        model: Model name for the Assisted-by commit trailer.
        backend: Backend name for the Assisted-by commit trailer.

    Returns:
        Formatted header string.
    """
    phase_map = {
        EXIT_CONFLICT: "CONFLICT RESOLUTION",
        EXIT_BUILD_ERROR: "BUILD ERROR RESOLUTION",
        EXIT_PTEST_ERROR: "TEST FAILURE RESOLUTION",
        0: "PATCH ANALYSIS",
    }
    phase = phase_map.get(exit_code, f"ERROR (exit {exit_code})")
    upstream_sha = get_upstream_sha(cve_info, workspace_path)
    all_shas = get_all_upstream_shas(cve_info, workspace_path)

    # Pre-compute the allowed file list from ALL upstream SHAs
    allowed_files: set[str] = set()
    for sha in all_shas:
        files = run_git_stdout(
            ['show', '--name-only', '--format=', sha], cwd=workspace_path
        )
        allowed_files.update(f for f in files.splitlines() if f)

    # Fallback: if SHAs don't exist in repo, derive allowed files from
    # the workspace diff (what the corrector actually changed/conflicted)
    if not allowed_files:
        diff_files = run_git_stdout(
            ['diff', '--name-only', 'original-version..HEAD'],
            cwd=workspace_path
        )
        allowed_files.update(f for f in diff_files.splitlines() if f)
        # Also include files with unresolved conflicts
        conflict_files = run_git_stdout(
            ['diff', '--name-only', '--diff-filter=U'], cwd=workspace_path
        )
        allowed_files.update(f for f in conflict_files.splitlines() if f)

    allowed_list = '\n'.join(sorted(allowed_files))

    sha_display = upstream_sha
    if len(all_shas) > 1:
        sha_display = ', '.join(f'`{s[:12]}`' for s in all_shas)

    # Compute log paths
    build_dir = get_build_dir(workspace_path)
    agent_dir = workspace_path.parent.parent / 'cve_agent' / recipe
    yocto_tmp = None
    for tmp_name in ('tmp-glibc', 'tmp'):
        candidate = build_dir / tmp_name
        if candidate.exists():
            yocto_tmp = candidate
            break

    log_lines = (
        f"- **Agent dir** (build logs): `{agent_dir}`\n"
        f"- **Yocto build dir**: `{build_dir}`"
    )
    if yocto_tmp:
        log_lines += f"\n- **Yocto tmp dir**: `{yocto_tmp}` (task logs under `work/<arch>/{recipe}/*/temp/`)"

    return (
        f"# CVE Agent Context: {cve_id}\n\n"
        f"- **Recipe**: {recipe}\n"
        f"- **Phase**: {phase}\n"
        f"- **Backend**: {backend}\n"
        f"- **Model**: {model}\n"
        f"- **Workspace**: `{workspace_path}`\n"
        f"- **Working directory**: `cd {workspace_path}`\n"
        f"- **Upstream SHA(s)**: {sha_display}\n"
        f"{log_lines}\n\n"
        f"## Allowed Files (ONLY these may be staged with `git add`)\n\n"
        f"```\n{allowed_list}\n```\n\n"
        f"**Any file not in this list MUST NOT be staged or modified.**"
    )


def _build_phase_instructions() -> str:
    """Load agent instructions from AGENT_INSTRUCTIONS.md."""
    if not AGENT_INSTRUCTIONS.exists():
        return "## Instructions\n\nSee cve_agent/AGENT_INSTRUCTIONS.md for workflow details."
    return AGENT_INSTRUCTIONS.read_text(encoding='utf-8')


def _gather_context_for_exit_code(workspace_path: Path, exit_code: int,
                                  cve_info: dict) -> str:
    """Dispatch to the appropriate context gatherer based on exit code.

    Args:
        workspace_path: Path to workspace.
        exit_code: Exit code from cve_corrector.
        cve_info: CVE metadata dict.

    Returns:
        Context section string.
    """
    if exit_code == EXIT_CONFLICT:
        return _gather_conflict_context(workspace_path, cve_info)
    if exit_code == EXIT_BUILD_ERROR:
        return _gather_build_error_context(workspace_path)
    if exit_code == EXIT_PTEST_ERROR:
        return _gather_ptest_error_context(workspace_path)
    return _gather_analysis_context(workspace_path, cve_info)


def _gather_conflict_context(workspace_path: Path, cve_info: dict) -> str:
    """Gather context for conflict resolution.

    Args:
        workspace_path: Path to workspace with active conflict.
        cve_info: CVE metadata with hashes and patches.

    Returns:
        Formatted conflict context string.
    """
    status = run_git_stdout(['status'], cwd=workspace_path)
    upstream_sha = get_upstream_sha(cve_info, workspace_path)
    upstream_stat = ""
    if upstream_sha:
        upstream_stat = run_git_stdout(['show', '--stat', upstream_sha], cwd=workspace_path)

    conflicted_files = _get_conflicted_files(workspace_path)
    file_history = ""
    for filepath in conflicted_files[:5]:
        history = run_git_stdout(['log', '--oneline', '-20', '--', filepath], cwd=workspace_path)
        file_history += f"\n### {filepath}\n```\n{history}\n```\n"

    return (
        f"## Conflict Details\n\n"
        f"### Git Status\n```\n{status}\n```\n\n"
        f"Run `git diff` to see the current conflicts.\n\n"
        f"### Upstream Commit (stat)\n```\n{upstream_stat}\n```\n"
        f"Run `git show {upstream_sha}` to see the full upstream diff.\n\n"
        f"### File History\n{file_history}"
    )


def _gather_build_error_context(workspace_path: Path) -> str:
    """Gather context for build error resolution.

    Args:
        workspace_path: Path to workspace where build failed.

    Returns:
        Formatted build error context string.
    """
    last_commit = run_git_stdout(['show', '--stat', 'HEAD'], cwd=workspace_path)

    return (
        f"## Build Error Details\n\n"
        f"### Last Commit (stat)\n```\n{last_commit}\n```\n\n"
        f"Run `git show HEAD` to see the full diff.\n\n"
        f"Check build logs in the Yocto build directory for specific errors.\n"
        f"Run `devtool build <recipe>` to reproduce."
    )


def _gather_ptest_error_context(workspace_path: Path) -> str:
    """Gather context for ptest failure resolution.

    Reads the cve_corrector state file to extract before/after ptest results
    and the ptest log files for detailed failure information.

    Args:
        workspace_path: Path to workspace where ptest failed.

    Returns:
        Formatted ptest error context string.
    """
    last_commit = run_git_stdout(['show', '--stat', 'HEAD'], cwd=workspace_path)
    ptest_section = _read_ptest_results(workspace_path)

    return (
        f"## Test Failure Details\n\n"
        f"{ptest_section}\n\n"
        f"### Last Commit (stat)\n```\n{last_commit}\n```\n\n"
        f"Run `git show HEAD` to see the full diff.\n\n"
        f"**Rule**: Test cases must NEVER change. Only backported files may be "
        f"modified.\nAnalyse the backport commit intent and adjust it to pass "
        f"tests while preserving the fix.\n\n"
        f"In the `### Conflicts Resolved` commit message section, document:\n"
        f"- Which ptest cases failed\n"
        f"- What code change caused the failure\n"
        f"- How the backported code was corrected to fix it"
    )


def _read_ptest_results(workspace_path: Path) -> str:
    """Read ptest before/after results from the cve_corrector state file and logs.

    Args:
        workspace_path: Path to workspace.

    Returns:
        Formatted ptest results section.
    """
    state_file = _find_state_file(workspace_path)
    lines = ["### Ptest Results\n"]

    if state_file and state_file.exists():
        data = json.loads(state_file.read_text(encoding='utf-8'))
        ptest_before = data.get('ptest_before')
        if ptest_before:
            lines.append(f"**Before patch**:\n```\n{ptest_before}\n```\n")

    # Read ptest log for detailed failure output
    recipe = workspace_path.name
    build_dir = get_build_dir(workspace_path)
    ptest_log = _find_ptest_log(build_dir, recipe)
    if ptest_log:
        content = ptest_log.read_text(encoding='utf-8')
        failing = [line for line in content.splitlines() if 'FAILED:' in line]
        if failing:
            lines.append("**Failing test cases**:\n```\n" +
                         '\n'.join(failing) + "\n```\n")

    if len(lines) == 1:
        lines.append("(No ptest result data found in state file or logs)\n")

    return '\n'.join(lines)


def _find_ptest_log(build_dir: Path, recipe: str) -> Path | None:
    """Find the most recent ptest log for a recipe.

    Args:
        build_dir: Yocto build directory.
        recipe: Recipe name.

    Returns:
        Path to the ptest log, or None.
    """
    for tmp_dir in ('tmp-glibc', 'tmp'):
        logs = list((build_dir / tmp_dir).glob(
            f'work/*/core-image-minimal/*/testimage/ptest_log/{recipe}'))
        if logs:
            return sorted(logs)[-1]
    return None


def _gather_analysis_context(workspace_path: Path, cve_info: dict) -> str:
    """Gather context for mandatory patch analysis (clean apply).

    Args:
        workspace_path: Path to workspace with applied patch.
        cve_info: CVE metadata dict.

    Returns:
        Formatted analysis context string.
    """
    applied = run_git_stdout(['log', 'original-version..HEAD', '--oneline'], cwd=workspace_path)
    upstream_sha = get_upstream_sha(cve_info, workspace_path)
    upstream_info = ""
    if upstream_sha:
        upstream_stat = run_git_stdout(['show', '--stat', upstream_sha], cwd=workspace_path)
        upstream_info = (
            f"\n### Upstream Commit (stat)\n```\n{upstream_stat}\n```\n"
            f"Run `git show {upstream_sha}` to see the full upstream diff."
        )

    return (
        f"## Patch Analysis\n\n"
        f"### Applied Commits\n```\n{applied}\n```\n\n"
        f"Run `git show HEAD` to see the latest commit diff."
        f"{upstream_info}\n\n"
        f"Analyse the applied commits. If incompatible with the stable base, "
        f"adapt and document changes in the commit message."
    )


def _find_state_file(workspace_path: Path) -> Path | None:
    """Find the cve_corrector state file for this workspace.

    Args:
        workspace_path: Path to workspace.

    Returns:
        Path to state JSON file, or None if not found.
    """
    recipe_name = workspace_path.name
    build_dir = get_build_dir(workspace_path)
    state_dir = build_dir / 'cve_corrector'
    state_file = state_dir / f'{recipe_name}.json'
    if state_file.exists():
        return state_file
    return None


def _get_conflicted_files(workspace_path: Path) -> list[str]:
    """Get list of files with merge conflicts.

    Args:
        workspace_path: Path to workspace.

    Returns:
        List of conflicted file paths relative to workspace.
    """
    result = subprocess.run(
        ['git', 'diff', '--name-only', '--diff-filter=U'],
        cwd=workspace_path, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        return []
    return [f for f in result.stdout.strip().splitlines() if f]


def _gather_knowledge(knowledge_base: KnowledgeBase | None, recipe: str,
                      workspace_path: Path) -> str:
    """Query knowledge base for similar resolution patterns.

    Args:
        knowledge_base: KnowledgeBase instance, or None.
        recipe: Recipe name to search for.
        workspace_path: Path to workspace for file context.

    Returns:
        Formatted knowledge base section, or empty string.
    """
    if knowledge_base is None:
        return ""

    conflicted_files = _get_conflicted_files(workspace_path)
    similar = knowledge_base.find_similar(recipe, conflicted_files)
    if not similar:
        return ""

    lines = ["## Previous Similar Resolutions\n"]
    for pattern in similar:
        lines.append(
            f"### {pattern.cve_id} ({pattern.recipe})\n"
            f"- **Summary**: {pattern.resolution_summary}"
        )
        if pattern.upstream_sha:
            lines.append(f"- **Upstream commit**: {pattern.upstream_sha}")
        if pattern.affected_files:
            lines.append(f"- **Files modified**: {', '.join(pattern.affected_files)}")
        if pattern.per_file_changes:
            lines.append("- **Per-file changes**:")
            for fpath, desc in pattern.per_file_changes.items():
                lines.append(f"  - `{fpath}`: {desc}")
        if pattern.diff_stat:
            lines.append(f"- **Diff stat**:\n```\n{pattern.diff_stat}\n```")
        if pattern.commit_message:
            lines.append(f"- **Commit message**:\n```\n{pattern.commit_message}\n```")
        lines.append("")
    return '\n'.join(lines)
