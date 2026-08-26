# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Context builder for kiro-cli sessions.

Gathers comprehensive context about conflicts, build errors, or test failures
and writes a structured context.md file for Claude to consume.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .knowledge import KnowledgeBase

from shared import TEXT_ENCODING, TEXT_ERRORS

from . import (
    EXIT_BUILD_ERROR,
    EXIT_CONFLICT,
    EXIT_PTEST_ERROR,
    get_agent_dir,
    get_build_dir,
)
from .git import (
    compute_allowed_files,
    get_all_upstream_shas,
    get_upstream_sha,
    merge_diff_flags,
    run_capture,
    run_git_stdout,
)
from .interdiff import generate_interdiff

# Per-phase workflow fragments embedded into context.md by exit code. The
# phase-independent core is delivered separately via the system prompt; exit 0
# (analysis) has no fragment — the core's Analyse step covers it.
_PHASE_INSTRUCTION_FILES = {
    EXIT_CONFLICT: "conflict.md",
    EXIT_BUILD_ERROR: "build.md",
    EXIT_PTEST_ERROR: "ptest.md",
}


def build_context(workspace_path: Path, exit_code: int, cve_id: str,
                  cve_info: dict, knowledge_base: KnowledgeBase | None = None,
                  model: str = "", backend: str = "",
                  backend_profile: str | None = None) -> Path:
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
                      model, backend, backend_profile),
        _build_phase_instructions(exit_code),
        _gather_context_for_exit_code(workspace_path, exit_code, cve_info),
    ]

    if exit_code != EXIT_CONFLICT:
        interdiff_section = _gather_interdiff(workspace_path, cve_info)
        if interdiff_section:
            sections.append(interdiff_section)

    similar_patterns = _gather_knowledge(knowledge_base, recipe, workspace_path)
    if similar_patterns:
        sections.append(similar_patterns)

    # Include human feedback from previous review if present
    feedback_file = agent_dir / 'human_feedback.txt'
    if feedback_file.exists():
        feedback = feedback_file.read_text(encoding='utf-8').strip()
        if feedback:
            # Quote every line: the feedback may be a multi-line report (e.g.
            # a commit-note budget verdict), and prefixing only the first line
            # breaks the block out of the markdown quote.
            quoted = '\n'.join(f"> {line}" if line else '>'
                               for line in feedback.splitlines())
            sections.append(
                f"## Human Feedback (from previous review)\n\n"
                f"The reviewer requested the following changes:\n\n"
                f"{quoted}\n\n"
                f"Apply ONLY these requested changes to the current code in "
                f"the workspace. Do not redo the entire resolution."
            )
        feedback_file.unlink()

    context_file.write_text('\n\n'.join(s for s in sections if s),
                            encoding='utf-8')
    return context_file


def _build_header(cve_id: str, recipe: str, exit_code: int,
                  workspace_path: Path, cve_info: dict,
                  model: str = "", backend: str = "",
                  backend_profile: str | None = None) -> str:
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

    # The allowed file list is computed by the same helper the session's scope
    # guard uses, so context.md can never advertise a different scope than the
    # pre-commit hook enforces. It is merge-commit aware: `git show` prints no
    # diff (and no file list) for a merge, which used to yield an empty list.
    allowed_files = compute_allowed_files(cve_info, workspace_path)

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

    if backend == "openai":
        execution_guidance = (
            "- **Tool execution**: this native session has no shell. Use only "
            "the typed file, Git, build, and terminal tools advertised by the "
            "backend; pass workspace-relative paths where requested.\n"
        )
        allowed_heading = "Allowed Files (ONLY these may be modified or staged)"
    else:
        execution_guidance = (
            "- **Working directory**: your shell ALREADY runs inside the "
            "workspace above. Run every command **bare** (e.g. `git status`) — "
            "do NOT prefix `cd` and do NOT chain with `&&`, `;`, or `|`. The "
            "command allow-list matches whole commands, so `cd ... && git "
            "status` is rejected while a plain `git status` is accepted.\n"
        )
        allowed_heading = "Allowed Files (ONLY these may be staged with `git add`)"

    profile_line = (
        f"- **Backend profile**: {backend_profile}\n"
        if backend_profile is not None else ""
    )
    return (
        f"# CVE Agent Context: {cve_id}\n\n"
        f"- **Recipe**: {recipe}\n"
        f"- **Phase**: {phase}\n"
        f"- **Backend**: {backend}\n"
        f"{profile_line}"
        f"- **Model**: {model}\n"
        f"- **Workspace**: `{workspace_path}`\n"
        f"{execution_guidance}"
        f"- **Upstream SHA(s)**: {sha_display}\n"
        f"{log_lines}\n\n"
        f"## {allowed_heading}\n\n"
        f"```\n{allowed_list}\n```\n\n"
        f"**Any file not in this list MUST NOT be staged or modified.**"
    )


def _build_phase_instructions(exit_code: int) -> str:
    """Return the phase-specific workflow instructions for this exit code.

    The phase-independent core (tools, scope rules, analysis, build
    verification, commit format) reaches the model via the session's system
    prompt (kiro-cli's ``prompt: file://...`` / the ``claude`` CLI's
    ``--append-system-prompt`` / the native OpenAI-compatible conversation;
    see the backend modules). The per-phase steps live in small fragment files
    under ``cve_agent/instructions/`` and are embedded here into ``context.md``
    for the matching exit code ONLY, so a session receives just the workflow
    its phase needs instead of the whole manual.

    Returns an empty string when there is no fragment for the exit code
    (analysis / exit 0) or the file is missing, so ``build_context`` omits the
    section entirely.
    """
    filename = _PHASE_INSTRUCTION_FILES.get(exit_code)
    if not filename:
        return ""
    fragment = Path(__file__).parent / "instructions" / filename
    if not fragment.is_file():
        return ""
    return f"## Instructions\n\n{fragment.read_text(encoding='utf-8').strip()}"


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
        return _gather_ptest_error_context(workspace_path, cve_info)
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
    show_cmd = f"git show {upstream_sha}"
    if upstream_sha:
        flags = merge_diff_flags(workspace_path, upstream_sha)
        upstream_stat = run_git_stdout(
            ['show', *flags, '--stat', upstream_sha], cwd=workspace_path)
        show_cmd = ' '.join(['git', 'show', *flags, upstream_sha])

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
        f"Run `{show_cmd}` to see the full upstream diff.\n\n"
        f"### File History\n{file_history}"
    )


def _gather_build_error_context(workspace_path: Path) -> str:
    """Gather the dynamic build-error data (last commit; log pointers).

    The static how-to-fix guidance (stale-sstate recovery, cross-recipe
    aborts) lives in the ``build.md`` phase fragment embedded alongside this
    section in ``context.md`` — it is not repeated here.

    Args:
        workspace_path: Path to workspace where build failed.

    Returns:
        Formatted build error context string.
    """
    last_commit = run_git_stdout(['show', '--stat', 'HEAD'], cwd=workspace_path)

    return (
        f"## Build Error Details\n\n"
        f"### Last Commit (stat)\n```\n{last_commit}\n```\n\n"
        f"Run `git show HEAD` to see the full diff. Check the build logs in "
        f"the Yocto build directory (paths in the context header) for the "
        f"specific error, and `devtool build <recipe>` to reproduce."
    )


def _gather_ptest_error_context(workspace_path: Path, cve_info: dict) -> str:
    """Gather the dynamic ptest-failure data (results, last commit, SHAs).

    Reads the cve_corrector state file to extract before/after ptest results
    and the ptest log files for detailed failure information. The static
    how-to-fix guidance (defect-vs-companion-commit triage, upstream history
    search, ``suggested_commits`` escalation, "never hand-edit tests") lives
    in the ``ptest.md`` phase fragment embedded alongside this section in
    ``context.md`` — it is not repeated here.

    Args:
        workspace_path: Path to workspace where ptest failed.
        cve_info: CVE metadata dict (used to resolve the upstream SHA so the
            agent can search upstream history for a companion fix).

    Returns:
        Formatted ptest error context string.
    """
    last_commit = run_git_stdout(['show', '--stat', 'HEAD'], cwd=workspace_path)
    ptest_section = _read_ptest_results(workspace_path)
    upstream_sha = get_upstream_sha(cve_info, workspace_path)
    sha = upstream_sha if upstream_sha and upstream_sha != "unknown" else "<upstream_sha>"

    return (
        f"## Test Failure Details\n\n"
        f"{ptest_section}\n\n"
        f"### Last Commit (stat)\n```\n{last_commit}\n```\n\n"
        f"Run `git show HEAD` for the current backport, and `git show {sha}` "
        f"for the upstream fix you backported."
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
        ptest_after = data.get('ptest_after')
        if ptest_after:
            lines.append(
                "**After patch** — the `Failing cases:` listed here are the "
                "regressions you must investigate and resolve (each name is a "
                "ptest case; reproduce and analyse it):\n"
                f"```\n{ptest_after}\n```\n")

    # Read ptest log for detailed failure output
    recipe = workspace_path.name
    build_dir = get_build_dir(workspace_path)
    ptest_log = _find_ptest_log(build_dir, recipe)
    if ptest_log:
        content = ptest_log.read_text(encoding=TEXT_ENCODING, errors=TEXT_ERRORS)
        failing = [line for line in content.splitlines()
                   if re.match(r'\s*FAIL:', line)]
        aborted = [line for line in content.splitlines()
                   if line.startswith('TIMEOUT:') or
                   line.startswith('ERROR: Exited from signal')]
        if failing:
            lines.append("**Failing test cases**:\n```\n" +
                         '\n'.join(failing) + "\n```\n")
        if aborted:
            lines.append("**Aborted/killed test cases** (no PASS/FAIL result "
                         "reported — likely hung or timed out):\n```\n" +
                         '\n'.join(aborted) + "\n```\n")

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
        flags = merge_diff_flags(workspace_path, upstream_sha)
        upstream_stat = run_git_stdout(
            ['show', *flags, '--stat', upstream_sha], cwd=workspace_path)
        upstream_info = (
            f"\n### Upstream Commit (stat)\n```\n{upstream_stat}\n```\n"
            f"Run `{' '.join(['git', 'show', *flags, upstream_sha])}` to see "
            f"the full upstream diff."
        )

    return (
        f"## Patch Analysis\n\n"
        f"### Applied Commits\n```\n{applied}\n```\n\n"
        f"Run `git show HEAD` to see the latest commit diff."
        f"{upstream_info}\n\n"
        f"Analyse the applied commits. If incompatible with the stable base, "
        f"adapt and document changes in the commit message."
    )


def _gather_interdiff(workspace_path: Path, cve_info: dict) -> str:
    """Build an optional interdiff section showing the adaptation delta.

    Computes the diff-of-diffs between the upstream commit and the
    backported change on HEAD, so the AI sees precisely how the backport
    already deviates from upstream. Returns an empty string whenever a
    concise delta can't be produced (e.g. the ``interdiff`` binary isn't
    installed) — callers should skip appending it in that case.

    Args:
        workspace_path: Path to workspace with an applied backport commit.
        cve_info: CVE metadata dict (used to resolve upstream SHA).

    Returns:
        Formatted interdiff section, or empty string if unavailable.
    """
    upstream_sha = get_upstream_sha(cve_info, workspace_path)
    if not upstream_sha or upstream_sha == "unknown":
        return ""

    upstream_diff = run_git_stdout(['show', upstream_sha], cwd=workspace_path)
    backport_diff = run_git_stdout(
        ['diff', 'original-version..HEAD'], cwd=workspace_path
    )
    interdiff = generate_interdiff(upstream_diff, backport_diff)
    if not interdiff:
        return ""

    return (
        f"## Interdiff (upstream \u2192 backport)\n\n"
        f"The following shows only the lines that differ between the "
        f"upstream patch and the current backport — i.e. how the backport "
        f"already deviates from upstream.\n\n"
        f"```diff\n{interdiff}\n```"
    )


def _find_state_file(workspace_path: Path) -> Path | None:
    """Find the cve_corrector state file for this workspace.

    Args:
        workspace_path: Path to workspace.

    Returns:
        Path to state JSON file, or None if not found.
    """
    recipe_name = workspace_path.name
    # The corrector saves state under the devtool workspace, at
    # get_build_path()/workspace/cve_corrector/<recipe>.json (see
    # cve_corrector.bitbake_ops.get_state_dir). That is two levels up from the
    # recipe source dir — the same base get_agent_dir() uses. A previous
    # version looked at get_build_dir()/cve_corrector (three levels up, one
    # directory too high) and silently never found the state file, so ptest
    # before/after results — and their `Failing cases:` list — never reached
    # the agent's context.
    state_dir = workspace_path.parent.parent / 'cve_corrector'
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
    result = run_capture(
        ['git', 'diff', '--name-only', '--diff-filter=U'],
        cwd=workspace_path
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
