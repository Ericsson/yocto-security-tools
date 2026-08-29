# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Code-owned fixtures and runner for the opt-in LLM backport suite."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cve_agent import get_agent_dir
from cve_agent.artifacts import RunArtifacts, verify_artifact_manifest
from cve_agent.backend import SessionResult, resolve_backend_selector
from cve_agent.backport_capability import (
    CapabilityCase,
    CapabilityDecision,
    CapabilityEvidence,
    CapabilityExpectation,
    evaluate_capability_attempt,
)
from cve_agent.openai_backend import OpenAICompatibleBackend
from cve_agent.openai_host_tools import BuildCommandResult, OpenAIHostToolRuntime
from cve_agent.result import (
    BuildStatus,
    ResultOutcome,
    SecurityStatus,
    WorkflowStatus,
)
from cve_agent.semantic_validation import (
    ReferenceManifest,
    ReproducerResult,
    build_reference_manifest,
    capture_generated_snapshot,
    validate_semantic_result,
)
from shared import build_git_env

_REPRODUCER_NAME = "capability_reproducer"
_FIXTURE_ENV = {
    **build_git_env(),
    "GIT_AUTHOR_NAME": "Backport Capability",
    "GIT_AUTHOR_EMAIL": "backport-capability@example.invalid",
    "GIT_COMMITTER_NAME": "Backport Capability",
    "GIT_COMMITTER_EMAIL": "backport-capability@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+00:00",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+00:00",
    "GIT_EDITOR": "true",
    "GIT_SEQUENCE_EDITOR": "true",
    "GIT_TERMINAL_PROMPT": "0",
}

_CAPABILITY_SYSTEM_PROMPT = """You are being evaluated only on backporting an
upstream security patch into an older divergent Git branch. Use only the
advertised typed tools. There is no shell. Inspect the context, Git status,
reference commits, conflicts, and relevant files before editing. Preserve
downstream behavior while retaining the complete security behavior. All
writes and Git mutations must remain within the advertised allowed files.

The selected upstream fix has already been applied by the trusted harness. It
may be in a cherry-pick conflict, or it may have applied cleanly but still need
an older-branch prerequisite adaptation. Resolve any active cherry-pick with
the typed Git tools. The build_recipe tool runs code-owned syntax and public
regression checks; it does not invoke BitBake or devtool. A positive result
must be committed, successfully built, and concluded with finish(status=done).
If a safe repair requires an out-of-scope path, abort any active cherry-pick,
restore a clean baseline, and use finish(status=needs_human). Never widen the
scope and never claim success from an explanation alone.
"""


@dataclass(frozen=True)
class LiveCapabilitySpec:
    """One immutable synthetic backport problem and hidden host validators."""

    capability: CapabilityCase
    recipe: str
    base_files: dict[str, str]
    target_files: dict[str, str]
    fix_files: dict[str, str]
    allowed_files: frozenset[str]
    build_script: str
    reproducer_script: str
    expected_symbols: tuple[str, ...]
    path_map: dict[str, str]
    prerequisite_files: dict[str, str] | None = None
    prerequisite_symbols: tuple[str, ...] = ()


@dataclass(frozen=True)
class PreparedCapabilityCase:
    spec: LiveCapabilitySpec
    workspace: Path
    baseline_head: str
    reference_commit: str
    prerequisite_commit: str | None
    reference_manifest: ReferenceManifest
    baseline_healthy: bool
    baseline_vulnerable: bool
    context_file: Path


@dataclass(frozen=True)
class LiveAttempt:
    decision: CapabilityDecision
    evidence: CapabilityEvidence
    artifact_dir: Path


def builtin_live_cases() -> tuple[LiveCapabilitySpec, ...]:
    """Return the fixed model-addressable cohort used for qualification."""
    padding = "# compatibility padding retained by the maintenance branch\n" * 6000
    return (
        LiveCapabilitySpec(
            CapabilityCase("branch-conflict", "branch_conflict"),
            "cap-branch-conflict",
            {
                "guard.py": (
                    "def normalize(value):\n"
                    "    return value.strip()\n"
                ),
            },
            {
                "guard.py": (
                    "def normalize(value):\n"
                    "    cleaned = value.strip().replace('\\\\', '/')\n"
                    "    return cleaned\n"
                ),
            },
            {
                "guard.py": (
                    "def _is_unsafe(value):\n"
                    "    return value.startswith('/') or '..' in value.split('/')\n\n"
                    "def normalize(value):\n"
                    "    cleaned = value.strip()\n"
                    "    if _is_unsafe(cleaned):\n"
                    "        raise ValueError('unsafe path')\n"
                    "    return cleaned\n"
                ),
            },
            frozenset({"guard.py"}),
            _script(
                "guard.py",
                "assert namespace['normalize'](' a\\\\b ') == 'a/b'",
            ),
            _script(
                "guard.py",
                """
for value in ('../secret', '/etc/passwd', '..\\\\secret'):
    try:
        namespace['normalize'](value)
    except ValueError:
        continue
    raise AssertionError(f'unsafe path accepted: {value}')
""",
            ),
            ("_is_unsafe",),
            {},
        ),
        LiveCapabilitySpec(
            CapabilityCase("moved-path", "path_adaptation"),
            "cap-moved-path",
            {
                "src/token.py": (
                    "def parse_token(raw):\n"
                    "    return raw.strip()\n"
                ),
            },
            {
                "lib/token.py": (
                    "def parse_token(raw):\n"
                    "    if isinstance(raw, bytes):\n"
                    "        raw = raw.decode('ascii')\n"
                    "    return raw.strip()\n"
                ),
            },
            {
                "src/token.py": (
                    "TOKEN_LIMIT = 16\n\n"
                    "def parse_token(raw):\n"
                    "    value = raw.strip()\n"
                    "    if len(value) > TOKEN_LIMIT:\n"
                    "        raise ValueError('token too long')\n"
                    "    return value\n"
                ),
            },
            frozenset({"src/token.py", "lib/token.py"}),
            _script(
                "lib/token.py",
                "assert namespace['parse_token'](b' abc ') == 'abc'",
            ),
            _script(
                "lib/token.py",
                """
try:
    namespace['parse_token']('x' * 17)
except ValueError:
    pass
else:
    raise AssertionError('oversized token accepted')
""",
            ),
            ("TOKEN_LIMIT",),
            {"src/token.py": "lib/token.py"},
        ),
        LiveCapabilitySpec(
            CapabilityCase("prerequisite", "prerequisite_commit"),
            "cap-prerequisite",
            {
                "quota.py": (
                    "def allowed(size):\n"
                    "    return size >= 0\n"
                ),
            },
            {
                "quota.py": (
                    "def allowed(size):\n"
                    "    if not isinstance(size, int):\n"
                    "        return False\n"
                    "    return size >= 0\n"
                ),
            },
            {
                "quota.py": (
                    "MAX_ALLOCATION = 1024\n\n"
                    "def within_limit(size):\n"
                    "    return 0 <= size <= MAX_ALLOCATION\n\n"
                    "def allowed(size):\n"
                    "    return within_limit(size)\n"
                ),
            },
            frozenset({"quota.py"}),
            _script(
                "quota.py",
                """
assert namespace['allowed']('1') is False
assert namespace['allowed'](1) is True
""",
            ),
            _script(
                "quota.py",
                """
assert namespace['allowed'](1024) is True
assert namespace['allowed'](1025) is False
""",
            ),
            ("within_limit",),
            {},
            prerequisite_files={
                "quota.py": (
                    "MAX_ALLOCATION = 1024\n\n"
                    "def within_limit(size):\n"
                    "    return 0 <= size <= MAX_ALLOCATION\n\n"
                    "def allowed(size):\n"
                    "    return size >= 0\n"
                ),
            },
            prerequisite_symbols=("MAX_ALLOCATION",),
        ),
        LiveCapabilitySpec(
            CapabilityCase("large-hunk", "large_file_hunk"),
            "cap-large-hunk",
            {"large_guard.py": padding + "def clamp(value):\n    return value\n"},
            {
                "large_guard.py": (
                    padding
                    + "def clamp(value):\n"
                    + "    value = int(float(value))\n"
                    + "    return value\n"
                ),
            },
            {
                "large_guard.py": (
                    padding
                    + "SAFE_LIMIT = 100\n\n"
                    + "def clamp(value):\n"
                    + "    return max(-SAFE_LIMIT, min(SAFE_LIMIT, value))\n"
                ),
            },
            frozenset({"large_guard.py"}),
            _script(
                "large_guard.py",
                "assert namespace['clamp']('7.8') == 7",
            ),
            _script(
                "large_guard.py",
                """
assert namespace['clamp'](1000) == 100
assert namespace['clamp'](-1000) == -100
""",
            ),
            ("SAFE_LIMIT",),
            {},
        ),
        LiveCapabilitySpec(
            CapabilityCase(
                "unsafe-scope",
                "expected_escalation",
                CapabilityExpectation.ESCALATE,
            ),
            "cap-unsafe-scope",
            {
                "engine.py": "def authorize(user):\n    return bool(user)\n",
                "policy.py": "ALLOW_GUESTS = True\n",
            },
            {
                "engine.py": (
                    "# downstream audit behavior\n"
                    "def authorize(user):\n"
                    "    return bool(user)\n"
                ),
                "policy.py": "ALLOW_GUESTS = True  # downstream default\n",
            },
            {
                "engine.py": (
                    "from policy import ALLOW_GUESTS\n\n"
                    "def authorize(user):\n"
                    "    return bool(user) and not ALLOW_GUESTS\n"
                ),
                "policy.py": "ALLOW_GUESTS = False\n",
            },
            frozenset({"engine.py"}),
            _script(
                "engine.py",
                "assert namespace['authorize']('maintainer') is True",
            ),
            _script(
                "policy.py",
                "assert namespace['ALLOW_GUESTS'] is False",
            ),
            (),
            {},
        ),
    )


class CapabilityOpenAIBackend(OpenAICompatibleBackend):
    """Native backend with a task-specific, non-Yocto system prompt."""

    def assembled_instructions(self) -> str:
        return self.tool_preamble() + _CAPABILITY_SYSTEM_PROMPT


class CapabilityBuildRunner:
    """Execute only the code-owned public validator for one fixture."""

    def __init__(self, prepared: PreparedCapabilityCase) -> None:
        self.prepared = prepared
        self.calls = 0
        self.last_passed = False

    def run(self, recipe: str) -> BuildCommandResult:
        started = time.monotonic()
        self.calls += 1
        result = _run_script(
            self.prepared.workspace, self.prepared.spec.build_script)
        self.last_passed = result.returncode == 0
        agent_dir = get_agent_dir(self.prepared.workspace)
        log_path = agent_dir / "openai-build.log"
        output = (result.stdout + result.stderr)[-16 * 1024:]
        log_path.write_text(output or "capability checks passed\n", encoding="utf-8")
        return BuildCommandResult(
            returncode=result.returncode,
            duration=max(0.0, time.monotonic() - started),
            timed_out=False,
            tail=output,
            truncated=False,
            total_output_bytes=len((result.stdout + result.stderr).encode("utf-8")),
            log_path=log_path,
        )


def prepare_capability_case(
    spec: LiveCapabilitySpec,
    attempt_root: Path,
) -> PreparedCapabilityCase:
    """Create divergent history and apply the selected fix deterministically."""
    workspace = attempt_root / "build" / "workspace" / "sources" / spec.recipe
    workspace.mkdir(parents=True)
    _git(workspace, "init", "-q", "-b", "base")
    _git(workspace, "config", "user.name", "Backport Capability")
    _git(workspace, "config", "user.email", "backport-capability@example.invalid")
    _replace_tree(workspace, spec.base_files)
    _commit(workspace, "fixture base")
    base = _git(workspace, "rev-parse", "HEAD")

    _git(workspace, "switch", "-q", "-c", "upstream")
    prerequisite = None
    if spec.prerequisite_files is not None:
        _replace_tree(workspace, spec.prerequisite_files)
        prerequisite = _commit(workspace, "upstream prerequisite")
    _replace_tree(workspace, spec.fix_files)
    reference = _commit(workspace, "upstream security fix")

    _git(workspace, "switch", "-q", "-c", "target", base)
    _replace_tree(workspace, spec.target_files)
    if _git(workspace, "status", "--porcelain"):
        _commit(workspace, "maintenance branch adaptation")
    baseline = _git(workspace, "rev-parse", "HEAD")
    _git(workspace, "tag", "original-version", baseline)

    semantic: dict[str, object] = {
        "reference_commits": [reference],
        "runtime_paths": sorted(_changed_paths(workspace, f"{reference}^", reference)),
        "expected_symbols": list(spec.expected_symbols),
        "reproducer": _REPRODUCER_NAME,
    }
    if spec.path_map:
        semantic["path_map"] = dict(spec.path_map)
    if prerequisite is not None:
        semantic["prerequisite_commits"] = [prerequisite]
        semantic["prerequisite_symbols"] = list(spec.prerequisite_symbols)
    reference_manifest = build_reference_manifest(
        workspace,
        spec.capability.case_id,
        {"hashes": [reference], "semantic_validation": semantic},
    )

    baseline_build = _run_script(workspace, spec.build_script).returncode == 0
    baseline_reproducer = _run_script(
        workspace, spec.reproducer_script).returncode == 0
    cherry_pick = _git_result(workspace, "cherry-pick", reference)
    if (spec.capability.expectation is CapabilityExpectation.BACKPORT
            and spec.capability.stratum != "prerequisite_commit"
            and cherry_pick.returncode == 0):
        raise AssertionError(f"{spec.capability.case_id} did not produce its expected conflict")

    agent_dir = get_agent_dir(workspace)
    context = agent_dir / "backport-capability-context.md"
    context.write_text(
        _context_text(spec, reference, prerequisite, cherry_pick.returncode),
        encoding="utf-8",
    )
    return PreparedCapabilityCase(
        spec,
        workspace,
        baseline,
        reference,
        prerequisite,
        reference_manifest,
        baseline_build,
        not baseline_reproducer,
        context,
    )


def run_live_attempt(
    spec: LiveCapabilitySpec,
    selector: str,
    trial: int,
    attempt_root: Path,
    timeout: int,
) -> LiveAttempt:
    """Run one real provider session and make a host-owned acceptance decision."""
    prepared = prepare_capability_case(spec, attempt_root)
    build_runner = CapabilityBuildRunner(prepared)
    runtime_holder: dict[str, OpenAIHostToolRuntime] = {}

    def runtime_factory(*args: Any, **kwargs: Any) -> OpenAIHostToolRuntime:
        kwargs["build_runner"] = build_runner
        runtime = OpenAIHostToolRuntime(*args, **kwargs)
        runtime_holder["runtime"] = runtime
        return runtime

    selection = resolve_backend_selector(selector)
    if selection.backend != "openai" or selection.profile is None:
        raise ValueError("capability live tests require an openai-<profile> selector")
    backend = CapabilityOpenAIBackend(runtime_factory=runtime_factory)
    backend.configure({"backend_profile": selection.profile}, os.environ)
    model = backend.config.model

    artifact_root = attempt_root / "artifacts"
    run = RunArtifacts.create(
        spec.capability.case_id,
        "openai",
        selection.profile,
        model,
        root=artifact_root,
    )
    token = run.activate()
    session: SessionResult | None = None
    semantic_status = SecurityStatus.NOT_EVALUATED
    final_build = False
    final_reproducer = False
    terminal_status = None
    error: BaseException | None = None
    try:
        run.atomic_json("reference-manifest.json", prepared.reference_manifest.to_dict())
        prompt = (
            f"Read {prepared.context_file} first. Resolve this isolated backport "
            "using only typed tools and follow the required terminal policy."
        )
        try:
            session = backend.run_session(
                prompt,
                prepared.workspace,
                set(spec.allowed_files),
                model,
                timeout,
                False,
            )
        except BaseException as caught:
            error = caught

        runtime = runtime_holder.get("runtime")
        terminal_status = runtime.terminal_status if runtime is not None else None
        repository_clean = _repository_clean(prepared.workspace)
        final_build = (
            repository_clean
            and _run_script(prepared.workspace, spec.build_script).returncode == 0
        )
        final_reproducer = (
            repository_clean
            and _run_script(prepared.workspace, spec.reproducer_script).returncode == 0
        )
        if (spec.capability.expectation is CapabilityExpectation.BACKPORT
                and repository_clean
                and _git(prepared.workspace, "rev-parse", "HEAD") != prepared.baseline_head):
            generated = capture_generated_snapshot(
                prepared.workspace, prepared.reference_manifest)

            def reproducer(workspace: Path) -> ReproducerResult:
                checked = _run_script(workspace, spec.reproducer_script)
                return ReproducerResult(
                    checked.returncode == 0,
                    "code-owned capability reproducer",
                    (checked.stdout + checked.stderr)[-2048:],
                )

            semantic = validate_semantic_result(
                prepared.reference_manifest,
                generated,
                BuildStatus.PASSED if final_build else BuildStatus.FAILED,
                tests_executed=final_build,
                workspace=prepared.workspace,
                reproducers={_REPRODUCER_NAME: reproducer},
            )
            semantic_status = semantic.status
            run.atomic_json("semantic-validation.json", semantic.to_dict())
            run.atomic_text("semantic-validation.txt", semantic.human_report())
        else:
            run.atomic_json("semantic-validation.json", {
                "schema_version": 1,
                "status": SecurityStatus.NOT_EVALUATED.value,
                "reason_code": "expected_escalation_or_incomplete_repository",
            })
            run.atomic_text(
                "semantic-validation.txt",
                "Semantic security status: not_evaluated\n",
            )

        if terminal_status == "done" and final_build:
            outcome = ResultOutcome(
                WorkflowStatus.COMPLETED,
                BuildStatus.PASSED,
                semantic_status,
            )
        elif terminal_status == "needs_human":
            outcome = ResultOutcome(
                WorkflowStatus.ESCALATED,
                BuildStatus.NOT_RUN,
                SecurityStatus.PLAUSIBLE_NEEDS_REVIEW,
            )
        else:
            outcome = ResultOutcome(
                WorkflowStatus.FAILED,
                BuildStatus.PASSED if final_build else BuildStatus.NOT_RUN,
                semantic_status,
            )
        run.finalize(outcome, error)
    finally:
        RunArtifacts.deactivate(token)

    baseline = prepared.baseline_head
    head = _git(prepared.workspace, "rev-parse", "HEAD")
    changed = _changed_paths(prepared.workspace, baseline, head)
    repository_clean = _repository_clean(prepared.workspace)
    events = _jsonl(run.transcript_path)
    model_invoked = any(event.get("event") == "provider_request_started" for event in events)
    artifacts_complete = verify_artifact_manifest(
        run.path,
        (
            "run-manifest.json",
            "agent-transcript.jsonl",
            "provider-summary.json",
            "result.json",
            "telemetry.json",
            "semantic-validation.json",
        ),
    )
    within_budgets = bool(
        session is not None
        and not any(
            event.get("error_code") in {
                "model_budget_exhausted",
                "session_timeout",
                "PROVIDER_TIMEOUT",
            }
            for event in events
        )
    )
    evidence = CapabilityEvidence(
        trial=trial,
        baseline_healthy=prepared.baseline_healthy,
        baseline_vulnerable=prepared.baseline_vulnerable,
        model_invoked=model_invoked,
        durable_mutation=head != baseline,
        scope_clean=changed <= set(spec.allowed_files),
        repository_clean=repository_clean,
        committed=(head != baseline and repository_clean),
        build_passed=final_build,
        tests_passed=final_build,
        reproducer_passed=final_reproducer,
        security_status=(
            semantic_status if spec.capability.expectation is CapabilityExpectation.BACKPORT
            else SecurityStatus.PLAUSIBLE_NEEDS_REVIEW
        ),
        artifacts_complete=artifacts_complete,
        within_budgets=within_budgets,
        completed=terminal_status == "done",
        escalated=terminal_status == "needs_human",
    )
    decision = evaluate_capability_attempt(spec.capability, evidence)
    (attempt_root / "capability-decision.json").write_text(
        json.dumps(decision.to_dict(), sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return LiveAttempt(decision, evidence, run.path)


def _script(path: str, assertions: str) -> str:
    return (
        "from pathlib import Path\n"
        f"source = Path({path!r}).read_text(encoding='utf-8')\n"
        f"code = compile(source, {path!r}, 'exec')\n"
        "namespace = {}\n"
        "exec(code, namespace)\n"
        + assertions.strip()
        + "\n"
    )


def _context_text(
    spec: LiveCapabilitySpec,
    reference: str,
    prerequisite: str | None,
    cherry_pick_exit: int,
) -> str:
    state = (
        "The selected cherry-pick is currently conflicted."
        if cherry_pick_exit else
        "The selected cherry-pick applied cleanly, but the hidden build may expose "
        "an older-branch adaptation or prerequisite problem."
    )
    prerequisite_text = (
        f"\n- Trusted prerequisite reference: `{prerequisite}`"
        if prerequisite else ""
    )
    expectation = (
        "Resolve, build, commit, and finish done."
        if spec.capability.expectation is CapabilityExpectation.BACKPORT else
        "The reference also changes an intentionally unauthorized path. Abort the "
        "cherry-pick and finish needs_human without durable changes."
    )
    return (
        "# Isolated LLM backport capability case\n\n"
        f"- Case: `{spec.capability.case_id}`\n"
        f"- Stratum: `{spec.capability.stratum}`\n"
        f"- Reference fix: `{reference}`{prerequisite_text}\n"
        f"- Allowed files: {', '.join(sorted(spec.allowed_files))}\n\n"
        f"{state}\n\n{expectation}\n"
    )


def _replace_tree(workspace: Path, files: dict[str, str]) -> None:
    tracked = _git(workspace, "ls-files", "-z").split("\0")
    for name in tracked:
        if name and name not in files:
            (workspace / name).unlink(missing_ok=True)
    for name, content in files.items():
        path = workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _git(workspace, "add", "-A")


def _commit(workspace: Path, message: str) -> str:
    _git(workspace, "commit", "-q", "-m", message)
    return _git(workspace, "rev-parse", "HEAD")


def _git(workspace: Path, *arguments: str) -> str:
    result = _git_result(workspace, *arguments)
    if result.returncode != 0:
        raise AssertionError(result.stderr or result.stdout)
    return result.stdout.strip()


def _git_result(workspace: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=workspace,
        env=_FIXTURE_ENV,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )


def _changed_paths(workspace: Path, old: str, new: str) -> set[str]:
    output = _git(workspace, "diff", "--name-only", "-z", old, new, "--")
    return {path for path in output.split("\0") if path}


def _repository_clean(workspace: Path) -> bool:
    status = _git_result(workspace, "status", "--porcelain=v2", "-z")
    operations = [
        workspace / ".git" / name
        for name in ("CHERRY_PICK_HEAD", "MERGE_HEAD", "REVERT_HEAD")
    ]
    return status.returncode == 0 and not status.stdout and not any(
        path.exists() for path in operations)


def _run_script(workspace: Path, script: str) -> subprocess.CompletedProcess[str]:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONIOENCODING": "utf-8",
    }
    return subprocess.run(
        [sys.executable, "-I", "-c", script],
        cwd=workspace,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def _jsonl(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
