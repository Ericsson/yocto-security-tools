# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Deterministic, transactional patch transfer across source layouts."""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path, PurePosixPath

from shared import build_git_env

from .utils import run_cmd_capture

TRANSFER_SCHEMA_VERSION = 1
MAX_TRANSFER_PATHS = 100_000
MAX_TRANSFER_FILE_BYTES = 4 * 1024 * 1024
MAX_TRANSFER_TOTAL_BYTES = 16 * 1024 * 1024
MAX_TRANSFER_HUNKS = 2_000
MAX_TRANSFER_LINES = 200_000
MAX_TRANSFER_DIAGNOSTIC_PATHS = 32
_OBJECT_RE = re.compile(r"^[0-9a-f]{40,64}$")


class TransferCode(str, Enum):
    NO_TARGET_PATH = "TRANSFER_NO_TARGET_PATH"
    AMBIGUOUS_MAPPING = "TRANSFER_AMBIGUOUS_MAPPING"
    CONTEXT_MISMATCH = "TRANSFER_CONTEXT_MISMATCH"
    UNSUPPORTED_FILE_TYPE = "TRANSFER_UNSUPPORTED_FILE_TYPE"
    SCOPE_VIOLATION = "TRANSFER_SCOPE_VIOLATION"
    APPLY_FAILED = "TRANSFER_APPLY_FAILED"
    POSTCHECK_FAILED = "TRANSFER_POSTCHECK_FAILED"


class TransferError(RuntimeError):
    """Bounded deterministic transfer failure."""

    def __init__(self, code: TransferCode, message: str) -> None:
        self.code = code
        super().__init__(f"{code.value}: {message[:512]}")


@dataclass(frozen=True)
class TreeEntry:
    path: str
    mode: str
    object_id: str


@dataclass(frozen=True)
class TransferEntry:
    source_status: str
    source_old_path: str | None
    source_new_path: str | None
    source_old_mode: str | None
    source_new_mode: str | None
    target_old_path: str | None
    target_new_path: str | None
    mapping_method: str
    confidence: str
    old_anchor_sha256: str | None
    rejection_reason: str | None = None


@dataclass(frozen=True)
class TransferManifest:
    schema_version: int
    source_commits: tuple[str, ...]
    parent_bases: tuple[str, ...]
    target_initial_head: str
    target_final_head: str
    entries: tuple[TransferEntry, ...]
    final_changed_paths: tuple[str, ...]
    omitted_already_present_paths: tuple[str, ...]
    verification: str
    failure_code: str | None

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "source_commits": list(self.source_commits),
            "parent_bases": list(self.parent_bases),
            "target_initial_head": self.target_initial_head,
            "target_final_head": self.target_final_head,
            "entries": [asdict(entry) for entry in self.entries],
            "final_changed_paths": list(self.final_changed_paths),
            "omitted_already_present_paths": list(self.omitted_already_present_paths),
            "verification": self.verification,
            "failure_code": self.failure_code,
        }


def transfer_manifest_path(workspace: Path, recipe: str) -> Path:
    return (workspace.parent.parent / "cve_corrector" / "transfers"
            / f"{recipe}.json")


def validate_transfer_config(
    source_prefix: str | None, explicit_mapping: dict[str, str] | None,
) -> tuple[str | None, dict[str, str]]:
    """Validate trusted metadata without accepting path syntax extensions."""
    prefix = None
    if source_prefix is not None:
        prefix = _safe_path(source_prefix.rstrip("/")) + "/"
    mapping: dict[str, str] = {}
    for source, target in (explicit_mapping or {}).items():
        mapping[_safe_path(source)] = _safe_path(target)
    if len(mapping) > MAX_TRANSFER_PATHS or len(set(mapping.values())) != len(mapping):
        raise TransferError(
            TransferCode.AMBIGUOUS_MAPPING, "explicit mappings must be one-to-one")
    return prefix, mapping


def transfer_commits(
    workspace: Path,
    commits: list[str],
    recipe: str,
    cve_id: str,
    *,
    source_prefix: str | None = None,
    explicit_mapping: dict[str, str] | None = None,
) -> TransferManifest:
    """Plan, apply, verify, and commit a bounded source commit sequence."""
    if not commits or len(commits) > MAX_TRANSFER_PATHS:
        raise TransferError(TransferCode.APPLY_FAILED, "invalid source commit set")
    prefix, explicit = validate_transfer_config(source_prefix, explicit_mapping)
    workspace = workspace.resolve(strict=True)
    initial_head = _git(workspace, "rev-parse", "--verify", "HEAD^{commit}").strip()
    initial_status = _git(workspace, "status", "--porcelain=v2", "-z")
    if initial_status:
        raise TransferError(TransferCode.APPLY_FAILED, "target tree is not clean")
    all_entries: list[TransferEntry] = []
    parents: list[str] = []
    created_paths: set[str] = set()
    try:
        for commit_input in commits:
            commit = _git(
                workspace, "rev-parse", "--verify", f"{commit_input}^{{commit}}",
            ).strip()
            parent_line = _git(
                workspace, "rev-list", "--parents", "-n", "1", commit).split()
            if len(parent_line) != 2:
                raise TransferError(
                    TransferCode.UNSUPPORTED_FILE_TYPE,
                    "transfer source must be a non-merge commit",
                )
            parent = parent_line[1]
            parents.append(parent)
            entries = _plan_commit(workspace, parent, commit, prefix, explicit)
            all_entries.extend(entries)
            created_paths.update(
                entry.target_new_path for entry in entries
                if entry.source_status == "A" and entry.target_new_path)
            _apply_entries(workspace, parent, commit, entries)
            _verify_and_commit(workspace, entries, commit, cve_id)
        final_paths = tuple(sorted(_changed_paths(
            _git(workspace, "diff", "--name-status", "-z", initial_head, "HEAD"))))
        expected = _expected_paths(all_entries)
        if set(final_paths) != expected:
            raise TransferError(
                TransferCode.POSTCHECK_FAILED, "final changed path set differs from plan")
        manifest = TransferManifest(
            TRANSFER_SCHEMA_VERSION,
            tuple(_git(workspace, "rev-parse", f"{value}^{{commit}}").strip()
                  for value in commits),
            tuple(parents), initial_head,
            _git(workspace, "rev-parse", "--verify", "HEAD^{commit}").strip(),
            tuple(all_entries), final_paths,
            tuple(sorted({entry.target_new_path for entry in all_entries
                          if entry.mapping_method == "already_present"
                          and entry.target_new_path})),
            "verified", None,
        )
        _write_manifest(transfer_manifest_path(workspace, recipe), manifest)
        return manifest
    except TransferError as error:
        _rollback(workspace, initial_head, created_paths)
        manifest = TransferManifest(
            TRANSFER_SCHEMA_VERSION,
            tuple(value for value in commits if _OBJECT_RE.fullmatch(value)),
            tuple(parents), initial_head, initial_head,
            tuple(all_entries), (), (), "rejected", error.code.value,
        )
        _write_manifest(transfer_manifest_path(workspace, recipe), manifest)
        if _git(workspace, "status", "--porcelain=v2", "-z") != initial_status:
            raise TransferError(
                TransferCode.POSTCHECK_FAILED, "rollback did not restore target") from error
        raise


def _plan_commit(
    workspace: Path, parent: str, commit: str, prefix: str | None,
    explicit: dict[str, str],
) -> list[TransferEntry]:
    source_before = _tree(workspace, parent)
    source_after = _tree(workspace, commit)
    target = _tree(workspace, "HEAD")
    changes = _name_status(workspace, parent, commit)
    if not changes or len(changes) > MAX_TRANSFER_PATHS:
        raise TransferError(TransferCode.APPLY_FAILED, "empty or excessive source change")
    planned: list[TransferEntry] = []
    reserved: set[str] = set()
    for status_code, old_path, new_path in changes:
        old_entry = source_before.get(old_path) if old_path else None
        new_entry = source_after.get(new_path) if new_path else None
        _validate_types(status_code, old_entry, new_entry)
        target_old, method, anchor = _map_old(
            workspace, old_path, old_entry, new_entry, target, prefix, explicit)
        target_new = _map_new(
            status_code, old_path, new_path, target_old, target,
            prefix, explicit)
        current_paths = {path for path in (target_old, target_new) if path}
        if reserved & current_paths:
            raise TransferError(
                TransferCode.AMBIGUOUS_MAPPING, "two source paths map to one target")
        reserved.update(current_paths)
        planned.append(TransferEntry(
            status_code, old_path, new_path,
            old_entry.mode if old_entry else None,
            new_entry.mode if new_entry else None,
            target_old, target_new, method, "high", anchor,
        ))
    return planned


def _map_old(
    workspace: Path, source_path: str | None, source_entry: TreeEntry | None,
    new_entry: TreeEntry | None, target: dict[str, TreeEntry],
    prefix: str | None, explicit: dict[str, str],
) -> tuple[str | None, str, str | None]:
    if source_path is None or source_entry is None:
        return None, "creation", None
    anchor_bytes = _blob(workspace, source_entry.object_id)
    anchor = hashlib.sha256(anchor_bytes).hexdigest()
    if source_path in target:
        path, method = source_path, "exact"
    elif (prefix and source_path.startswith(prefix)
          and source_path[len(prefix):] in target):
        path, method = source_path[len(prefix):], "configured_prefix"
    elif explicit.get(source_path) in target:
        path, method = explicit[source_path], "explicit"
    else:
        path = method = ""
    if (path and new_entry is not None and target[path].mode == new_entry.mode
            and _blob(workspace, target[path].object_id)
            == _blob(workspace, new_entry.object_id)):
        return path, "already_present", anchor
    if not path:
        possible = [entry for entry in target.values()
                    if entry.mode == source_entry.mode
                    and (_suffix_related(source_path, entry.path)
                         or PurePosixPath(entry.path).name
                         == PurePosixPath(source_path).name)]
        anchored = [entry.path for entry in possible
                    if _blob(workspace, entry.object_id) == anchor_bytes]
        suffix = [path for path in anchored
                  if _suffix_related(source_path, path)]
        pool = suffix or [path for path in anchored
                          if PurePosixPath(path).name == PurePosixPath(source_path).name]
        if len(pool) == 1:
            path, method = pool[0], "unique_content_anchor"
        elif len(pool) > 1:
            raise TransferError(
                TransferCode.AMBIGUOUS_MAPPING,
                f"multiple anchored targets for {source_path}",
            )
    if not path and new_entry is not None:
        new_bytes = _blob(workspace, new_entry.object_id)
        fixed = [entry.path for entry in target.values()
                 if entry.mode == new_entry.mode
                 and (_suffix_related(source_path, entry.path)
                      or PurePosixPath(entry.path).name
                      == PurePosixPath(source_path).name)
                 and _blob(workspace, entry.object_id) == new_bytes]
        if len(fixed) == 1:
            return fixed[0], "already_present", anchor
        if len(fixed) > 1:
            raise TransferError(
                TransferCode.AMBIGUOUS_MAPPING,
                f"multiple already-fixed targets for {source_path}")
    if not path:
        raise TransferError(
            TransferCode.NO_TARGET_PATH, f"no unique target for {source_path}")
    if target[path].mode != source_entry.mode:
        raise TransferError(
            TransferCode.UNSUPPORTED_FILE_TYPE, f"mode mismatch for {source_path}")
    return path, method, anchor


def _map_new(
    status_code: str, old_path: str | None, new_path: str | None,
    target_old: str | None, target: dict[str, TreeEntry], prefix: str | None,
    explicit: dict[str, str],
) -> str | None:
    if new_path is None:
        return None
    if status_code in {"M", "T"}:
        return target_old
    if status_code.startswith("R") and old_path and target_old:
        explicit_target = explicit.get(new_path)
        if explicit_target:
            candidate = explicit_target
        elif prefix and new_path.startswith(prefix):
            candidate = new_path[len(prefix):]
        else:
            old_parent = PurePosixPath(target_old).parent
            candidate = (old_parent / PurePosixPath(new_path).name).as_posix()
        if candidate in target and candidate != target_old:
            raise TransferError(
                TransferCode.AMBIGUOUS_MAPPING, "rename destination already exists")
        return _safe_path(candidate)
    if status_code == "A":
        creation_candidate = explicit.get(new_path)
        if creation_candidate is None and prefix and new_path.startswith(prefix):
            creation_candidate = new_path[len(prefix):]
        if creation_candidate is None:
            creation_candidate = new_path
        creation_candidate = _safe_path(creation_candidate)
        if creation_candidate in target:
            raise TransferError(
                TransferCode.AMBIGUOUS_MAPPING, "creation target already exists")
        return creation_candidate
    raise TransferError(TransferCode.UNSUPPORTED_FILE_TYPE, "unsupported change status")


def _validate_types(
    status_code: str, old: TreeEntry | None, new: TreeEntry | None,
) -> None:
    supported = {"100644", "100755"}
    for entry in (old, new):
        if entry is not None and entry.mode not in supported:
            raise TransferError(
                TransferCode.UNSUPPORTED_FILE_TYPE, "symlink, gitlink, or special file")
    if status_code == "T" or (old and new and old.mode != new.mode):
        raise TransferError(TransferCode.UNSUPPORTED_FILE_TYPE, "mode change")


def _apply_entries(
    workspace: Path, parent: str, commit: str, entries: list[TransferEntry],
) -> None:
    total = 0
    for entry in entries:
        if entry.mapping_method == "already_present":
            continue
        old_data = (_object_path_bytes(workspace, parent, entry.source_old_path)
                    if entry.source_old_path else b"")
        new_data = (_object_path_bytes(workspace, commit, entry.source_new_path)
                    if entry.source_new_path else b"")
        total += len(old_data) + len(new_data)
        if total > MAX_TRANSFER_TOTAL_BYTES:
            raise TransferError(TransferCode.APPLY_FAILED, "transfer byte limit exceeded")
        if b"\0" in old_data or b"\0" in new_data:
            raise TransferError(TransferCode.UNSUPPORTED_FILE_TYPE, "binary change")
        target_old = entry.target_old_path
        target_new = entry.target_new_path
        target_data = (_read_target(workspace, target_old) if target_old else b"")
        adapted = _adapt_text(old_data, new_data, target_data)
        if target_old and target_new and target_old != target_new:
            _unlink_target(workspace, target_old)
        if target_new is None:
            if target_old:
                _unlink_target(workspace, target_old)
            continue
        _write_target(workspace, target_new, adapted,
                      executable=entry.source_new_mode == "100755")


def _adapt_text(old: bytes, new: bytes, target: bytes) -> bytes:
    if target == old:
        return new
    old_lines = old.decode("utf-8", errors="strict").splitlines(keepends=True)
    new_lines = new.decode("utf-8", errors="strict").splitlines(keepends=True)
    target_lines = target.decode("utf-8", errors="strict").splitlines(keepends=True)
    if max(len(old_lines), len(new_lines), len(target_lines)) > MAX_TRANSFER_LINES:
        raise TransferError(TransferCode.APPLY_FAILED, "line limit exceeded")
    opcodes = [opcode for opcode in difflib.SequenceMatcher(
        None, old_lines, new_lines, autojunk=False).get_opcodes()
        if opcode[0] != "equal"]
    if len(opcodes) > MAX_TRANSFER_HUNKS:
        raise TransferError(TransferCode.APPLY_FAILED, "hunk limit exceeded")
    for _, old_start, old_end, new_start, new_end in opcodes:
        needle = old_lines[old_start:old_end]
        replacement = new_lines[new_start:new_end]
        candidates = _candidate_positions(target_lines, needle, old_lines, old_start, old_end)
        if len(candidates) != 1:
            raise TransferError(
                TransferCode.CONTEXT_MISMATCH, "change has no unique content anchor")
        position = candidates[0]
        target_lines[position:position + len(needle)] = replacement
    return "".join(target_lines).encode("utf-8")


def _candidate_positions(
    target: list[str], needle: list[str], source: list[str], start: int, end: int,
) -> list[int]:
    if needle:
        positions = [index for index in range(len(target) - len(needle) + 1)
                     if target[index:index + len(needle)] == needle]
    else:
        positions = list(range(len(target) + 1))
    before = source[max(0, start - 3):start]
    after = source[end:end + 3]
    anchored = [position for position in positions
                if (not before or target[max(0, position - len(before)):position] == before)
                and (not after or target[position + len(needle):
                                         position + len(needle) + len(after)] == after)]
    if anchored:
        return anchored
    # A pure insertion has no removed text to anchor it. Stable branches often
    # add a comment or setting on one side of the upstream insertion point, so
    # requiring all three lines on both sides rejects an otherwise unique
    # anchor. Rank every position by the number of immediately adjacent exact
    # context lines (up to three per side), then accept only one unique best
    # position with at least two matching lines. Ties and weak one-line hints
    # remain ambiguous and rejected.
    if not needle:
        scores: dict[int, int] = {}
        for position in positions:
            before_score = 0
            for size in range(min(len(before), position), 0, -1):
                if target[position - size:position] == before[-size:]:
                    before_score = size
                    break
            after_score = 0
            for size in range(min(len(after), len(target) - position), 0, -1):
                if target[position:position + size] == after[:size]:
                    after_score = size
                    break
            scores[position] = before_score + after_score
        best_score = max(scores.values(), default=0)
        best = [position for position, score in scores.items()
                if score == best_score]
        if best_score >= 2 and len(best) == 1:
            return best
    return positions


def _verify_and_commit(
    workspace: Path, entries: list[TransferEntry], source_commit: str, cve_id: str,
) -> None:
    paths = sorted(_expected_paths(entries))
    if not paths:
        return
    for path in paths:
        _safe_path(path)
    result = run_cmd_capture(["git", "add", "-A", "--", *paths], cwd=workspace)
    if result.returncode != 0:
        raise TransferError(TransferCode.APPLY_FAILED, "fixed staging failed")
    actual = set(_changed_paths(_git(
        workspace, "diff", "--cached", "--name-status", "-z")))
    if actual != set(paths):
        raise TransferError(TransferCode.POSTCHECK_FAILED, "staged path set differs")
    message = _git(workspace, "show", "-s", "--format=%B", source_commit)
    if not message.strip() or len(message.encode("utf-8")) > 64 * 1024:
        message = f"Apply {cve_id} source transfer\n"
    descriptor, name = tempfile.mkstemp(prefix="cve-transfer-message-")
    try:
        os.write(descriptor, message.encode("utf-8"))
        os.close(descriptor)
        descriptor = -1
        result = run_cmd_capture(["git", "commit", "-F", name], cwd=workspace)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        Path(name).unlink(missing_ok=True)
    if result.returncode != 0:
        raise TransferError(TransferCode.APPLY_FAILED, "fixed commit failed")
    committed = set(_changed_paths(_git(
        workspace, "diff-tree", "--no-commit-id", "--name-status", "-z", "-r", "HEAD")))
    if committed != set(paths):
        raise TransferError(TransferCode.POSTCHECK_FAILED, "commit path set differs")


def _tree(workspace: Path, revision: str) -> dict[str, TreeEntry]:
    output = _git(workspace, "ls-tree", "-r", "-z", revision)
    tree: dict[str, TreeEntry] = {}
    for record in output.split("\0"):
        if not record:
            continue
        metadata, separator, path = record.partition("\t")
        fields = metadata.split()
        if not separator or len(fields) != 3:
            raise TransferError(TransferCode.APPLY_FAILED, "malformed target inventory")
        mode, kind, object_id = fields
        if kind not in {"blob", "commit"}:
            raise TransferError(TransferCode.UNSUPPORTED_FILE_TYPE, "unknown tree entry")
        tree[path] = TreeEntry(_safe_path(path), mode, object_id)
    if len(tree) > MAX_TRANSFER_PATHS:
        raise TransferError(TransferCode.APPLY_FAILED, "target inventory limit exceeded")
    return tree


def _name_status(
    workspace: Path, parent: str, commit: str,
) -> list[tuple[str, str | None, str | None]]:
    output = _git(workspace, "diff", "--name-status", "-z", "-M", parent, commit)
    tokens = [token for token in output.split("\0") if token]
    changes = []
    index = 0
    while index < len(tokens):
        status_code = tokens[index]
        index += 1
        kind = status_code[0]
        if kind in {"R", "C"}:
            if index + 1 >= len(tokens):
                raise TransferError(TransferCode.APPLY_FAILED, "malformed rename")
            old_path, new_path = tokens[index:index + 2]
            index += 2
        elif kind == "A":
            old_path, new_path = None, tokens[index]
            index += 1
        elif kind == "D":
            old_path, new_path = tokens[index], None
            index += 1
        elif kind in {"M", "T"}:
            old_path = new_path = tokens[index]
            index += 1
        else:
            raise TransferError(TransferCode.UNSUPPORTED_FILE_TYPE, "unsupported diff status")
        changes.append((kind if kind != "R" else status_code, old_path, new_path))
    return changes


def _changed_paths(output: str) -> list[str]:
    tokens = [token for token in output.split("\0") if token]
    paths: list[str] = []
    index = 0
    while index < len(tokens):
        status_code = tokens[index]
        index += 1
        count = 2 if status_code.startswith(("R", "C")) else 1
        paths.extend(tokens[index:index + count])
        index += count
    return paths


def _expected_paths(entries: list[TransferEntry]) -> set[str]:
    return {path for entry in entries
            if entry.mapping_method != "already_present"
            for path in (entry.target_old_path, entry.target_new_path) if path}


def _object_path_bytes(workspace: Path, revision: str, path: str | None) -> bytes:
    if path is None:
        return b""
    object_id = _git(workspace, "rev-parse", f"{revision}:{path}").strip()
    return _blob(workspace, object_id)


def _blob(workspace: Path, object_id: str) -> bytes:
    try:
        size = int(_git(workspace, "cat-file", "-s", object_id).strip())
    except ValueError as error:
        raise TransferError(TransferCode.APPLY_FAILED, "invalid blob size") from error
    if size > MAX_TRANSFER_FILE_BYTES:
        raise TransferError(TransferCode.APPLY_FAILED, "file byte limit exceeded")
    result = subprocess.run(
        ["git", "cat-file", "blob", object_id], cwd=workspace,
        env=build_git_env(), stdin=subprocess.DEVNULL, capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise TransferError(TransferCode.APPLY_FAILED, "blob unavailable")
    data = result.stdout
    if len(data) != size or len(data) > MAX_TRANSFER_FILE_BYTES:
        raise TransferError(TransferCode.APPLY_FAILED, "file byte limit exceeded")
    return data


def _read_target(workspace: Path, path: str) -> bytes:
    target = _target_path(workspace, path)
    try:
        data = target.read_bytes()
    except OSError as error:
        raise TransferError(TransferCode.APPLY_FAILED, "target read failed") from error
    if len(data) > MAX_TRANSFER_FILE_BYTES:
        raise TransferError(TransferCode.APPLY_FAILED, "target file limit exceeded")
    return data


def _write_target(workspace: Path, path: str, data: bytes, *, executable: bool) -> None:
    target = _target_path(workspace, path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        target.write_bytes(data)
        target.chmod(0o755 if executable else 0o644)
    except OSError as error:
        raise TransferError(TransferCode.APPLY_FAILED, "target write failed") from error


def _unlink_target(workspace: Path, path: str) -> None:
    target = _target_path(workspace, path)
    try:
        target.unlink()
    except OSError as error:
        raise TransferError(TransferCode.APPLY_FAILED, "target delete failed") from error


def _target_path(workspace: Path, path: str) -> Path:
    safe = _safe_path(path)
    target = workspace.joinpath(*PurePosixPath(safe).parts)
    try:
        parent = target.parent.resolve(strict=True)
    except OSError:
        # A creation may introduce one new final directory only when its
        # existing ancestor remains inside the repository.
        parent = target.parent
        while not parent.exists() and parent != workspace:
            parent = parent.parent
        try:
            parent = parent.resolve(strict=True)
        except OSError as nested:
            raise TransferError(TransferCode.SCOPE_VIOLATION, "unsafe target parent") from nested
    if parent != workspace and workspace not in parent.parents:
        raise TransferError(TransferCode.SCOPE_VIOLATION, "target escapes workspace")
    current = workspace
    for part in PurePosixPath(safe).parts[:-1]:
        current /= part
        if current.is_symlink():
            raise TransferError(TransferCode.SCOPE_VIOLATION, "symlink path component")
    return target


def _rollback(workspace: Path, head: str, created_paths: set[str]) -> None:
    run_cmd_capture(["git", "reset", "--hard", head], cwd=workspace)
    for path in created_paths:
        target = workspace.joinpath(*PurePosixPath(path).parts)
        tracked = run_cmd_capture(
            ["git", "ls-files", "--error-unmatch", "--", path], cwd=workspace)
        if target.exists() and tracked.returncode != 0:
            target.unlink(missing_ok=True)


def _write_manifest(path: Path, manifest: TransferManifest) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=".transfer-", suffix=".json")
    try:
        os.fchmod(descriptor, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(manifest.to_dict(), output, sort_keys=True, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


def verified_transfer_paths(path: Path, current_head: str) -> tuple[str, ...] | None:
    """Read the small security-critical subset of a verified manifest."""
    try:
        if path.stat().st_size > 1024 * 1024:
            return None
        value = json.loads(path.read_bytes().decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    if (not isinstance(value, dict)
            or value.get("schema_version") != TRANSFER_SCHEMA_VERSION
            or value.get("verification") != "verified"
            or value.get("failure_code") is not None
            or value.get("target_final_head") != current_head):
        return None
    paths = value.get("final_changed_paths")
    if (not isinstance(paths, list) or not paths or len(paths) > MAX_TRANSFER_PATHS
            or not all(isinstance(path, str) for path in paths)):
        return None
    try:
        normalized = tuple(sorted({_safe_path(path) for path in paths}))
    except TransferError:
        return None
    return normalized if len(normalized) == len(paths) else None


def _git(workspace: Path, *args: str) -> str:
    result = run_cmd_capture(["git", *args], cwd=workspace)
    if result.returncode != 0:
        raise TransferError(TransferCode.APPLY_FAILED, "fixed Git inspection failed")
    if len(result.stdout.encode("utf-8")) > MAX_TRANSFER_TOTAL_BYTES:
        raise TransferError(TransferCode.APPLY_FAILED, "Git output limit exceeded")
    return result.stdout


def _safe_path(path: str) -> str:
    if (not isinstance(path, str) or not path or path.startswith("/")
            or "\\" in path or "\0" in path or "\n" in path or "\r" in path
            or "\t" in path or any(part in {"", ".", "..", ".git"}
                                   for part in PurePosixPath(path).parts)):
        raise TransferError(TransferCode.SCOPE_VIOLATION, "unsafe repository path")
    return PurePosixPath(path).as_posix()


def _suffix_related(source: str, target: str) -> bool:
    source_parts = PurePosixPath(source).parts
    target_parts = PurePosixPath(target).parts
    common = 0
    for left, right in zip(reversed(source_parts), reversed(target_parts)):
        if left != right:
            break
        common += 1
    return common >= min(2, len(source_parts), len(target_parts))
