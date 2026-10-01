# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Prepare patches and bbappends from cached OpenEmbedded status results."""

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from cve_metadata_extractor.oe_status import _get_repo_url
from shared import TEXT_ENCODING, TEXT_ERRORS

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")
_RECIPE_RE = re.compile(r"^[A-Za-z0-9.+_-]+$")

def _cache_mapping(cache: dict) -> tuple[dict[str, dict], list[dict]]:
    """Infer CVE and branch pairs from merged cache entries."""
    mapping = {}
    unresolved = []
    for key, entry in cache.items():
        if not isinstance(key, str) or not isinstance(entry, dict):
            continue
        parts = key.split(":")
        if len(parts) < 2 or not _CVE_RE.fullmatch(parts[0]):
            continue
        cve = parts[0]
        branch_parts = parts[1:]
        if branch_parts[-1] in ("with-token", "without-token"):
            branch_parts.pop()
        branch = ":".join(branch_parts)
        if not branch:
            continue
        status = entry.get("status")
        if isinstance(status, str) and "merged:" in status:
            mapping[f"{cve}:{branch}"] = {"cve": cve, "branch": branch}

    return mapping, unresolved

def _write_generated_mapping(path: Path, mapping: dict[str, dict], dry_run: bool) -> None:
    """Persist the inferred mapping atomically for review and reproducibility."""
    if dry_run:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(mapping, indent=2) + "\n"
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(
                "w", encoding=TEXT_ENCODING, dir=path.parent, delete=False) as temp_file:
            temp_file.write(payload)
            temp_path = Path(temp_file.name)
        os.replace(temp_path, path)
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink()

def _branch_repositories(branch: str) -> list[tuple[str, str]]:
    """Return repository/ref pairs in the same order as the OE status check."""
    candidates = [
        (_get_repo_url("oe_core_url"), branch),
        (_get_repo_url("oe_core_contrib_url"), f"stable/{branch}-next"),
        (_get_repo_url("meta_openembedded_url"), branch),
        (_get_repo_url("meta_openembedded_url"), f"{branch}-next"),
        (_get_repo_url("meta_openembedded_contrib_url"), f"stable/{branch}-next"),
    ]

    return list(dict.fromkeys(candidates))

def _find_upstream_recipe(repo_dir: Path, branch: str, recipe: str,
                          target_version: str) -> tuple[str, str] | None:
    """Find the recipe's upstream layer-relative path and version on a branch."""
    candidates = []
    for repo_url, ref in _branch_repositories(branch):
        repo = repo_dir / repo_url.rstrip("/").rsplit("/", 1)[-1]
        if not repo.is_dir():
            continue
        result = subprocess.run(
            ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", ref],
            capture_output=True, check=False, encoding=TEXT_ENCODING,
            errors=TEXT_ERRORS, timeout=100)
        if result.returncode != 0:
            continue
        for upstream_path in result.stdout.splitlines():
            recipe_path = Path(upstream_path)
            if (recipe_path.suffix != ".bb"
                    or recipe_path.parent.name != recipe
                    or not recipe_path.name.startswith(f"{recipe}_")
                    or not any(part.startswith("recipes-")
                               for part in recipe_path.parts)):
                continue
            version = recipe_path.stem[len(recipe) + 1:]
            if version:
                candidates.append((upstream_path, version))
        if candidates:
            break
    if not candidates:
        return None
    for upstream_path, version in candidates:
        if version == target_version:
            return upstream_path, version

    return candidates[0]

def _find_merged_commits(repo_dir: Path, cve: str, branch: str
                         ) -> tuple[Path, str, list[str]] | None:
    """Find CVE-matching commits in existing OE clones without fetching."""
    for repo_url, ref in _branch_repositories(branch):
        repo = repo_dir / repo_url.rstrip("/").rsplit("/", 1)[-1]
        if not repo.is_dir():
            continue
        result = subprocess.run(
            ["git", "-C", str(repo), "log", ref, "--grep", cve,
             "--format=%H%x00%P%x00%s"],
            capture_output=True, check=False, encoding=TEXT_ENCODING,
            errors=TEXT_ERRORS, timeout=100)
        if result.returncode != 0:
            continue
        commits = []
        for line in result.stdout.splitlines():
            fields = line.split("\x00", 2)
            if len(fields) != 3:
                continue
            commit, parents, subject = fields
            if cve in subject and len(parents.split()) <= 1:
                commits.append(commit)
        if commits:
            return repo, ref, list(reversed(commits))

    return None

def _annotate_patch(patch: str, cve: str, upstream_url: str) -> str:
    """Add standard CVE and Upstream-Status headers to a format-patch result."""
    if "\n---\n" not in patch:
        raise ValueError("Git did not produce a format-patch message")
    before, after = patch.split("\n---\n", 1)
    headers = []
    if f"CVE: {cve}" not in before:
        headers.append(f"CVE: {cve}")
    if "Upstream-Status:" not in before:
        headers.append(f"Upstream-Status: Backport [{upstream_url}]")
    if headers:
        before = before.rstrip("\n") + "\n\n" + "\n".join(headers)
    return before + "\n---\n" + after

def _commit_patches(repo: Path, commit: str, recipe_path: str,
                    cve: str) -> list[str]:
    """Read CVE patch files changed by an OE recipe commit, not its Git diff."""
    changed = subprocess.run(
        ["git", "-C", str(repo), "diff-tree", "--no-commit-id", "--name-only",
         "--diff-filter=AM", "-r", "--root", commit],
        capture_output=True, check=True, encoding=TEXT_ENCODING,
        errors=TEXT_ERRORS, timeout=100).stdout
    recipe_dir = Path(recipe_path).parent
    patches = []
    for changed_path in changed.splitlines():
        path = Path(changed_path)
        if path.suffix != ".patch" or not path.is_relative_to(recipe_dir):
            continue
        content = subprocess.run(
            ["git", "-C", str(repo), "show", f"{commit}:{changed_path}"],
            capture_output=True, check=True, encoding=TEXT_ENCODING,
            errors=TEXT_ERRORS, timeout=100).stdout
        if (cve in path.name or f"CVE: {cve}" in content) and "\n---\n" in content:
            patches.append(content)

    return patches

def _resolve_layer_path(layer_dir: Path, relative_path: str) -> Path:
    """Resolve a relative layer path while rejecting traversal and symlinks."""
    relative = Path(relative_path)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        raise ValueError(f"layer path must be a clean relative path: {relative_path}")
    root = layer_dir.resolve()
    target = root / relative
    if not target.resolve().is_relative_to(root):
        raise ValueError(f"layer path escapes layer root: {relative_path}")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"layer path contains a symlink: {relative_path}")
    if target.suffix != ".bbappend":
        raise ValueError(f"mapped destination must be a .bbappend: {relative_path}")

    return target

def _write_if_new(path: Path, content: str, dry_run: bool,
                  allow_update: bool = False) -> bool:
    """Write content atomically, accepting identical existing output only."""
    encoded = content.encode(TEXT_ENCODING, errors=TEXT_ERRORS)
    if path.is_symlink():
        raise ValueError(f"refusing to write through symlink: {path}")
    if path.exists():
        if path.read_bytes() == encoded:
            return False
        if not allow_update:
            raise FileExistsError(f"refusing to overwrite existing file: {path}")
    if dry_run:
        return True
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temp_file:
            temp_file.write(encoded)
            temp_path = Path(temp_file.name)
        os.replace(temp_path, path)
    finally:
        if temp_path and temp_path.exists():
            temp_path.unlink()

    return True

def _bbappend_content(existing: str, patch_names: list[str], cve: str,
                      branch: str, target_version: str,
                      upstream_version: str) -> str:
    """Append commented patch configuration without replacing existing content."""
    content = existing
    additions = []
    if '${THISDIR}/cve-oe-backport:' not in content:
        additions.append('FILESEXTRAPATHS:prepend := "${THISDIR}/cve-oe-backport:"\n')
    for name in patch_names:
        if f"file://{name}" not in content:
            additions.append(
                f"# Generated by cve-oe-backport for {cve} from {branch}; "
                f"metadata PV {target_version}, upstream recipe PV {upstream_version}.")
            additions.append(f'SRC_URI += " file://{name}"\n')
    if not additions:
        return content

    return content + "\n".join(additions) + "\n"

def prepare_backports(cache: dict, metadata: dict, repo_dir: Path, layer_dir: Path,
                      dry_run: bool = False, packages: set[str] | None = None,
                      cve_ids: set[str] | None = None) -> list[dict]:
    """Infer and generate patches and bbappends for recent merged cache entries."""
    if not layer_dir.is_dir():
        raise ValueError(f"layer directory does not exist: {layer_dir}")
    cached_entries, unresolved = _cache_mapping(cache)
    cached_entries = {
        key: entry for key, entry in cached_entries.items()
        if (cve_ids is None or entry["cve"] in cve_ids)
        and (packages is None or (
            isinstance(metadata.get(entry["cve"]), dict)
            and metadata[entry["cve"]].get("name") in packages))
    }
    mapping = {}
    results = [{"status": "error", **item} for item in unresolved]
    per_cve_count = {}
    for cached in cached_entries.values():
        per_cve_count[cached["cve"]] = per_cve_count.get(cached["cve"], 0) + 1

    for cached in cached_entries.values():
        cve = cached["cve"]
        branch = cached["branch"]
        cve_metadata = metadata.get(cve)
        if not isinstance(cve_metadata, dict):
            results.append({"cve": cve, "branch": branch, "status": "skipped",
                            "reason": "CVE metadata entry not found"})
            continue
        recipe = cve_metadata.get("name")
        target_version = cve_metadata.get("version")
        if (not isinstance(recipe, str) or not _RECIPE_RE.fullmatch(recipe)
                or not isinstance(target_version, str) or not target_version):
            results.append({"cve": cve, "branch": branch, "status": "error",
                            "reason": "CVE metadata needs a valid name and version"})
            continue
        try:
            found = _find_merged_commits(repo_dir, cve, branch)
            if not found:
                raise ValueError("merged status has no matching commit in local OE clones")
            repo, _ref, commits = found
            upstream_recipe = _find_upstream_recipe(
                repo_dir, branch, recipe, target_version)
            if not upstream_recipe:
                raise ValueError(f"could not find upstream recipe {recipe} on {branch}")
            upstream_path, upstream_version = upstream_recipe
            upstream_parts = Path(upstream_path).parts
            category_index = next(
                index for index, part in enumerate(upstream_parts)
                if part.startswith("recipes-"))
            layer_recipe_dir = Path(*upstream_parts[category_index:-1])
            append_name = layer_recipe_dir / f"{recipe}_{target_version}.bbappend"
            bbappend = _resolve_layer_path(layer_dir, str(append_name))
            prefix = cve
            if per_cve_count[cve] > 1:
                prefix = f"{cve}-{re.sub(r'[^A-Za-z0-9._-]+', '-', branch)}"
            patch_dir = bbappend.parent / "cve-oe-backport"
            if patch_dir.is_symlink():
                raise ValueError(f"refusing to write through symlink: {patch_dir}")
            patch_texts = []
            for commit in commits:
                source_patches = _commit_patches(repo, commit, upstream_path, cve)
                if not source_patches:
                    raise ValueError(f"OE commit {commit} has no CVE patch for {recipe}")
                repo_url = next(url for url, ref in _branch_repositories(branch)
                                if (repo_dir / url.rstrip("/").rsplit("/", 1)[-1]) == repo
                                and ref == _ref)
                for source_patch in source_patches:
                    patch_texts.append(_annotate_patch(
                        source_patch, cve, f"{repo_url.rstrip('/')}/commit/?id={commit}"))
            patch_names = ([f"{prefix}.patch"] if len(patch_texts) == 1 else
                           [f"{prefix}-{index}.patch"
                            for index in range(1, len(patch_texts) + 1)])
            existing = bbappend.read_text(encoding=TEXT_ENCODING) if bbappend.exists() else ""
            append_text = _bbappend_content(
                existing, patch_names, cve, branch, target_version, upstream_version)
            output_files = [(patch_dir / name, patch_text)
                            for name, patch_text in zip(patch_names, patch_texts, strict=True)]
            output_files.append((bbappend, append_text))
            for path, content in output_files:
                if path.is_symlink():
                    raise ValueError(f"refusing to write through symlink: {path}")
                if path != bbappend and path.exists() and path.read_bytes() != content.encode(
                        TEXT_ENCODING, errors=TEXT_ERRORS):
                    raise FileExistsError(f"refusing to overwrite existing file: {path}")
            for path, content in output_files:
                _write_if_new(path, content, dry_run, allow_update=(path == bbappend))
            warning = None
            if target_version != upstream_version:
                warning = (f"metadata version {target_version} differs from "
                           f"upstream {branch} recipe version {upstream_version}; "
                           "patch prepared anyway")
            mapping[f"{cve}:{branch}"] = {
                "cve": cve, "branch": branch, "recipe": recipe,
                "metadata_version": target_version,
                "upstream_version": upstream_version,
                "bbappend": str(bbappend.relative_to(layer_dir)),
                "warning": warning,
            }
            results.append({"cve": cve, "recipe": recipe, "status": "prepared",
                            "branch": branch,
                            "bbappend": str(bbappend),
                            "patches": [str(patch_dir / name) for name in patch_names],
                            "warning": warning})
        except (OSError, ValueError, subprocess.SubprocessError, StopIteration) as exc:
            results.append({"cve": cve, "status": "error", "reason": str(exc)})

    _write_generated_mapping(repo_dir / "oe-backport-mapping.generated.json",
                             mapping, dry_run)

    return results

def main() -> int:
    """CLI for preparing layer patches from the OE status cache."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-dir", type=Path, required=True,
                        help="Directory containing the local OE repository clones")
    parser.add_argument("--layer-dir", type=Path, required=True,
                        help="Existing layer root where mapped files will be written")
    parser.add_argument("--cve-info", type=Path, default=Path("cve-metadata.json"),
                        help="CVE metadata input (default: ./cve-metadata.json)")
    parser.add_argument("--status-cache", type=Path,
                        help="Status cache path (default: REPO_DIR/oe-status-cache.json)")
    parser.add_argument("--package", action="append", metavar="NAME",
                        help="Only prepare this package (repeatable)")
    parser.add_argument("--cve-id", action="append", metavar="CVE-ID",
                        help="Only prepare this CVE (repeatable)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report planned output without writing files")
    args = parser.parse_args()
    cache_path = args.status_cache or args.repo_dir / "oe-status-cache.json"
    try:
        cache = json.loads(cache_path.read_text(encoding=TEXT_ENCODING))
        metadata = json.loads(args.cve_info.read_text(encoding=TEXT_ENCODING))
        if not isinstance(cache, dict):
            raise ValueError("status cache must contain a JSON object")
        if not isinstance(metadata, dict):
            raise ValueError("CVE metadata must contain a JSON object")
        results = prepare_backports(cache, metadata, args.repo_dir, args.layer_dir,
                                    dry_run=args.dry_run,
                                    packages=set(args.package) if args.package else None,
                                    cve_ids=set(args.cve_id) if args.cve_id else None)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    failed = False
    if not results:
        print("No merged CVE statuses matched the requested selection; no patches prepared.")
    for result in results:
        cve = result["cve"]
        if result["status"] == "prepared":
            print(f"{cve}: {'would prepare' if args.dry_run else 'prepared'} "
                  f"{result['recipe']} ({result['branch']}) -> {result['bbappend']}")
            if result.get("warning"):
                print(f"  WARNING: {result['warning']}")
            for patch in result["patches"]:
                print(f"  {patch}")
        elif result["status"] == "skipped":
            print(f"{cve}: skipped ({result['reason']})")
        else:
            failed = True
            print(f"{cve}: error ({result['reason']})")
    if not args.dry_run:
        print(f"Generated mapping: {args.repo_dir / 'oe-backport-mapping.generated.json'}")

    return 1 if failed else 0

if __name__ == "__main__":
    raise SystemExit(main())
