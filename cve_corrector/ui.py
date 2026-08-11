# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""User-facing output and instructions for CVE corrector."""
from pathlib import Path
from typing import Optional


def print_conflict_instructions(workspace_path: Path, recipe: str,
                                series_state: Optional[dict] = None) -> None:
    """Print instructions for resolving conflicts."""
    print("=" * 60)
    print("CONFLICT DETECTED - Manual resolution required")
    print("=" * 60)
    print(f"\nSource directory: {workspace_path}")

    if series_state:
        total = len(series_state.get('commits', []))
        applied = len(series_state.get('applied_commits', []))
        remaining = len(series_state.get('remaining_commits', []))
        failed = series_state.get('failed_at', 'unknown')[:8]
        print(f"\nSeries progress: {applied}/{total} commits applied")
        print(f"Failed at commit: {failed}")
        print(f"Remaining commits: {remaining}")
        print("\nNote: After resolving conflicts and running 'git cherry-pick --no-edit --continue',")
        print("      git will automatically apply the remaining commits in the series.")

    print("\nResolve conflicts manually using:")
    print(f"  cd {workspace_path}")
    print("  git status                    # View conflicted files")
    print("  git diff                      # View conflicts")
    print("  git mergetool                 # Use merge tool to resolve")
    print("  git add <file>                # Mark as resolved")
    print("  git cherry-pick --no-edit --continue    # Complete cherry-pick")
    print(f"  devtool build {recipe}        # Test the build")
    print("\nAfter resolving conflicts, resume with:")
    print("  cve-corrector --continue")
    print("=" * 60 + "\n")


def print_edit_instructions(workspace_path: Path, recipe: str, commit_hash: str) -> None:
    """Print instructions for edit mode."""
    print("=" * 60)
    print("EDIT MODE - Patch applied successfully")
    print("=" * 60)
    print(f"\nSource directory: {workspace_path}")
    print(f"\nPatch from commit {commit_hash[:8]} has been applied.")
    print("\nYou can now edit the changes:")
    print(f"  cd {workspace_path}")
    print("  git log -1                    # View applied commit")
    print("  git show                      # View changes")
    print("  git add <file>                # Stage changes")
    print("  git commit --amend            # Update commit")
    print(f"  devtool build {recipe}        # Test the build")
    print("\nAfter editing, continue with:")
    print("  cve-corrector --continue")
    print("=" * 60 + "\n")


def print_build_failure_instructions(workspace_path: Path, recipe: str) -> None:
    """Print instructions for resolving build failures after patch application."""
    print("=" * 60)
    print("BUILD FAILED - Manual fix required")
    print("=" * 60)
    print(f"\nSource directory: {workspace_path}")
    print(f"\nThe patch applied cleanly but the build failed for {recipe}.")
    print("\nDebug and fix the build using:")
    print(f"  cd {workspace_path}")
    print(f"  devtool build {recipe}        # Reproduce the failure")
    print("  # Fix the source code")
    print("  git add <file>                # Stage your changes")
    print("  git commit --amend            # Amend the patch commit")
    print("\nAfter fixing the build, resume with:")
    print("  cve-corrector --continue")
    print("=" * 60 + "\n")


def print_manual_instructions(workspace_path: Path, recipe: str,
                              hashes: list, series: list) -> None:
    """Print instructions for manual patching mode.

    Args:
        workspace_path: Path to devtool workspace source directory
        recipe: Recipe name being patched
        hashes: List of upstream fix commit hashes
        series: List of series dicts — an ordered set of commits that must
            all be applied, from a pull request or from repeated
            ``--fix-url``
    """
    print("=" * 60)
    print("MANUAL MODE - Environment ready for manual patching")
    print("=" * 60)
    print(f"\nSource directory: {workspace_path}")
    print("\nApply your patches manually:")
    print(f"  cd {workspace_path}")
    if hashes:
        print("\nUpstream fix commit(s):")
        for h in hashes:
            print(f"  git cherry-pick {h[:12]}")
    if series:
        print(f"\nDependent commit series available ({len(series)} series)")
    print("\nUseful commands:")
    print(f"  devtool build {recipe}        # Test the build")
    print("  git log --oneline             # View commit history")
    print("  git diff HEAD~1               # View last change")
    print("\nWhen ready, continue with:")
    print("  cve-corrector --continue")
    print("=" * 60 + "\n")
