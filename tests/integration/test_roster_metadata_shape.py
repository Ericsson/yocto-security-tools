# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Guard the benchmark metadata fixture against fix-commit noise.

The benchmark measures how close cve-agent gets to the patch a human landed in
OE-Core. That comparison is only meaningful if, for every roster CVE, the
metadata names *exactly* the upstream commit(s) OE-Core backported — as one
standalone hash, or as one ordered series when the fix is a dependent chain.

Extra candidates are not harmless padding. Four separate consumers key off
these fields:

* ``cherry_pick.apply_single_commits`` treats ``hashes`` as *alternatives* and
  stops at the first that applies, so an extra commit can be shipped as "the"
  fix (a fork's commit, a release bump, or half of a chain).
* ``cherry_pick.apply_series`` tries ``series`` in order, so a competing series
  ahead of OE's real chain wins.
* ``cve_agent.git.get_all_upstream_shas`` falls back to ``hashes[0]`` to
  compute the AI's allowed-file scope.
* ``cve_agent.semantic_validation`` derives its reference commits from
  ``series[0]`` or ``hashes[0]``.

These checks are structural and offline; ``tests/integration`` scripts recover
the ground truth itself from an OE-Core checkout, which CI does not have.
"""
import json
from pathlib import Path

import pytest

from shared.url_parser import extract_commit_hash

_ROOT = Path(__file__).resolve().parent.parent.parent
_METADATA = _ROOT / 'tests' / 'integration' / 'test-cve-metadata-agent.json'
_ROSTER_DIR = _ROOT / 'tests' / 'benchmark'

# openssh's OE-Core patch for CVE-2024-6387 is an Ubuntu-derived hand edit
# (it wraps the sshsigdie() logging call in `#if 0`); its Upstream-Status names
# a launchpad packaging commit, not an openssh-portable commit. There is no
# upstream commit to align to, so the single-fix/one-series shape cannot be
# asserted for it — only that no other project's commits are offered.
_NO_UPSTREAM_GROUND_TRUTH = {'CVE-2024-6387'}


def _rosters() -> dict[str, dict]:
    """Every CVE across every committed benchmark roster."""
    merged: dict[str, dict] = {}
    for path in sorted(_ROSTER_DIR.glob('benchmark-roster*.json')):
        merged.update(json.loads(path.read_text()))
    return merged


@pytest.fixture(scope='module')
def metadata() -> dict:
    return json.loads(_METADATA.read_text())


@pytest.fixture(scope='module')
def rosters() -> dict:
    return _rosters()


def test_rosters_are_not_empty(rosters):
    assert rosters, 'no benchmark rosters found'


def test_every_roster_cve_is_in_the_metadata(rosters, metadata):
    """A missing entry fails the run with exit 6 (EXIT_METADATA_ERROR)."""
    missing = sorted(cve for cve in rosters if cve not in metadata)
    assert not missing, f'roster CVEs absent from the fixture: {missing}'


def test_roster_recipe_matches_the_metadata(rosters, metadata):
    mismatched = {
        cve: (info['recipe'], metadata[cve].get('name'))
        for cve, info in rosters.items()
        if cve in metadata and metadata[cve].get('name') != info['recipe']
    }
    assert not mismatched, f'roster/metadata recipe disagreement: {mismatched}'


def test_fix_commits_are_a_single_standalone_or_a_single_series(rosters, metadata):
    """Exactly one shape per CVE: standalone hashes, or one ordered series.

    A second series competes with OE's real chain for both cherry-pick order
    and the semantic gate's reference commits.
    """
    bad = {}
    for cve in sorted(rosters):
        entry = metadata.get(cve)
        if entry is None or cve in _NO_UPSTREAM_GROUND_TRUTH:
            continue
        hashes = entry.get('hashes') or []
        series = entry.get('series') or []
        if len(series) > 1:
            bad[cve] = f'{len(series)} competing series'
        elif series and hashes:
            # `standalone_candidates` drops chain members from `hashes`, but a
            # non-chain hash left beside a series is still offered as a
            # fallback the human patch never used.
            bad[cve] = f'series plus {len(hashes)} standalone hash(es)'
        elif not series and not hashes:
            bad[cve] = 'no fix commits at all'
        elif series and len(series[0].get('commits') or []) < 2:
            bad[cve] = 'single-commit series should be a standalone hash'
    assert not bad, f'ambiguous fix-commit shape: {bad}'


def test_no_duplicate_fix_commits(rosters, metadata):
    dupes = {}
    for cve in sorted(rosters):
        entry = metadata.get(cve)
        if entry is None:
            continue
        commits = list(entry.get('hashes') or [])
        for series in entry.get('series') or []:
            commits += list(series.get('commits') or [])
        lowered = [c.lower() for c in commits]
        if len(lowered) != len(set(lowered)):
            dupes[cve] = commits
    assert not dupes, f'duplicate fix commits: {dupes}'


def test_recorded_commits_are_full_length_hex(rosters, metadata):
    """Abbreviated shas are ambiguous to git and rejected by the semantic gate."""
    bad = {}
    for cve in sorted(rosters):
        entry = metadata.get(cve)
        if entry is None:
            continue
        commits = list(entry.get('hashes') or [])
        for series in entry.get('series') or []:
            commits += list(series.get('commits') or [])
        offenders = [c for c in commits
                     if len(c) < 12 or not all(x in '0123456789abcdef' for x in c.lower())]
        if offenders:
            bad[cve] = offenders
    assert not bad, f'unusable commit spellings: {bad}'


def test_patch_urls_resolve_to_a_recorded_fix_commit(rosters, metadata):
    """``patches[0]`` heads the ``--fix-url`` chain on an agent-driven re-run.

    ``cve_agent.orchestrator._original_fix_url`` picks the first ``patches``
    entry that resolves to a commit, so an advisory link or a fork's commit
    sitting at the front sends the re-run at the wrong change.
    """
    bad = {}
    for cve in sorted(rosters):
        entry = metadata.get(cve)
        if entry is None or cve in _NO_UPSTREAM_GROUND_TRUTH:
            continue
        recorded = [c.lower() for c in (entry.get('hashes') or [])]
        for series in entry.get('series') or []:
            recorded += [c.lower() for c in (series.get('commits') or [])]
        offenders = []
        for url in entry.get('patches') or []:
            found = extract_commit_hash(url)
            if not found or not any(found.lower().startswith(r)
                                    or r.startswith(found.lower())
                                    for r in recorded):
                offenders.append(url)
        if offenders:
            bad[cve] = offenders
    assert not bad, f'patch URLs that are not the recorded fix: {bad}'


def test_hash_details_only_describe_recorded_fix_commits(rosters, metadata):
    """``hash_details`` URLs seed upstream-repo deduction in ``workspace.py``.

    An entry for a fork's commit points the clone at the wrong project.
    """
    bad = {}
    for cve in sorted(rosters):
        entry = metadata.get(cve)
        if entry is None or cve in _NO_UPSTREAM_GROUND_TRUTH:
            continue
        recorded = [c.lower() for c in (entry.get('hashes') or [])]
        for series in entry.get('series') or []:
            recorded += [c.lower() for c in (series.get('commits') or [])]
        offenders = [d.get('hash') for d in entry.get('hash_details') or []
                     if not any((d.get('hash') or '').lower().startswith(r)
                                or r.startswith((d.get('hash') or '').lower())
                                for r in recorded)]
        if offenders:
            bad[cve] = offenders
    assert not bad, f'hash_details for commits that are not the fix: {bad}'


def test_openssh_exception_carries_no_foreign_project_commits(metadata):
    """The one CVE without OE ground truth must still stay within its project.

    CVE-2024-6387 was recorded with commits from the openela and hpn-ssh forks,
    neither of which can be cherry-picked into openssh-portable.
    """
    entry = metadata['CVE-2024-6387']
    urls = [d.get('url') or '' for d in entry.get('hash_details') or []]
    urls += list(entry.get('patches') or [])
    foreign = [u for u in urls
               if extract_commit_hash(u)
               and 'openssh/openssh-portable' not in u]
    assert not foreign, f'non-openssh commits offered as the fix: {foreign}'
