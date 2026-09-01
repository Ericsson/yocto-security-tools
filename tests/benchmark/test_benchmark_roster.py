# SPDX-License-Identifier: MIT
"""Integrity tests for the committed benchmark rosters.

Four rosters ship. Three hold CVEs that need resolution — a recoverable exit
(conflict/ptest/build) — nested for comparability: default (6) ⊂ balanced (8)
⊂ extended (21). ``tier`` on those three is derived from conflict/file
complexity (:func:`score_tier`), not diff size, since diffing against a
reference fix has no meaning until a conflict is actually resolved.

The fourth, ``benchmark-roster-clean-apply.json``, holds CVEs whose
cherry-pick applies with no conflict at all (``exit_code == 0``). It is NOT
nested in the other three — a clean apply is a different kind of case, not a
"lower difficulty" version of the same one — and its schema uses ``phase:
"clean_apply"`` instead of ``tier``, since score_tier has nothing to measure
when there is no conflict to size.

All four are hand-curated, but every field is supposed to be real measured
data in the exact shape ``run_benchmark.sh --retier`` writes. These tests
catch the drift a manual edit introduces: a tier that disagrees with
:func:`score_tier`, a missing field, or an exit code that doesn't belong in
that roster's category.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from cve_agent import RECOVERABLE_EXITS
from tests.benchmark.bench_lib import ordered_roster_cases, score_tier

BENCH_DIR = Path(__file__).resolve().parent
DEFAULT_ROSTER = BENCH_DIR / "benchmark-roster.json"
BALANCED_ROSTER = BENCH_DIR / "benchmark-roster-balanced.json"
EXTENDED_ROSTER = BENCH_DIR / "benchmark-roster-extended.json"
CLEAN_APPLY_ROSTER = BENCH_DIR / "benchmark-roster-clean-apply.json"

# The three "needs resolution" rosters, nested smallest first.
RESOLUTION_ROSTERS = (DEFAULT_ROSTER, BALANCED_ROSTER, EXTENDED_ROSTER)
NESTING = RESOLUTION_ROSTERS
ALL_ROSTERS = (*RESOLUTION_ROSTERS, CLEAN_APPLY_ROSTER)

EXPECTED_SIZES = {
    DEFAULT_ROSTER.name: 6,
    BALANCED_ROSTER.name: 8,
    EXTENDED_ROSTER.name: 21,
    CLEAN_APPLY_ROSTER.name: 5,
}

RESOLUTION_FIELDS = {
    "conflict_markers",
    "exit_code",
    "files_involved",
    "recipe",
    "tier",
}

CLEAN_APPLY_FIELDS = {
    "diff_lines",
    "exit_code",
    "phase",
    "recipe",
    "series_len",
}


def _load(path: Path) -> dict[str, dict]:
    """Load a roster JSON file."""
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(params=RESOLUTION_ROSTERS, ids=lambda p: p.name)
def roster(request: pytest.FixtureRequest) -> dict[str, dict]:
    """Each of the three resolution rosters in turn."""
    return _load(request.param)


@pytest.fixture(params=(BALANCED_ROSTER, EXTENDED_ROSTER), ids=lambda p: p.name)
def broad_roster(request: pytest.FixtureRequest) -> dict[str, dict]:
    """The two resolution rosters curated for tier and complexity spread."""
    return _load(request.param)


class TestRosterFilesExist:
    """All four rosters ship, and the three resolution rosters nest."""

    def test_all_rosters_are_committed(self) -> None:
        for path in ALL_ROSTERS:
            assert path.is_file(), f"{path.name} is missing"

    def test_expected_sizes(self) -> None:
        for path in ALL_ROSTERS:
            assert len(_load(path)) == EXPECTED_SIZES[path.name], path.name

    def test_rosters_are_nested(self) -> None:
        """default ⊆ balanced ⊆ extended, so runs stay comparable."""
        for smaller, larger in zip(NESTING, NESTING[1:]):
            assert set(_load(smaller)) <= set(_load(larger)), (
                f"{smaller.name} is not a subset of {larger.name}"
            )

    def test_shared_entries_are_identical(self) -> None:
        """The same CVE must not carry different measured stats in each file."""
        for smaller, larger in zip(NESTING, NESTING[1:]):
            small_data, large_data = _load(smaller), _load(larger)
            for cve, entry in small_data.items():
                assert entry == large_data[cve], (
                    f"{cve} differs between {smaller.name} and {larger.name}"
                )

    def test_clean_apply_roster_is_not_nested_in_the_others(self) -> None:
        """clean-apply is a separate case, not a subset/superset relationship
        with the resolution rosters — a CVE could coincidentally appear in
        both, but there is no subset requirement either way."""
        clean_apply_ids = set(_load(CLEAN_APPLY_ROSTER))
        extended_ids = set(_load(EXTENDED_ROSTER))
        assert not (clean_apply_ids & extended_ids), (
            "a CVE appears in both the clean-apply and extended rosters — "
            "pick a fresh CVE for one of them so the two stay independent "
            "measurements"
        )


class TestResolutionRosterSchema:
    """Every resolution-roster entry carries exactly the fields --retier
    reads and writes, and only a recoverable exit code."""

    def test_roster_is_non_empty(self, roster: dict[str, dict]) -> None:
        assert roster

    def test_every_entry_has_the_required_fields(self, roster: dict[str, dict]) -> None:
        for cve, entry in roster.items():
            assert set(entry) == RESOLUTION_FIELDS, f"{cve} has fields {sorted(entry)}"

    def test_field_types(self, roster: dict[str, dict]) -> None:
        for cve, entry in roster.items():
            assert isinstance(entry["recipe"], str) and entry["recipe"], cve
            assert isinstance(entry["tier"], str), cve
            for numeric in ("conflict_markers", "exit_code", "files_involved"):
                assert isinstance(entry[numeric], int), f"{cve}.{numeric}"
                assert entry[numeric] >= 0, f"{cve}.{numeric}"

    def test_cve_ids_are_well_formed(self, roster: dict[str, dict]) -> None:
        for cve in roster:
            assert cve.startswith("CVE-"), cve
            year, number = cve.removeprefix("CVE-").split("-")
            assert year.isdigit() and number.isdigit(), cve

    def test_exit_code_is_recoverable(self, roster: dict[str, dict]) -> None:
        """A resolution roster only ever holds a CVE that needs resolution --
        a clean exit belongs in the clean-apply roster, and any other exit
        means the corrector bailed before reaching a conflict at all, which
        --retier's guard refuses to record here."""
        for cve, entry in roster.items():
            assert entry["exit_code"] in RECOVERABLE_EXITS, (
                f"{cve} has exit_code={entry['exit_code']}, not recoverable "
                f"({sorted(RECOVERABLE_EXITS)})"
            )


class TestResolutionRosterConsistency:
    """The recorded tier must match how it is derived from conflict/file data."""

    def test_tier_agrees_with_score_tier(self, roster: dict[str, dict]) -> None:
        for cve, entry in roster.items():
            expected = score_tier(
                entry["exit_code"], entry["conflict_markers"], entry["files_involved"])
            assert entry["tier"] == expected, (
                f"{cve} records tier={entry['tier']} but score_tier says {expected}"
            )

    def test_tiers_are_known_values(self, roster: dict[str, dict]) -> None:
        for cve, entry in roster.items():
            assert entry["tier"] in ("easy", "medium", "hard"), cve

    def test_files_involved_never_exceeds_conflict_markers_much(
        self, roster: dict[str, dict]
    ) -> None:
        """Sanity bound: files_involved counts distinct files, so it can never
        exceed conflict_markers (each file needs at least one marker to be
        counted) -- except the structural-failure case where both are 0."""
        for cve, entry in roster.items():
            assert entry["files_involved"] <= max(entry["conflict_markers"], 1) * 50, cve
            if entry["conflict_markers"] == 0:
                assert entry["files_involved"] == 0, (
                    f"{cve}: 0 markers but files_involved="
                    f"{entry['files_involved']} -- a file can't be 'involved' "
                    f"in a conflict with no marker for it"
                )

    def test_ordered_cases_cover_every_entry(self, roster: dict[str, dict]) -> None:
        """--list-cases / --run-case must be able to address the whole roster."""
        cases = ordered_roster_cases(roster)
        assert len(cases) == len(roster)
        assert {c["cve_id"] for c in cases} == set(roster)
        assert [c["case"] for c in cases] == list(range(1, len(roster) + 1))


class TestBroadRosterComposition:
    """Spread guards on the balanced and extended resolution rosters."""

    def test_at_least_two_tiers_are_represented(self, broad_roster: dict[str, dict]) -> None:
        """The real conflict/file-complexity distribution across the pool
        this project draws from has very few 'medium' CVEs (2 of 22 measured
        at calibration time), so a full 3-tier guarantee is not realistic --
        but a roster with only one tier would defeat the purpose of tiering
        at all."""
        assert len({e["tier"] for e in broad_roster.values()}) >= 2

    def test_no_recipe_monoculture(self, broad_roster: dict[str, dict]) -> None:
        """A recipe repeated too often would bias the benchmark toward it."""
        counts = Counter(e["recipe"] for e in broad_roster.values())
        recipe, count = counts.most_common(1)[0]
        assert count <= 2, f"{recipe} appears {count} times"

    def test_hard_entries_span_the_conflict_complexity_range(
        self, broad_roster: dict[str, dict]
    ) -> None:
        markers = sorted(
            e["conflict_markers"] for e in broad_roster.values() if e["tier"] == "hard"
        )
        assert markers, "broad roster must have at least one hard entry"
        assert markers[-1] >= 10, "no sizeable multi-marker conflict at the high end"


class TestCleanApplyRosterSchema:
    """The clean-apply roster's schema is deliberately different: `phase`
    instead of `tier`, since score_tier's conflict/file complexity has
    nothing to measure on a clean apply."""

    @pytest.fixture
    def clean_apply(self) -> dict[str, dict]:
        return _load(CLEAN_APPLY_ROSTER)

    def test_every_entry_has_the_required_fields(
        self, clean_apply: dict[str, dict]
    ) -> None:
        for cve, entry in clean_apply.items():
            assert set(entry) == CLEAN_APPLY_FIELDS, (
                f"{cve} has fields {sorted(entry)}")

    def test_no_tier_field(self, clean_apply: dict[str, dict]) -> None:
        """A `tier` key here would imply conflict-complexity tiering applies
        to a case that has no conflict at all -- regression guard for
        accidentally carrying the old schema over."""
        for cve, entry in clean_apply.items():
            assert "tier" not in entry, cve

    def test_phase_is_clean_apply(self, clean_apply: dict[str, dict]) -> None:
        for cve, entry in clean_apply.items():
            assert entry["phase"] == "clean_apply", cve

    def test_exit_code_is_always_zero(self, clean_apply: dict[str, dict]) -> None:
        for cve, entry in clean_apply.items():
            assert entry["exit_code"] == 0, (
                f"{cve} has exit_code={entry['exit_code']}, but this roster "
                f"is only for a clean cherry-pick"
            )

    def test_field_types(self, clean_apply: dict[str, dict]) -> None:
        for cve, entry in clean_apply.items():
            assert isinstance(entry["recipe"], str) and entry["recipe"], cve
            for numeric in ("diff_lines", "series_len"):
                assert isinstance(entry[numeric], int), f"{cve}.{numeric}"
                assert entry[numeric] >= 0, f"{cve}.{numeric}"
            assert entry["series_len"] >= 1, cve

    def test_cve_ids_are_well_formed(self, clean_apply: dict[str, dict]) -> None:
        for cve in clean_apply:
            assert cve.startswith("CVE-"), cve
            year, number = cve.removeprefix("CVE-").split("-")
            assert year.isdigit() and number.isdigit(), cve

    def test_ordered_cases_cover_every_entry(
        self, clean_apply: dict[str, dict]
    ) -> None:
        """ordered_roster_cases() falls back to `phase` when `tier` is
        absent, so --list-cases must still address every clean-apply CVE."""
        cases = ordered_roster_cases(clean_apply)
        assert len(cases) == len(clean_apply)
        assert {c["cve_id"] for c in cases} == set(clean_apply)
