# SPDX-License-Identifier: MIT
"""Integrity tests for the committed benchmark rosters.

Three rosters ship — the small default (`benchmark-roster.json`), a 20-CVE
balanced one, and a 40-CVE extended one. They are nested (default ⊂ balanced ⊂
extended) so results stay comparable across them. All three are hand-curated,
but every field is supposed to be real measured data in the exact shape
``run_benchmark.sh --retier`` writes. These tests catch the drift a manual edit
introduces: a tier that disagrees with :func:`score_tier`, a missing field, or
a conflict-marker count on a clean run (which ``--retier`` would silently reset
to 0 on the next probe).

Composition guards that only make sense for a broad roster (tier spread,
recipe cap, conflict-complexity range) are asserted on the balanced and
extended rosters only — the default roster is deliberately narrow and cheap.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from tests.benchmark.bench_lib import ordered_roster_cases, score_tier

BENCH_DIR = Path(__file__).resolve().parent
DEFAULT_ROSTER = BENCH_DIR / "benchmark-roster.json"
BALANCED_ROSTER = BENCH_DIR / "benchmark-roster-balanced.json"
EXTENDED_ROSTER = BENCH_DIR / "benchmark-roster-extended.json"
ALL_ROSTERS = (DEFAULT_ROSTER, BALANCED_ROSTER, EXTENDED_ROSTER)

# Nesting chain, smallest first. Each roster must be a subset of the next.
NESTING = (DEFAULT_ROSTER, BALANCED_ROSTER, EXTENDED_ROSTER)

EXPECTED_SIZES = {
    DEFAULT_ROSTER.name: 7,
    BALANCED_ROSTER.name: 20,
    EXTENDED_ROSTER.name: 40,
}

EXPECTED_COMPOSITION = {
    BALANCED_ROSTER.name: {"easy": 6, "medium": 6, "hard": 8},
    EXTENDED_ROSTER.name: {"easy": 6, "medium": 10, "hard": 24},
}

REQUIRED_FIELDS = {
    "conflict_markers",
    "diff_lines",
    "exit_code",
    "recipe",
    "series_len",
    "tier",
}


def _load(path: Path) -> dict[str, dict]:
    """Load a roster JSON file."""
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture(params=ALL_ROSTERS, ids=lambda p: p.name)
def roster(request: pytest.FixtureRequest) -> dict[str, dict]:
    """Each committed roster in turn."""
    return _load(request.param)


@pytest.fixture(params=(BALANCED_ROSTER, EXTENDED_ROSTER), ids=lambda p: p.name)
def broad_roster(request: pytest.FixtureRequest) -> dict[str, dict]:
    """The two rosters curated for tier and complexity spread."""
    return _load(request.param)


class TestRosterFilesExist:
    """All three rosters ship, and they nest."""

    def test_all_rosters_are_committed(self) -> None:
        for path in ALL_ROSTERS:
            assert path.is_file(), f"{path.name} is missing"

    def test_expected_sizes(self) -> None:
        for path in ALL_ROSTERS:
            assert len(_load(path)) == EXPECTED_SIZES[path.name], path.name

    def test_expected_composition(self) -> None:
        for path, expected in (
            (BALANCED_ROSTER, EXPECTED_COMPOSITION[BALANCED_ROSTER.name]),
            (EXTENDED_ROSTER, EXPECTED_COMPOSITION[EXTENDED_ROSTER.name]),
        ):
            counts = Counter(e["tier"] for e in _load(path).values())
            assert dict(counts) == expected, f"{path.name}: {dict(counts)}"

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


class TestRosterSchema:
    """Every entry carries exactly the fields --retier reads and writes."""

    def test_roster_is_non_empty(self, roster: dict[str, dict]) -> None:
        assert roster

    def test_every_entry_has_the_required_fields(self, roster: dict[str, dict]) -> None:
        for cve, entry in roster.items():
            assert set(entry) == REQUIRED_FIELDS, f"{cve} has fields {sorted(entry)}"

    def test_field_types(self, roster: dict[str, dict]) -> None:
        for cve, entry in roster.items():
            assert isinstance(entry["recipe"], str) and entry["recipe"], cve
            assert isinstance(entry["tier"], str), cve
            for numeric in ("conflict_markers", "diff_lines", "exit_code", "series_len"):
                assert isinstance(entry[numeric], int), f"{cve}.{numeric}"
                assert entry[numeric] >= 0, f"{cve}.{numeric}"

    def test_cve_ids_are_well_formed(self, roster: dict[str, dict]) -> None:
        for cve in roster:
            assert cve.startswith("CVE-"), cve
            year, number = cve.removeprefix("CVE-").split("-")
            assert year.isdigit() and number.isdigit(), cve

    def test_series_len_is_at_least_one(self, roster: dict[str, dict]) -> None:
        """A fix is one commit or a chain of several — never zero."""
        for cve, entry in roster.items():
            assert entry["series_len"] >= 1, cve


class TestRosterConsistency:
    """The recorded tier and marker count must match how they are derived."""

    def test_tier_agrees_with_score_tier(self, roster: dict[str, dict]) -> None:
        for cve, entry in roster.items():
            expected = score_tier(entry["exit_code"], entry["diff_lines"], entry["series_len"])
            assert entry["tier"] == expected, (
                f"{cve} records tier={entry['tier']} but score_tier says {expected}"
            )

    def test_clean_runs_have_no_conflict_markers(self, roster: dict[str, dict]) -> None:
        """run_benchmark.sh only counts markers when exit_code != 0.

        An entry that violates this would be silently rewritten by the next
        --retier, making the committed roster and a re-probed one disagree.
        """
        for cve, entry in roster.items():
            if entry["exit_code"] == 0:
                assert entry["conflict_markers"] == 0, cve

    def test_tiers_are_known_values(self, roster: dict[str, dict]) -> None:
        for cve, entry in roster.items():
            assert entry["tier"] in ("easy", "medium", "hard"), cve

    def test_ordered_cases_cover_every_entry(self, roster: dict[str, dict]) -> None:
        """--list-cases / --run-case must be able to address the whole roster."""
        cases = ordered_roster_cases(roster)
        assert len(cases) == len(roster)
        assert {c["cve_id"] for c in cases} == set(roster)
        assert [c["case"] for c in cases] == list(range(1, len(roster) + 1))


class TestBroadRosterComposition:
    """Spread guards on the balanced and extended rosters."""

    def test_all_three_tiers_are_represented(self, broad_roster: dict[str, dict]) -> None:
        assert {e["tier"] for e in broad_roster.values()} == {"easy", "medium", "hard"}

    def test_hard_tier_is_the_largest(self, broad_roster: dict[str, dict]) -> None:
        """Models only differentiate on runs that actually reach the agent."""
        counts = Counter(e["tier"] for e in broad_roster.values())
        assert counts["hard"] > counts["easy"]
        assert counts["hard"] >= counts["medium"]

    def test_no_recipe_monoculture(self, broad_roster: dict[str, dict]) -> None:
        """A recipe repeated too often would bias the benchmark toward it."""
        counts = Counter(e["recipe"] for e in broad_roster.values())
        recipe, count = counts.most_common(1)[0]
        assert count <= 2, f"{recipe} appears {count} times"

    def test_recipe_diversity(self, broad_roster: dict[str, dict]) -> None:
        """At least 3/4 of entries should be on distinct recipes."""
        recipes = {e["recipe"] for e in broad_roster.values()}
        assert len(recipes) >= 0.75 * len(broad_roster)

    def test_hard_entries_span_the_conflict_complexity_range(
        self, broad_roster: dict[str, dict]
    ) -> None:
        markers = sorted(
            e["conflict_markers"] for e in broad_roster.values() if e["tier"] == "hard"
        )
        assert markers[0] == 0, "no structural-failure (0-marker) hard entry"
        assert markers[-1] >= 30, "no sprawling multi-file conflict at the high end"

    def test_medium_tier_is_mostly_commit_series(
        self, broad_roster: dict[str, dict]
    ) -> None:
        """The medium tier exists to test dependent chains, not just big diffs."""
        mediums = [e for e in broad_roster.values() if e["tier"] == "medium"]
        series = [e for e in mediums if e["series_len"] > 1]
        assert len(series) >= len(mediums) - 1
