# SPDX-License-Identifier: MIT
"""Tests for tools/plot_source_distribution.py (data layer only).

matplotlib is not a dev dependency, so only the pure functions are covered;
the tool imports matplotlib lazily inside the plotting functions.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_TOOL_PATH = Path(__file__).resolve().parents[2] / "tools" / "plot_source_distribution.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("plot_source_distribution", _TOOL_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tool = _load_tool()


def _data() -> dict:
    return {
        "CVE-1": {
            "hash_details": [
                {"hash": "a", "source": "osv, secretvendor"},
                {"hash": "b", "source": "oe_patch"},
            ],
            "patch_details": [{"url": "u", "source": "oe_patch_header"}],
            "references": [{"url": "r", "sources": ["otherclosed"]}],
        },
    }


def test_oe_sources_are_not_internal():
    assert not tool.is_internal_source("oe_patch")
    assert not tool.is_internal_source("oe_patch_header")
    assert not tool.is_internal_source("osv")
    assert tool.is_internal_source("secretvendor")


def test_oe_sources_survive_upstream_filter():
    index = tool.build_source_index(_data())
    filtered = tool.filter_index_to_upstream(index)
    assert set(filtered["all_sources"]) == {"osv", "oe_patch", "oe_patch_header"}


def test_oe_sources_count_as_public_in_gain():
    index = tool.build_source_index(_data())
    gain = tool.compute_upstream_vs_combined_gain(index, total_cves=1)
    # Hashes a (osv) and b (oe_patch) are both public; the internal source
    # adds no hash beyond what public sources already found.
    assert gain["upstream_hashes"] == 2
    assert gain["combined_hashes"] == 2
    assert gain["has_external_sources"] is True


def test_anonymize_replaces_only_internal_names():
    index = tool.build_source_index(_data())
    anon = tool.anonymize_index(index)
    assert set(anon["all_sources"]) == {
        "osv", "oe_patch", "oe_patch_header", "internal-1", "internal-2"}
    for field in ("cves_by_source", "cves_with_hash_by_source", "hashes_by_source",
                  "hash_count_by_source", "patch_count_by_source"):
        assert "secretvendor" not in anon[field]
        assert "otherclosed" not in anon[field]


def test_anonymize_preserves_data_and_stays_internal():
    index = tool.build_source_index(_data())
    mapping = tool.anonymization_map(index)
    anon = tool.anonymize_index(index)
    alias = mapping["secretvendor"]
    assert anon["hashes_by_source"][alias] == index["hashes_by_source"]["secretvendor"]
    assert anon["hash_count_by_source"][alias] == 1
    assert tool.is_internal_source(alias)


def test_anonymize_mapping_is_stable_and_collision_free():
    index = tool.build_source_index(_data())
    assert tool.anonymization_map(index) == tool.anonymization_map(index)

    data = _data()
    data["CVE-2"] = {"hash_details": [{"hash": "c", "source": "internal-1"}]}
    index = tool.build_source_index(data)
    mapping = tool.anonymization_map(index)
    # 'internal-1' is itself an (internal) source name and gets renamed; no
    # two sources may share an alias.
    assert len(set(mapping.values())) == len(mapping)
    anon = tool.anonymize_index(index)
    assert len(anon["all_sources"]) == len(index["all_sources"])
