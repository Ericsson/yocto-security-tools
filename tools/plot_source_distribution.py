#!/usr/bin/env python3
# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Standalone analysis of CVE source distribution and complementarity.

Reads a cve-metadata.json file (produced by cve-metadata-extractor, optionally
enriched with additional closed sources not part of the extractor's own
registry) and generates PNG charts showing:

  1. coverage_by_source.png    - how many CVEs each source contributed data for
  2. coverage_by_source_upstream_only.png
                                - same as #1, but restricted to public upstream
                                 sources only (any source name not registered by
                                 cve_metadata_extractor is excluded at the data
                                 level, not just visually)
  3. upstream_vs_combined_gain.png
                                - how much upstream+closed coverage improves
                                 over upstream-only (unioned, not double-counted):
                                 CVEs with any data, CVEs with a fix-commit hash,
                                 and distinct fix-commit hashes
  4. volume_by_source.png      - how many fix-commit hash entries each source contributed
  5. overlap_cve_level.png     - pairwise Jaccard overlap: both sources said
                                 *something* about the same CVE
  6. overlap_hash_level.png    - pairwise Jaccard overlap: both sources pointed
                                 to the exact same fix commit hash
  7. unique_contribution.png   - hashes found by only one source (what would be
                                 lost if that source were dropped)

Any source name found in the input file that is not registered by
cve_metadata_extractor's own SOURCE_REGISTRY (see UPSTREAM_SOURCES below) is
treated as closed enrichment data and visually distinguished (orange color
+ caption note) in every chart. This script never hardcodes the name of any
specific closed source — the distinction is derived entirely from
cve_metadata_extractor's actual registered sources.

nvd is merged into cvelistv5 before any metric is computed (see MERGED_SOURCES
below) since NVD mirrors CVEListV5 data and the two show 100% overlap in
practice; keeping them separate would double-count the same underlying data.

This is a standalone, dev-only tool. It is NOT part of the installed
yocto-security-tools package and requires matplotlib, which is not a runtime
dependency of the project (see AGENTS.md "Minimize Dependencies").

Usage:
    pip install matplotlib
    python3 tools/plot_source_distribution.py cve-metadata.json --output-dir plots/
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

# Ground truth: the exact set of source names registered by the public
# cve-metadata-extractor tool itself (cve_metadata_extractor/*.py ->
# SOURCE_REGISTRY.append()/.extend() calls: debian.py, osv.py, ubuntu.py,
# uct.py, cvelistv5.py). Any source name found in a cve-metadata.json file
# that is NOT in this set is treated as closed enrichment data layered on
# top of the extractor's own output (e.g. by a private plugin) — never
# hardcoded by name here, so this script carries no reference to any
# particular enrichment vendor.
UPSTREAM_SOURCES = {'debian', 'osv', 'ubuntu', 'uct', 'cvelistv5', 'nvd'}


def is_internal_source(source: str) -> bool:
    """True if a source name is not part of the public extractor's registry."""
    return source not in UPSTREAM_SOURCES

# Display names for chart labels. The underlying data key ('uct') matches the
# extractor's source name (cve_metadata_extractor/uct.py, Ubuntu CVE Tracker);
# charts show the more recognizable 'ubuntu' label instead.
DISPLAY_NAMES = {'uct': 'ubuntu'}

# Sources to merge into a single canonical entity before computing any metric.
# nvd mirrors/derives its CVE records from cvelistv5 upstream, so in practice
# they are the same underlying data reported under two labels (confirmed by a
# CVE-level and hash-level Jaccard similarity of 1.00 in this dataset). Treating
# them as one source avoids double-counting redundancy and correctly surfaces
# the small amount of data (~6% of hashes in a sample run) that neither source
# alone reports uniquely, but the merged pair does relative to all other sources.
MERGED_SOURCES = {'nvd': 'cvelistv5'}

_SOURCE_SPLIT_RE = re.compile(r',\s*')


def canonicalize_source(source: str) -> str:
    """Map a raw source token to its canonical (post-merge) key."""
    return MERGED_SOURCES.get(source, source)


def display_name(source: str) -> str:
    """Map an internal source key to its chart display label."""
    return DISPLAY_NAMES.get(source, source)


def _split_sources(source_field: str) -> list[str]:
    """Split a comma-joined 'source' string (e.g. 'osv, debian') into tokens."""
    if not source_field:
        return []
    tokens = [s for s in _SOURCE_SPLIT_RE.split(source_field.strip()) if s]
    return [canonicalize_source(t) for t in tokens]


def load_metadata(path: Path) -> dict[str, Any]:
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def build_source_index(data: dict[str, Any]) -> dict:
    """Walk cve-metadata.json and build source-attribution indexes.

    Returns a dict with:
      cves_by_source: {source: set(cve_id)}            -- CVE-level coverage (any data)
      cves_with_hash_by_source: {source: set(cve_id)}  -- CVE-level coverage (has a fix hash)
      hashes_by_source: {source: set(cve_id, hash)}     -- hash-level coverage
      hash_count_by_source: {source: int}               -- raw hash entries
      patch_count_by_source: {source: int}              -- raw patch entries
      all_sources: sorted list of all source names seen
    """
    cves_by_source: dict[str, set] = defaultdict(set)
    cves_with_hash_by_source: dict[str, set] = defaultdict(set)
    hashes_by_source: dict[str, set] = defaultdict(set)
    hash_count_by_source: dict[str, int] = defaultdict(int)
    patch_count_by_source: dict[str, int] = defaultdict(int)

    for cve_id, info in data.items():
        for h in info.get('hash_details', []) or []:
            tokens = _split_sources(h.get('source', ''))
            hash_key = h.get('hash')
            for s in tokens:
                cves_by_source[s].add(cve_id)
                hash_count_by_source[s] += 1
                if hash_key:
                    hashes_by_source[s].add((cve_id, hash_key))
                    cves_with_hash_by_source[s].add(cve_id)

        for p in info.get('patch_details', []) or []:
            tokens = _split_sources(p.get('source', ''))
            for s in tokens:
                cves_by_source[s].add(cve_id)
                patch_count_by_source[s] += 1

        for r in info.get('references', []) or []:
            for s in r.get('sources', []) or []:
                cves_by_source[canonicalize_source(s)].add(cve_id)

    all_sources = sorted(cves_by_source.keys())
    return {
        'cves_by_source': dict(cves_by_source),
        'cves_with_hash_by_source': dict(cves_with_hash_by_source),
        'hashes_by_source': dict(hashes_by_source),
        'hash_count_by_source': dict(hash_count_by_source),
        'patch_count_by_source': dict(patch_count_by_source),
        'all_sources': all_sources,
    }


def compute_upstream_vs_combined_gain(index: dict, total_cves: int) -> dict:
    """Compare upstream-only coverage against upstream + closed enrichment.

    Answers: how much does adding closed enrichment sources (on top of
    cve-metadata-extractor's own public upstream sources) actually improve
    coverage? Unions sets across sources rather than summing per-source
    counts, so a CVE/hash found by multiple sources is not double-counted.
    """
    external_sources = [s for s in index['all_sources'] if s not in UPSTREAM_SOURCES]

    def union_over(field: str, sources: list) -> set:
        result: set = set()
        for s in sources:
            result |= index[field].get(s, set())
        return result

    upstream_cves = union_over('cves_by_source', list(UPSTREAM_SOURCES))
    upstream_hash_cves = union_over('cves_with_hash_by_source', list(UPSTREAM_SOURCES))
    upstream_hashes = union_over('hashes_by_source', list(UPSTREAM_SOURCES))

    all_sources = list(UPSTREAM_SOURCES) + external_sources
    combined_cves = union_over('cves_by_source', all_sources)
    combined_hash_cves = union_over('cves_with_hash_by_source', all_sources)
    combined_hashes = union_over('hashes_by_source', all_sources)

    return {
        'total_cves': total_cves,
        'upstream_cves': len(upstream_cves),
        'upstream_hash_cves': len(upstream_hash_cves),
        'upstream_hashes': len(upstream_hashes),
        'combined_cves': len(combined_cves),
        'combined_hash_cves': len(combined_hash_cves),
        'combined_hashes': len(combined_hashes),
        'has_external_sources': bool(external_sources),
    }


def filter_index_to_upstream(index: dict) -> dict:
    """Return a copy of the index with all non-upstream source data removed.

    Strictly drops any source not in UPSTREAM_SOURCES from every set/count
    *before* it reaches a plotting function, so closed enrichment data is
    never read into a chart for upstream-only comparisons (not just hidden or
    re-colored after the fact).
    """
    allowed = UPSTREAM_SOURCES
    return {
        'cves_by_source': {s: v for s, v in index['cves_by_source'].items() if s in allowed},
        'cves_with_hash_by_source': {
            s: v for s, v in index['cves_with_hash_by_source'].items() if s in allowed},
        'hashes_by_source': {s: v for s, v in index['hashes_by_source'].items() if s in allowed},
        'hash_count_by_source': {
            s: v for s, v in index['hash_count_by_source'].items() if s in allowed},
        'patch_count_by_source': {
            s: v for s, v in index['patch_count_by_source'].items() if s in allowed},
        'all_sources': sorted(s for s in index['all_sources'] if s in allowed),
    }


def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def _bar_colors(sources: list[str]) -> list[str]:
    return ['#d95f02' if is_internal_source(s) else '#1b9e77' for s in sources]


def _add_internal_source_note(fig, extra: str = '') -> None:
    note = (
        "Orange = closed enrichment sources not part of "
        "cve-metadata-extractor's public upstream pipeline."
    )
    if extra:
        note = f"{note}\n{extra}"
    fig.text(0.5, 0.01, note, ha='center', va='bottom', fontsize=8, wrap=True,
              style='italic', color='#555555')


def plot_coverage_by_source(index: dict, output_dir: Path, total_cves: int) -> Path:
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    sources = sorted(index['all_sources'],
                      key=lambda s: len(index['cves_by_source'][s]), reverse=True)
    hash_counts = [len(index['cves_with_hash_by_source'].get(s, set())) for s in sources]
    total_counts = [len(index['cves_by_source'][s]) for s in sources]
    other_counts = [t - h for t, h in zip(total_counts, hash_counts)]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    labels = [display_name(s) for s in sources]
    hash_bars = ax.bar(labels, hash_counts, color=_bar_colors(sources))
    ax.bar(labels, other_counts, bottom=hash_counts, color=_bar_colors(sources), alpha=0.4)

    for bar_total, total, hash_count in zip(hash_bars, total_counts, hash_counts):
        pct_total = 100 * total / total_cves if total_cves else 0
        pct_hash = 100 * hash_count / total_cves if total_cves else 0
        ax.text(bar_total.get_x() + bar_total.get_width() / 2, total,
                f"{total} ({pct_total:.0f}%)\nhash: {hash_count} ({pct_hash:.0f}%)",
                ha='center', va='bottom', fontsize=8)

    # Legend proxy patches use the same green as upstream-source bars (the
    # majority case); closed-enrichment bars are still drawn in orange via
    # _bar_colors, distinguished by the caption note below.
    legend_handles = [
        Patch(facecolor='#1b9e77', label='CVEs with a fix-commit hash'),
        Patch(facecolor='#1b9e77', alpha=0.4, label='CVEs with only patch/reference data (no hash)'),
    ]
    ax.set_ylabel('Number of CVEs covered')
    ax.set_title(f'CVE coverage per source (of {total_cves} total CVEs)')
    ax.set_ylim(0, max(total_counts) * 1.25 if total_counts else 1)
    ax.legend(handles=legend_handles, loc='upper right', fontsize=8)
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    _add_internal_source_note(
        fig, "Solid = CVEs where the source provided an actual fix-commit hash; "
             "faded = CVEs where it only added patch links or references without a hash.")

    out_path = output_dir / 'coverage_by_source.png'
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_coverage_by_source_upstream_only(index: dict, output_dir: Path,
                                           total_cves: int) -> Path:
    """CVE coverage chart restricted to public upstream sources only.

    Takes an index already filtered by filter_index_to_upstream() — any source
    not registered by cve_metadata_extractor is absent from the data passed
    in, not merely excluded from the drawing step.
    """
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    sources = sorted(index['all_sources'],
                      key=lambda s: len(index['cves_by_source'][s]), reverse=True)
    hash_counts = [len(index['cves_with_hash_by_source'].get(s, set())) for s in sources]
    total_counts = [len(index['cves_by_source'][s]) for s in sources]
    other_counts = [t - h for t, h in zip(total_counts, hash_counts)]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    labels = [display_name(s) for s in sources]
    hash_bars = ax.bar(labels, hash_counts, color='#1b9e77')
    ax.bar(labels, other_counts, bottom=hash_counts, color='#1b9e77', alpha=0.4)

    for bar_total, total, hash_count in zip(hash_bars, total_counts, hash_counts):
        pct_total = 100 * total / total_cves if total_cves else 0
        pct_hash = 100 * hash_count / total_cves if total_cves else 0
        ax.text(bar_total.get_x() + bar_total.get_width() / 2, total,
                f"{total} ({pct_total:.0f}%)\nhash: {hash_count} ({pct_hash:.0f}%)",
                ha='center', va='bottom', fontsize=8)

    legend_handles = [
        Patch(facecolor='#1b9e77', label='CVEs with a fix-commit hash'),
        Patch(facecolor='#1b9e77', alpha=0.4, label='CVEs with only patch/reference data (no hash)'),
    ]
    ax.set_ylabel('Number of CVEs covered')
    ax.set_title(f'CVE coverage per source — public upstream sources only\n'
                 f'(of {total_cves} total CVEs)')
    ax.set_ylim(0, max(total_counts) * 1.25 if total_counts else 1)
    ax.legend(handles=legend_handles, loc='upper right', fontsize=8)
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.text(0.5, 0.01,
              "Excludes any source not registered by cve-metadata-extractor's own "
              "SOURCE_REGISTRY; shows only its public upstream sources.",
              ha='center', va='bottom', fontsize=8, style='italic', color='#555555')

    out_path = output_dir / 'coverage_by_source_upstream_only.png'
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_upstream_vs_combined_gain(index: dict, output_dir: Path, total_cves: int) -> Path:
    """Show how much closed enrichment sources add on top of upstream alone.

    Three side-by-side metric pairs (upstream-only vs. upstream+closed):
    CVEs with any data, CVEs with a fix-commit hash, and distinct fix-commit
    hashes. Sets are unioned across sources, so overlapping contributions
    are not double-counted — this directly answers "how much do we gain by
    adding closed/proprietary enrichment on top of public upstream data?"
    """
    import matplotlib.pyplot as plt

    gain = compute_upstream_vs_combined_gain(index, total_cves)

    metrics = [
        ('CVEs with\nany data', gain['upstream_cves'], gain['combined_cves']),
        ('CVEs with a\nfix-commit hash', gain['upstream_hash_cves'], gain['combined_hash_cves']),
        ('Distinct fix-\ncommit hashes', gain['upstream_hashes'], gain['combined_hashes']),
    ]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    x = range(len(metrics))
    width = 0.35
    labels = [m[0] for m in metrics]
    upstream_vals = [m[1] for m in metrics]
    combined_vals = [m[2] for m in metrics]

    bars_up = ax.bar([i - width / 2 for i in x], upstream_vals, width,
                      color='#1b9e77', label='Public upstream sources only')
    bars_comb = ax.bar([i + width / 2 for i in x], combined_vals, width,
                        color='#7570b3', label='Upstream + closed enrichment')

    for bar in bars_up:
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f"{int(bar.get_height())}", ha='center', va='bottom', fontsize=9)
    for bar, up_val in zip(bars_comb, upstream_vals):
        gain_val = bar.get_height() - up_val
        pct = 100 * gain_val / up_val if up_val else 0
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f"{int(bar.get_height())}\n(+{int(gain_val)}, +{pct:.0f}%)",
                ha='center', va='bottom', fontsize=9)

    ax.set_xticks(list(x))
    ax.set_xticklabels(labels)
    ax.set_ylabel('Count')
    ax.set_title(f'Coverage gain from closed enrichment sources\n(of {total_cves} total CVEs)')
    ax.set_ylim(0, max(combined_vals) * 1.25 if combined_vals else 1)
    ax.legend(loc='upper right', fontsize=8)
    fig.tight_layout(rect=(0, 0.05, 1, 1))

    if not gain['has_external_sources']:
        note = ("No closed enrichment sources found in this file — "
                "all data comes from public upstream sources.")
    else:
        note = ("Bars are unioned across sources (a CVE/hash found by multiple "
                "sources is counted once), so this reflects real added coverage, "
                "not the sum of individual sources' contributions.")
    fig.text(0.5, 0.01, note, ha='center', va='bottom', fontsize=8,
              style='italic', color='#555555', wrap=True)

    out_path = output_dir / 'upstream_vs_combined_gain.png'
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_volume_by_source(index: dict, output_dir: Path) -> Path:
    import matplotlib.pyplot as plt

    sources = sorted(
        index['all_sources'],
        key=lambda s: index['hash_count_by_source'].get(s, 0),
        reverse=True,
    )
    hash_counts = [index['hash_count_by_source'].get(s, 0) for s in sources]
    labels = [display_name(s) for s in sources]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    bars = ax.bar(labels, hash_counts, color=_bar_colors(sources))
    for bar, count in zip(bars, hash_counts):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height(),
                f"{count}", ha='center', va='bottom', fontsize=8)

    ax.set_ylabel('Number of fix-commit hash entries contributed')
    ax.set_title('Fix-commit hash volume contributed per source')
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    _add_internal_source_note(
        fig, "Volume reflects verbosity, not necessarily unique or higher-quality data.")

    out_path = output_dir / 'volume_by_source.png'
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def _plot_overlap_heatmap(sources: list[str], sets_by_source: dict[str, set],
                           title: str, filename: str, output_dir: Path) -> Path:
    import matplotlib.pyplot as plt
    import numpy as np

    n = len(sources)
    matrix = np.zeros((n, n))
    for i, a in enumerate(sources):
        for j, b in enumerate(sources):
            matrix[i, j] = jaccard(sets_by_source.get(a, set()), sets_by_source.get(b, set()))

    fig, ax = plt.subplots(figsize=(7.5, 6.5))
    im = ax.imshow(matrix, cmap='viridis', vmin=0, vmax=1)
    labels = [display_name(s) for s in sources]
    ax.set_xticks(range(n))
    ax.set_yticks(range(n))
    ax.set_xticklabels(labels, rotation=45, ha='right')
    ax.set_yticklabels(labels)

    for i in range(n):
        for j in range(n):
            ax.text(j, i, f"{matrix[i, j]:.2f}", ha='center', va='center',
                    color='white' if matrix[i, j] < 0.6 else 'black', fontsize=8)

    # Mark internal-source rows/cols in a distinct color.
    for idx, source_name in enumerate(sources):
        if is_internal_source(source_name):
            ax.get_xticklabels()[idx].set_color('#d95f02')
            ax.get_yticklabels()[idx].set_color('#d95f02')

    fig.colorbar(im, ax=ax, label='Jaccard similarity')
    ax.set_title(title)
    fig.tight_layout(rect=(0, 0.07, 1, 1))
    _add_internal_source_note(
        fig, "Orange axis labels = closed enrichment sources.")

    out_path = output_dir / filename
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def plot_overlap_cve_level(index: dict, output_dir: Path) -> Path:
    return _plot_overlap_heatmap(
        index['all_sources'], index['cves_by_source'],
        'Pairwise overlap — CVE level\n(did both sources report *something* on the same CVE?)',
        'overlap_cve_level.png', output_dir,
    )


def plot_overlap_hash_level(index: dict, output_dir: Path) -> Path:
    sources_with_hashes = [s for s in index['all_sources'] if index['hashes_by_source'].get(s)]
    return _plot_overlap_heatmap(
        sources_with_hashes, index['hashes_by_source'],
        'Pairwise overlap — hash level\n(did both sources point to the *identical* fix commit?)',
        'overlap_hash_level.png', output_dir,
    )


def plot_unique_contribution(index: dict, output_dir: Path) -> Path:
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    hashes_by_source = index['hashes_by_source']
    sources = [s for s in index['all_sources'] if hashes_by_source.get(s)]

    # For each (cve_id, hash) pair, find which sources reported it.
    owners: dict[tuple, set] = defaultdict(set)
    for s in sources:
        for key in hashes_by_source[s]:
            owners[key].add(s)

    unique_counts: dict[str, int] = defaultdict(int)
    total_counts: dict[str, int] = defaultdict(int)
    # For hashes found by exactly 2 sources, count how often each *other*
    # source is the pairing partner, per source.
    pair_partner_counts: dict[str, Counter] = defaultdict(Counter)
    for found_by in owners.values():
        for s in found_by:
            total_counts[s] += 1
        if len(found_by) == 1:
            only_source = next(iter(found_by))
            unique_counts[only_source] += 1
        elif len(found_by) == 2:
            a, b = tuple(found_by)
            pair_partner_counts[a][b] += 1
            pair_partner_counts[b][a] += 1

    paired_counts = {s: sum(pair_partner_counts[s].values()) for s in sources}
    other_counts = {
        s: total_counts.get(s, 0) - unique_counts.get(s, 0) - paired_counts.get(s, 0)
        for s in sources
    }

    def dominant_partner_label(s: str) -> str:
        """Label for the dominant 'exactly one other source' partner, if any."""
        partners = pair_partner_counts.get(s)
        if not partners:
            return ''
        top_partner, _ = partners.most_common(1)[0]
        return display_name(top_partner)

    sources_sorted = sorted(sources, key=lambda s: unique_counts.get(s, 0), reverse=True)
    unique_vals = [unique_counts.get(s, 0) for s in sources_sorted]
    paired_vals = [paired_counts.get(s, 0) for s in sources_sorted]
    other_vals = [other_counts.get(s, 0) for s in sources_sorted]
    total_vals = [total_counts.get(s, 0) for s in sources_sorted]

    fig, ax = plt.subplots(figsize=(9.5, 6))
    unique_labels = [display_name(s) for s in sources_sorted]
    bars_other = ax.bar(unique_labels, other_vals, color='#cccccc')
    ax.bar(unique_labels, paired_vals, bottom=other_vals, color='#6699cc')
    ax.bar(unique_labels, unique_vals,
           bottom=[o + p for o, p in zip(other_vals, paired_vals)],
           color='#1b9e77')

    for bar_other, s, u, p, t in zip(bars_other, sources_sorted, unique_vals,
                                      paired_vals, total_vals):
        pct_u = 100 * u / t if t else 0
        partner_label = dominant_partner_label(s)
        lines = [f"{u}/{t} unique ({pct_u:.0f}%)"]
        if p and partner_label:
            lines.append(f"paired w/ {partner_label}: {p}")
        ax.text(bar_other.get_x() + bar_other.get_width() / 2, t,
                "\n".join(lines), ha='center', va='bottom', fontsize=7.5)

    ax.set_ylim(0, max(total_vals) * 1.3 if total_vals else 1)

    # This chart uses a fixed 3-color legend (not per-source colors), since it
    # shows how many *other* sources agree on a hash, not internal/upstream
    # status — so it does not use _add_internal_source_note here.
    legend_handles = [
        Patch(facecolor='#cccccc', label='found by 3+ sources'),
        Patch(facecolor='#6699cc', label='found by exactly 1 other source (paired)'),
        Patch(facecolor='#1b9e77', label='unique to this source'),
    ]
    ax.set_ylabel('Distinct fix-commit hashes')
    ax.set_title('Unique contribution per source\n'
                 '(hashes found by only that source, only one other, or 3+ sources)')
    ax.legend(handles=legend_handles, fontsize=8)
    fig.tight_layout(rect=(0, 0.06, 1, 1))
    fig.text(0.5, 0.01,
              "A low unique-contribution % suggests a source adds little information "
              "not already found elsewhere. The 'paired' segment names the source it "
              "most often overlaps with when exactly two sources agree.",
              ha='center', va='bottom', fontsize=8, style='italic', color='#555555',
              wrap=True)

    out_path = output_dir / 'unique_contribution.png'
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def print_summary(index: dict, total_cves: int) -> None:
    print(f"Total CVEs in file: {total_cves}")
    if MERGED_SOURCES:
        for merged_from, merged_into in MERGED_SOURCES.items():
            print(f"Note: '{merged_from}' data merged into '{merged_into}' "
                  f"(same underlying data, reported under two labels).")
    print(f"Sources found: {', '.join(display_name(s) for s in index['all_sources'])}")
    print()
    print(f"{'source':<12} {'cves':>6} {'hash_entries':>13} {'patch_entries':>14} {'internal?':>10}")
    for s in sorted(index['all_sources'], key=lambda s: len(index['cves_by_source'][s]),
                     reverse=True):
        print(f"{display_name(s):<12} {len(index['cves_by_source'][s]):>6} "
              f"{index['hash_count_by_source'].get(s, 0):>13} "
              f"{index['patch_count_by_source'].get(s, 0):>14} "
              f"{'yes' if is_internal_source(s) else '':>10}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Analyze CVE source distribution/complementarity from a '
                     'cve-metadata.json file and generate PNG charts.')
    parser.add_argument('metadata_file', type=Path,
                         help='Path to cve-metadata.json (output of cve-metadata-extractor, '
                              'optionally enriched with additional closed sources)')
    parser.add_argument('--output-dir', type=Path, default=Path('.'),
                         help='Directory to write PNG charts to (default: current directory)')
    args = parser.parse_args()

    try:
        import matplotlib  # noqa: F401
    except ImportError:
        print("error: matplotlib is required for this script but is not installed.\n"
              "This is a standalone dev tool; matplotlib is intentionally not a runtime\n"
              "dependency of yocto-security-tools. Install it with:\n\n"
              "    pip install matplotlib\n", file=sys.stderr)
        return 1

    if not args.metadata_file.is_file():
        print(f"error: file not found: {args.metadata_file}", file=sys.stderr)
        return 1

    args.output_dir.mkdir(parents=True, exist_ok=True)

    data = load_metadata(args.metadata_file)
    total_cves = len(data)
    if total_cves == 0:
        print("error: metadata file contains no CVEs", file=sys.stderr)
        return 1

    index = build_source_index(data)
    if not index['all_sources']:
        print("error: no source attribution found in metadata file", file=sys.stderr)
        return 1

    print_summary(index, total_cves)
    upstream_index = filter_index_to_upstream(index)

    generated = [
        plot_coverage_by_source(index, args.output_dir, total_cves),
        plot_coverage_by_source_upstream_only(upstream_index, args.output_dir, total_cves),
        plot_upstream_vs_combined_gain(index, args.output_dir, total_cves),
        plot_volume_by_source(index, args.output_dir),
        plot_overlap_cve_level(index, args.output_dir),
        plot_overlap_hash_level(index, args.output_dir),
        plot_unique_contribution(index, args.output_dir),
    ]

    print("Generated:")
    for path in generated:
        print(f"  {path}")

    return 0


if __name__ == '__main__':
    sys.exit(main())
