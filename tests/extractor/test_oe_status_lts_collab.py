# Copyright (C) 2026 Ericsson AB
# SPDX-License-Identifier: MIT
"""Optional meta-lts-collab search in the OE status check."""
from unittest.mock import patch

from cve_metadata_extractor import oe_status


def _searched_repos(lts_collab):
    searched = []

    def fake_in_branch(repo, branch, cve):
        searched.append((repo, branch))
        return None

    with patch.object(oe_status, 'do_get_repo', side_effect=lambda d, url: url), \
         patch.object(oe_status, 'get_cve_in_branch', side_effect=fake_in_branch):
        status = oe_status._do_check_status_uncached(
            None, '/tmp', 'CVE-2026-1', 'kirkstone', lts_collab)
    return status, searched


def test_lts_collab_not_searched_by_default():
    status, searched = _searched_repos(False)
    assert status == 'not_found'
    assert not any('meta-lts-collab' in repo for repo, _ in searched)


def test_lts_collab_searched_on_request():
    _, searched = _searched_repos(True)
    assert searched[-1] == ('https://github.com/garmin/meta-lts-collab', 'kirkstone')


def test_lts_collab_hit_is_labelled():
    def fake_in_branch(repo, branch, cve):
        return 'merged: x' if 'meta-lts-collab' in repo else None

    with patch.object(oe_status, 'do_get_repo', side_effect=lambda d, url: url), \
         patch.object(oe_status, 'get_cve_in_branch', side_effect=fake_in_branch):
        status = oe_status._do_check_status_uncached(
            None, '/tmp', 'CVE-2026-1', 'kirkstone', True)
    assert status == 'meta-lts-collab: merged: x'
