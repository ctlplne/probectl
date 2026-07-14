# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Offline stock-client replay contract for RouteViews/RIS MRT fixtures."""

from __future__ import annotations

import io

from mrt_fixtures import bgp4mp_update_as4, peer_index_table, rib_ipv4

from probectl_analyzer.mrt import stream_mrt


def test_offline_interop_routeviews_ris_mrt_replay_flows_through_parser():
    data = (
        peer_index_table(peer_as=64511, peer_ip="192.0.2.1")
        + rib_ipv4("192.0.2.0/24", [64511, 64500, 64496], ts=1_777_000_900)
        + bgp4mp_update_as4("198.51.100.0/24", [64511, 64502], ts=1_777_000_901)
    )

    routes = list(stream_mrt(io.BytesIO(data)))

    assert [r.prefix for r in routes] == ["192.0.2.0/24", "198.51.100.0/24"]
    assert routes[0].peer_asn == 64511
    assert routes[0].origin_asn == 64496
    assert routes[1].origin_asn == 64502
