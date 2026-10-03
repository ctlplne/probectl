# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Regression for ING-25: one MRT record must not materialize an unbounded NLRI list.

MRT dumps come from RouteViews / RIPE RIS mirrors and are untrusted fetched content
(docs/guardrails.md G7-10). A BGP4MP UPDATE record carries a 2-byte BGP message
length; the trailing-NLRI scan must be bounded by that declared length, not by the
MRT record framing (which may span up to MAX_MRT_RECORD_LENGTH = 16 MiB). A record
that declares a tiny BGP message but is framed large used to drive the parser to
read prefixes to the end of the record, so a single crafted record allocated >1 GiB.
"""

from __future__ import annotations

import io
import ipaddress
import struct

from probectl_analyzer.mrt import stream_mrt

TYPE_BGP4MP = 16
SUB_BGP4MP_MESSAGE_AS4 = 4
BGP_UPDATE = 2
AFI_IPV4 = 1

# Declared BGP message = 19-byte header + withdrawn_len(2) + total_attr_len(2),
# both zero: a well-formed but empty UPDATE that announces no prefixes at all.
DECLARED_MSG_LEN = 23

# Bytes of 0x00 appended AFTER the declared message, still inside the MRT record
# frame. Each 0x00 decodes as a length-0 ("0.0.0.0/0") NLRI prefix, so the unfixed
# parser materializes one BGPRoute per padding byte. 100 KiB keeps the RED run's
# allocation modest (~tens of MiB) while staying wildly disproportionate to the
# 23-byte declared message; scaling this toward 16 MiB reproduces the >1 GiB RSS.
_NLRI_PADDING = 100_000


def _malicious_bgp4mp_record() -> bytes:
    """A BGP4MP_MESSAGE_AS4 record whose BGP message under-claims its framed size."""
    # Declared UPDATE body: no withdrawals, no path attributes, no NLRI.
    update = struct.pack(">H", 0) + struct.pack(">H", 0)
    assert DECLARED_MSG_LEN == 19 + len(update)
    msg = (
        b"\xff" * 16  # BGP marker
        + struct.pack(">H", DECLARED_MSG_LEN)  # BGP message length (small, honest-looking)
        + struct.pack(">B", BGP_UPDATE)
        + update
    )
    body = struct.pack(">I", 64511) + struct.pack(">I", 0)  # peer / local AS (4-byte)
    body += struct.pack(">H", 0) + struct.pack(">H", AFI_IPV4)  # ifindex + AFI
    body += ipaddress.IPv4Address("192.0.2.1").packed
    body += ipaddress.IPv4Address("192.0.2.2").packed
    body += msg
    body += b"\x00" * _NLRI_PADDING  # attacker padding the old parser scanned as NLRI
    return struct.pack(">IHHI", 0, TYPE_BGP4MP, SUB_BGP4MP_MESSAGE_AS4, len(body)) + body


def test_nlri_parse_is_bounded_by_declared_bgp_message_length():
    record = _malicious_bgp4mp_record()
    # Framed far larger than the declared message, but within the 16 MiB record cap.
    assert len(record) > _NLRI_PADDING

    routes = list(stream_mrt(io.BytesIO(record)))

    # The number of prefixes a record can yield must be bounded by the declared BGP
    # message length (each NLRI prefix needs >= 1 byte). The unfixed parser yields
    # one route per padding byte (~100k) from a 23-byte message; the fix bounds the
    # scan to the declared body, which announces nothing.
    assert len(routes) <= DECLARED_MSG_LEN, (
        f"NLRI parse yielded {len(routes)} prefixes from a {DECLARED_MSG_LEN}-byte "
        f"BGP message — unbounded by the declared length (ING-25 / G7-10)"
    )
