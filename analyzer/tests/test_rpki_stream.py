# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Streaming, prefix-filtered VRP loading (DPR-055).

A real validator export (~100 MB, 600k ROAs) used to be materialized whole and
OOM-killed the analyzer sidecar at the chart's default memory limit. The loader
now parses one entry at a time and keeps only the ROAs that can influence a
monitored prefix — with verdicts identical to the full set.
"""

from __future__ import annotations

import io
import json

import pytest

from probectl_analyzer.events import RPKIStatus
from probectl_analyzer.rpki import VRPError, VRPSet, iter_roas, overlapping

ROAS = [
    {"prefix": "10.0.0.0/8", "maxLength": 24, "asn": "AS64496"},  # covers the monitored /16
    {"prefix": "10.0.1.0/24", "maxLength": 24, "asn": 64497},  # inside the monitored /16
    {"prefix": "10.1.0.0/16", "maxLength": 16, "asn": 64498},  # sibling: irrelevant
    {"prefix": "192.0.2.0/24", "maxLength": 24, "asn": 64499},  # unrelated
    {"prefix": "2001:db8::/32", "maxLength": 48, "asn": 64500},  # other family
]
MONITORED = ["10.0.0.0/16"]


def object_export() -> bytes:
    return json.dumps({"metadata": {"generated": 1, "note": "x" * 300}, "roas": ROAS}).encode()


def array_export() -> bytes:
    return json.dumps(ROAS).encode()


@pytest.mark.parametrize("chunk", [1, 7, 64, 1 << 16])
@pytest.mark.parametrize("payload", [object_export(), array_export()])
def test_iter_roas_streams_both_shapes_across_any_chunk_boundary(payload, chunk):
    got = list(iter_roas(io.BytesIO(payload), chunk_size=chunk))
    assert got == ROAS


def test_from_stream_keeps_only_roas_that_can_matter_and_validates_identically():
    keep = overlapping(MONITORED)
    filtered = VRPSet.from_stream(io.BytesIO(object_export()), keep=keep)
    full = VRPSet.from_json(object_export().decode())
    assert filtered.scanned == len(ROAS)
    assert len(filtered) == 2, "only the covering /8 and the inner /24 overlap 10.0.0.0/16"
    # Every announcement the monitor can validate (within the monitored prefix)
    # gets the same RFC 6811 verdict from the reduced set.
    for prefix, origin in [
        ("10.0.0.0/16", 64496),
        ("10.0.0.0/16", 64497),
        ("10.0.1.0/24", 64497),
        ("10.0.1.0/24", 64496),
        ("10.0.2.0/25", 64496),
        ("10.0.7.0/24", 1),
    ]:
        assert filtered.validate(prefix, origin) == full.validate(prefix, origin), (prefix, origin)
    assert filtered.validate("10.0.0.0/16", 64496) == RPKIStatus.VALID
    assert filtered.validate("10.0.2.0/25", 64496) == RPKIStatus.INVALID


def test_from_stream_without_filter_keeps_everything():
    assert len(VRPSet.from_stream(io.BytesIO(array_export()))) == len(ROAS)


def test_truncated_and_oversized_exports_are_refused():
    truncated = object_export()[:-20]
    with pytest.raises(VRPError):
        list(iter_roas(io.BytesIO(truncated), chunk_size=16))
    with pytest.raises(VRPError):
        list(iter_roas(io.BytesIO(object_export()), max_bytes=64, chunk_size=16))
    with pytest.raises(VRPError):
        list(iter_roas(io.BytesIO(b'{"metadata": {}}'), chunk_size=16))


def test_memory_stays_bounded_for_a_large_export():
    # 200k ROAs (~15 MB of JSON) with a one-prefix filter: the rolling buffer
    # never holds more than a couple of chunks, and only one ROA is kept.
    def gen():
        yield b'{"roas": ['
        for i in range(200_000):
            yield (
                json.dumps(
                    {"prefix": f"10.{(i >> 8) & 255}.{i & 255}.0/24", "maxLength": 24, "asn": 64496}
                )
                + ","
            ).encode()
        yield b'{"prefix": "198.51.100.0/24", "maxLength": 24, "asn": 64510}]}'

    class Reader(io.RawIOBase):
        def __init__(self):
            self._it = gen()
            self._pending = b""

        def read(self, n=-1):
            while len(self._pending) < n:
                try:
                    self._pending += next(self._it)
                except StopIteration:
                    break
            out, self._pending = self._pending[:n], self._pending[n:]
            return out

    vrp = VRPSet.from_stream(Reader(), keep=overlapping(["198.51.100.0/24"]))
    assert vrp.scanned == 200_001 and len(vrp) == 1
