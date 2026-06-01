"""Property-based tests (Hypothesis) for the untrusted-input parsers.

These are the Python counterpart to the Go fuzz targets: the MRT parser and the
RPKI validator both consume adversarial input, so the invariants are checked over
thousands of generated cases rather than a handful of hand-picked ones.
"""

from __future__ import annotations

import io
import ipaddress

from hypothesis import given
from hypothesis import strategies as st
from mrt_fixtures import rib_ipv4

from netctl_analyzer.events import RPKIStatus
from netctl_analyzer.mrt import MRTError, stream_mrt
from netctl_analyzer.rpki import VRPSet

asns = st.integers(min_value=1, max_value=2**32 - 1)


@st.composite
def ipv4_networks(draw) -> str:
    addr = draw(st.integers(min_value=0, max_value=2**32 - 1))
    plen = draw(st.integers(min_value=8, max_value=32))
    return str(ipaddress.ip_network((addr, plen), strict=False))


@given(st.binary(max_size=256))
def test_stream_mrt_never_crashes_on_arbitrary_bytes(data: bytes):
    """Arbitrary input must surface only as a controlled MRTError — never an
    uncaught struct/index/value error (the streaming-parser robustness goal)."""
    try:
        list(stream_mrt(io.BytesIO(data)))
    except MRTError:
        pass  # controlled, expected for malformed framing


@given(prefix=ipv4_networks(), as_path=st.lists(asns, min_size=1, max_size=8))
def test_rib_record_roundtrips(prefix: str, as_path: list[int]):
    """Any well-formed RIB record round-trips through the parser exactly."""
    routes = list(stream_mrt(io.BytesIO(rib_ipv4(prefix, as_path))))
    assert len(routes) == 1
    assert routes[0].prefix == prefix
    assert routes[0].as_path == as_path
    assert routes[0].origin_asn == as_path[-1]


VRP = VRPSet.from_dicts(
    [
        {"prefix": "192.0.2.0/24", "maxLength": 24, "asn": 64496},
        {"prefix": "10.0.0.0/8", "maxLength": 16, "asn": 64500},
    ]
)


@given(prefix=ipv4_networks(), origin=st.integers(min_value=0, max_value=2**32 - 1))
def test_rpki_validate_is_total_and_sound(prefix: str, origin: int):
    """validate() never raises, always returns a known status, and a VALID verdict
    is justified by a covering ROA that matches the origin and max length."""
    status = VRP.validate(prefix, origin)
    assert status in {
        RPKIStatus.VALID,
        RPKIStatus.INVALID,
        RPKIStatus.NOT_FOUND,
        RPKIStatus.UNKNOWN,
    }
    if status is RPKIStatus.VALID:
        net = ipaddress.ip_network(prefix, strict=False)
        assert any(
            roa.asn == origin
            and net.version == roa.network.version
            and net.subnet_of(roa.network)
            and net.prefixlen <= roa.max_length
            for roa in VRP._roas
        )
