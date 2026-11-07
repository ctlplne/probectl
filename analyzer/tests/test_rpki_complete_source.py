# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Whole validator export acceptance; no partial set may become authoritative."""

import io
import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from probectl_analyzer.events import RPKIStatus
from probectl_analyzer.rpki import VRPError, VRPSet, iter_roas

ROA = {"prefix": "203.0.113.0/24", "maxLength": 24, "asn": 64500}
ENTRY = json.dumps(ROA).encode()


@pytest.mark.parametrize("chunk", [1, 7, 64, 65536])
@pytest.mark.parametrize(
    "payload",
    [
        b'{"roas":[' + ENTRY + b"]",
        b'{"roas":[' + ENTRY + b'],"metadata":',
        b'{"roas":[' + ENTRY + b"]} trailing",
        b"[" + ENTRY + b"] null",
        b"[" + ENTRY + ENTRY + b"]",
        b"[" + ENTRY + b",," + ENTRY + b"]",
        b"[" + ENTRY + b",]",
        b'{"roas":[' + ENTRY + b"],}",
        b'{"roas":[' + ENTRY + b'],"roas":[]}',
        b'{"roas":[' + ENTRY + b'],"ro\\u0061s":[]}',
        b'{"metadata":1,"roas":[' + ENTRY + b'],"metadata":2}',
        b'{"metadata":{"roas":[' + ENTRY + b"]}}",
        b'{"roas":[1,' + ENTRY + b"]}",
        b'{"roas":[' + ENTRY + b'],"metadata":NaN}',
        b'{"roas":[' + ENTRY + b'],"metadata":Infinity}',
        b'{"roas":[' + ENTRY + b"]}\xff",
        b'{"roas":[' + ENTRY + b"]}\xe2\x82",
        b'{"roas":[{"prefix":"203.0.113.0/24","asn":64500,"asn":65010}]}',
    ],
)
def test_complete_loader_refuses_partial_or_ambiguous_export(payload, chunk):
    with pytest.raises(VRPError):
        # Exercise the production publication boundary as well as tiny chunks.
        VRPSet.from_stream(io.BytesIO(payload))
    with pytest.raises(VRPError):
        list(iter_roas(io.BytesIO(payload), chunk_size=chunk))


@pytest.mark.parametrize("chunk", [1, 7, 64, 65536])
def test_complete_loader_keeps_real_root_and_validates_metadata_on_both_sides(chunk):
    payload = (
        b'{"before":{"roas":[],"note":"braces } ] and escaped \\"quote\\""},'
        b'"count":1e3,"roas":[' + ENTRY + b'],"after":[true,null,{"quoted":"\\\\end"}]} \n'
    )
    assert list(iter_roas(io.BytesIO(payload), chunk_size=chunk)) == [ROA]
    loaded = VRPSet.from_stream(io.BytesIO(payload))
    assert loaded.validate("203.0.113.0/24", 64500) == RPKIStatus.VALID


def test_complete_loader_counts_bytes_after_roa_array_and_rejects_filtered_bad_tail():
    prefix = b'{"roas":[' + ENTRY + b"]}"
    with pytest.raises(VRPError):
        VRPSet.from_stream(io.BytesIO(prefix + b" " * 4096), max_bytes=len(prefix) + 100)
    with pytest.raises(VRPError):
        VRPSet.from_stream(io.BytesIO(prefix[:-1]), keep=lambda _: False)


@pytest.mark.parametrize(
    "change",
    [
        {"asn": -1},
        {"asn": 4294967296},
        {"asn": True},
        {"asn": 1.5},
        {"maxLength": 23},
        {"maxLength": 33},
        {"maxLength": 24.5},
        {"maxLength": True},
        {"prefix": 123},
        {"prefix": "not-a-prefix"},
        {"prefix": "2001:db8::/32", "maxLength": 129},
    ],
)
def test_complete_loader_refuses_invalid_vrp_even_if_filter_would_hide_it(change):
    payload = json.dumps({"roas": [{**ROA, **change}]}).encode()
    with pytest.raises(VRPError):
        VRPSet.from_stream(io.BytesIO(payload), keep=lambda _: False)


def test_complete_loader_preserves_full_asn_family_and_large_value_reach():
    roas = [
        {"prefix": "0.0.0.0/0", "maxLength": 32, "asn": 0},
        {"prefix": "2001:db8::/32", "maxLength": 128, "asn": "AS4294967295"},
        {**ROA, "note": "界" * (2 << 20)},
    ]
    payload = json.dumps(
        {"metadata": {"note": "x" * (2 << 20)}, "roas": roas}, ensure_ascii=False
    ).encode()
    loaded = VRPSet.from_stream(io.BytesIO(payload))
    assert len(loaded) == 3
    assert loaded.validate("203.0.113.0/24", 64500) == RPKIStatus.VALID
    assert loaded.validate("2001:db8:1::/48", 4294967295) == RPKIStatus.VALID
    assert list(iter_roas(io.BytesIO(payload))) == roas


def test_rpki_production_loader_never_publishes_an_incomplete_document():
    for payload in (
        b'{"roas":[' + ENTRY + b"]",
        b'{"roas":[' + ENTRY + b"]} null",
        b'{"metadata":{"roas":[' + ENTRY + b"]}}",
        b'{"roas":[null,' + ENTRY + b"]}",
    ):
        try:
            VRPSet.from_stream(io.BytesIO(payload))
        except VRPError:
            continue
        pytest.fail("incomplete validator export became an authoritative VRP set")


def test_complete_loader_admits_whole_values_only_after_finite_resource_admission(monkeypatch):
    from probectl_analyzer import rpki

    payload = json.dumps({"roas": [{**ROA, "note": "x" * 1024}]}).encode()
    monkeypatch.setattr(rpki, "MAX_VRP_BYTES", 4096)
    with pytest.raises(VRPError, match="memory admission"):
        list(iter_roas(io.BytesIO(payload), max_bytes=4096))
    assert list(iter_roas(io.BytesIO(payload), max_bytes=8 << 20)) == [{**ROA, "note": "x" * 1024}]


def test_rpki_pipeline_degrades_an_incomplete_source_to_unknown(tmp_path):
    from probectl_analyzer.config import AnalyzerConfig, MonitoredPrefix
    from probectl_analyzer.pipeline import load_vrp

    path = tmp_path / "validator.json"
    path.write_bytes(b'{"roas":[' + ENTRY + b"]")
    config = AnalyzerConfig(
        tenant_id="11111111-1111-4111-8111-111111111111",
        monitored_prefixes=[MonitoredPrefix("203.0.113.0/24")],
        rpki_vrp_file=str(path),
    )
    assert load_vrp(config) is None, "incomplete validator source escaped graceful unknown status"


def test_streamed_vrp_value_is_framed_and_decoded_once(monkeypatch):
    payload = json.dumps({"roas": [{**ROA, "note": "x" * (256 << 10)}]}).encode()
    original = json.JSONDecoder
    calls = 0

    class CountingDecoder(original):
        def raw_decode(self, text, idx=0):
            nonlocal calls
            calls += 1
            return super().raw_decode(text, idx)

    monkeypatch.setattr(json, "JSONDecoder", CountingDecoder)
    assert len(VRPSet.from_stream(io.BytesIO(payload))) == 1
    assert calls == 2, "VRP streamed value was decoded more than once"


_JSON_METADATA = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(min_value=-(1 << 64), max_value=1 << 64)
    | st.text(max_size=64),
    lambda child: (
        st.lists(child, max_size=5) | st.dictionaries(st.text(max_size=16), child, max_size=5)
    ),
    max_leaves=12,
)


@settings(max_examples=40, deadline=None)
@given(metadata=_JSON_METADATA, chunk=st.sampled_from([1, 7, 64, 8192]), ascii_only=st.booleans())
def test_complete_vrp_stream_matches_json_for_nested_metadata_and_rejects_lost_close(
    metadata, chunk, ascii_only
):
    payload = json.dumps(
        {"before": metadata, "roas": [ROA], "after": metadata}, ensure_ascii=ascii_only
    ).encode()
    assert list(iter_roas(io.BytesIO(payload), chunk_size=chunk)) == [ROA]
    with pytest.raises(VRPError):
        list(iter_roas(io.BytesIO(payload[:-1]), chunk_size=chunk))
