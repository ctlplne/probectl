# SPDX-License-Identifier: BUSL-1.1
#
# Use of this source code is governed by the Business Source License 1.1
# in the LICENSE file at the root of this repository; on its Change Date
# each version converts to the Mozilla Public License 2.0.

"""Complete AS path semantics shared by the existing public-source adapters.

These pure codecs grant no source authority or current-RIB completeness. Their
callers retain the source record's byte/cardinality admission before decoding.
Kinds match RFC4271/RFC5065 and the control plane's structured path codec.
"""

from dataclasses import dataclass

AS_SET, AS_SEQUENCE, AS_CONFED_SEQUENCE, AS_CONFED_SET = 1, 2, 3, 4
AS_TRANS = 23456


@dataclass(frozen=True)
class ASPathSegment:
    kind: int
    values: tuple[int, ...]


@dataclass(frozen=True)
class ASPath:
    segments: tuple[ASPathSegment, ...]
    as4_action: str = "absent"
    confederations_discarded: bool = False


def parse_as_path(value: bytes, width: int) -> tuple[ASPathSegment, ...]:
    """Decode only the source-declared ASN width; never guess or return a prefix."""
    if width not in (2, 4):
        raise ValueError("AS path width must be 2 or 4")
    segments = []
    position = 0
    while position < len(value):
        if len(value) - position < 2:
            raise ValueError("truncated AS path segment")
        kind, count = value[position], value[position + 1]
        position += 2
        if kind not in (1, 2, 3, 4) or count == 0 or count > (len(value) - position) // width:
            raise ValueError("malformed AS path segment")
        end = position + count * width
        values = tuple(
            int.from_bytes(value[i : i + width], "big") for i in range(position, end, width)
        )
        segments.append(ASPathSegment(kind, values))
        position = end
    return tuple(segments)


def _selection_length(segments: tuple[ASPathSegment, ...]) -> int:
    return sum(
        1 if s.kind == AS_SET else len(s.values) if s.kind == AS_SEQUENCE else 0 for s in segments
    )


def reconstruct_as_path(
    value: bytes,
    four_byte: bool,
    as4: bytes | None = None,
    aggregator_asn: int | None = None,
    as4_aggregator: bool = False,
) -> ASPath:
    """RFC6793 §§4.2.3/6, matching the existing Go reconstruction semantics."""
    legacy = parse_as_path(value, 4 if four_byte else 2)
    if as4 is None:
        return ASPath(legacy)
    if four_byte:
        return ASPath(legacy, "ignored_four_octet_session")
    if aggregator_asn is not None and as4_aggregator and aggregator_asn != AS_TRANS:
        return ASPath(legacy, "ignored_legacy_aggregation")
    if len(as4) < 6 or len(as4) % 2:
        return ASPath(legacy, "ignored_malformed")
    try:
        extended = parse_as_path(as4, 4)
    except ValueError:
        return ASPath(legacy, "ignored_malformed")
    public = tuple(s for s in extended if s.kind in (AS_SET, AS_SEQUENCE))
    discarded = len(public) != len(extended)
    keep = _selection_length(legacy) - _selection_length(public)
    if keep < 0:
        return ASPath(legacy, "ignored_longer_than_legacy", discarded)
    leading = []
    for segment in legacy:
        if segment.kind in (AS_CONFED_SEQUENCE, AS_CONFED_SET):
            leading.append(segment)
            continue
        if keep == 0:
            break
        if segment.kind == AS_SET:
            leading.append(segment)
            keep -= 1
            continue
        take = min(keep, len(segment.values))
        leading.append(ASPathSegment(segment.kind, segment.values[:take]))
        keep -= take
        if take < len(segment.values):
            break
    return ASPath(tuple(leading) + public, "reconstructed", discarded)


def path_origin(segments: tuple[ASPathSegment, ...]) -> int | None:
    """An unordered set, AS_TRANS or confed-only path proves no unique origin."""
    for segment in reversed(segments):
        if segment.kind in (AS_CONFED_SEQUENCE, AS_CONFED_SET):
            continue
        if segment.kind == AS_SEQUENCE and segment.values[-1] not in (0, AS_TRANS):
            return segment.values[-1]
        break
    return None
