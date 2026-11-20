// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

const (
	mrtCommonHeaderBytes = 12
	mrtTableDumpV2Type   = 13
	mrtPeerIndexSubtype  = 1
)

var errMRTArchiveIncomplete = errors.New("bgp: incomplete MRT archive")

// MRTArchiveBudget bounds raw archive admission independently of individual
// parser memory and work bounds.
type MRTArchiveBudget struct {
	ArchiveBytes, Records int64
	Frame                 UpdateFrameBudget
}

func (limits MRTArchiveBudget) valid() bool {
	return limits.ArchiveBytes >= mrtCommonHeaderBytes && limits.Records >= 1 &&
		limits.Frame.MemoryBytes > 4096 && limits.Frame.WorkUnits > 4096
}

// MRTBaseline keeps original collector clocks and the complete peer roster.
// Publication must use whole-file acceptance in the same staging transaction.
type MRTBaseline struct {
	PeerIndex MRTPeerIndex
	Bytes     int64
	Records   int64
}

// StageMRTBaseline validates every record before declaring clean EOF. The
// receiving staging callback must remain inert until this function succeeds.
// It sees bounded records in file order rather than a materialized full RIB.
func StageMRTBaseline(ctx context.Context, reader io.Reader, budget MRTArchiveBudget,
	stage func(context.Context, MRTPeerIndex, MRTRIBRecord) error) (MRTBaseline, error) {
	if reader == nil || stage == nil || !budget.valid() {
		return MRTBaseline{}, ErrMRTBudget
	}
	stream := mrtArchiveReader{source: reader, limits: budget}
	index, err := stageMRTBaselineIndex(ctx, &stream)
	if err != nil {
		return MRTBaseline{}, err
	}
	for {
		raw, err := stream.next(ctx)
		if err == io.EOF {
			return MRTBaseline{PeerIndex: index, Bytes: stream.bytes, Records: stream.records}, nil
		}
		if err != nil {
			return MRTBaseline{}, err
		}
		rib, err := decodeMRTRIB(ctx, raw, len(index.Peers), budget.Frame, true)
		if err != nil {
			return MRTBaseline{}, stream.recordError(raw, err)
		}
		if err := stage(ctx, index, rib); err != nil {
			return MRTBaseline{}, err
		}
	}
}

// RFC6396 erratum 6640 documents original public dumps containing a full
// MP_REACH value. The archive reader validates its complete encoding and
// requires the duplicated NLRI to identify the exact enclosing RIB path.
func decodeArchiveMRTNextHops(ctx context.Context, attrs []RouteAttribute, family RouteFamily, route RoutePrefix, budget MultiprotocolBudget) ([]netip.Addr, error) {
	var value []byte
	for _, attr := range attrs {
		if attr.Type == 15 {
			return nil, ErrMRTRecord
		}
		if attr.Type == 14 {
			value = attr.Value
		}
	}
	if len(value) < 5 || int(value[0]) == len(value)-1 {
		return nil, ErrMRTRecord
	}
	nextHopAFI := uint16(1)
	if value[3] == 16 || value[3] == 32 {
		nextHopAFI = 2
	}
	reach, err := parseMPReachRoutes(ctx, value, nextHopAFI, route.HasPathID, budget)
	if err != nil {
		return nil, err
	}
	if reach.Family != family || len(reach.Prefixes) != 1 || reach.Prefixes[0] != route {
		return nil, ErrMRTRecord
	}
	return reach.NextHops, nil
}

func (reader *mrtArchiveReader) recordError(raw []byte, err error) error {
	return fmt.Errorf("MRT record %d at byte %d (type %d, subtype %d): %w", reader.records, reader.bytes-int64(len(raw)),
		binary.BigEndian.Uint16(raw[4:6]), binary.BigEndian.Uint16(raw[6:8]), err)
}

func stageMRTBaselineIndex(ctx context.Context, stream *mrtArchiveReader) (MRTPeerIndex, error) {
	first, err := stream.next(ctx)
	if err == io.EOF {
		return MRTPeerIndex{}, errMRTArchiveIncomplete
	}
	if err != nil {
		return MRTPeerIndex{}, err
	}
	if binary.BigEndian.Uint16(first[4:6]) != mrtTableDumpV2Type ||
		binary.BigEndian.Uint16(first[6:8]) != mrtPeerIndexSubtype {
		return MRTPeerIndex{}, ErrMRTRecord
	}
	peers, err := DecodeMRTPeerIndex(ctx, first, stream.limits.Frame)
	if err != nil {
		return MRTPeerIndex{}, err
	}
	if peers.ObservedUnixNanos <= 0 {
		return MRTPeerIndex{}, ErrMRTRecord
	}
	return peers, nil
}

type mrtArchiveReader struct {
	source         io.Reader
	limits         MRTArchiveBudget
	bytes, records int64
	reusable       []byte
}

func (reader *mrtArchiveReader) next(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var header [mrtCommonHeaderBytes]byte
	n, err := io.ReadFull(reader.source, header[:])
	if err != nil {
		if n == 0 && errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, errors.Join(errMRTArchiveIncomplete, err)
	}
	bodySize := int64(binary.BigEndian.Uint32(header[8:12]))
	recordSize := bodySize + mrtCommonHeaderBytes
	if reader.records >= reader.limits.Records || recordSize > reader.limits.ArchiveBytes-reader.bytes ||
		recordSize > (reader.limits.Frame.MemoryBytes-4096)/128 || recordSize > (reader.limits.Frame.WorkUnits-4096)/16 ||
		recordSize > int64(int(^uint(0)>>1)) {
		return nil, ErrMRTBudget
	}
	if cap(reader.reusable) < int(recordSize) {
		reader.reusable = make([]byte, int(recordSize))
	}
	raw := reader.reusable[:int(recordSize)]
	copy(raw, header[:])
	if _, err := io.ReadFull(reader.source, raw[mrtCommonHeaderBytes:]); err != nil {
		return nil, errors.Join(errMRTArchiveIncomplete, err)
	}
	reader.records++
	reader.bytes += recordSize
	return raw, ctx.Err()
}
