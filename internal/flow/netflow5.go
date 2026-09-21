// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/ctlplne/probectl/internal/wire"
)

// NetFlow v5: a fixed 24-byte header followed by count fixed 48-byte records.
// The header carries the exporter clock (sysUptime + unix time) used to map
// the per-record first/last switched uptimes onto absolute timestamps, and a
// 16-bit sampling field (2-bit mode + 14-bit interval).
const (
	nf5HeaderLen = 24
	nf5RecordLen = 48
	// nf5MaxCount bounds the record count claimed by the header (the protocol
	// itself caps a datagram at 30 records; refuse anything larger — untrusted
	// input must not size allocations).
	nf5MaxCount = 30
)

// decodeNetFlow5 decodes one v5 datagram into records. exporter is the UDP
// source address of the datagram; now is the collector receive time.
func decodeNetFlow5(pkt []byte, exporter string, now time.Time) ([]Record, error) {
	if len(pkt) < nf5HeaderLen {
		return nil, fmt.Errorf("netflow5: datagram too short: %d bytes", len(pkt))
	}
	hdr := wire.New(pkt[:nf5HeaderLen])
	if v := hdr.U16(); v != 5 {
		return nil, fmt.Errorf("netflow5: unexpected version %d", v)
	}
	count := int(hdr.U16())
	if count == 0 || count > nf5MaxCount {
		return nil, fmt.Errorf("netflow5: implausible record count %d", count)
	}
	if len(pkt) < nf5HeaderLen+count*nf5RecordLen {
		return nil, fmt.Errorf("netflow5: truncated: header claims %d records, have %d bytes", count, len(pkt))
	}

	sysUptimeMS := hdr.U32()
	unixSecs := hdr.U32()
	unixNsecs := hdr.U32()
	hdr.Skip(4) // flow sequence
	// engineType/engineID identify the exporter slot; the observation domain
	// is engineType<<8|engineID for template-state symmetry.
	domain := uint32(hdr.U8())<<8 | uint32(hdr.U8())
	sampling := hdr.U16()
	if err := hdr.Err(); err != nil {
		return nil, fmt.Errorf("netflow5: header: %w", err)
	}
	rate := uint64(sampling & 0x3FFF) // low 14 bits; 0 => unsampled
	if rate == 0 {
		rate = 1
	}

	exportTime := time.Unix(int64(unixSecs), int64(unixNsecs))
	bootTime := exportTime.Add(-time.Duration(sysUptimeMS) * time.Millisecond)

	// Each record is read through its OWN length-delimited sub-reader
	// (internal/wire), so a field can never read into the next record and the
	// wire layout is stated once, in order, instead of as 16 hand-computed
	// offsets. Field order is RFC 3954 §A: addrs, ifs, counters, timestamps,
	// ports, pad, flags, proto, tos, AS numbers, masks, pad.
	body := wire.New(pkt[nf5HeaderLen:])
	out := make([]Record, 0, count)
	for i := 0; i < count; i++ {
		r := body.Sub(nf5RecordLen)
		src, dst, nextHop := r.Array4(), r.Array4(), r.Array4()
		inIf, outIf := r.U16(), r.U16()
		packets, bytesCount := r.U32(), r.U32()
		first, last := r.U32(), r.U32()
		srcPort, dstPort := r.U16(), r.U16()
		r.Skip(1) // pad1
		tcpFlags, transport, tos := r.U8(), r.U8(), r.U8()
		srcAS, dstAS := r.U16(), r.U16()
		if err := r.Err(); err != nil {
			return nil, fmt.Errorf("netflow5: record %d: %w", i, err)
		}
		out = append(out, Record{
			Exporter:          exporter,
			ObservationDomain: domain,
			Protocol:          ProtoNetFlow5,
			ObservedAt:        now,
			Start:             bootTime.Add(time.Duration(first) * time.Millisecond),
			End:               bootTime.Add(time.Duration(last) * time.Millisecond),
			SrcAddr:           netip.AddrFrom4(src),
			DstAddr:           netip.AddrFrom4(dst),
			NextHop:           netip.AddrFrom4(nextHop),
			InIf:              uint32(inIf),
			OutIf:             uint32(outIf),
			Packets:           uint64(packets),
			Bytes:             uint64(bytesCount),
			SrcPort:           srcPort,
			DstPort:           dstPort,
			TCPFlags:          tcpFlags,
			Transport:         transport,
			ToS:               tos,
			SrcAS:             uint32(srcAS),
			DstAS:             uint32(dstAS),
			SamplingRate:      rate,
		})
	}
	return out, nil
}
