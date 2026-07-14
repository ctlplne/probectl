// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flow

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
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
	if v := binary.BigEndian.Uint16(pkt[0:2]); v != 5 {
		return nil, fmt.Errorf("netflow5: unexpected version %d", v)
	}
	count := int(binary.BigEndian.Uint16(pkt[2:4]))
	if count == 0 || count > nf5MaxCount {
		return nil, fmt.Errorf("netflow5: implausible record count %d", count)
	}
	if len(pkt) < nf5HeaderLen+count*nf5RecordLen {
		return nil, fmt.Errorf("netflow5: truncated: header claims %d records, have %d bytes", count, len(pkt))
	}

	sysUptimeMS := binary.BigEndian.Uint32(pkt[4:8])
	unixSecs := binary.BigEndian.Uint32(pkt[8:12])
	unixNsecs := binary.BigEndian.Uint32(pkt[12:16])
	// engineType/engineID (pkt[20], pkt[21]) identify the exporter slot; the
	// observation domain is engineType<<8|engineID for template-state symmetry.
	domain := uint32(pkt[20])<<8 | uint32(pkt[21])
	sampling := binary.BigEndian.Uint16(pkt[22:24])
	rate := uint64(sampling & 0x3FFF) // low 14 bits; 0 => unsampled
	if rate == 0 {
		rate = 1
	}

	exportTime := time.Unix(int64(unixSecs), int64(unixNsecs))
	bootTime := exportTime.Add(-time.Duration(sysUptimeMS) * time.Millisecond)

	out := make([]Record, 0, count)
	for i := 0; i < count; i++ {
		r := pkt[nf5HeaderLen+i*nf5RecordLen:]
		first := binary.BigEndian.Uint32(r[24:28])
		last := binary.BigEndian.Uint32(r[28:32])
		rec := Record{
			Exporter:          exporter,
			ObservationDomain: domain,
			Protocol:          ProtoNetFlow5,
			ObservedAt:        now,
			Start:             bootTime.Add(time.Duration(first) * time.Millisecond),
			End:               bootTime.Add(time.Duration(last) * time.Millisecond),
			SrcAddr:           netip.AddrFrom4([4]byte(r[0:4])),
			DstAddr:           netip.AddrFrom4([4]byte(r[4:8])),
			NextHop:           netip.AddrFrom4([4]byte(r[8:12])),
			InIf:              uint32(binary.BigEndian.Uint16(r[12:14])),
			OutIf:             uint32(binary.BigEndian.Uint16(r[14:16])),
			Packets:           uint64(binary.BigEndian.Uint32(r[16:20])),
			Bytes:             uint64(binary.BigEndian.Uint32(r[20:24])),
			SrcPort:           binary.BigEndian.Uint16(r[32:34]),
			DstPort:           binary.BigEndian.Uint16(r[34:36]),
			TCPFlags:          r[37],
			Transport:         r[38],
			ToS:               r[39],
			SrcAS:             uint32(binary.BigEndian.Uint16(r[40:42])),
			DstAS:             uint32(binary.BigEndian.Uint16(r[42:44])),
			SamplingRate:      rate,
		}
		out = append(out, rec)
	}
	return out, nil
}
