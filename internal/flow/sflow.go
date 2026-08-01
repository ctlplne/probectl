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

	"github.com/ctlplne/probectl/internal/wire"
)

// sFlow v5: an XDR-encoded datagram of samples. probectl decodes flow samples
// (format 1) and expanded flow samples (format 3), extracting the raw-packet-
// header record (format 1) and parsing Ethernet/802.1Q/IPv4/IPv6/TCP/UDP far
// enough for the 5-tuple. Counter samples are skipped by length (interface
// counters are the S39 device plane's job). Every sample carries its own
// sampling rate — sFlow is sampled by construction.
const (
	sflowMaxSamples = 256
	sflowMaxRecords = 64
)

// decodeSFlow decodes one sFlow v5 datagram.
func decodeSFlow(pkt []byte, exporter string, now time.Time) ([]Record, error) {
	r := wire.New(pkt)
	if v := r.U32(); v != 5 {
		return nil, fmt.Errorf("sflow: unexpected version %d", v)
	}
	addrType := r.U32()
	switch addrType {
	case 1:
		r.Skip(4)
	case 2:
		r.Skip(16)
	default:
		return nil, fmt.Errorf("sflow: bad agent address type %d", addrType)
	}
	subAgent := r.U32()
	r.Skip(4) // sequence number
	r.Skip(4) // uptime ms
	n := int(r.U32())
	if r.Err() != nil {
		return nil, fmt.Errorf("sflow: truncated header")
	}
	if n <= 0 || n > sflowMaxSamples {
		return nil, fmt.Errorf("sflow: implausible sample count %d", n)
	}

	var out []Record
	for i := 0; i < n && r.Err() == nil; i++ {
		sampleType := r.U32()
		sampleLen := int(r.U32())
		body := r.BytesAligned(sampleLen, 4)
		if r.Err() != nil {
			return out, fmt.Errorf("sflow: truncated sample %d", i)
		}
		format := sampleType & 0xFFF
		if sampleType>>12 != 0 { // enterprise-specific sample: skip
			continue
		}
		switch format {
		case 1: // flow sample
			decodeSFlowSample(body, false, exporter, subAgent, now, &out)
		case 3: // expanded flow sample
			decodeSFlowSample(body, true, exporter, subAgent, now, &out)
		default: // counter samples (2, 4) and others: skipped by length
		}
	}
	return out, nil
}

// decodeSFlowSample decodes one (expanded) flow sample's records.
func decodeSFlowSample(b []byte, expanded bool, exporter string, subAgent uint32, now time.Time, out *[]Record) {
	r := wire.New(b)
	r.Skip(4) // sequence number
	var inIf, outIf uint32
	if expanded {
		r.Skip(8) // source id type + index
		rate := r.U32()
		r.Skip(8)       // sample pool + drops
		r.Skip(4)       // input format
		inIf = r.U32()  // input value
		r.Skip(4)       // output format
		outIf = r.U32() // output value
		decodeSFlowRecords(r, exporter, subAgent, rate, inIf, outIf, now, out)
		return
	}
	r.Skip(4) // source id (type<<24|index)
	rate := r.U32()
	r.Skip(8) // sample pool + drops
	inIf = r.U32()
	outIf = r.U32()
	decodeSFlowRecords(r, exporter, subAgent, rate, inIf, outIf, now, out)
}

func decodeSFlowRecords(r *wire.Reader, exporter string, subAgent, rate, inIf, outIf uint32, now time.Time, out *[]Record) {
	n := int(r.U32())
	if n <= 0 || n > sflowMaxRecords || r.Err() != nil {
		return
	}
	for i := 0; i < n && r.Err() == nil; i++ {
		recType := r.U32()
		recLen := int(r.U32())
		body := r.BytesAligned(recLen, 4)
		if r.Err() != nil {
			return
		}
		if recType&0xFFF != 1 || recType>>12 != 0 {
			continue // only the raw-packet-header record is mapped
		}
		rec, ok := parseRawPacketHeader(body)
		if !ok {
			continue
		}
		rec.Exporter = exporter
		rec.ObservationDomain = subAgent
		rec.Protocol = ProtoSFlow5
		rec.ObservedAt = now
		rec.Start, rec.End = now, now // sFlow samples are instantaneous
		rec.InIf, rec.OutIf = inIf, outIf
		if rate == 0 {
			rate = 1
		}
		rec.SamplingRate = uint64(rate)
		rec.Packets = 1
		*out = append(*out, rec)
	}
}

// parseRawPacketHeader parses an sFlow raw-packet-header record: header
// protocol (1 = Ethernet), frame length, stripped bytes, and the leading bytes
// of the sampled frame, from which the 5-tuple is parsed.
func parseRawPacketHeader(b []byte) (Record, bool) {
	r := wire.New(b)
	proto := r.U32()
	frameLen := r.U32()
	r.Skip(4) // stripped
	hdrLen := int(r.U32())
	hdr := r.BytesAligned(hdrLen, 4)
	if r.Err() != nil || proto != 1 { // 1 = ETHERNET-ISO8023
		return Record{}, false
	}
	rec := Record{Bytes: uint64(frameLen)}
	if !parseEthernet(hdr, &rec) {
		return Record{}, false
	}
	return rec, true
}

// parseEthernet walks Ethernet → optional 802.1Q → IPv4/IPv6 → TCP/UDP far
// enough to fill the 5-tuple. Anything unparseable simply yields ok=false —
// sampled headers are routinely truncated.
func parseEthernet(h []byte, rec *Record) bool {
	if len(h) < 14 {
		return false
	}
	etherType := binary.BigEndian.Uint16(h[12:14])
	off := 14
	if etherType == 0x8100 { // 802.1Q
		if len(h) < 18 {
			return false
		}
		rec.VLAN = binary.BigEndian.Uint16(h[14:16]) & 0x0FFF
		etherType = binary.BigEndian.Uint16(h[16:18])
		off = 18
	}
	switch etherType {
	case 0x0800: // IPv4
		return parseIPv4(h[off:], rec)
	case 0x86DD: // IPv6
		return parseIPv6(h[off:], rec)
	default:
		return false
	}
}

func parseIPv4(h []byte, rec *Record) bool {
	if len(h) < 20 || h[0]>>4 != 4 {
		return false
	}
	ihl := int(h[0]&0x0F) * 4
	if ihl < 20 || len(h) < ihl {
		return false
	}
	rec.ToS = h[1]
	rec.Transport = h[9]
	rec.SrcAddr = netip.AddrFrom4([4]byte(h[12:16]))
	rec.DstAddr = netip.AddrFrom4([4]byte(h[16:20]))
	parseL4(h[ihl:], rec)
	return true
}

func parseIPv6(h []byte, rec *Record) bool {
	if len(h) < 40 || h[0]>>4 != 6 {
		return false
	}
	rec.ToS = (h[0]&0x0F)<<4 | h[1]>>4 // traffic class
	rec.Transport = h[6]               // next header (extension headers not walked)
	rec.SrcAddr = netip.AddrFrom16([16]byte(h[8:24]))
	rec.DstAddr = netip.AddrFrom16([16]byte(h[24:40]))
	parseL4(h[40:], rec)
	return true
}

func parseL4(h []byte, rec *Record) {
	switch rec.Transport {
	case 6: // TCP
		if len(h) >= 14 {
			rec.SrcPort = binary.BigEndian.Uint16(h[0:2])
			rec.DstPort = binary.BigEndian.Uint16(h[2:4])
			rec.TCPFlags = h[13]
		} else if len(h) >= 4 {
			rec.SrcPort = binary.BigEndian.Uint16(h[0:2])
			rec.DstPort = binary.BigEndian.Uint16(h[2:4])
		}
	case 17: // UDP
		if len(h) >= 4 {
			rec.SrcPort = binary.BigEndian.Uint16(h[0:2])
			rec.DstPort = binary.BigEndian.Uint16(h[2:4])
		}
	}
}
