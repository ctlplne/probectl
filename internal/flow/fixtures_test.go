// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flow

import (
	"encoding/binary"
	"time"
)

// wire is a tiny big-endian packet builder: the test-side encoder that the
// decoders are checked against ("fixture captures" synthesized byte-precisely
// from the RFCs — deterministic and reviewable, unlike opaque pcaps).
type wireBuf struct{ b []byte }

func (w *wireBuf) u8(v byte) *wireBuf { w.b = append(w.b, v); return w }
func (w *wireBuf) u16(v uint16) *wireBuf {
	w.b = binary.BigEndian.AppendUint16(w.b, v)
	return w
}
func (w *wireBuf) u32(v uint32) *wireBuf {
	w.b = binary.BigEndian.AppendUint32(w.b, v)
	return w
}
func (w *wireBuf) u64(v uint64) *wireBuf {
	w.b = binary.BigEndian.AppendUint64(w.b, v)
	return w
}
func (w *wireBuf) raw(p []byte) *wireBuf { w.b = append(w.b, p...); return w }
func (w *wireBuf) pad(n int) *wireBuf {
	for i := 0; i < n; i++ {
		w.b = append(w.b, 0)
	}
	return w
}

// --- NetFlow v5 -------------------------------------------------------------

type nf5rec struct {
	src, dst, nexthop [4]byte
	inIf, outIf       uint16
	pkts, bytes       uint32
	first, last       uint32 // sysUptime ms
	sport, dport      uint16
	flags, proto, tos byte
	srcAS, dstAS      uint16
}

func buildNF5(sysUptimeMS, unixSecs uint32, sampling uint16, recs []nf5rec) []byte {
	w := &wireBuf{}
	w.u16(5).u16(uint16(len(recs))).u32(sysUptimeMS).u32(unixSecs).u32(0).u32(1)
	w.u8(1).u8(2)   // engine type/id -> domain 0x0102
	w.u16(sampling) // 2-bit mode + 14-bit interval
	for _, r := range recs {
		w.raw(r.src[:]).raw(r.dst[:]).raw(r.nexthop[:])
		w.u16(r.inIf).u16(r.outIf)
		w.u32(r.pkts).u32(r.bytes).u32(r.first).u32(r.last)
		w.u16(r.sport).u16(r.dport)
		w.u8(0).u8(r.flags).u8(r.proto).u8(r.tos)
		w.u16(r.srcAS).u16(r.dstAS)
		w.u8(24).u8(24).u16(0) // masks + pad
	}
	return w.b
}

// --- NetFlow v9 -------------------------------------------------------------

func nf9Header(count uint16, sysUptimeMS, unixSecs, sourceID uint32) *wireBuf {
	w := &wireBuf{}
	w.u16(9).u16(count).u32(sysUptimeMS).u32(unixSecs).u32(77).u32(sourceID)
	return w
}

// buildNF9Template builds a template flowset (set ID 0) with one template.
func buildNF9Template(sysUptimeMS, unixSecs, sourceID uint32, tid uint16, fields [][2]uint16) []byte {
	w := nf9Header(1, sysUptimeMS, unixSecs, sourceID)
	setLen := 4 + 4 + len(fields)*4
	w.u16(0).u16(uint16(setLen))
	w.u16(tid).u16(uint16(len(fields)))
	for _, f := range fields {
		w.u16(f[0]).u16(f[1])
	}
	return w.b
}

// buildNF9OptionsTemplate builds an options-template flowset (set ID 1):
// scope fields then option fields, both as (type, len) pairs.
func buildNF9OptionsTemplate(sysUptimeMS, unixSecs, sourceID uint32, tid uint16, scope, options [][2]uint16) []byte {
	w := nf9Header(1, sysUptimeMS, unixSecs, sourceID)
	body := 6 + (len(scope)+len(options))*4
	pad := (4 - (4+body)%4) % 4
	w.u16(1).u16(uint16(4 + body + pad))
	w.u16(tid).u16(uint16(len(scope) * 4)).u16(uint16(len(options) * 4))
	for _, f := range append(append([][2]uint16{}, scope...), options...) {
		w.u16(f[0]).u16(f[1])
	}
	w.pad(pad)
	return w.b
}

// buildNF9Data builds a data flowset for tid from pre-encoded record rows.
func buildNF9Data(sysUptimeMS, unixSecs, sourceID uint32, tid uint16, rows [][]byte) []byte {
	w := nf9Header(uint16(len(rows)), sysUptimeMS, unixSecs, sourceID)
	body := 0
	for _, r := range rows {
		body += len(r)
	}
	pad := (4 - (4+body)%4) % 4
	w.u16(tid).u16(uint16(4 + body + pad))
	for _, r := range rows {
		w.raw(r)
	}
	w.pad(pad)
	return w.b
}

// --- IPFIX ------------------------------------------------------------------

// ipfixMsg wraps sets into a length-correct IPFIX message header.
func ipfixMsg(exportSecs, domain uint32, sets ...[]byte) []byte {
	body := 0
	for _, s := range sets {
		body += len(s)
	}
	w := &wireBuf{}
	w.u16(10).u16(uint16(16 + body)).u32(exportSecs).u32(9001).u32(domain)
	for _, s := range sets {
		w.raw(s)
	}
	return w.b
}

// ipfixField is one template field spec; Enterprise != 0 emits the PEN form.
type ipfixField struct {
	ID         uint16
	Len        uint16
	Enterprise uint32
}

func ipfixTemplateSet(setID, tid uint16, scopeCount uint16, fields []ipfixField) []byte {
	w := &wireBuf{}
	hdr := 4
	if setID == 3 {
		hdr = 6
	}
	body := hdr
	for _, f := range fields {
		body += 4
		if f.Enterprise != 0 {
			body += 4
		}
	}
	w.u16(setID).u16(uint16(4 + body))
	w.u16(tid).u16(uint16(len(fields)))
	if setID == 3 {
		w.u16(scopeCount)
	}
	for _, f := range fields {
		typ := f.ID
		if f.Enterprise != 0 {
			typ |= 0x8000
		}
		w.u16(typ).u16(f.Len)
		if f.Enterprise != 0 {
			w.u32(f.Enterprise)
		}
	}
	return w.b
}

func ipfixDataSet(tid uint16, rows ...[]byte) []byte {
	body := 0
	for _, r := range rows {
		body += len(r)
	}
	w := &wireBuf{}
	w.u16(tid).u16(uint16(4 + body))
	for _, r := range rows {
		w.raw(r)
	}
	return w.b
}

// --- sFlow v5 ---------------------------------------------------------------

// buildEthIPv4TCP builds an Ethernet/802.1Q(optional)/IPv4/TCP header blob.
func buildEthIPv4TCP(vlan uint16, src, dst [4]byte, sport, dport uint16, tcpFlags byte, proto byte) []byte {
	w := &wireBuf{}
	w.raw(make([]byte, 12)) // MACs
	if vlan != 0 {
		w.u16(0x8100).u16(vlan)
	}
	w.u16(0x0800)
	// IPv4, IHL 5
	w.u8(0x45).u8(0xB8).u16(60) // tos 0xB8
	w.u32(0).u8(64).u8(proto).u16(0)
	w.raw(src[:]).raw(dst[:])
	// L4
	w.u16(sport).u16(dport)
	if proto == 6 {
		w.u32(1).u32(2).u8(0x50).u8(tcpFlags).u16(0) // seq/ack/offset/flags/window
	}
	return w.b
}

func buildEthIPv6UDP(src, dst [16]byte, sport, dport uint16) []byte {
	w := &wireBuf{}
	w.raw(make([]byte, 12)).u16(0x86DD)
	w.u8(0x60).u8(0).u16(0) // version/tc/flow
	w.u16(8).u8(17).u8(64)  // payload len, next header UDP, hop limit
	w.raw(src[:]).raw(dst[:])
	w.u16(sport).u16(dport).u16(8).u16(0)
	return w.b
}

// buildSFlowRaw wraps a packet header into a flow sample (expanded=false uses
// format 1; true uses format 3) inside a full sFlow v5 datagram.
func buildSFlowRaw(rate, inIf, outIf uint32, hdr []byte, expanded bool, extraCounterSample bool) []byte {
	pad := (4 - len(hdr)%4) % 4

	// flow record: raw packet header
	rec := &wireBuf{}
	rec.u32(1)                // header protocol: ethernet
	rec.u32(1500)             // frame length
	rec.u32(4)                // stripped
	rec.u32(uint32(len(hdr))) // header length
	rec.raw(hdr).pad(pad)     // header + XDR pad
	record := (&wireBuf{}).u32(1).u32(uint32(len(rec.b))).raw(rec.b).b

	// flow sample
	s := &wireBuf{}
	s.u32(101) // sequence
	if expanded {
		s.u32(0).u32(3)                // source id type/index
		s.u32(rate).u32(100000).u32(0) // rate, pool, drops
		s.u32(0).u32(inIf).u32(0).u32(outIf)
	} else {
		s.u32(3)                       // source id
		s.u32(rate).u32(100000).u32(0) // rate, pool, drops
		s.u32(inIf).u32(outIf)
	}
	s.u32(1) // record count
	s.raw(record)
	format := uint32(1)
	if expanded {
		format = 3
	}
	sample := (&wireBuf{}).u32(format).u32(uint32(len(s.b))).raw(s.b).b

	n := uint32(1)
	var counter []byte
	if extraCounterSample {
		body := (&wireBuf{}).u32(7).u32(3).u32(0).b // junk counter body
		counter = (&wireBuf{}).u32(2).u32(uint32(len(body))).raw(body).b
		n = 2
	}

	w := &wireBuf{}
	w.u32(5).u32(1).raw([]byte{192, 0, 2, 1}) // version, v4 agent
	w.u32(3)                                  // sub-agent id
	w.u32(900).u32(123456).u32(n)             // seq, uptime, samples
	w.raw(sample).raw(counter)
	return w.b
}

// testTime is the fixed collector receive time used across decoder tests.
var testTime = time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
