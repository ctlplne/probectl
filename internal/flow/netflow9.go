// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flow

import (
	"encoding/binary"
	"fmt"
	"time"
)

// NetFlow v9 (RFC 3954): a 20-byte header followed by flowsets. Set ID 0 is a
// template flowset, 1 an options-template flowset, and IDs > 255 are data
// flowsets decoded via a previously cached template. Templates and the options
// sampling state are cached per (exporter, source ID) with TTL + size bounds.
const (
	nf9HeaderLen = 20
	// nf9MaxRecordsPerPacket bounds the records one datagram may yield —
	// untrusted input must not size allocations (a 64 KiB datagram cannot
	// plausibly carry more, even with tiny templates).
	nf9MaxRecordsPerPacket = 4096
)

type nf9Decoder struct {
	templates *templateCache
	sampling  *samplingState
}

// decode decodes one v9 datagram. templateMisses counts data flowsets dropped
// because their template has not been seen yet (the exporter will re-send it).
func (d *nf9Decoder) decode(pkt []byte, exporter string, now time.Time) (recs []Record, templateMisses int, err error) {
	if len(pkt) < nf9HeaderLen {
		return nil, 0, fmt.Errorf("netflow9: datagram too short: %d bytes", len(pkt))
	}
	if v := binary.BigEndian.Uint16(pkt[0:2]); v != 9 {
		return nil, 0, fmt.Errorf("netflow9: unexpected version %d", v)
	}
	sysUptimeMS := binary.BigEndian.Uint32(pkt[4:8])
	unixSecs := binary.BigEndian.Uint32(pkt[8:12])
	domain := binary.BigEndian.Uint32(pkt[16:20]) // source ID

	export := time.Unix(int64(unixSecs), 0)
	clk := ieClock{boot: export.Add(-time.Duration(sysUptimeMS) * time.Millisecond), export: export}

	off := nf9HeaderLen
	for off+4 <= len(pkt) {
		setID := binary.BigEndian.Uint16(pkt[off : off+2])
		setLen := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		if setLen < 4 || off+setLen > len(pkt) {
			return recs, templateMisses, fmt.Errorf("netflow9: bad flowset length %d at offset %d", setLen, off)
		}
		body := pkt[off+4 : off+setLen]
		switch {
		case setID == 0:
			d.parseTemplates(body, exporter, domain, false)
		case setID == 1:
			d.parseOptionsTemplates(body, exporter, domain)
		case setID > 255:
			n, miss := d.decodeData(body, setID, exporter, domain, now, clk, &recs)
			templateMisses += miss
			if n > nf9MaxRecordsPerPacket {
				return recs, templateMisses, fmt.Errorf("netflow9: record bound exceeded")
			}
		}
		off += setLen
	}
	return recs, templateMisses, nil
}

// parseTemplates parses a template flowset: repeated (templateID, fieldCount,
// fieldCount x (type, length)).
func (d *nf9Decoder) parseTemplates(b []byte, exporter string, domain uint32, _ bool) {
	off := 0
	for off+4 <= len(b) {
		tid := binary.BigEndian.Uint16(b[off : off+2])
		fc := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		off += 4
		if tid < 256 || fc <= 0 || fc > 512 || off+fc*4 > len(b) {
			return // malformed remainder — stop, keep what we have
		}
		fields := make([]templateField, 0, fc)
		for i := 0; i < fc; i++ {
			fields = append(fields, templateField{
				ID:     binary.BigEndian.Uint16(b[off : off+2]),
				Length: binary.BigEndian.Uint16(b[off+2 : off+4]),
			})
			off += 4
		}
		d.templates.put(templateKey{exporter, domain, tid}, templateRecord{Fields: fields})
	}
}

// parseOptionsTemplates parses an options-template flowset (RFC 3954 §6.2):
// (templateID, scopeLenBytes, optionLenBytes, scope fields…, option fields…).
func (d *nf9Decoder) parseOptionsTemplates(b []byte, exporter string, domain uint32) {
	off := 0
	for off+6 <= len(b) {
		tid := binary.BigEndian.Uint16(b[off : off+2])
		scopeBytes := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		optionBytes := int(binary.BigEndian.Uint16(b[off+4 : off+6]))
		off += 6
		if tid < 256 || scopeBytes < 0 || optionBytes < 0 || off+scopeBytes+optionBytes > len(b) ||
			(scopeBytes+optionBytes) == 0 || (scopeBytes%4 != 0) || (optionBytes%4 != 0) {
			return
		}
		nScope, nOpt := scopeBytes/4, optionBytes/4
		fields := make([]templateField, 0, nScope+nOpt)
		for i := 0; i < nScope+nOpt; i++ {
			fields = append(fields, templateField{
				ID:     binary.BigEndian.Uint16(b[off : off+2]),
				Length: binary.BigEndian.Uint16(b[off+2 : off+4]),
			})
			off += 4
		}
		d.templates.put(templateKey{exporter, domain, tid},
			templateRecord{Fields: fields, Options: true, ScopeLen: nScope})
		// v9 options templates are followed by padding to a 4-byte boundary;
		// the loop's +6 guard simply stops on residual padding.
	}
}

// decodeData decodes a data flowset against its cached template. Options data
// updates the exporter sampling state; flow data appends records.
func (d *nf9Decoder) decodeData(b []byte, tid uint16, exporter string, domain uint32, now time.Time, clk ieClock, out *[]Record) (n, templateMisses int) {
	tmpl, ok := d.templates.get(templateKey{exporter, domain, tid})
	if !ok {
		return 0, 1
	}
	width := tmpl.fixedWidth()
	if width <= 0 { // v9 has no variable-length fields; refuse zero-width
		return 0, 0
	}
	exporterRate := d.sampling.get(exporter, domain)
	off := 0
	for off+width <= len(b) && len(*out) < nf9MaxRecordsPerPacket {
		row := b[off : off+width]
		off += width
		n++
		if tmpl.Options {
			fo := 0
			for _, f := range tmpl.Fields {
				if rate := optionsSamplingRate(f.ID, row[fo:fo+int(f.Length)]); rate > 0 {
					d.sampling.set(exporter, domain, rate)
					exporterRate = rate
				}
				fo += int(f.Length)
			}
			continue
		}
		rec := Record{
			Exporter:          exporter,
			ObservationDomain: domain,
			Protocol:          ProtoNetFlow9,
			ObservedAt:        now,
			SamplingRate:      exporterRate,
		}
		fo := 0
		var inline uint64
		for _, f := range tmpl.Fields {
			if r := applyIE(&rec, f.ID, row[fo:fo+int(f.Length)], clk); r > 0 {
				inline = r
			}
			fo += int(f.Length)
		}
		if inline > 0 {
			rec.SamplingRate = inline
		}
		if rec.Start.IsZero() {
			rec.Start = clk.export
		}
		if rec.End.IsZero() {
			rec.End = clk.export
		}
		*out = append(*out, rec)
	}
	return n, 0
}
