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

// IPFIX (RFC 7011): a 16-byte message header followed by sets. Set ID 2 is a
// template set, 3 an options-template set, IDs >= 256 are data sets. IPFIX
// extends v9 with enterprise-specific elements (high bit of the type, followed
// by a 4-byte enterprise number) and variable-length fields (length 0xFFFF:
// the value is prefixed by 1 byte, or 255 + 2 bytes for long values). probectl
// skips enterprise and variable-length values it does not map, by length.
const (
	ipfixHeaderLen           = 16
	ipfixMaxRecordsPerPacket = 4096
)

type ipfixDecoder struct {
	templates *templateCache
	sampling  *samplingState
}

func (d *ipfixDecoder) decode(pkt []byte, exporter string, now time.Time) (recs []Record, templateMisses int, err error) {
	if len(pkt) < ipfixHeaderLen {
		return nil, 0, fmt.Errorf("ipfix: message too short: %d bytes", len(pkt))
	}
	if v := binary.BigEndian.Uint16(pkt[0:2]); v != 10 {
		return nil, 0, fmt.Errorf("ipfix: unexpected version %d", v)
	}
	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if msgLen < ipfixHeaderLen || msgLen > len(pkt) {
		return nil, 0, fmt.Errorf("ipfix: bad message length %d (have %d)", msgLen, len(pkt))
	}
	exportSecs := binary.BigEndian.Uint32(pkt[4:8])
	domain := binary.BigEndian.Uint32(pkt[12:16])
	clk := ieClock{export: time.Unix(int64(exportSecs), 0)} // no sysUptime in IPFIX

	off := ipfixHeaderLen
	for off+4 <= msgLen {
		setID := binary.BigEndian.Uint16(pkt[off : off+2])
		setLen := int(binary.BigEndian.Uint16(pkt[off+2 : off+4]))
		if setLen < 4 || off+setLen > msgLen {
			return recs, templateMisses, fmt.Errorf("ipfix: bad set length %d at offset %d", setLen, off)
		}
		body := pkt[off+4 : off+setLen]
		switch {
		case setID == 2:
			d.parseTemplates(body, exporter, domain, false)
		case setID == 3:
			d.parseTemplates(body, exporter, domain, true)
		case setID >= 256:
			miss := d.decodeData(body, setID, exporter, domain, now, clk, &recs)
			templateMisses += miss
		}
		off += setLen
	}
	return recs, templateMisses, nil
}

// parseTemplates parses (options-)template records. An IPFIX options template
// header is (templateID, fieldCount, scopeFieldCount); a regular template is
// (templateID, fieldCount). Field specs are (type[, enterprise], length) with
// the enterprise bit in the type's MSB.
func (d *ipfixDecoder) parseTemplates(b []byte, exporter string, domain uint32, options bool) {
	off := 0
	hdr := 4
	if options {
		hdr = 6
	}
	for off+hdr <= len(b) {
		tid := binary.BigEndian.Uint16(b[off : off+2])
		fc := int(binary.BigEndian.Uint16(b[off+2 : off+4]))
		scope := 0
		if options {
			scope = int(binary.BigEndian.Uint16(b[off+4 : off+6]))
		}
		off += hdr
		if tid < 256 || fc <= 0 || fc > 512 || scope < 0 || scope > fc {
			return
		}
		fields := make([]templateField, 0, fc)
		ok := true
		for i := 0; i < fc; i++ {
			if off+4 > len(b) {
				ok = false
				break
			}
			typ := binary.BigEndian.Uint16(b[off : off+2])
			length := binary.BigEndian.Uint16(b[off+2 : off+4])
			off += 4
			f := templateField{ID: typ & 0x7FFF, Length: length}
			if typ&0x8000 != 0 { // enterprise-specific: 4-byte PEN follows
				if off+4 > len(b) {
					ok = false
					break
				}
				f.Enterprise = binary.BigEndian.Uint32(b[off : off+4])
				off += 4
			}
			fields = append(fields, f)
		}
		if !ok {
			return
		}
		d.templates.put(templateKey{exporter, domain, tid},
			templateRecord{Fields: fields, Options: options, ScopeLen: scope})
	}
}

// decodeData walks data records against the template, handling variable-length
// fields. Records from options templates update sampling state.
func (d *ipfixDecoder) decodeData(b []byte, tid uint16, exporter string, domain uint32, now time.Time, clk ieClock, out *[]Record) (templateMisses int) {
	tmpl, ok := d.templates.get(templateKey{exporter, domain, tid})
	if !ok {
		return 1
	}
	exporterRate := d.sampling.get(exporter, domain)
	off := 0
	for len(*out) < ipfixMaxRecordsPerPacket {
		// A record needs at least 1 byte per field remaining; the per-field
		// reads below bound-check precisely. Stop on residual padding.
		if minW := tmpl.fixedWidth(); minW > 0 && off+minW > len(b) {
			break
		}
		if off >= len(b) || len(b)-off < len(tmpl.Fields) {
			break
		}
		rec := Record{
			Exporter:          exporter,
			ObservationDomain: domain,
			Protocol:          ProtoIPFIX,
			ObservedAt:        now,
			SamplingRate:      exporterRate,
		}
		var inline uint64
		bad := false
		for _, f := range tmpl.Fields {
			flen := int(f.Length)
			if f.Length == 0xFFFF { // variable length (RFC 7011 §7)
				if off >= len(b) {
					bad = true
					break
				}
				flen = int(b[off])
				off++
				if flen == 255 {
					if off+2 > len(b) {
						bad = true
						break
					}
					flen = int(binary.BigEndian.Uint16(b[off : off+2]))
					off += 2
				}
			}
			if off+flen > len(b) {
				bad = true
				break
			}
			val := b[off : off+flen]
			off += flen
			if f.Enterprise != 0 {
				continue // vendor-specific: skipped by length
			}
			if tmpl.Options {
				if rate := optionsSamplingRate(f.ID, val); rate > 0 {
					d.sampling.set(exporter, domain, rate)
					exporterRate = rate
				}
				continue
			}
			if r := applyIE(&rec, f.ID, val, clk); r > 0 {
				inline = r
			}
		}
		if bad {
			break
		}
		if tmpl.Options {
			continue
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
	return 0
}
