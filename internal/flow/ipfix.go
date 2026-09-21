// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"fmt"
	"time"

	"github.com/ctlplne/probectl/internal/wire"
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
	r := wire.New(pkt)
	if v := r.U16(); v != 10 {
		return nil, 0, fmt.Errorf("ipfix: unexpected version %d", v)
	}
	msgLen := int(r.U16())
	if msgLen < ipfixHeaderLen || msgLen > len(pkt) {
		return nil, 0, fmt.Errorf("ipfix: bad message length %d (have %d)", msgLen, len(pkt))
	}
	exportSecs := r.U32()
	r.Skip(4)         // sequence number
	domain := r.U32() // observation domain
	if err := r.Err(); err != nil {
		return nil, 0, fmt.Errorf("ipfix: header: %w", err)
	}
	clk := ieClock{export: time.Unix(int64(exportSecs), 0)} // no sysUptime in IPFIX

	// The message length is authoritative over the datagram: sets are walked
	// inside a sub-reader bounded by it, and each set inside its own frame.
	msg := wire.New(pkt[ipfixHeaderLen:msgLen])
	for msg.Remaining() >= 4 {
		setOffset := ipfixHeaderLen + msg.Offset()
		setID := msg.U16()
		setLen := int(msg.U16())
		if setLen < 4 || setLen-4 > msg.Remaining() {
			return recs, templateMisses, fmt.Errorf("ipfix: bad set length %d at offset %d", setLen, setOffset)
		}
		body := msg.Bytes(setLen - 4)
		switch {
		case setID == 2:
			d.parseTemplates(body, exporter, domain, false)
		case setID == 3:
			d.parseTemplates(body, exporter, domain, true)
		case setID >= 256:
			miss := d.decodeData(body, setID, exporter, domain, now, clk, &recs)
			templateMisses += miss
		}
	}
	if err := msg.Err(); err != nil {
		return recs, templateMisses, fmt.Errorf("ipfix: %w", err)
	}
	return recs, templateMisses, nil
}

// parseTemplates parses (options-)template records. An IPFIX options template
// header is (templateID, fieldCount, scopeFieldCount); a regular template is
// (templateID, fieldCount). Field specs are (type[, enterprise], length) with
// the enterprise bit in the type's MSB.
func (d *ipfixDecoder) parseTemplates(b []byte, exporter string, domain uint32, options bool) {
	hdr := 4
	if options {
		hdr = 6
	}
	r := wire.New(b)
	for r.Remaining() >= hdr {
		tid := r.U16()
		fc := int(r.U16())
		scope := 0
		if options {
			scope = int(r.U16())
		}
		if tid < 256 || fc <= 0 || fc > 512 || scope < 0 || scope > fc {
			return
		}
		fields := make([]templateField, 0, fc)
		for i := 0; i < fc; i++ {
			if r.Remaining() < 4 {
				return
			}
			typ := r.U16()
			length := r.U16()
			f := templateField{ID: typ & 0x7FFF, Length: length}
			if typ&0x8000 != 0 { // enterprise-specific: 4-byte PEN follows
				if r.Remaining() < 4 {
					return
				}
				f.Enterprise = r.U32()
			}
			fields = append(fields, f)
		}
		if r.Err() != nil {
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
	set := wire.New(b)
	for len(*out) < ipfixMaxRecordsPerPacket {
		// A record needs at least 1 byte per field remaining; the per-field
		// reads below bound-check precisely. Stop on residual padding.
		if minW := tmpl.fixedWidth(); minW > 0 && set.Remaining() < minW {
			break
		}
		if set.Empty() || set.Remaining() < len(tmpl.Fields) {
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
				if set.Empty() {
					bad = true
					break
				}
				flen = int(set.U8())
				if flen == 255 {
					if set.Remaining() < 2 {
						bad = true
						break
					}
					flen = int(set.U16())
				}
			}
			if flen > set.Remaining() {
				bad = true
				break
			}
			val := set.Bytes(flen)
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
