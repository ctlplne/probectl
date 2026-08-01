// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flow

import (
	"fmt"
	"time"

	"github.com/ctlplne/probectl/internal/wire"
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
	r := wire.New(pkt)
	if v := r.U16(); v != 9 {
		return nil, 0, fmt.Errorf("netflow9: unexpected version %d", v)
	}
	r.Skip(2) // record count (advisory; the flowset walk is authoritative)
	sysUptimeMS := r.U32()
	unixSecs := r.U32()
	r.Skip(4)         // sequence number
	domain := r.U32() // source ID
	if err := r.Err(); err != nil {
		return nil, 0, fmt.Errorf("netflow9: header: %w", err)
	}

	export := time.Unix(int64(unixSecs), 0)
	clk := ieClock{boot: export.Add(-time.Duration(sysUptimeMS) * time.Millisecond), export: export}

	// Each flowset is consumed through its OWN length-delimited sub-reader, so
	// a lying set length can never reach past its own frame.
	for r.Remaining() >= 4 {
		setOffset := r.Offset()
		setID := r.U16()
		setLen := int(r.U16())
		if setLen < 4 || setLen-4 > r.Remaining() {
			return recs, templateMisses, fmt.Errorf("netflow9: bad flowset length %d at offset %d", setLen, setOffset)
		}
		body := r.Bytes(setLen - 4)
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
	}
	if err := r.Err(); err != nil {
		return recs, templateMisses, fmt.Errorf("netflow9: %w", err)
	}
	return recs, templateMisses, nil
}

// parseTemplates parses a template flowset: repeated (templateID, fieldCount,
// fieldCount x (type, length)).
func (d *nf9Decoder) parseTemplates(b []byte, exporter string, domain uint32, _ bool) {
	r := wire.New(b)
	for r.Remaining() >= 4 {
		tid := r.U16()
		fc := int(r.U16())
		if tid < 256 || fc <= 0 || fc > 512 || fc*4 > r.Remaining() {
			return // malformed remainder — stop, keep what we have
		}
		fields := make([]templateField, 0, fc)
		for i := 0; i < fc; i++ {
			fields = append(fields, templateField{ID: r.U16(), Length: r.U16()})
		}
		if r.Err() != nil {
			return
		}
		d.templates.put(templateKey{exporter, domain, tid}, templateRecord{Fields: fields})
	}
}

// parseOptionsTemplates parses an options-template flowset (RFC 3954 §6.2):
// (templateID, scopeLenBytes, optionLenBytes, scope fields…, option fields…).
func (d *nf9Decoder) parseOptionsTemplates(b []byte, exporter string, domain uint32) {
	r := wire.New(b)
	for r.Remaining() >= 6 {
		tid := r.U16()
		scopeBytes := int(r.U16())
		optionBytes := int(r.U16())
		if tid < 256 || scopeBytes < 0 || optionBytes < 0 || scopeBytes+optionBytes > r.Remaining() ||
			(scopeBytes+optionBytes) == 0 || (scopeBytes%4 != 0) || (optionBytes%4 != 0) {
			return
		}
		nScope, nOpt := scopeBytes/4, optionBytes/4
		fields := make([]templateField, 0, nScope+nOpt)
		for i := 0; i < nScope+nOpt; i++ {
			fields = append(fields, templateField{ID: r.U16(), Length: r.U16()})
		}
		if r.Err() != nil {
			return
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
	set := wire.New(b)
	// Each record, and each field within it, is a length-delimited sub-reader:
	// a template whose field lengths overrun the row can consume at most that
	// row, and never the next record's bytes.
	for set.Remaining() >= width && len(*out) < nf9MaxRecordsPerPacket {
		row := set.Sub(width)
		n++
		if tmpl.Options {
			for _, f := range tmpl.Fields {
				if rate := optionsSamplingRate(f.ID, row.Bytes(int(f.Length))); rate > 0 {
					d.sampling.set(exporter, domain, rate)
					exporterRate = rate
				}
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
		var inline uint64
		for _, f := range tmpl.Fields {
			if r := applyIE(&rec, f.ID, row.Bytes(int(f.Length)), clk); r > 0 {
				inline = r
			}
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
