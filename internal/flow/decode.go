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

// Decoder turns raw exporter datagrams into normalized records, holding the
// v9/IPFIX template caches and per-exporter sampling state. One Decoder is
// shared by all listeners (templates are keyed by exporter + domain), and it
// is safe for concurrent use.
type Decoder struct {
	nf9   nf9Decoder
	ipfix ipfixDecoder
}

// NewDecoder builds a Decoder with bounded, TTL'd template state.
func NewDecoder(templateTTL time.Duration, maxTemplates int) *Decoder {
	tc := newTemplateCache(templateTTL, maxTemplates)
	ss := newSamplingState()
	return &Decoder{
		nf9:   nf9Decoder{templates: tc, sampling: ss},
		ipfix: ipfixDecoder{templates: tc, sampling: ss},
	}
}

// Decode dispatches on the datagram's wire format. NetFlow v5/v9 and IPFIX
// start with a 16-bit version (5, 9, 10); sFlow v5 starts with a 32-bit
// version whose first two bytes are zero — which makes sniffing unambiguous.
// templateMisses counts v9/IPFIX data sets dropped for a not-yet-seen template.
func (d *Decoder) Decode(pkt []byte, exporter string, now time.Time) (recs []Record, templateMisses int, err error) {
	if len(pkt) < 4 {
		return nil, 0, fmt.Errorf("flow: datagram too short: %d bytes", len(pkt))
	}
	switch binary.BigEndian.Uint16(pkt[0:2]) {
	case 5:
		recs, err = decodeNetFlow5(pkt, exporter, now)
		return recs, 0, err
	case 9:
		return d.nf9.decode(pkt, exporter, now)
	case 10:
		return d.ipfix.decode(pkt, exporter, now)
	case 0: // 32-bit version field: sFlow
		if binary.BigEndian.Uint32(pkt[0:4]) == 5 {
			recs, err = decodeSFlow(pkt, exporter, now)
			return recs, 0, err
		}
	}
	return nil, 0, fmt.Errorf("flow: unrecognized datagram (first bytes %x)", pkt[:4])
}

// TemplateCount reports cached v9/IPFIX templates (stats/tests).
func (d *Decoder) TemplateCount() int { return d.nf9.templates.len() }
