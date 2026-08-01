// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bgp

import (
	"bytes"
	"testing"
)

// FuzzBMPFraming drives the BMP wire framing (readBMPMessage) with arbitrary
// bytes: a router session is untrusted input, and the framing decides how many
// bytes the rest of the decoder is handed. It must never panic and never
// return a payload longer than the frame claimed (Foundation-Loop S-7f81b4c2).
func FuzzBMPFraming(f *testing.F) {
	// A well-formed route-monitoring frame: version 3, length, type 0.
	f.Add([]byte{0x03, 0x00, 0x00, 0x00, 0x06, 0x00})
	f.Add([]byte{0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0x00}) // absurd length
	f.Add([]byte{0x03, 0x00, 0x00, 0x00, 0x05})       // length under the header
	f.Add([]byte{0x04, 0x00, 0x00, 0x00, 0x06, 0x00}) // wrong version
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		typ, payload, err := readBMPMessage(bytes.NewReader(data))
		if err != nil {
			return
		}
		if len(payload) > len(data) {
			t.Fatalf("framing returned %d payload bytes from a %d-byte stream (type %d)",
				len(payload), len(data), typ)
		}
	})
}

// FuzzBMPRouteMonitoring drives the per-message decode path — the BGP UPDATE
// parser, its NLRI walk and the AS_PATH segment decoder — with arbitrary
// payloads. Everything below it now reads through internal/wire; this proves
// the composition never panics and never invents an unbounded path.
func FuzzBMPRouteMonitoring(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xFF}, 64))
	// AS_PATH attribute shapes: 2-byte and 4-byte ASNs, and a lying count.
	f.Add([]byte{0x40, 0x02, 0x06, 0x02, 0x02, 0xFD, 0xE8, 0xFD, 0xE9})
	f.Add([]byte{0x40, 0x02, 0x0A, 0x02, 0x02, 0x00, 0x00, 0xFD, 0xE8, 0x00, 0x00, 0xFD, 0xE9})
	f.Add([]byte{0x40, 0x02, 0x04, 0x02, 0xFF, 0x00, 0x01})

	f.Fuzz(func(t *testing.T, payload []byte) {
		obs, err := parseBMPRouteMonitoring(payload)
		if err != nil {
			return
		}
		for _, r := range obs.routes {
			if len(r.ASPath) > maxBMPASPathEntries {
				t.Fatalf("AS_PATH of %d entries exceeds the %d ceiling", len(r.ASPath), maxBMPASPathEntries)
			}
		}
	})
}

// FuzzBGPASPath isolates the AS_PATH attribute decoder, the parser the
// assessment named as having the weakest bounds discipline.
func FuzzBGPASPath(f *testing.F) {
	f.Add([]byte{0x40, 0x02, 0x06, 0x02, 0x02, 0xFD, 0xE8, 0xFD, 0xE9})
	f.Add([]byte{0x40, 0x02, 0x00})
	f.Add([]byte{0x02, 0x7F})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, attrs []byte) {
		path, err := parseBGPASPath(attrs)
		if err != nil {
			return
		}
		if len(path) > maxBMPASPathEntries {
			t.Fatalf("AS_PATH of %d entries exceeds the %d ceiling", len(path), maxBMPASPathEntries)
		}
	})
}
