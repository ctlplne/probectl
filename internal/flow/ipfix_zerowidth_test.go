// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"testing"
	"time"
)

// TestIPFIXZeroWidthTemplateCannotWedgeOrAmplify (ING-02): an IPFIX template
// whose fields are all fixed length 0 consumes no bytes per data record. Before
// the fix the record loop never advanced the reader, so an options template
// (which never appends) spun a worker forever on one tiny datagram — about six
// packets wedge every flow listener — and a data template amplified a single
// byte into ipfixMaxRecordsPerPacket fabricated flows. NetFlow v9 already
// refuses zero-width templates; IPFIX must too. The decode must return promptly
// with zero records for both shapes.
func TestIPFIXZeroWidthTemplateCannotWedgeOrAmplify(t *testing.T) {
	cases := []struct {
		name  string
		setID uint16 // 3 = options template set, 2 = (regular) data template set
		tid   uint16
	}{
		{"options template would spin forever", 3, 256},
		{"data template would amplify one byte", 2, 257},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// One field, fixed length 0, no variable-length field (0xFFFF).
			tmpl := ipfixTemplateSet(tc.setID, tc.tid, 1, []ipfixField{{ID: ieProtocol, Len: 0}})
			data := ipfixDataSet(tc.tid, []byte{0x00})
			pkt := ipfixMsg(uint32(testTime.Unix()), 9, tmpl, data)

			d := NewDecoder(time.Hour, 128)
			type result struct {
				recs   []Record
				misses int
			}
			done := make(chan result, 1)
			start := time.Now()
			// Pre-fix this hangs, so run it off the test goroutine and fail on a
			// deadline instead of letting the whole suite time out at 10 minutes.
			go func() {
				recs, misses, _ := d.Decode(pkt, "198.51.100.7", testTime)
				done <- result{recs, misses}
			}()
			select {
			case r := <-done:
				if n := len(r.recs); n != 0 {
					t.Fatalf("zero-width %s yielded %d records, want 0 (amplification)", tc.name, n)
				}
				if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
					t.Fatalf("decode of a zero-width template took %v, want near-immediate", elapsed)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("IPFIX decode did not return within 2s: the zero-width %s wedged the record loop", tc.name)
			}
		})
	}
}

// TestIPFIXZeroWidthTemplateIsNotCached (ING-02): the malformed template is
// rejected at cache-store time, so it is never usable and its data set is a
// plain template miss — the fix is at the storage boundary, not a band-aid in
// one caller.
func TestIPFIXZeroWidthTemplateIsNotCached(t *testing.T) {
	d := NewDecoder(time.Hour, 128)
	tmpl := ipfixTemplateSet(3, 256, 1, []ipfixField{{ID: ieProtocol, Len: 0}})
	if _, _, err := d.Decode(ipfixMsg(uint32(testTime.Unix()), 9, tmpl), "198.51.100.7", testTime); err != nil {
		t.Fatalf("template set decode: %v", err)
	}
	if n := d.TemplateCount(); n != 0 {
		t.Fatalf("zero-width template was cached (%d templates), want 0", n)
	}
	// A data set referencing it is counted as a miss, never decoded.
	_, misses, err := d.Decode(ipfixMsg(uint32(testTime.Unix()), 9, ipfixDataSet(256, []byte{0x00})), "198.51.100.7", testTime)
	if err != nil {
		t.Fatalf("data set decode: %v", err)
	}
	if misses != 1 {
		t.Fatalf("data set for a rejected template: misses=%d, want 1", misses)
	}
}
