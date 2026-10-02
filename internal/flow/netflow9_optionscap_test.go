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

// nf9OptionFields builds n identical (type, length) option-field specs for a
// NetFlow v9 options template. The element id/length are irrelevant to template
// caching — only the declared field count matters here.
func nf9OptionFields(n int) [][2]uint16 {
	f := make([][2]uint16, n)
	for i := range f {
		f[i] = [2]uint16{ieProtocol, 1}
	}
	return f
}

// TestNetFlow9OptionsTemplateFieldCap is the ING-06 regression: NetFlow v9
// options-template parsing sized its field slice from the attacker-declared
// scope/option byte counts with no field-count cap, so a crafted template could
// declare up to a whole flowset of field specs, and a stream of distinct
// template IDs accreted unbounded collector heap in the template cache
// (~4096 datagrams retained ~512 MiB). The fix rejects any options template
// above 512 fields (docs/guardrails.md G7-12: untrusted ingest, fail closed).
func TestNetFlow9OptionsTemplateFieldCap(t *testing.T) {
	unix := uint32(testTime.Unix())

	// (a) An options template above 512 fields (1 scope + 512 option = 513) is
	// dropped, not cached — fed through the real v9 parse entry point.
	d := NewDecoder(time.Hour, 4096)
	oversized := buildNF9OptionsTemplate(0, unix, 7, 256,
		[][2]uint16{{1, 4}}, nf9OptionFields(512))
	if _, _, err := d.Decode(oversized, exporter, testTime); err != nil {
		t.Fatalf("oversized options template must be dropped quietly, not error the datagram: %v", err)
	}
	if got := d.TemplateCount(); got != 0 {
		t.Fatalf("options template with 513 fields was cached: TemplateCount=%d, want 0 (rejected)", got)
	}

	// (b) 4096 hostile datagrams, each a distinct template ID carrying an
	// oversized options template, retain a bounded, small amount of heap: none
	// are admitted to the cache, so it never grows regardless of the cap.
	const capTemplates = 256
	d = NewDecoder(time.Hour, capTemplates)
	for i := 0; i < 4096; i++ {
		tid := uint16(256 + i)
		pkt := buildNF9OptionsTemplate(0, unix, 7, tid,
			[][2]uint16{{1, 4}}, nf9OptionFields(512))
		if _, _, err := d.Decode(pkt, exporter, testTime); err != nil {
			t.Fatalf("hostile datagram %d errored the parse: %v", i, err)
		}
	}
	if got := d.TemplateCount(); got > capTemplates {
		t.Fatalf("template cache grew past its cap under hostile load: %d > %d", got, capTemplates)
	}
	if got := d.TemplateCount(); got != 0 {
		t.Fatalf("oversized options templates were retained: TemplateCount=%d, want 0", got)
	}

	// (c) Even with 512-field templates admitted, the cache stays bounded by its
	// cap: 4096 distinct VALID options templates evict down to the cap, never
	// growing without bound.
	d = NewDecoder(time.Hour, capTemplates)
	for i := 0; i < 4096; i++ {
		tid := uint16(256 + i)
		// 1 scope + 511 option = 512 fields: exactly the cap, must be admitted.
		pkt := buildNF9OptionsTemplate(0, unix, 7, tid,
			[][2]uint16{{1, 4}}, nf9OptionFields(511))
		if _, _, err := d.Decode(pkt, exporter, testTime); err != nil {
			t.Fatalf("valid datagram %d errored the parse: %v", i, err)
		}
	}
	if got := d.TemplateCount(); got > capTemplates {
		t.Fatalf("cache of valid templates grew past its cap: %d > %d", got, capTemplates)
	}
	if got := d.TemplateCount(); got == 0 {
		t.Fatalf("valid 512-field options templates were all rejected: TemplateCount=0 (over-rejection)")
	}
}
