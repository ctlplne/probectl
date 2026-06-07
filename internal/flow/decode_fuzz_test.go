package flow

import (
	"testing"
	"time"
)

// FuzzDecode (U-082): flow datagrams arrive over UDP from exporters — fully
// untrusted bytes. The decoder must never panic, whatever the input: short
// packets, lying header counts, truncated templates, hostile field lengths.
// All four wire formats share the one entry point (NetFlow v5/v9, IPFIX,
// sFlow), so a single target covers every dispatch path.
func FuzzDecode(f *testing.F) {
	// Version-dispatch seeds: v5, v9, IPFIX (10), sFlow (32-bit 5), junk.
	f.Add([]byte{0x00, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0x00, 0x09, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0x00, 0x0a, 0x00, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0x00, 0x00, 0x00, 0x05, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0})
	// v9 template flowset header (id 0) with a hostile field count.
	f.Add([]byte{0x00, 0x09, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0x00, 0x00, 0x00, 0x0c, 0x01, 0x00, 0xff, 0xff})
	f.Add([]byte{})
	f.Add([]byte{0xff})

	now := time.Unix(1750000000, 0)
	f.Fuzz(func(t *testing.T, pkt []byte) {
		d := NewDecoder(time.Minute, 64)
		recs, _, _ := d.Decode(pkt, "203.0.113.9", now)
		// Whatever came back must be safely iterable (no torn records).
		for i := range recs {
			_ = recs[i].SrcAddr
			_ = recs[i].DstAddr
		}
		// A second datagram against the same decoder exercises template reuse.
		_, _, _ = d.Decode(pkt, "203.0.113.9", now)
	})
}
