package path

import (
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// TestParseTimeExceededWithMPLS round-trips a Time Exceeded carrying an MPLS
// label stack (RFC 4950) that quotes one of our Paris probes, and asserts both
// the MPLS detection and the TTL/flow matching.
func TestParseTimeExceededWithMPLS(t *testing.T) {
	probe := craftParisEcho(0x1234, 5, 0xabcd, 40)

	// Quote the probe behind a minimal IPv4 header, as a router would.
	quoted := make([]byte, 20, 28)
	quoted[0] = 0x45 // version 4, IHL 5
	quoted = append(quoted, probe[:8]...)

	msg := icmp.Message{
		Type: ipv4.ICMPTypeTimeExceeded,
		Code: 0,
		Body: &icmp.TimeExceeded{
			Data: quoted,
			Extensions: []icmp.Extension{
				&icmp.MPLSLabelStack{
					Class:  1, // MPLS Label Stack class
					Type:   1,
					Labels: []icmp.MPLSLabel{{Label: 100, TC: 4, S: false, TTL: 1}, {Label: 200, TC: 0, S: true, TTL: 2}},
				},
			},
		},
	}
	raw, err := msg.Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, ok := parseICMPv4(raw)
	if !ok || resp.kind != respTimeExceeded {
		t.Fatalf("parse: ok=%v kind=%v", ok, resp.kind)
	}
	if resp.origID != 0x1234 || resp.origSeq != 5 || resp.origFlow != 0xabcd {
		t.Errorf("embedded probe = id %#x seq %d flow %#x", resp.origID, resp.origSeq, resp.origFlow)
	}
	if len(resp.mpls) != 2 {
		t.Fatalf("mpls labels = %d, want 2: %+v", len(resp.mpls), resp.mpls)
	}
	if resp.mpls[0].Label != 100 || resp.mpls[0].TC != 4 || resp.mpls[0].S {
		t.Errorf("label0 = %+v", resp.mpls[0])
	}
	if resp.mpls[1].Label != 200 || !resp.mpls[1].S || resp.mpls[1].TTL != 2 {
		t.Errorf("label1 = %+v", resp.mpls[1])
	}
}

func TestParseEchoReply(t *testing.T) {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Code: 0,
		Body: &icmp.Echo{ID: 0x4321, Seq: 9},
	}
	raw, err := msg.Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, ok := parseICMPv4(raw)
	if !ok || resp.kind != respEchoReply || resp.echoID != 0x4321 || resp.echoSeq != 9 {
		t.Fatalf("echo reply parse: ok=%v kind=%v id=%#x seq=%d", ok, resp.kind, resp.echoID, resp.echoSeq)
	}
}
