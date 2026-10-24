// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/crypto"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/ctlplne/probectl/internal/l7redact"
	"github.com/ctlplne/probectl/internal/threat"
)

var testDNSKey = []byte("ndr-test-dns-token-key-not-secret")

// testDNSFeatures mirrors what the eBPF agent computes from a raw name.
func testDNSFeatures(raw string) *ebpfv1.DNSFeatures {
	first := raw
	if i := strings.IndexByte(raw, '.'); i > 0 {
		first = raw[:i]
	}
	var freq [256]int
	for i := 0; i < len(first); i++ {
		freq[first[i]]++
	}
	var h float64
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / float64(len(first))
			h -= p * math.Log2(p)
		}
	}
	f := &ebpfv1.DNSFeatures{FirstLabelEntropy: h, FirstLabelLength: uint32(len(first)), QnameBytes: uint32(len(raw)),
		NameToken: crypto.Default.Sign(testDNSKey, []byte("n:"+raw))[:8]}
	if d := l7redact.RegisteredDomain(raw); d != "" && len(d) < len(raw) {
		f.SubdomainToken = crypto.Default.Sign(testDNSKey, []byte("s:"+raw[:len(raw)-len(d)-1]))[:8]
	}
	return f
}

// D-65: the stored DNS name loses its identifiers (templated, or only the
// registered domain under the regulated profile), and the DGA and tunneling
// detectors still fire — they score on the raw name's in-agent features. The
// summaries quote the stored form only.
func TestNDRDetectorsFireFromInAgentFeatures(t *testing.T) {
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		regulated bool
	}{{"default profile: templated names", false}, {"regulated profile: registered domain only", true}} {
		t.Run(tc.name, func(t *testing.T) {
			detections := threat.NewDetectionStore(0)
			cs := NewNDRConsumer(nil, ndrEngine(t, nil), nil, intelTestLog()).withDetections(detections).
				WithL7IngestStrip(newL7IngestStrip(nil, tc.regulated, nil))
			var calls []*ebpfv1.L7Call
			var raws []string
			for i := 0; i < 40; i++ {
				dga := fmt.Sprintf("xq%dk7vz0my%dwt3hjb%dfp8c.evil-rendezvous.example", i*7+13, i*31+5, i*17+3)
				tunnel := fmt.Sprintf("%s.%s.exfil.example.net", strings.Repeat(fmt.Sprintf("a%04x", i*977), 8), strings.Repeat("b", 50))
				raws = append(raws, dga, tunnel)
				for _, n := range []string{dga, tunnel} {
					calls = append(calls, &ebpfv1.L7Call{TenantId: "t1", Source: "host-7", Protocol: "dns", Method: "A",
						Resource: n, StartUnixNano: at.Add(time.Duration(i) * time.Second).UnixNano(), DnsFeatures: testDNSFeatures(n)})
				}
			}
			raw, _ := proto.Marshal(&ebpfv1.FlowBatch{L7Calls: calls})
			if err := cs.handleEBPFBatch(context.Background(), bus.Message{Value: raw}); err != nil {
				t.Fatal(err)
			}
			kinds := map[string]bool{}
			for _, d := range detections.List("t1") {
				kinds[d.Kind] = true
				for _, r := range raws {
					if strings.Contains(d.Summary, r) || strings.Contains(fmt.Sprint(d), r) {
						t.Fatalf("a detection quotes a raw name: %+v", d)
					}
				}
				if tc.regulated && strings.Contains(d.Summary, "{id}") {
					t.Fatalf("regulated detection quotes more than the registered domain: %q", d.Summary)
				}
			}
			if !kinds["ndr.dns_dga"] || !kinds["ndr.dns_exfil"] {
				t.Fatalf("detectors lost their signal: kinds=%v", kinds)
			}
		})
	}
}
