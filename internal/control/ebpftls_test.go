// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/ctlplne/probectl/internal/threat"
)

func TestEBPFTLSPostureIsTenantScopedAndHonest(t *testing.T) {
	_, der, err := crypto.GenerateTestCert(crypto.TestCertOptions{
		CommonName: "api.example", DNSNames: []string{"api.example"}, NotAfter: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	postures := threat.NewPostureStore(0)
	consumer := NewEBPFTLSPostureConsumer(nil, postures, buildTLSAnalyzer(&config.Config{}), intelTestLog()).
		WithTenantBinding(ndrFakeBinding{"agent-a": "tenant-a"})
	now := time.Now().UTC().Truncate(time.Second)
	batch := &ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{
		{
			TenantId: "tenant-a", AgentId: "agent-a", Destination: "10.0.0.8", DestinationPort: 443,
			Method: "GET", Resource: "/private/customer/42", TlsVisibility: "observed",
			TlsVersion: "1.3", TlsCipher: "TLS_AES_128_GCM_SHA256", TlsServerName: "api.example",
			TlsPeerCertificateDer: der, TlsVerification: "verified", TlsObservationSource: "fixture",
			TlsHandshakeUnixNano: now.UnixNano(), TlsConfidence: 94,
		},
		{
			TenantId: "tenant-a", AgentId: "agent-a", Destination: "10.0.0.9", DestinationPort: 443,
			TlsVisibility: "encrypted_unknown", TlsObservationSource: "uprobe",
			TlsHandshakeUnixNano: now.UnixNano(),
		},
		{
			TenantId: "tenant-a", AgentId: "agent-a", Destination: "10.0.0.10", DestinationPort: 8443,
			TlsVisibility: "sidecar_unknown", TlsObservationSource: "sidecar",
			TlsHandshakeUnixNano: now.UnixNano(),
		},
	}}
	if err := consumer.handle(context.Background(), mustEBPFTLSMessage(t, batch)); err != nil {
		t.Fatal(err)
	}
	if got := postures.Len("tenant-a"); got != 3 {
		t.Fatalf("tenant-a posture count = %d, want 3", got)
	}
	if got := postures.Len("tenant-b"); got != 0 {
		t.Fatalf("cross-tenant posture count = %d", got)
	}

	observed := findTLSPosture(t, postures.List("tenant-a"), "api.example:443")
	if observed.State != threat.PostureObserved || observed.Source != "ebpf" || observed.Capture != "fixture" ||
		observed.Visibility != "observed" || observed.Confidence != 94 || observed.TLSVersion != "1.3" || observed.Leaf == nil {
		t.Fatalf("observed posture = %+v", observed)
	}
	unknown := findTLSPosture(t, postures.List("tenant-a"), "10.0.0.9:443")
	if unknown.State != threat.PostureUnknown || unknown.Visibility != "encrypted_unknown" || unknown.TLSVersion != "" || unknown.Leaf != nil {
		t.Fatalf("encrypted visibility must remain unknown: %+v", unknown)
	}
	sidecar := findTLSPosture(t, postures.List("tenant-a"), "10.0.0.10:8443")
	if sidecar.State != threat.PostureUnknown || sidecar.Visibility != "sidecar_unknown" {
		t.Fatalf("sidecar visibility must remain unknown: %+v", sidecar)
	}

	encoded, err := json.Marshal(observed)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte("/private/customer/42"), []byte("GET")} {
		if bytes.Contains(encoded, forbidden) {
			t.Fatalf("TLS posture retained application payload %q: %s", forbidden, encoded)
		}
	}
}

func TestEBPFTLSPostureMalformedAndWrongTenantMutateNothing(t *testing.T) {
	postures := threat.NewPostureStore(0)
	consumer := NewEBPFTLSPostureConsumer(nil, postures, buildTLSAnalyzer(&config.Config{}), intelTestLog()).
		WithTenantBinding(ndrFakeBinding{"agent-a": "tenant-a"})
	now := time.Now().UnixNano()
	valid := &ebpfv1.L7Call{
		TenantId: "tenant-a", AgentId: "agent-a", Destination: "10.0.0.1", DestinationPort: 443,
		TlsVisibility: "observed", TlsVersion: "1.3", TlsConfidence: 90,
		TlsVerification: "unknown", TlsObservationSource: "fixture", TlsHandshakeUnixNano: now,
	}
	invalid := proto.Clone(valid).(*ebpfv1.L7Call)
	invalid.Destination = "10.0.0.2"
	invalid.TlsPeerCertificateDer = []byte("not a certificate")
	if err := consumer.handle(context.Background(), mustEBPFTLSMessage(t, &ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{valid, invalid}})); err != nil {
		t.Fatal(err)
	}
	if got := postures.Len("tenant-a"); got != 0 {
		t.Fatalf("malformed mixed batch partially mutated %d postures", got)
	}

	wrong := proto.Clone(valid).(*ebpfv1.L7Call)
	wrong.TenantId = "tenant-victim"
	if err := consumer.handle(context.Background(), mustEBPFTLSMessage(t, &ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{wrong}})); err != nil {
		t.Fatal(err)
	}
	if postures.Len("tenant-a") != 0 || postures.Len("tenant-victim") != 0 {
		t.Fatal("wrong-tenant eBPF TLS batch mutated posture")
	}

	if err := consumer.handle(context.Background(), bus.Message{Value: []byte{0xff, 0x01}}); err != nil {
		t.Fatal(err)
	}
	if postures.Len("tenant-a") != 0 {
		t.Fatal("malformed protobuf mutated posture")
	}
}

func mustEBPFTLSMessage(t *testing.T, batch *ebpfv1.FlowBatch) bus.Message {
	t.Helper()
	raw, err := proto.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	return bus.Message{Value: raw}
}

func findTLSPosture(t *testing.T, postures []threat.Posture, target string) threat.Posture {
	t.Helper()
	for _, posture := range postures {
		if posture.Target == target {
			return posture
		}
	}
	t.Fatalf("posture %q not found: %+v", target, postures)
	return threat.Posture{}
}

// DPR-196: the live C-library uprobe has no 5-tuple, so every L7 call it emits
// carries no destination (internal/ebpf/l7chunk.go sets Destination: Endpoint{}).
// The posture consumer rejected the WHOLE batch on the first such record, which
// meant the eBPF plane put nothing at all in the TLS inventory: four hours of
// soak, 17,690 L7 calls captured, and the tenant's /v1/tls/posture held two
// entries, both from the HTTP synthetic. The only signal was 6,086 identical
// WARN lines saying "malformed metadata batch" and naming the agent id — the one
// field that was fine.
func TestEBPFTLSPostureKeepsRecordsAroundTheKnownUprobeGap(t *testing.T) {
	postures := threat.NewPostureStore(0)
	consumer := NewEBPFTLSPostureConsumer(nil, postures, buildTLSAnalyzer(&config.Config{}), intelTestLog()).
		WithTenantBinding(ndrFakeBinding{"agent-a": "tenant-a"})
	now := time.Now().UnixNano()
	usable := &ebpfv1.L7Call{
		TenantId: "tenant-a", AgentId: "agent-a", Destination: "10.0.0.1", DestinationPort: 443,
		TlsVisibility: "observed", TlsVersion: "1.3", TlsConfidence: 90,
		TlsVerification: "unknown", TlsObservationSource: "uprobe", TlsHandshakeUnixNano: now,
	}
	// What the live uprobe actually emits: it can prove the bytes were encrypted
	// and nothing else, and it has no socket peer to name.
	uprobe := &ebpfv1.L7Call{
		TenantId: "tenant-a", AgentId: "agent-a",
		TlsVisibility: "encrypted_unknown", TlsObservationSource: "uprobe", TlsHandshakeUnixNano: now,
	}
	if err := consumer.handle(context.Background(),
		mustEBPFTLSMessage(t, &ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{uprobe, usable}})); err != nil {
		t.Fatal(err)
	}
	if got := postures.Len("tenant-a"); got != 1 {
		t.Fatalf("posture count = %d, want 1 — the destination-less record must not take the usable one with it", got)
	}
	findTLSPosture(t, postures.List("tenant-a"), "10.0.0.1:443")

	// And the skip is counted under its own name, so an operator sees a number
	// for a known gap rather than a wall of "malformed".
	totals := consumer.skippedTotals()
	if totals[tlsSkipNoTarget] != 1 {
		t.Errorf("skipped totals = %v, want one %s", totals, tlsSkipNoTarget)
	}
	if len(totals) != 1 {
		t.Errorf("no other reason should have fired: %v", totals)
	}
}

// A value a correct producer never emits is still evidence about the producer,
// and still refuses the batch (§7.10). What changed is that the refusal names
// which property failed instead of saying "malformed".
func TestEBPFTLSPostureStillRefusesABatchWithAnImpossibleValue(t *testing.T) {
	now := time.Now().UnixNano()
	base := &ebpfv1.L7Call{
		TenantId: "tenant-a", AgentId: "agent-a", Destination: "10.0.0.1", DestinationPort: 443,
		TlsVisibility: "observed", TlsVersion: "1.3", TlsConfidence: 90,
		TlsVerification: "unknown", TlsObservationSource: "fixture", TlsHandshakeUnixNano: now,
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ebpfv1.L7Call)
		want   string
	}{
		{"unparseable certificate", func(c *ebpfv1.L7Call) { c.TlsPeerCertificateDer = []byte("not a certificate") }, tlsSkipBadCertificate},
		{"confidence out of range", func(c *ebpfv1.L7Call) { c.TlsConfidence = 250 }, tlsSkipBadConfidence},
		{"visibility that does not exist", func(c *ebpfv1.L7Call) { c.TlsVisibility = "definitely_fine" }, tlsSkipUnknownVisibility},
		{"verification that does not exist", func(c *ebpfv1.L7Call) { c.TlsVerification = "probably" }, tlsSkipBadVerification},
		{"observed with no version", func(c *ebpfv1.L7Call) { c.TlsVersion = "" }, tlsSkipNoVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			postures := threat.NewPostureStore(0)
			consumer := NewEBPFTLSPostureConsumer(nil, postures, buildTLSAnalyzer(&config.Config{}), intelTestLog()).
				WithTenantBinding(ndrFakeBinding{"agent-a": "tenant-a"})
			good := proto.Clone(base).(*ebpfv1.L7Call)
			bad := proto.Clone(base).(*ebpfv1.L7Call)
			bad.Destination = "10.0.0.2"
			tc.mutate(bad)
			if err := consumer.handle(context.Background(),
				mustEBPFTLSMessage(t, &ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{good, bad}})); err != nil {
				t.Fatal(err)
			}
			if got := postures.Len("tenant-a"); got != 0 {
				t.Errorf("a batch carrying an impossible value must mutate nothing, got %d postures", got)
			}
			if totals := consumer.skippedTotals(); totals[tc.want] == 0 {
				t.Errorf("the refusal must be counted under %s, got %v", tc.want, totals)
			}
		})
	}
}

// The summary is rate-limited per replica, because the whole point was that one
// known gap produced 6,086 log lines in four hours.
func TestEBPFTLSPostureSkipSummaryIsRateLimited(t *testing.T) {
	var buf bytes.Buffer
	postures := threat.NewPostureStore(0)
	consumer := NewEBPFTLSPostureConsumer(nil, postures, buildTLSAnalyzer(&config.Config{}),
		slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))).
		WithTenantBinding(ndrFakeBinding{"agent-a": "tenant-a"})
	clock := time.Now()
	consumer.nowFn = func() time.Time { return clock }

	uprobe := &ebpfv1.L7Call{
		TenantId: "tenant-a", AgentId: "agent-a",
		TlsVisibility: "encrypted_unknown", TlsObservationSource: "uprobe",
		TlsHandshakeUnixNano: clock.UnixNano(),
	}
	for i := 0; i < 40; i++ {
		if err := consumer.handle(context.Background(),
			mustEBPFTLSMessage(t, &ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{uprobe}})); err != nil {
			t.Fatal(err)
		}
	}
	lines := bytes.Count(buf.Bytes(), []byte("ebpf tls posture:"))
	if lines != 1 {
		t.Errorf("40 batches produced %d log lines, want 1 — this is the spam the fix exists to stop", lines)
	}
	if totals := consumer.skippedTotals(); totals[tlsSkipNoTarget] != 40 {
		t.Errorf("every skip must still be counted: %v", totals)
	}
	// The one line must say the agent is fine, not that the data is malformed.
	out := buf.String()
	if strings.Contains(out, "malformed") {
		t.Errorf("a documented structural gap must not be reported as malformed data: %s", out)
	}
	if !strings.Contains(out, "nothing is wrong with the agent") {
		t.Errorf("the summary must say the agent is not at fault: %s", out)
	}

	// Past the interval it reports again, with the running total.
	clock = clock.Add(11 * time.Minute)
	if err := consumer.handle(context.Background(),
		mustEBPFTLSMessage(t, &ebpfv1.FlowBatch{L7Calls: []*ebpfv1.L7Call{uprobe}})); err != nil {
		t.Fatal(err)
	}
	if lines := bytes.Count(buf.Bytes(), []byte("ebpf tls posture:")); lines != 2 {
		t.Errorf("after the interval it must report again, got %d lines", lines)
	}
}
