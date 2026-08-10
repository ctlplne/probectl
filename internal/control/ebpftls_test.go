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
