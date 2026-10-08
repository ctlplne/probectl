// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	probectlc "github.com/ctlplne/probectl/internal/crypto"
)

// A strict-lane deployment (WIRE-001; mandatory for the multi-tenant and
// regulated profiles) refuses BGP events on the shared lane, so the BGP
// collectors publish on their tenant's own lane, probectl.t-<slug>.bgp.events
// (DPR-049). Before this they always routed through the isolation router, which
// gives a pooled tenant the shared lane — and in the out-of-process collectors
// no router is installed at all — so every BGP event was dropped there.

func TestPublishEventOnLaneUsesTheTenantLane(t *testing.T) {
	pub := &capturePublisher{}
	ev := Event{TenantID: "tenant-a", EventType: "possible_hijack", Severity: "critical", Confidence: 0.9,
		Prefix: "203.0.113.0/24", NewOriginASN: 64666, DetectedAtUnixNano: time.Now().UnixNano()}
	if err := PublishEventOnLane(context.Background(), pub, ev, "t-acme"); err != nil {
		t.Fatal(err)
	}
	msgs := waitCaptured(t, pub, 1)
	if msgs[0].topic != "probectl.t-acme.bgp.events" || tenantFromBGPKey(msgs[0].key) != "tenant-a" {
		t.Fatalf("published on %q keyed %q, want the tenant lane keyed by tenant-a", msgs[0].topic, msgs[0].key)
	}
	for _, bad := range []string{"", "  ", "BAD NS"} {
		if err := PublishEventOnLane(context.Background(), pub, ev, bad); err == nil {
			t.Fatalf("namespace %q must be refused, never fall back to the shared lane", bad)
		}
	}
	if n := len(pub.msgs); n != 1 {
		t.Fatalf("a refused lane published %d events", n-1)
	}
}

func TestBridgeWithBusNamespacePublishesOnTheTenantLane(t *testing.T) {
	pub := &capturePublisher{}
	line := `{"tenant_id":"tenant-a","event_type":"possible_hijack","severity":"critical","confidence":0.9,` +
		`"prefix":"203.0.113.0/24","new_origin_asn":64666,"detected_at_unix_nano":1700000000000000000}` + "\n"
	stats, err := NewBridge(pub, discardLogger()).WithExpectedTenant("tenant-a").WithBusNamespace("t-acme").
		Ingest(context.Background(), strings.NewReader(line))
	if err != nil || stats.Published != 1 {
		t.Fatalf("ingest = %+v, %v; want one published event", stats, err)
	}
	if topic := pub.msgs[0].topic; topic != "probectl.t-acme.bgp.events" {
		t.Fatalf("bridge published on %q, want the tenant lane", topic)
	}
}

// TestBMPLaneBoundListenerServesOnlyItsTenant: a listener bound to a tenant's
// lane publishes that tenant's routes on the lane and refuses another tenant's
// router after authentication, so one tenant's lane never carries another's
// routes (G7-1).
func TestBMPLaneBoundListenerServesOnlyItsTenant(t *testing.T) {
	ca, err := probectlc.GenerateCA("bmp-lane-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile := writePEM(t, dir, "ca.crt", ca.CertPEM())
	serverCert, serverKey, err := ca.IssueServerCert("bmp-listener", []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg, err := probectlc.ServerBMPMTLSConfig(writePEM(t, dir, "server.crt", serverCert), writePEM(t, dir, "server.key", serverKey), caFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	pub := &capturePublisher{}
	listener := NewBMPListener(ln, pub, "bmp-test", discardLogger(),
		WithBMPIssuedIdentityVerifier(allowBMPIdentity),
		WithBMPTenantLane("tenant-a", "t-acme"))
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- listener.Serve(ctx) }()

	// Tenant B's router authenticates but is refused by tenant A's listener.
	certPEM, keyPEM, err := ca.IssueClientCert("router-b", probectlc.BMPSPIFFEID("tenant-b", "router-b"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := probectlc.ClientMTLSConfig(writePEM(t, dir, "router-b.crt", certPEM), writePEM(t, dir, "router-b.key", keyPEM), caFile)
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg); err == nil {
		_, _ = conn.Write(buildBMPRouteMonitoring(64512, "192.0.2.12", []uint32{64512, 64501}, "198.51.100.0/24", time.Now()))
		_ = conn.Close()
	}
	sendBMPMessage(t, ca, caFile, dir, ln.Addr().String(), "tenant-a", "router-a",
		buildBMPRouteMonitoring(64511, "192.0.2.11", []uint32{64511, 64500}, "203.0.113.0/24", time.Now()))

	msgs := waitCaptured(t, pub, 1)
	time.Sleep(100 * time.Millisecond) // a wrongly admitted tenant-B session would have published by now
	pub.mu.Lock()
	n := len(pub.msgs)
	pub.mu.Unlock()
	if n != 1 || msgs[0].topic != "probectl.t-acme.bgp.events" || tenantFromBGPKey(msgs[0].key) != "tenant-a" {
		t.Fatalf("lane-bound listener published %d events (first on %q keyed %q), want only tenant-a's on its lane", n, msgs[0].topic, msgs[0].key)
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("serve returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not stop")
	}
}

func TestBMPTenantLaneNeedsBothHalvesAndAValidNamespace(t *testing.T) {
	for _, tc := range []struct{ tenant, namespace string }{
		{"tenant-a", ""}, {"", "t-acme"}, {"tenant-a", "BAD NS"},
	} {
		ln, err := net.Listen("tcp", "127.0.0.1:0") // Serve refuses before it accepts anything
		if err != nil {
			t.Fatal(err)
		}
		err = NewBMPListener(ln, &capturePublisher{}, "bmp-test", discardLogger(),
			WithBMPIssuedIdentityVerifier(allowBMPIdentity), WithBMPTenantLane(tc.tenant, tc.namespace)).Serve(context.Background())
		_ = ln.Close()
		if err == nil {
			t.Fatalf("tenant lane %q/%q must refuse to serve", tc.tenant, tc.namespace)
		}
	}
}
