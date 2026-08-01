// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bgp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	probectlc "github.com/ctlplne/probectl/internal/crypto"
	bgpv1 "github.com/ctlplne/probectl/internal/gen/probectl/bgp/v1"
)

func TestBMPListenerPartitionsTenantScopedPeers(t *testing.T) {
	ca, err := probectlc.GenerateCA("bmp-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile := writePEM(t, dir, "ca.crt", ca.CertPEM())
	serverCert, serverKey, err := ca.IssueServerCert("bmp-listener", []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCertFile := writePEM(t, dir, "server.crt", serverCert)
	serverKeyFile := writePEM(t, dir, "server.key", serverKey)
	serverCfg, err := probectlc.ServerBMPMTLSConfig(serverCertFile, serverKeyFile, caFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}

	pub := &capturePublisher{}
	inv := NewBMPPeerInventory()
	listener := NewBMPListener(
		ln,
		pub,
		"bmp-test",
		discardLogger(),
		withBMPPeerInventory(inv),
		WithBMPIssuedIdentityVerifier(allowBMPIdentity),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- listener.Serve(ctx) }()

	seenAt := time.Unix(1_700_000_000, 123_456_000)
	sendBMPMessage(t, ca, caFile, dir, ln.Addr().String(), "tenant-a", "router-a",
		buildBMPRouteMonitoring(64511, "192.0.2.11", []uint32{64511, 64500}, "203.0.113.0/24", seenAt))
	sendBMPMessage(t, ca, caFile, dir, ln.Addr().String(), "tenant-b", "router-b",
		buildBMPRouteMonitoring(64512, "192.0.2.12", []uint32{64512, 64501}, "198.51.100.0/24", seenAt.Add(time.Second)))

	msgs := waitCaptured(t, pub, 2)
	byTenant := map[string]*bgpv1.BGPEvent{}
	for _, msg := range msgs {
		if msg.topic != bus.BGPEventsTopic {
			t.Fatalf("topic = %q, want %q", msg.topic, bus.BGPEventsTopic)
		}
		var ev bgpv1.BGPEvent
		if err := proto.Unmarshal(msg.value, &ev); err != nil {
			t.Fatalf("unmarshal bgp event: %v", err)
		}
		if tenantFromBGPKey(msg.key) != ev.GetTenantId() {
			t.Fatalf("bus key %q does not preserve tenant prefix %q", msg.key, ev.GetTenantId())
		}
		if string(msg.key) == ev.GetTenantId() {
			t.Fatalf("bus key %q is raw tenant id; want tenant-bucketed key", msg.key)
		}
		byTenant[ev.GetTenantId()] = &ev
	}
	if got := byTenant["tenant-a"]; got == nil || got.GetPrefix() != "203.0.113.0/24" || got.GetNewOriginAsn() != 64500 {
		t.Fatalf("tenant-a event = %+v, want its own prefix/origin", got)
	}
	if got := byTenant["tenant-b"]; got == nil || got.GetPrefix() != "198.51.100.0/24" || got.GetNewOriginAsn() != 64501 {
		t.Fatalf("tenant-b event = %+v, want its own prefix/origin", got)
	}
	if byTenant["tenant-a"].GetPrefix() == byTenant["tenant-b"].GetPrefix() {
		t.Fatal("tenant route events collapsed onto one prefix")
	}

	peers := inv.snapshot()
	if len(peers) != 2 {
		t.Fatalf("inventory size = %d, want 2: %+v", len(peers), peers)
	}
	if peers[0].TenantID != "tenant-a" || peers[0].AgentID != "router-a" || peers[0].PeerASN != 64511 ||
		peers[0].RouteAnnouncements != 1 {
		t.Fatalf("peer[0] = %+v, want tenant-a/router-a/AS64511", peers[0])
	}
	if peers[1].TenantID != "tenant-b" || peers[1].AgentID != "router-b" || peers[1].PeerASN != 64512 ||
		peers[1].RouteAnnouncements != 1 {
		t.Fatalf("peer[1] = %+v, want tenant-b/router-b/AS64512", peers[1])
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

func TestBMPListenerRefusesUnregisteredSelfIssuedRouter(t *testing.T) {
	ca, err := probectlc.GenerateCA("bmp-unregistered-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile := writePEM(t, dir, "ca.crt", ca.CertPEM())
	serverCert, serverKey, err := ca.IssueServerCert("bmp-listener", []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg, err := probectlc.ServerBMPMTLSConfig(
		writePEM(t, dir, "server.crt", serverCert),
		writePEM(t, dir, "server.key", serverKey),
		caFile,
	)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}

	pub := &capturePublisher{}
	listener := NewBMPListener(
		ln,
		pub,
		"bmp-test",
		discardLogger(),
		WithBMPIssuedIdentityVerifier(func(context.Context, string, string, string, string) (bool, error) {
			return false, nil
		}),
	)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- listener.Serve(ctx) }()

	// This certificate chains to the listener CA but was minted directly and
	// has no corresponding agent_identities row. The old listener trusted the
	// CA-shaped identity alone and therefore admitted it.
	certPEM, keyPEM, err := ca.IssueClientCert(
		"self-issued-router",
		probectlc.BMPSPIFFEID("tenant-a", "self-issued-router"),
		time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := probectlc.ClientMTLSConfig(
		writePEM(t, dir, "self-issued.crt", certPEM),
		writePEM(t, dir, "self-issued.key", keyPEM),
		caFile,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg.ServerName = "127.0.0.1"
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err == nil {
		_, _ = conn.Write(buildBMPRouteMonitoring(
			64511,
			"192.0.2.11",
			[]uint32{64511, 64500},
			"203.0.113.0/24",
			time.Now(),
		))
		_ = conn.Close()
	}

	time.Sleep(100 * time.Millisecond)
	pub.mu.Lock()
	published := len(pub.msgs)
	pub.mu.Unlock()
	if published != 0 {
		t.Fatalf("unregistered self-issued router published %d BMP events, want 0", published)
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

func TestBMPRegisteredRevokeRefusedTwoTenant(t *testing.T) {
	ca, err := probectlc.GenerateCA("bmp-revoke-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile := writePEM(t, dir, "ca.crt", ca.CertPEM())
	serverCert, serverKey, err := ca.IssueServerCert("bmp-listener", []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg, err := probectlc.ServerBMPMTLSConfig(
		writePEM(t, dir, "server.crt", serverCert),
		writePEM(t, dir, "server.key", serverKey),
		caFile,
	)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}

	type peerMaterial struct {
		certFile string
		keyFile  string
		spiffe   string
		serial   string
	}
	issue := func(tenantID, routerID string) peerMaterial {
		t.Helper()
		spiffe := probectlc.BMPSPIFFEID(tenantID, routerID)
		certPEM, keyPEM, err := ca.IssueClientCert(routerID, spiffe, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			t.Fatal("decode client certificate")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return peerMaterial{
			certFile: writePEM(t, dir, tenantID+"-"+routerID+".crt", certPEM),
			keyFile:  writePEM(t, dir, tenantID+"-"+routerID+".key", keyPEM),
			spiffe:   spiffe,
			serial:   leaf.SerialNumber.Text(16),
		}
	}
	peerA := issue("tenant-a", "router-a")
	peerB := issue("tenant-b", "router-b")
	issued := map[string]bool{
		"tenant-a|router-a|" + peerA.spiffe + "|" + peerA.serial: true,
		"tenant-b|router-b|" + peerB.spiffe + "|" + peerB.serial: true,
	}
	verifier := func(_ context.Context, tenantID, routerID, spiffeID, serial string) (bool, error) {
		return issued[tenantID+"|"+routerID+"|"+spiffeID+"|"+serial], nil
	}
	revocations := probectlc.NewRevocationList()
	pub := &capturePublisher{}
	listener := NewBMPListener(
		ln,
		pub,
		"bmp-test",
		discardLogger(),
		WithBMPIssuedIdentityVerifier(verifier),
		WithBMPRevocationList(revocations),
	)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- listener.Serve(ctx) }()

	sendBMPWithCertificate(
		t,
		caFile,
		ln.Addr().String(),
		peerA.certFile,
		peerA.keyFile,
		buildBMPRouteMonitoring(64511, "192.0.2.11", []uint32{64511}, "203.0.113.0/24", time.Now()),
	)
	_ = waitCaptured(t, pub, 1)

	revocations.RevokeID(peerA.spiffe)
	sendBMPWithCertificate(
		t,
		caFile,
		ln.Addr().String(),
		peerA.certFile,
		peerA.keyFile,
		buildBMPRouteMonitoring(64511, "192.0.2.11", []uint32{64511}, "203.0.114.0/24", time.Now()),
	)
	time.Sleep(100 * time.Millisecond)
	pub.mu.Lock()
	afterARevoke := len(pub.msgs)
	pub.mu.Unlock()
	if afterARevoke != 1 {
		t.Fatalf("revoked tenant-A router published again: messages=%d, want 1", afterARevoke)
	}

	sendBMPWithCertificate(
		t,
		caFile,
		ln.Addr().String(),
		peerB.certFile,
		peerB.keyFile,
		buildBMPRouteMonitoring(64512, "192.0.2.12", []uint32{64512}, "198.51.100.0/24", time.Now()),
	)
	_ = waitCaptured(t, pub, 2)

	revocations.RevokeSerial(peerB.serial)
	sendBMPWithCertificate(
		t,
		caFile,
		ln.Addr().String(),
		peerB.certFile,
		peerB.keyFile,
		buildBMPRouteMonitoring(64512, "192.0.2.12", []uint32{64512}, "198.51.101.0/24", time.Now()),
	)
	time.Sleep(100 * time.Millisecond)
	pub.mu.Lock()
	afterBSerialRevoke := len(pub.msgs)
	pub.mu.Unlock()
	if afterBSerialRevoke != 2 {
		t.Fatalf("serial-revoked tenant-B router published again: messages=%d, want 2", afterBSerialRevoke)
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

func TestBMPPeerIdentityRefusesPlaintext(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = server.Close() }()
	defer func() { _ = client.Close() }()
	_, err := bmpPeerIdentity(context.Background(), server)
	if !errors.Is(err, errPlaintextBMP) {
		t.Fatalf("error = %v, want errPlaintextBMP", err)
	}
}

func allowBMPIdentity(context.Context, string, string, string, string) (bool, error) {
	return true, nil
}

func sendBMPMessage(t *testing.T, ca *probectlc.CA, caFile, dir, addr, tenantID, agentID string, msg []byte) {
	t.Helper()
	certPEM, keyPEM, err := ca.IssueClientCert(agentID, probectlc.BMPSPIFFEID(tenantID, agentID), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certFile := writePEM(t, dir, agentID+".crt", certPEM)
	keyFile := writePEM(t, dir, agentID+".key", keyPEM)
	sendBMPWithCertificate(t, caFile, addr, certFile, keyFile, msg)
}

func sendBMPWithCertificate(t *testing.T, caFile, addr, certFile, keyFile string, msg []byte) {
	t.Helper()
	cfg, err := probectlc.ClientMTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
}

func waitCaptured(t *testing.T, pub *capturePublisher, want int) []capturedMsg {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pub.mu.Lock()
		if len(pub.msgs) >= want {
			out := append([]capturedMsg(nil), pub.msgs...)
			pub.mu.Unlock()
			return out
		}
		pub.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	pub.mu.Lock()
	defer pub.mu.Unlock()
	t.Fatalf("captured %d messages, want %d: %+v", len(pub.msgs), want, pub.msgs)
	return nil
}

func writePEM(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildBMPRouteMonitoring(peerASN uint32, peerAddr string, asPath []uint32, prefix string, ts time.Time) []byte {
	bgpUpdate := buildBGPUpdate(asPath, prefix)
	payload := make([]byte, bmpPeerHeaderLen+len(bgpUpdate))
	addr := netip.MustParseAddr(peerAddr).As4()
	copy(payload[22:26], addr[:])
	binary.BigEndian.PutUint32(payload[26:30], peerASN)
	binary.BigEndian.PutUint32(payload[34:38], uint32(ts.Unix()))
	binary.BigEndian.PutUint32(payload[38:42], uint32(ts.Nanosecond()/1000))
	copy(payload[bmpPeerHeaderLen:], bgpUpdate)

	msg := make([]byte, bmpCommonHeaderLen+len(payload))
	msg[0] = bmpVersion
	binary.BigEndian.PutUint32(msg[1:5], uint32(len(msg)))
	msg[5] = bmpRouteMonitoring
	copy(msg[bmpCommonHeaderLen:], payload)
	return msg
}

func buildBGPUpdate(asPath []uint32, prefix string) []byte {
	pathValue := []byte{2, byte(len(asPath))}
	for _, asn := range asPath {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], asn)
		pathValue = append(pathValue, b[:]...)
	}
	asPathAttr := []byte{0x40, bgpPathAttrASPath, byte(len(pathValue))}
	asPathAttr = append(asPathAttr, pathValue...)
	nlri := buildIPv4NLRI(prefix)

	body := make([]byte, 0, 4+len(asPathAttr)+len(nlri))
	body = append(body, 0, 0) // withdrawn-routes length
	var attrLen [2]byte
	binary.BigEndian.PutUint16(attrLen[:], uint16(len(asPathAttr)))
	body = append(body, attrLen[:]...)
	body = append(body, asPathAttr...)
	body = append(body, nlri...)

	msg := make([]byte, bgpHeaderLen+len(body))
	for i := 0; i < 16; i++ {
		msg[i] = 0xff
	}
	binary.BigEndian.PutUint16(msg[16:18], uint16(len(msg)))
	msg[18] = bgpMessageTypeUpdate
	copy(msg[bgpHeaderLen:], body)
	return msg
}

func buildIPv4NLRI(s string) []byte {
	prefix := netip.MustParsePrefix(s).Masked()
	addr := prefix.Addr().As4()
	n := (prefix.Bits() + 7) / 8
	out := []byte{byte(prefix.Bits())}
	out = append(out, addr[:n]...)
	return out
}
