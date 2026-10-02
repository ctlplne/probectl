// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/siem"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestSyslogTLSClientCertDeliversToDeviceReadPath is the RTP-09 acceptance: an
// authenticated rsyslog-style sender presenting a TLS client certificate
// delivers a record that surfaces via the device syslog read path
// (GET /v1/device/syslog); an unauthenticated sender (CA-valid cert, unknown
// subject) is rejected and never persisted; and a connection with no client
// certificate fails closed at the handshake. Certs are minted via internal/crypto
// (never crypto/ecdsa|rand|x509 directly).
func TestSyslogTLSClientCertDeliversToDeviceReadPath(t *testing.T) {
	ca, err := crypto.GenerateCA("probectl-syslog-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, serverKey, err := ca.IssueServerCert("127.0.0.1", []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, clientKey, err := ca.IssueClientCert("edge-fw", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rogueCert, rogueKey, err := ca.IssueClientCert("rogue", "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	caFile := writePEM(t, dir, "ca.pem", ca.CertPEM())
	serverCertFile := writePEM(t, dir, "server.pem", serverCert)
	serverKeyFile := writePEM(t, dir, "server-key.pem", serverKey)
	clientCertFile := writePEM(t, dir, "client.pem", clientCert)
	clientKeyFile := writePEM(t, dir, "client-key.pem", clientKey)
	rogueCertFile := writePEM(t, dir, "rogue.pem", rogueCert)
	rogueKeyFile := writePEM(t, dir, "rogue-key.pem", rogueKey)

	tenant := tenancy.DefaultTenantID.String()

	// The server serves GET /v1/device/syslog from the same ops store the sink
	// writes to, so an accepted line lands on the read path (RTP-09).
	srv := testServer(fakePinger{})
	sink := NewDeviceSyslogSink(srv.DeviceOps())
	receiver, err := siem.NewSyslogReceiver(siem.SyslogReceiverConfig{
		Sources: []siem.SyslogSource{{
			Name:             "edge-fw",
			TenantID:         tenant,
			TLSClientSubject: "CN=edge-fw,O=probectl",
		}},
	}, sink)
	if err != nil {
		t.Fatal(err)
	}

	tlsCfg, err := crypto.ServerClientCertTLSConfig(serverCertFile, serverKeyFile, caFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveDone := make(chan struct{})
	go func() {
		_ = receiver.Serve(ctx, ln)
		close(serveDone)
	}()
	addr := ln.Addr().String()

	// Authenticated client-cert sender → one RFC 5424 line.
	clientTLS, err := crypto.ClientMTLSConfig(clientCertFile, clientKeyFile, caFile)
	if err != nil {
		t.Fatal(err)
	}
	line := `<34>1 2026-06-30T13:00:00Z edge-1 firewall 731 link_down ` +
		`[probectlSrc@32473 ifIndex="7"] uplink down on Gi0/1`
	sendSyslogLine(t, addr, clientTLS, line)

	got := awaitSyslog(t, srv, 1)
	if got[0].TenantID != tenant {
		t.Fatalf("delivered row tenant = %q, want %q", got[0].TenantID, tenant)
	}
	if got[0].Hostname != "edge-1" || got[0].AppName != "firewall" {
		t.Fatalf("rfc5424 header not parsed on the read path: %+v", got[0])
	}
	if got[0].Version != 1 {
		t.Fatalf("rfc5424 version = %d, want 1: %+v", got[0].Version, got[0])
	}
	if got[0].Device != "edge-1" || got[0].Message != "uplink down on Gi0/1" {
		t.Fatalf("delivered row device/message = %+v", got[0])
	}
	if got[0].Labels["auth_method"] != "tls-client-cert" {
		t.Fatalf("auth method provenance = %q, want tls-client-cert", got[0].Labels["auth_method"])
	}

	// Unauthenticated sender: a CA-valid certificate with an UNKNOWN subject is
	// rejected at the per-source credential check and never persisted.
	rogueTLS, err := crypto.ClientMTLSConfig(rogueCertFile, rogueKeyFile, caFile)
	if err != nil {
		t.Fatal(err)
	}
	sendSyslogLine(t, addr, rogueTLS, `<34>1 2026-06-30T13:00:05Z rogue-1 malware - - - rogue line`)
	// Give the server a moment to process (and reject) the rogue line, then
	// confirm nothing new was stored.
	time.Sleep(250 * time.Millisecond)
	if after := currentSyslog(t, srv); len(after) != 1 {
		t.Fatalf("unauthenticated sender was not rejected: read path has %d rows: %+v", len(after), after)
	}

	// No client certificate at all → the sender cannot deliver a record: the
	// listener requires and verifies a client certificate, so a cert-less
	// connection is refused and nothing is persisted (fail closed, G7-12).
	noCertTLS, err := crypto.HardenedClientTLSConfigWithCAFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	if conn, derr := tls.Dial("tcp", addr, noCertTLS); derr == nil {
		_, _ = conn.Write([]byte(line + "\n"))
		_ = conn.Close()
	}
	time.Sleep(250 * time.Millisecond)
	if after := currentSyslog(t, srv); len(after) != 1 {
		t.Fatalf("a sender with no client certificate delivered a record: read path has %d rows", len(after))
	}

	cancel()
	<-serveDone
}

func writePEM(t *testing.T, dir, name string, pemBytes []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func sendSyslogLine(t *testing.T, addr string, cfg *tls.Config, line string) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(line + "\n")); err != nil {
		t.Fatalf("write syslog line: %v", err)
	}
}

// awaitSyslog polls the device syslog read path (as the default tenant) until it
// returns want rows or the deadline passes.
func awaitSyslog(t *testing.T, srv *Server, want int) []device.SyslogEvent {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		rows := currentSyslog(t, srv)
		if len(rows) >= want {
			return rows
		}
		if time.Now().After(deadline) {
			t.Fatalf("device syslog read path never showed %d row(s); got %d", want, len(rows))
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func currentSyslog(t *testing.T, srv *Server) []device.SyslogEvent {
	t.Helper()
	rec := do(srv, http.MethodGet, "/v1/device/syslog?limit=50")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/device/syslog = %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items []device.SyslogEvent `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode syslog list: %v", err)
	}
	return resp.Items
}
