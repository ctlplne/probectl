package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// presentedSerial dials the listener with cfg and returns the client-cert
// serial the SERVER saw — i.e. the identity actually presented on the wire.
func presentedSerial(t *testing.T, serverCfg *tls.Config, clientCfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	result := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			result <- "accept: " + err.Error()
			return
		}
		defer conn.Close()
		tc := conn.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			result <- "handshake: " + err.Error()
			return
		}
		certs := tc.ConnectionState().PeerCertificates
		if len(certs) == 0 {
			result <- "no-peer-cert"
			return
		}
		result <- certs[0].SerialNumber.String()
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	conn.Close()
	return <-result
}

// TestRotatingIdentityPicksUpRenewalWithoutRestart is the S41
// trustctl-identity mTLS test: a trustctl-style renewal overwrites the
// cert/key files in place, and the NEXT handshake presents the renewed
// certificate — same process, no restart.
func TestRotatingIdentityPicksUpRenewalWithoutRestart(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	ca, err := GenerateCA("trustctl-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sc, sk, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	spiffe := AgentSPIFFEID("tenant-123", "agent-abc")
	cc1, ck1, err := ca.IssueClientCert("agent-abc", spiffe, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	caFile := write("ca.crt", ca.CertPEM())
	certFile := write("client.crt", cc1)
	keyFile := write("client.key", ck1)
	serverCrt, serverKey := write("server.crt", sc), write("server.key", sk)

	serverCfg, err := ServerMTLSConfig(serverCrt, serverKey, caFile)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, ri, err := ClientMTLSConfigRotating(certFile, keyFile, caFile, "spiffe://probectl/")
	if err != nil {
		t.Fatal(err)
	}
	clientCfg.ServerName = "localhost"
	ri.interval = 0 // test: re-stat on every handshake

	serial1 := ri.Leaf().SerialNumber.String()
	if got := presentedSerial(t, serverCfg, clientCfg); got != serial1 {
		t.Fatalf("first handshake presented %s, want %s", got, serial1)
	}

	// trustctl renews: new cert/key written IN PLACE (new serial, same SPIFFE).
	cc2, ck2, err := ca.IssueClientCert("agent-abc", spiffe, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	write("client.crt", cc2)
	write("client.key", ck2)
	// Ensure the mtime visibly changes even on coarse filesystems.
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certFile, future, future); err != nil {
		t.Fatal(err)
	}

	got := presentedSerial(t, serverCfg, clientCfg)
	serial2 := ri.Leaf().SerialNumber.String()
	if serial2 == serial1 {
		t.Fatal("identity did not reload the renewed certificate")
	}
	if got != serial2 {
		t.Fatalf("post-renewal handshake presented %s, want renewed %s", got, serial2)
	}

	// A broken (mid-write) renewal keeps the last valid identity serving.
	write("client.crt", []byte("not a pem"))
	future = future.Add(2 * time.Second)
	if err := os.Chtimes(certFile, future, future); err != nil {
		t.Fatal(err)
	}
	if got := presentedSerial(t, serverCfg, clientCfg); got != serial2 {
		t.Fatalf("broken renewal: presented %s, want previous valid %s", got, serial2)
	}
}

func TestRotatingIdentityFailsClosedOnSPIFFEMismatch(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ca, err := GenerateCA("trustctl-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	right := AgentSPIFFEID("tenant-123", "agent-abc")
	cc, ck, err := ca.IssueClientCert("agent-abc", right, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := write("c.crt", cc), write("c.key", ck)

	// Initial load with a prefix the cert does NOT carry: refuse to start.
	if _, err := NewRotatingIdentity(certFile, keyFile, "spiffe://other-domain/"); err == nil ||
		!strings.Contains(err.Error(), "SPIFFE") {
		t.Fatalf("wrong-identity cert must fail closed at load, got %v", err)
	}

	// Valid start with a TENANT-PINNED prefix; then a renewal lands carrying
	// another tenant's identity: the old (still attested) identity keeps
	// serving — never the imposter (guardrails 1 + 4).
	ri, err := NewRotatingIdentity(certFile, keyFile, "spiffe://probectl/tenant/tenant-123/")
	if err != nil {
		t.Fatal(err)
	}
	ri.interval = 0
	serial1 := ri.Leaf().SerialNumber.String()

	wrong := AgentSPIFFEID("tenant-999", "agent-evil")
	cc2, ck2, err := ca.IssueClientCert("agent-evil", wrong, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	write("c.crt", cc2)
	write("c.key", ck2)
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certFile, future, future); err != nil {
		t.Fatal(err)
	}

	cert, err := ri.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if leaf.SerialNumber.String() != serial1 {
		t.Fatal("identity presented a cert with the wrong SPIFFE identity")
	}
}
