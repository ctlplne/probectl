package crypto

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type mtlsFixture struct {
	caFile, serverCrt, serverKey, clientCrt, clientKey, spiffe string
}

func mtlsMaterial(t *testing.T) mtlsFixture {
	t.Helper()
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	ca, err := GenerateCA("probectl-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sc, sk, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	spiffe := AgentSPIFFEID("tenant-123", "agent-abc")
	cc, ck, err := ca.IssueClientCert("agent-abc", spiffe, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return mtlsFixture{
		caFile:    write("ca.crt", ca.CertPEM()),
		serverCrt: write("server.crt", sc),
		serverKey: write("server.key", sk),
		clientCrt: write("client.crt", cc),
		clientKey: write("client.key", ck),
		spiffe:    spiffe,
	}
}

func TestMTLSHandshakeReadsSPIFFEID(t *testing.T) {
	f := mtlsMaterial(t)
	serverCfg, err := ServerMTLSConfig(f.serverCrt, f.serverKey, f.caFile)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := ClientMTLSConfig(f.clientCrt, f.clientKey, f.caFile)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg.ServerName = "localhost"

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
		id, err := SPIFFEIDFromCert(certs[0])
		if err != nil {
			result <- "spiffe: " + err.Error()
			return
		}
		result <- id.String()
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatalf("client handshake failed: %v", err)
	}
	conn.Close()

	if got := <-result; got != f.spiffe {
		t.Errorf("server read SPIFFE id %q, want %q", got, f.spiffe)
	}
}

func TestMTLSRejectsClientWithoutCert(t *testing.T) {
	f := mtlsMaterial(t)
	serverCfg, err := ServerMTLSConfig(f.serverCrt, f.serverKey, f.caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool, err := LoadCertPool(f.caFile)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.(*tls.Conn).Handshake() // expected to fail: no client cert
	}()

	clientCfg := &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	conn, err := tls.Dial("tcp", ln.Addr().String(), clientCfg)
	if err == nil {
		// In TLS 1.3 the client handshake can complete before the server's
		// client-auth failure arrives; the rejection then surfaces on the first
		// read. Either path means the connection was refused.
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, rerr := conn.Read(make([]byte, 1)); rerr == nil {
			t.Error("server must reject a client that presents no certificate")
		}
	}
}
