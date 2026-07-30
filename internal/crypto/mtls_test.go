// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type mtlsFixture struct {
	caFile, serverCrt, serverKey, clientCrt, clientKey, spiffe string
	ca                                                         *CA
}

func mtlsMaterial(t *testing.T) mtlsFixture {
	t.Helper()
	return mtlsMaterialForSPIFFE(t, AgentSPIFFEID("tenant-123", "agent-abc"))
}

func mtlsMaterialForSPIFFE(t *testing.T, spiffe string) mtlsFixture {
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
		ca:        ca,
	}
}

func issueClientLeafWithURIs(
	t *testing.T,
	ca *CA,
	rawURIs ...string,
) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := randomSerial()
	if err != nil {
		t.Fatal(err)
	}
	uris := make([]*url.URL, 0, len(rawURIs))
	for _, raw := range rawURIs {
		uri, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse test URI %q: %v", raw, err)
		}
		uris = append(uris, uri)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "ambiguous-agent",
			Organization: []string{"probectl"},
		},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:        uris,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		ca.cert,
		&key.PublicKey,
		ca.key,
	)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestServerMTLSRejectsIncompleteSPIFFEIdentity(t *testing.T) {
	for name, spiffe := range map[string]string{
		"empty tenant": "spiffe://probectl/tenant//agent/a1",
		"empty agent":  "spiffe://probectl/tenant/t1/agent/",
	} {
		t.Run(name, func(t *testing.T) {
			f := mtlsMaterialForSPIFFE(t, spiffe)
			serverCfg, err := ServerMTLSConfig(f.serverCrt, f.serverKey, f.caFile)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(mustReadFile(t, f.clientCrt))
			if block == nil {
				t.Fatal("client certificate PEM did not decode")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := leaf.Verify(x509.VerifyOptions{
				Roots:     serverCfg.ClientCAs,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}); err != nil {
				t.Fatalf("fixture must be CA-valid before identity policy runs: %v", err)
			}
			if err := serverCfg.VerifyPeerCertificate([][]byte{leaf.Raw}, nil); err == nil {
				t.Fatalf("ServerMTLSConfig accepted incomplete identity %q", spiffe)
			}
		})
	}
}

func TestServerMTLSRejectsAmbiguousSPIFFEURIAndMultipleSANs(t *testing.T) {
	f := mtlsMaterial(t)
	serverCfg, err := ServerMTLSConfig(f.serverCrt, f.serverKey, f.caFile)
	if err != nil {
		t.Fatal(err)
	}
	const canonical = "spiffe://probectl/tenant/tenant-123/agent/agent-abc"
	for name, uris := range map[string][]string{
		"userinfo": {"spiffe://operator@probectl/tenant/tenant-123/agent/agent-abc"},
		"query":    {canonical + "?tenant=other"},
		"fragment": {canonical + "#shadow"},
		"multiple": {
			canonical,
			"spiffe://probectl/tenant/other/agent/other",
		},
		"mixed URI schemes": {
			canonical,
			"https://probectl.example/agent/agent-abc",
		},
	} {
		t.Run(name, func(t *testing.T) {
			leaf := issueClientLeafWithURIs(t, f.ca, uris...)
			verifiedChains, err := leaf.Verify(x509.VerifyOptions{
				Roots:     serverCfg.ClientCAs,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			})
			if err != nil {
				t.Fatalf("fixture must be CA-valid before identity policy runs: %v", err)
			}
			if err := serverCfg.VerifyPeerCertificate(
				[][]byte{leaf.Raw},
				verifiedChains,
			); err == nil {
				t.Fatalf("ServerMTLSConfig accepted ambiguous URI SANs %#v", uris)
			}
		})
	}

	canonicalLeaf := issueClientLeafWithURIs(t, f.ca, canonical)
	verifiedChains, err := canonicalLeaf.Verify(x509.VerifyOptions{
		Roots:     serverCfg.ClientCAs,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("canonical fixture must be CA-valid: %v", err)
	}
	if err := serverCfg.VerifyPeerCertificate(
		[][]byte{canonicalLeaf.Raw},
		verifiedChains,
	); err != nil {
		t.Fatalf("canonical single URI SAN rejected: %v", err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
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
