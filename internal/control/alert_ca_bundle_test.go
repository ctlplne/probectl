// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestAlertSMTPTrustsTheConfiguredCABundle is the DPR-290 regression for the
// email channel: a relay behind an enterprise CA could be trusted only by
// replacing the whole process's system roots. With PROBECTL_ALERT_SMTP_CA_FILE
// the sender validates the relay against the operator's bundle; without it the
// same relay is refused.
func TestAlertSMTPTrustsTheConfiguredCABundle(t *testing.T) {
	// The relay is reached as localhost, the name its certificate carries.
	caFile, serverTLS := alertTestCA(t, "localhost")
	relay := testsupport.StartSMTPServer(t, serverTLS, "alerts", "relay-word-pass")
	_, port, _ := net.SplitHostPort(relay.Addr)
	cfg := &config.Config{
		AlertSMTPAddr:     "localhost:" + port,
		AlertSMTPFrom:     "probectl@msp.test",
		AlertSMTPTLSMode:  "starttls",
		AlertSMTPUsername: "alerts",
		AlertSMTPPassword: "relay-word-pass",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	withoutCA, err := BuildAlertChannelDeps(cfg, nil, statusQuietLog())
	if err != nil {
		t.Fatal(err)
	}
	if err := withoutCA.Mail.Send(ctx, []string{"noc@msp.test"}, "s", "b"); err == nil {
		t.Fatal("a relay signed by an unknown CA was trusted without a configured bundle")
	}

	cfg.AlertSMTPCAFile = caFile
	withCA, err := BuildAlertChannelDeps(cfg, nil, statusQuietLog())
	if err != nil {
		t.Fatal(err)
	}
	if err := withCA.Mail.Send(ctx, []string{"noc@msp.test"}, "probe", "body"); err != nil {
		t.Fatalf("delivery to the relay behind the configured CA failed: %v", err)
	}
	msgs := relay.Messages()
	if len(msgs) != 1 || !msgs[0].TLS || msgs[0].User != "alerts" || msgs[0].To[0] != "noc@msp.test" {
		t.Fatalf("relay accepted %+v, want one TLS-secured, authenticated message to noc@msp.test", msgs)
	}

	cfg.AlertSMTPCAFile = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := BuildAlertChannelDeps(cfg, nil, statusQuietLog()); err == nil {
		t.Fatal("an unreadable SMTP CA bundle must fail the boot")
	}
}

// TestAlertWebhookTrustsTheConfiguredCABundle is the DPR-290 regression for
// the webhook channel: PROBECTL_ALERT_WEBHOOK_CA_FILE anchors validation on
// the operator's bundle, and the SSRF guard still refuses a loopback receiver.
func TestAlertWebhookTrustsTheConfiguredCABundle(t *testing.T) {
	deps, err := BuildAlertChannelDeps(&config.Config{}, nil, statusQuietLog())
	if err != nil || deps.HTTPClient != nil {
		t.Fatalf("no webhook bundle must keep the default guarded client, got (%v, %v)", deps.HTTPClient, err)
	}
	caFile, _ := alertTestCA(t, "hooks.probectl.test")
	deps, err = BuildAlertChannelDeps(&config.Config{AlertWebhookCAFile: caFile}, nil, statusQuietLog())
	if err != nil || deps.HTTPClient == nil {
		t.Fatalf("a webhook bundle must yield a client, got (%v, %v)", deps.HTTPClient, err)
	}
	client, ok := deps.HTTPClient.(*http.Client)
	if !ok {
		t.Fatalf("webhook client is %T", deps.HTTPClient)
	}
	tr := client.Transport.(*http.Transport)
	leaf := alertTestLeaf(t, caFile)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: tr.TLSClientConfig.RootCAs, DNSName: "hooks.probectl.test"}); err != nil {
		t.Fatalf("the webhook client does not trust the configured bundle: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var accepted atomic.Bool
	go func() {
		if c, err := ln.Accept(); err == nil {
			accepted.Store(true)
			_ = c.Close()
		}
	}()
	req, _ := http.NewRequest(http.MethodPost, "https://"+ln.Addr().String()+"/hook", strings.NewReader("{}"))
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("the webhook client with a CA bundle reached a loopback receiver past the SSRF guard")
	}
	time.Sleep(50 * time.Millisecond)
	if accepted.Load() {
		t.Fatal("the guarded dialer opened a socket to the loopback receiver")
	}

	if _, err := BuildAlertChannelDeps(&config.Config{AlertWebhookCAFile: filepath.Join(t.TempDir(), "missing.pem")}, nil, statusQuietLog()); err == nil {
		t.Fatal("an unreadable webhook CA bundle must fail the boot")
	}
}

// alertTestCA writes a fresh CA's certificate to a file and returns it with a
// server TLS config for host signed by that CA. The issued leaf is kept next
// to the CA for alertTestLeaf.
func alertTestCA(t *testing.T, host string) (string, *tls.Config) {
	t.Helper()
	ca, err := crypto.GenerateCA("probectl-alert-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssueServerCert(host, []string{host}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "leaf.pem"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return caFile, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

func alertTestLeaf(t *testing.T, caFile string) *x509.Certificate {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(caFile), "leaf.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("leaf.pem holds no certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}
