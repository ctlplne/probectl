// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package alert

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// fakeSMTP is a minimal SMTP server for exercising SMTPSender's TLS contract.
// It records every MAIL FROM and whether one ever arrived before the session
// was TLS-secured — the property the sender must make impossible.
type fakeSMTP struct {
	ln       net.Listener
	tlsCfg   *tls.Config // nil = STARTTLS never offered
	implicit bool

	mu                sync.Mutex
	mailFrom          []string
	rcpt              []string
	data              string
	plaintextMailFrom bool
}

func newFakeSMTP(t *testing.T, tlsCfg *tls.Config, implicit bool) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSMTP{ln: ln, tlsCfg: tlsCfg, implicit: implicit}
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeSMTP) addr() string { return s.ln.Addr().String() }

func (s *fakeSMTP) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.session(conn)
	}
}

func (s *fakeSMTP) session(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	secured := false
	if s.implicit {
		tc := tls.Server(conn, s.tlsCfg)
		if err := tc.Handshake(); err != nil {
			return
		}
		conn = tc
		secured = true
	}
	w := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	w("220 fake ESMTP")
	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		upper := strings.ToUpper(cmd)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			w("250-fake greets you")
			if s.tlsCfg != nil && !s.implicit && !secured {
				w("250-STARTTLS")
			}
			w("250 OK")
		case upper == "STARTTLS":
			if s.tlsCfg == nil || secured {
				w("454 not available")
				continue
			}
			w("220 go ahead")
			tc := tls.Server(conn, s.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			conn = tc
			secured = true
			w2 := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
			_ = w2
			r = bufio.NewReader(conn)
			w = func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
		case strings.HasPrefix(upper, "MAIL FROM"):
			s.mu.Lock()
			s.mailFrom = append(s.mailFrom, cmd)
			if !secured {
				s.plaintextMailFrom = true
			}
			s.mu.Unlock()
			w("250 OK")
		case strings.HasPrefix(upper, "RCPT TO"):
			s.mu.Lock()
			s.rcpt = append(s.rcpt, cmd)
			s.mu.Unlock()
			w("250 OK")
		case upper == "DATA":
			w("354 end with .")
			var body strings.Builder
			for {
				dl, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dl, "\r\n") == "." {
					break
				}
				body.WriteString(dl)
			}
			s.mu.Lock()
			s.data = body.String()
			s.mu.Unlock()
			w("250 OK queued")
		case upper == "QUIT":
			w("221 bye")
			return
		default:
			w("250 OK")
		}
	}
}

// serverTLS builds a CA-signed server TLS config for 127.0.0.1 plus a client
// base config trusting that CA — all through internal/crypto (§7 guardrail 3).
func serverTLS(t *testing.T, hosts []string) (server *tls.Config, clientBase *tls.Config) {
	t.Helper()
	ca, err := crypto.GenerateCA("smtp-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssueServerCert("smtp-test", hosts, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("append CA cert")
	}
	clientBase = crypto.HardenedClientTLSConfig()
	clientBase.RootCAs = pool
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, clientBase
}

func TestSMTPSenderRefusesServerWithoutSTARTTLS(t *testing.T) {
	srv := newFakeSMTP(t, nil, false) // plaintext-only server
	sender := NewSMTPSender(srv.addr(), "probectl@example.test", nil, SMTPStartTLS, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := sender.Send(ctx, []string{"oncall@example.test"}, "s", "b")
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("plaintext-only server must be refused with a STARTTLS error, got %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.mailFrom) != 0 {
		t.Fatalf("sender issued MAIL FROM on an unsecured session: %v", srv.mailFrom)
	}
}

func TestSMTPSenderImplicitModeRefusesPlaintextServer(t *testing.T) {
	srv := newFakeSMTP(t, nil, false) // speaks plaintext; sender expects TLS-first
	sender := NewSMTPSender(srv.addr(), "probectl@example.test", nil, SMTPImplicitTLS, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sender.Send(ctx, []string{"oncall@example.test"}, "s", "b"); err == nil {
		t.Fatal("implicit-TLS sender accepted a plaintext server")
	}
}

func TestSMTPSenderValidatesServerCertificate(t *testing.T) {
	serverCfg, _ := serverTLS(t, []string{"other.example.test"}) // wrong name for 127.0.0.1
	srv := newFakeSMTP(t, serverCfg, false)
	_, clientBase := serverTLS(t, []string{"127.0.0.1"}) // trusts a DIFFERENT CA too
	sender := NewSMTPSender(srv.addr(), "probectl@example.test", nil, SMTPStartTLS, clientBase)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sender.Send(ctx, []string{"oncall@example.test"}, "s", "b"); err == nil {
		t.Fatal("sender accepted a certificate that verifies under neither name nor CA")
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.mailFrom) != 0 {
		t.Fatalf("sender proceeded past a failed certificate verification: %v", srv.mailFrom)
	}
}

func TestSMTPSenderDeliversOverSTARTTLS(t *testing.T) {
	serverCfg, clientBase := serverTLS(t, []string{"127.0.0.1"})
	srv := newFakeSMTP(t, serverCfg, false)
	sender := NewSMTPSender(srv.addr(), "probectl@example.test", nil, SMTPStartTLS, clientBase)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sender.Send(ctx, []string{"oncall@example.test"}, "probectl alert", "rule fired"); err != nil {
		t.Fatalf("starttls delivery failed: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.plaintextMailFrom {
		t.Fatal("MAIL FROM arrived before the session was TLS-secured")
	}
	if len(srv.mailFrom) != 1 || len(srv.rcpt) != 1 ||
		!strings.Contains(srv.data, "Subject: probectl alert") ||
		!strings.Contains(srv.data, "rule fired") {
		t.Fatalf("delivered message incomplete: from=%v rcpt=%v data=%q", srv.mailFrom, srv.rcpt, srv.data)
	}
}

func TestSMTPSenderDeliversOverImplicitTLS(t *testing.T) {
	serverCfg, clientBase := serverTLS(t, []string{"127.0.0.1"})
	srv := newFakeSMTP(t, serverCfg, true)
	sender := NewSMTPSender(srv.addr(), "probectl@example.test", nil, SMTPImplicitTLS, clientBase)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sender.Send(ctx, []string{"oncall@example.test"}, "probectl alert", "rule fired"); err != nil {
		t.Fatalf("implicit-tls delivery failed: %v", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.plaintextMailFrom || len(srv.mailFrom) != 1 || !strings.Contains(srv.data, "rule fired") {
		t.Fatalf("implicit delivery incomplete: plaintext=%v from=%v data=%q", srv.plaintextMailFrom, srv.mailFrom, srv.data)
	}
}
