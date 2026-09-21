// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"
	"unicode"

	"github.com/ctlplne/probectl/internal/crypto"
)

// Channel is a notification destination.
type Channel interface {
	Type() string
	Notify(ctx context.Context, a Alert) error
}

// Doer is the subset of *http.Client the webhook channel needs (injectable).
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// SignatureHeader carries the HMAC-SHA256 signature of the webhook body so the
// receiver can verify the sender (provider HMAC; receivers verify, CONTRIBUTING.md).
const SignatureHeader = "X-Probectl-Signature"

// WebhookChannel POSTs the alert payload to an HTTPS endpoint, optionally signed.
type WebhookChannel struct {
	url    string
	secret string
	client Doer
}

// NewWebhookChannel builds a webhook channel. A nil client uses a default HTTPS
// client (TLS certificate validation on, per guardrail 12).
func NewWebhookChannel(url, secret string, client Doer) *WebhookChannel {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &WebhookChannel{url: url, secret: secret, client: client}
}

func (w *WebhookChannel) Type() string { return "webhook" }

func (w *WebhookChannel) Notify(ctx context.Context, a Alert) error {
	body, err := json.Marshal(a.Payload())
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "probectl-alerting")
	if w.secret != "" {
		// HMAC via internal/crypto (FIPS-swappable; never a direct crypto/hmac).
		sig := crypto.Sign([]byte(w.secret), body)
		req.Header.Set(SignatureHeader, "sha256="+hex.EncodeToString(sig))
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

// MailSender sends a plaintext email (injectable; SMTPSender is the live impl).
type MailSender interface {
	Send(ctx context.Context, to []string, subject, body string) error
}

// EmailChannel notifies a set of recipients via a MailSender.
type EmailChannel struct {
	recipients []string
	sender     MailSender
}

// NewEmailChannel builds an email channel.
func NewEmailChannel(recipients []string, sender MailSender) *EmailChannel {
	return &EmailChannel{recipients: recipients, sender: sender}
}

func (e *EmailChannel) Type() string { return "email" }

func (e *EmailChannel) Notify(ctx context.Context, a Alert) error {
	if e.sender == nil {
		return fmt.Errorf("email channel has no configured mail sender")
	}
	subject := fmt.Sprintf("[probectl][%s] %s %s", a.Severity, a.RuleName, a.State)
	body := fmt.Sprintf("Rule %q is %s.\n\nMetric: %s\nValue: %v\nReason: %s\nWhen: %s\n",
		a.RuleName, a.State, a.Metric, a.Value, a.Reason, a.At.UTC().Format(time.RFC3339))
	return e.sender.Send(ctx, e.recipients, subject, body)
}

// SMTPTLSMode selects how the SMTP connection is secured. There is no
// plaintext mode: alert mail carries incident detail, and a mail transport
// without channel security fails closed (docs/guardrails.md G7-12).
type SMTPTLSMode string

const (
	// SMTPStartTLS dials plain TCP and REQUIRES the server to advertise
	// STARTTLS before any credential or message byte is sent (ports 587/25).
	SMTPStartTLS SMTPTLSMode = "starttls"
	// SMTPImplicitTLS speaks TLS from the first byte (SMTPS, port 465).
	SMTPImplicitTLS SMTPTLSMode = "implicit"
)

// SMTPSender delivers mail over a TLS-secured SMTP session. Certificate
// validation is always on; the TLS policy comes from internal/crypto.
type SMTPSender struct {
	addr    string // host:port
	from    string
	auth    smtp.Auth
	mode    SMTPTLSMode
	tlsBase *tls.Config
}

// NewSMTPSender builds an SMTP-backed MailSender. A nil tlsBase uses the
// hardened third-party client policy from internal/crypto (TLS 1.2 floor,
// certificate validation on); tests inject a config carrying their test CA.
func NewSMTPSender(addr, from string, auth smtp.Auth, mode SMTPTLSMode, tlsBase *tls.Config) *SMTPSender {
	if tlsBase == nil {
		tlsBase = crypto.HardenedClientTLSConfig()
	}
	if mode == "" {
		mode = SMTPStartTLS
	}
	return &SMTPSender{addr: addr, from: from, auth: auth, mode: mode, tlsBase: tlsBase}
}

// Send composes a minimal RFC 5322 message and delivers it over a session that
// is TLS-secured before authentication or content: implicit mode handshakes
// first; starttls mode refuses a server that does not offer STARTTLS.
// maxHeaderValue bounds a single header value. RFC 5322 allows 998 octets per
// line before folding; alert subjects are not the place to exercise that, and a
// rule name is a label rather than a document.
const maxHeaderValue = 400

// headerValue makes a string safe to place after "Name: " in a message header.
//
// DPR-243: it strips every control character, not just CR and LF. CR/LF are the
// injection vector — they terminate the header and let the next line be one the
// attacker chose — but NUL and the rest have no legitimate place in a header
// either, and an allowlist of "printable plus space" is a rule that stays true
// as this code changes. Runs of whitespace collapse so a stripped newline does
// not leave a ragged gap, and the result is bounded.
func headerValue(v string) string {
	var b strings.Builder
	b.Grow(len(v))
	lastWasSpace := false
	for _, r := range v {
		switch {
		case r == '\r' || r == '\n' || r == '\t' || unicode.IsControl(r):
			// Collapse to a single space rather than deleting, so two tokens
			// separated only by a newline do not silently become one word.
			if !lastWasSpace {
				b.WriteRune(' ')
				lastWasSpace = true
			}
		case r == ' ':
			if !lastWasSpace {
				b.WriteRune(' ')
				lastWasSpace = true
			}
		default:
			b.WriteRune(r)
			lastWasSpace = false
		}
	}
	out := strings.TrimSpace(b.String())
	if len(out) > maxHeaderValue {
		out = strings.TrimSpace(string([]rune(out)[:min(len([]rune(out)), maxHeaderValue)]))
	}
	return out
}

// encodedSubject sanitizes and then RFC 2047-encodes a subject, so a rule name
// in any language survives the trip while a rule name containing CRLF cannot
// forge a header. Sanitizing FIRST is deliberate: Q-encoding would also hide a
// newline, but only as a side effect of how mime.WordEncoder decides what needs
// encoding, and a security property should not rest on that.
func encodedSubject(subject string) string {
	return mime.QEncoding.Encode("utf-8", headerValue(subject))
}

func (s *SMTPSender) Send(ctx context.Context, to []string, subject, body string) error {
	host, _, err := net.SplitHostPort(s.addr)
	if err != nil {
		return fmt.Errorf("smtp: invalid address %q: %w", s.addr, err)
	}
	tlsCfg := s.tlsBase.Clone()
	tlsCfg.ServerName = host

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("smtp: dial: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if s.mode == SMTPImplicitTLS {
		conn = tls.Client(conn, tlsCfg)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp: handshake: %w", err)
	}
	defer func() { _ = c.Close() }()

	if s.mode == SMTPStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("smtp: server %s does not offer STARTTLS — refusing plaintext mail transport (guardrail 12)", s.addr)
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp: starttls: %w", err)
		}
	}
	if s.auth != nil {
		if err := c.Auth(s.auth); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}
	if err := c.Mail(s.from); err != nil {
		return fmt.Errorf("smtp: mail from: %w", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp: rcpt %s: %w", rcpt, err)
		}
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: data: %w", err)
	}
	msg := strings.Builder{}
	// DPR-243: every header value is sanitized. A header is CRLF-delimited, so a
	// value carrying \r or \n does not corrupt the header — it ENDS it and starts
	// another one the attacker chooses (Bcc:, Reply-To:, or a whole second body).
	// The subject is built from the rule name, which is tenant-supplied free text
	// arriving through the rule-create API, so this is untrusted input reaching a
	// protocol control surface: exactly guardrail 12's "fetched content
	// untrusted", one layer up.
	fmt.Fprintf(&msg, "From: %s\r\n", headerValue(s.from))
	fmt.Fprintf(&msg, "To: %s\r\n", headerValue(strings.Join(to, ", ")))
	fmt.Fprintf(&msg, "Subject: %s\r\n", encodedSubject(subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	// The body needs no escaping for structure: Data() returns a
	// textproto.DotWriter, which dot-stuffs, so a "\r\n.\r\n" in the body cannot
	// end the DATA section early.
	msg.WriteString(body)
	if _, err := io.WriteString(wc, msg.String()); err != nil {
		_ = wc.Close()
		return fmt.Errorf("smtp: write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp: close message: %w", err)
	}
	return c.Quit()
}
