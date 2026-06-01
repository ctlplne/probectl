package alert

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/crypto"
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
// receiver can verify the sender (provider HMAC; receivers verify, CLAUDE.md §6).
const SignatureHeader = "X-Netctl-Signature"

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
	req.Header.Set("User-Agent", "netctl-alerting")
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
	subject := fmt.Sprintf("[netctl][%s] %s %s", a.Severity, a.RuleName, a.State)
	body := fmt.Sprintf("Rule %q is %s.\n\nMetric: %s\nValue: %v\nReason: %s\nWhen: %s\n",
		a.RuleName, a.State, a.Metric, a.Value, a.Reason, a.At.UTC().Format(time.RFC3339))
	return e.sender.Send(ctx, e.recipients, subject, body)
}

// SMTPSender delivers mail via net/smtp.
type SMTPSender struct {
	addr string // host:port
	from string
	auth smtp.Auth
}

// NewSMTPSender builds an SMTP-backed MailSender.
func NewSMTPSender(addr, from string, auth smtp.Auth) *SMTPSender {
	return &SMTPSender{addr: addr, from: from, auth: auth}
}

// Send composes a minimal RFC 5322 message and sends it.
func (s *SMTPSender) Send(_ context.Context, to []string, subject, body string) error {
	msg := strings.Builder{}
	fmt.Fprintf(&msg, "From: %s\r\n", s.from)
	fmt.Fprintf(&msg, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&msg, "Subject: %s\r\n", subject)
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	msg.WriteString(body)
	return smtp.SendMail(s.addr, s.auth, s.from, to, []byte(msg.String()))
}
