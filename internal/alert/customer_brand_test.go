// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package alert

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/branding"
)

type brandTestMail struct {
	subject, body string
}

func (m *brandTestMail) Send(_ context.Context, _ []string, subject, body string) error {
	m.subject, m.body = subject, body
	return nil
}

func TestCustomerAlertEmailAndWebhookCarryFixedAttribution(t *testing.T) {
	t.Run("SMTP alert", proveCustomerSMTPAttribution)
	t.Run("report attachment", proveCustomerAttachmentAttribution)

	mail, web := &brandTestMail{}, &fakeDoer{}
	var lookups []string
	notifier := NewNotifier(ChannelDeps{Mail: mail, HTTPClient: web,
		Brand: func(_ context.Context, tenant string) branding.Branding {
			lookups = append(lookups, tenant)
			return branding.Branding{Customer: &branding.CustomerIdentity{Name: "Northstar"}}
		}}, nil)
	rule := thresholdRule()
	rule.TenantID = "tenant-northstar"
	rule.Channels = []ChannelSpec{{Type: "email", Recipients: []string{"example@example.test"}},
		{Type: "webhook", URL: "https://events.example.test", Secret: "fixture"}}
	if count := notifier.Deliver(t.Context(), rule, Alert{TenantID: "tenant-northstar", RuleName: "loss"}); count != 2 {
		t.Fatal("customer alert did not reach both channels")
	}
	if len(lookups) != 1 || lookups[0] != "tenant-northstar" || !strings.HasPrefix(mail.subject, "[Northstar]") ||
		!strings.HasPrefix(mail.body, "Northstar\nPowered by probectl (https://probectl.com)\n") {
		t.Fatal("the email did not draw from the tenant and fixed attribution")
	}
	var payload WebhookPayload
	if err := json.Unmarshal(web.lastBody, &payload); err != nil || payload.Brand != "Northstar" ||
		payload.PoweredBy != "Powered by probectl" || payload.PoweredByURL != "https://probectl.com" ||
		web.lastReq.Header.Get(SignatureHeader) == "" {
		t.Fatal("the signed webhook did not include fixed attribution", err)
	}
}

func proveCustomerSMTPAttribution(t *testing.T) {
	t.Helper()
	serverTLSConfig, clientTLSConfig := serverTLS(t, []string{"127.0.0.1"})
	server := newFakeSMTP(t, serverTLSConfig, false)
	sender := NewSMTPSender(server.addr(), "alerts@example.test", nil, SMTPStartTLS, clientTLSConfig)
	channel := NewEmailChannel([]string{"client@example.test"}, sender)
	customer := "Northstar <img>"
	ctx, cancel := context.WithTimeout(branding.WithOutput(t.Context(),
		branding.Branding{Customer: &branding.CustomerIdentity{Name: customer}}), 10*time.Second)
	defer cancel()
	if err := channel.Notify(ctx, Alert{RuleName: "loss", Reason: "<script>untrusted</script>"}); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	wire := server.data
	server.mu.Unlock()
	message, err := mail.ReadMessage(strings.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	html := assertCustomerMailAlternatives(t, message.Header.Get("Content-Type"), message.Body, customer)
	if !strings.Contains(html, "Northstar &lt;img&gt;") || !strings.Contains(html, "&lt;script&gt;untrusted&lt;/script&gt;") ||
		strings.Contains(html, "<img") || strings.Contains(html, "<script>") {
		t.Fatal("tenant text altered the alert's HTML markup")
	}
}

func proveCustomerAttachmentAttribution(t *testing.T) {
	t.Helper()
	serverTLSConfig, clientTLSConfig := serverTLS(t, []string{"127.0.0.1"})
	server := newFakeSMTP(t, serverTLSConfig, false)
	sender := NewSMTPSender(server.addr(), "reports@example.test", nil, SMTPStartTLS, clientTLSConfig)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	const body = "report,row\r\n"
	attachment := MailAttachment{
		Filename: "report.csv", MediaType: "text/csv", MessageID: "<brand-proof@example.test>",
		BrandName: "Northstar", Bytes: int64(len(body)), Body: strings.NewReader(body),
	}
	if err := sender.SendAttachment(ctx, []string{"client@example.test"}, "[Northstar] Monthly report", attachment); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	wire := server.data
	server.mu.Unlock()
	message, err := mail.ReadMessage(strings.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/mixed" {
		t.Fatal("report lost its MIME envelope", err)
	}
	parts := multipart.NewReader(message.Body, params["boundary"])
	intro, err := parts.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	assertCustomerMailAlternatives(t, intro.Header.Get("Content-Type"), intro, "Northstar")
	part, err := parts.NextPart()
	if err != nil || part.Header.Get("Content-Type") != "text/csv" ||
		part.Header.Get("Content-Transfer-Encoding") != "base64" {
		t.Fatal("branded email changed the report attachment", err)
	}
}

func assertCustomerMailAlternatives(t *testing.T, header string, body io.Reader, customer string) string {
	t.Helper()
	media, params, err := mime.ParseMediaType(header)
	if err != nil || media != "multipart/alternative" {
		t.Fatal("customer email is missing its plaintext and clickable HTML alternatives", err)
	}
	parts := multipart.NewReader(body, params["boundary"])
	plain, err := parts.NextPart()
	if err != nil || plain.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatal("customer email has no plaintext part", err)
	}
	text, err := io.ReadAll(plain)
	if err != nil || !strings.HasPrefix(strings.ReplaceAll(string(text), "\r\n", "\n"),
		customer+"\nPowered by probectl (https://probectl.com)\n") {
		t.Fatal("plaintext email is missing its fixed attribution", err)
	}
	rich, err := parts.NextPart()
	if err != nil || rich.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatal("customer email has no HTML part", err)
	}
	html, err := io.ReadAll(rich)
	if err != nil || !strings.Contains(string(html), `<a href="https://probectl.com" style="color:#fffefa;background-color:#231b16;`) ||
		!strings.Contains(string(html), ">Powered by probectl</a>") {
		t.Fatal("HTML email is missing its fixed attribution link", err)
	}
	return string(html)
}
