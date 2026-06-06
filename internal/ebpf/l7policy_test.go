package ebpf

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/ebpf/l7"
)

// U-003: capture is off by default and stays off without an exact-tenant
// consent — the gate requires BOTH flags and a tenant match.
func TestL7CaptureConsentGate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		want    bool
		reasony string
	}{
		{"default off", Config{TenantID: "t1"}, false, "OFF by default"},
		{"enabled without consent", Config{TenantID: "t1", L7CaptureEnabled: true}, false, "consent"},
		{"consent for another tenant", Config{TenantID: "t1", L7CaptureEnabled: true, L7CaptureConsentTenant: "t2"}, false, "does not match"},
		{"consent without enable", Config{TenantID: "t1", L7CaptureConsentTenant: "t1"}, false, "OFF by default"},
		{"enabled with matching consent", Config{TenantID: "t1", L7CaptureEnabled: true, L7CaptureConsentTenant: "t1"}, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := l7CaptureAuthorized(&tc.cfg)
			if ok != tc.want {
				t.Fatalf("authorized = %v (%s), want %v", ok, reason, tc.want)
			}
			if !ok && !strings.Contains(reason, tc.reasony) {
				t.Fatalf("reason %q should mention %q", reason, tc.reasony)
			}
		})
	}
}

// Config validation refuses enable-without-consent and unknown redaction
// modes (fail at load, not at capture time).
func TestL7CaptureConfigValidation(t *testing.T) {
	base := func() *Config {
		c := Default()
		c.TenantID = "t1"
		return c
	}
	c := base()
	c.L7CaptureEnabled = true
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "consent") {
		t.Fatalf("enable without consent must fail load: %v", err)
	}
	c = base()
	c.L7CaptureRedaction = "bodies-please"
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "l7_capture_redaction") {
		t.Fatalf("unknown redaction mode must fail load: %v", err)
	}
	c = base()
	c.L7CaptureEnabled = true
	c.L7CaptureConsentTenant = "t1"
	if err := c.validate(); err != nil {
		t.Fatalf("consented config must validate: %v", err)
	}
	if Default().L7CaptureEnabled {
		t.Fatal("L7 capture must default OFF")
	}
	if Default().L7CaptureRedaction != RedactHeaders {
		t.Fatal("redaction must default to headers mode")
	}
}

// The default agent posture: no fixture, no consent -> no L7 source at all
// (capture stays off; the flow plane is unaffected).
func TestAgentWithoutConsentHasNoL7Capture(t *testing.T) {
	cfg := Default()
	cfg.TenantID = "t1"
	cfg.FixturePath = "testdata/flows.json"
	a, err := New(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.l7source != nil {
		t.Fatal("agent attached an L7 source without consent (U-003)")
	}
}

// U-003 redaction boundary: HTTP bodies are zeroed in place — headers
// (protocol metadata) survive, the parser still extracts the call, and NO
// raw body byte persists beyond the boundary.
func TestRedactPayloadStripsBodiesKeepsMetadata(t *testing.T) {
	req := []byte("POST /login HTTP/1.1\r\nHost: app.example\r\nContent-Length: 27\r\n\r\npassword=hunter2&user=admin")
	red := RedactPayload(append([]byte(nil), req...), RedactHeaders)

	if len(red) != len(req) {
		t.Fatalf("length must be preserved for framing: %d != %d", len(red), len(req))
	}
	if !bytes.Contains(red, []byte("POST /login HTTP/1.1")) || !bytes.Contains(red, []byte("Content-Length: 27")) {
		t.Fatal("headers (protocol metadata) must survive")
	}
	if bytes.Contains(red, []byte("hunter2")) || bytes.Contains(red, []byte("admin")) {
		t.Fatalf("raw body persisted beyond the redaction boundary: %q", red)
	}
	body := red[bytes.Index(red, headerTerminator)+4:]
	for i, b := range body {
		if b != 0 {
			t.Fatalf("body byte %d not zeroed: %q", i, body)
		}
	}

	// The parser still produces the call from the redacted stream.
	p := l7.NewTracker(443)
	p.OnData(l7.DataEvent{Kind: l7.Request, Payload: red})
	calls := p.OnData(l7.DataEvent{Kind: l7.Response, Payload: []byte("HTTP/1.1 204 No Content\r\n\r\n")})
	if len(calls) != 1 || calls[0].Method != "POST" || calls[0].Resource != "/login" || calls[0].Status != "204" {
		t.Fatalf("redacted stream must still parse to metadata: %+v", calls)
	}
}

// Non-HTTP chunks keep only the protocol-detection window.
func TestRedactPayloadNonHTTPKeepsOnlyPrefix(t *testing.T) {
	chunk := bytes.Repeat([]byte{0xAB}, 512)
	red := RedactPayload(append([]byte(nil), chunk...), RedactHeaders)
	if len(red) != 512 {
		t.Fatal("length preserved")
	}
	for i := 0; i < redactKeepPrefix; i++ {
		if red[i] != 0xAB {
			t.Fatalf("detection window byte %d was clobbered", i)
		}
	}
	for i := redactKeepPrefix; i < len(red); i++ {
		if red[i] != 0 {
			t.Fatalf("byte %d past the window not zeroed", i)
		}
	}

	// Short chunks fit inside the window and pass through.
	short := []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	if got := RedactPayload(append([]byte(nil), short...), RedactHeaders); !bytes.Equal(got, short) {
		t.Fatal("short chunk must be untouched")
	}
}

// Full mode (consented debugging) leaves the payload intact.
func TestRedactPayloadFullMode(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\n\r\nsecret-body")
	if got := RedactPayload(append([]byte(nil), req...), RedactFull); !bytes.Equal(got, req) {
		t.Fatal("full mode must not modify the payload")
	}
}
