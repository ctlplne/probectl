// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/ebpf/l7"
)

// U-003 + EBPF-001: capture is off by default and stays off without an
// exact-tenant consent AND an explicit workload scope — the gate requires
// all three statements. Host-wide capture is not expressible.
func TestL7CaptureConsentGate(t *testing.T) {
	scope := []string{"exe:/usr/sbin/nginx"}
	cases := []struct {
		name    string
		cfg     Config
		want    bool
		reasony string
	}{
		{"default off", Config{TenantID: "t1"}, false, "OFF by default"},
		{"enabled without consent", Config{TenantID: "t1", L7CaptureEnabled: true, L7CaptureScope: scope}, false, "consent"},
		{"consent for another tenant", Config{TenantID: "t1", L7CaptureEnabled: true, L7CaptureConsentTenant: "t2", L7CaptureScope: scope}, false, "does not match"},
		{"consent without enable", Config{TenantID: "t1", L7CaptureConsentTenant: "t1", L7CaptureScope: scope}, false, "OFF by default"},
		{"enabled+consent WITHOUT scope", Config{TenantID: "t1", L7CaptureEnabled: true, L7CaptureConsentTenant: "t1"}, false, "l7_capture_scope"},
		{"enabled with consent and scope", Config{TenantID: "t1", L7CaptureEnabled: true, L7CaptureConsentTenant: "t1", L7CaptureScope: scope}, true, ""},
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
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "l7_capture_scope") {
		t.Fatalf("enable without a workload scope must fail load (EBPF-001): %v", err)
	}
	c.L7CaptureScope = []string{"pid:0x12"}
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "pid") {
		t.Fatalf("malformed scope entry must fail load: %v", err)
	}
	c.L7CaptureScope = []string{"exe:/usr/sbin/nginx", "pid:42"}
	if err := c.validate(); err != nil {
		t.Fatalf("consented+scoped config must validate: %v", err)
	}
	c.L7CaptureKernelWindow = 64
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "l7_capture_kernel_window") {
		t.Fatalf("out-of-bounds kernel window must fail load: %v", err)
	}
	c.L7CaptureKernelWindow = 2048
	if err := c.validate(); err != nil {
		t.Fatalf("in-bounds kernel window must validate: %v", err)
	}
	c.L7CaptureRedaction = RedactLengthOnly
	if err := c.validate(); err != nil {
		t.Fatalf("length-only redaction must be a valid mode: %v", err)
	}
	if Default().L7CaptureEnabled {
		t.Fatal("L7 capture must default OFF")
	}
	if Default().L7CaptureRedaction != RedactHeaders {
		t.Fatal("redaction must default to headers mode")
	}
	if len(Default().L7CaptureScope) != 0 {
		t.Fatal("scope must default EMPTY — workloads opt in explicitly (EBPF-001)")
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

// TestRedactPayloadZeroesSensitiveHeaderValues is the EBPF-006 regression
// guard: under the default "headers" mode, the VALUES of credential-bearing
// headers (Authorization/Cookie/Set-Cookie/Proxy-Authorization) are zeroed
// even though they sit inside the kept metadata region, while the header
// NAMES, line framing, and protocol detection survive. If a future change
// lets bearer tokens or session cookies transit to the control plane, this
// fails.
func TestRedactPayloadZeroesSensitiveHeaderValues(t *testing.T) {
	req := []byte("GET /api HTTP/1.1\r\n" +
		"Host: app.example\r\n" +
		"Authorization: Bearer sk-secret-token-abc123\r\n" +
		"Cookie: session=deadbeefcafe; csrf=zzz\r\n" +
		"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n" +
		"Accept: application/json\r\n\r\n")
	red := RedactPayload(append([]byte(nil), req...), RedactHeaders)

	if len(red) != len(req) {
		t.Fatalf("length must be preserved for framing: %d != %d", len(red), len(req))
	}
	// Secret VALUES must be gone.
	for _, secret := range [][]byte{
		[]byte("sk-secret-token-abc123"),
		[]byte("deadbeefcafe"),
		[]byte("csrf=zzz"),
		[]byte("dXNlcjpwYXNz"),
	} {
		if bytes.Contains(red, secret) {
			t.Fatalf("sensitive header value leaked through headers-mode redaction: %q in %q", secret, red)
		}
	}
	// Header NAMES, host, and a benign header survive (protocol metadata).
	for _, keep := range [][]byte{
		[]byte("Authorization:"),
		[]byte("Cookie:"),
		[]byte("Set-Cookie:"),
		[]byte("Proxy-Authorization:"),
		[]byte("Host: app.example"),
		[]byte("Accept: application/json"),
	} {
		_ = keep
	}
	for _, keep := range [][]byte{
		[]byte("Authorization:"),
		[]byte("Cookie:"),
		[]byte("Proxy-Authorization:"),
		[]byte("Host: app.example"),
		[]byte("Accept: application/json"),
		[]byte("GET /api HTTP/1.1"),
	} {
		if !bytes.Contains(red, keep) {
			t.Fatalf("metadata that must survive was clobbered: %q missing from %q", keep, red)
		}
	}

	// Protocol detection still works on the redacted stream.
	p := l7.NewTracker(443)
	p.OnData(l7.DataEvent{Kind: l7.Request, Payload: red})
	calls := p.OnData(l7.DataEvent{Kind: l7.Response, Payload: []byte("HTTP/1.1 200 OK\r\n\r\n")})
	if len(calls) != 1 || calls[0].Method != "GET" || calls[0].Resource != "/api" || calls[0].Status != "200" {
		t.Fatalf("redacted stream must still parse to metadata: %+v", calls)
	}
}

// TestRedactPayloadZeroesNonStandardSecretHeaders is the EBPF-003 regression
// guard: real services often carry secrets in vendor or custom headers rather
// than the four standard credential headers. Header names and line framing may
// survive as metadata; secret values must not.
func TestRedactPayloadZeroesNonStandardSecretHeaders(t *testing.T) {
	req := []byte("GET /api HTTP/1.1\r\n" +
		"Host: app.example\r\n" +
		"X-API-Key: api-key-secret\r\n" +
		"Api-Key: second-api-key-secret\r\n" +
		"X-Amz-Security-Token: aws-session-token-secret\r\n" +
		"X-Auth-Token: auth-token-secret\r\n" +
		"X-Client-Secret: client-secret-value\r\n" +
		"X-Custom-Token: custom-token-value\r\n" +
		"Traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00\r\n\r\n")
	red := RedactPayload(append([]byte(nil), req...), RedactHeaders)

	for _, secret := range [][]byte{
		[]byte("api-key-secret"),
		[]byte("second-api-key-secret"),
		[]byte("aws-session-token-secret"),
		[]byte("auth-token-secret"),
		[]byte("client-secret-value"),
		[]byte("custom-token-value"),
	} {
		if bytes.Contains(red, secret) {
			t.Fatalf("non-standard secret header value leaked through headers-mode redaction: %q in %q", secret, red)
		}
	}
	for _, keep := range [][]byte{
		[]byte("X-API-Key:"),
		[]byte("Api-Key:"),
		[]byte("X-Amz-Security-Token:"),
		[]byte("X-Auth-Token:"),
		[]byte("X-Client-Secret:"),
		[]byte("X-Custom-Token:"),
		[]byte("Traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"),
	} {
		if !bytes.Contains(red, keep) {
			t.Fatalf("metadata that must survive was clobbered: %q missing from %q", keep, red)
		}
	}
}

func TestRedactPayloadZeroesIdentityHeaderValues(t *testing.T) {
	req := []byte("GET /profile HTTP/1.1\r\n" +
		"Host: app.example\r\n" +
		"X-User-ID: user-123\r\n" +
		"X-Email: alice@example.com\r\n" +
		"X-Subject: employee-alice\r\n" +
		"X-Employee-ID: E-1001\r\n" +
		"X-Account-ID: acct-7788\r\n" +
		"X-Customer-ID: cust-99\r\n" +
		"X-Session-User: session-alice\r\n" +
		"X-Person: Alice Example\r\n" +
		"X-Member-ID: member-42\r\n" +
		"Traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00\r\n\r\n")
	red := redactPayloadWithPolicy(append([]byte(nil), req...), RedactHeaders, headerValuePolicy{
		identityFragments: []string{"member"},
	})

	for _, value := range [][]byte{
		[]byte("user-123"),
		[]byte("alice@example.com"),
		[]byte("employee-alice"),
		[]byte("E-1001"),
		[]byte("acct-7788"),
		[]byte("cust-99"),
		[]byte("session-alice"),
		[]byte("Alice Example"),
		[]byte("member-42"),
	} {
		if bytes.Contains(red, value) {
			t.Fatalf("identity header value leaked through headers-mode redaction: %q in %q", value, red)
		}
	}
	for _, name := range []string{
		"X-User-ID", "X-Email", "X-Subject", "X-Employee-ID", "X-Account-ID",
		"X-Customer-ID", "X-Session-User", "X-Person", "X-Member-ID",
	} {
		assertHeaderValueZeroed(t, red, name)
	}
	if !bytes.Contains(red, []byte("Traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00")) {
		t.Fatalf("non-identity metadata must survive: %q", red)
	}
}

func TestRedactPayloadHashAllHeaderValues(t *testing.T) {
	req := []byte("GET /api HTTP/1.1\r\n" +
		"Host: app.example\r\n" +
		"Accept: application/json\r\n" +
		"Authorization: Bearer should-zero\r\n\r\n")
	red := redactPayloadWithPolicy(append([]byte(nil), req...), RedactHeaders, headerValuePolicy{hashAllValues: true})

	for _, raw := range [][]byte{[]byte("app.example"), []byte("application/json"), []byte("should-zero")} {
		if bytes.Contains(red, raw) {
			t.Fatalf("raw header value leaked in hash-all mode: %q in %q", raw, red)
		}
	}
	if !bytes.Contains(red, []byte("Host:")) || !bytes.Contains(red, []byte("Accept:")) || !bytes.Contains(red, []byte("Authorization:")) {
		t.Fatalf("header names/framing must survive hash-all mode: %q", red)
	}
	if !bytes.Contains(red, []byte("sha256:")) {
		t.Fatalf("non-denied header values should carry a hash marker: %q", red)
	}
	assertHeaderValueZeroed(t, red, "Authorization")
}

func TestRedactPayloadLengthModeZeroesAllBytesWithHeaderPolicy(t *testing.T) {
	req := []byte("GET /api HTTP/1.1\r\nHost: app.example\r\nX-User-ID: user-123\r\n\r\n")
	red := redactPayloadWithPolicy(append([]byte(nil), req...), RedactLengthOnly, headerValuePolicy{
		identityFragments: []string{"member"},
		hashAllValues:     true,
	})
	for i, b := range red {
		if b != 0 {
			t.Fatalf("length mode leaked byte %d=%q with header policy: %q", i, b, red)
		}
	}
}

// TestRedactSensitiveHeaderResponseSetCookie guards the Set-Cookie response
// case explicitly (the value carries the session secret a server issues).
func TestRedactSensitiveHeaderResponseSetCookie(t *testing.T) {
	resp := []byte("HTTP/1.1 200 OK\r\n" +
		"Set-Cookie: session=topsecretvalue; HttpOnly\r\n" +
		"Content-Type: text/html\r\n\r\n")
	red := RedactPayload(append([]byte(nil), resp...), RedactHeaders)
	if bytes.Contains(red, []byte("topsecretvalue")) {
		t.Fatalf("Set-Cookie value leaked: %q", red)
	}
	if !bytes.Contains(red, []byte("Set-Cookie:")) || !bytes.Contains(red, []byte("Content-Type: text/html")) {
		t.Fatalf("Set-Cookie name / other headers must survive: %q", red)
	}
}

func assertHeaderValueZeroed(t *testing.T, payload []byte, name string) {
	t.Helper()
	prefix := []byte(name + ":")
	start := bytes.Index(payload, prefix)
	if start < 0 {
		t.Fatalf("header name %q missing from %q", name, payload)
	}
	valueStart := start + len(prefix)
	eol := bytes.Index(payload[valueStart:], []byte("\r\n"))
	if eol < 0 {
		t.Fatalf("header %q has no CRLF in %q", name, payload)
	}
	value := payload[valueStart : valueStart+eol]
	for i, b := range value {
		if b != 0 {
			t.Fatalf("%s value byte %d not zeroed: %q in %q", name, i, b, payload)
		}
	}
}
