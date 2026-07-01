// SPDX-License-Identifier: LicenseRef-probectl-TBD

package canary

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewHTTPDefaults(t *testing.T) {
	c, err := NewHTTP(Config{Target: "https://example.com/health"})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	h := c.(*httpCanary)
	if h.scheme != "https" || h.host != "example.com" || h.port != "443" {
		t.Errorf("got scheme=%s host=%s port=%s", h.scheme, h.host, h.port)
	}
	if h.method != http.MethodGet {
		t.Errorf("method = %q, want GET", h.method)
	}
	if !h.follow || h.insecure {
		t.Errorf("follow=%v insecure=%v, want true/false", h.follow, h.insecure)
	}
	if h.timeout != 10*time.Second {
		t.Errorf("timeout = %s, want 10s", h.timeout)
	}
	if h.maxBody != defaultMaxBody {
		t.Errorf("maxBody = %d", h.maxBody)
	}
	if !h.statusOK(200) || !h.statusOK(399) || h.statusOK(400) {
		t.Error("default expect should accept 2xx-3xx only")
	}
	if h.Describe().Type != httpType {
		t.Errorf("Describe().Type = %q", h.Describe().Type)
	}
}

func TestHTTPTransportIgnoresAmbientProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:18080")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:18081")

	c, err := NewHTTP(Config{Target: "https://example.com/health"})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	h := c.(*httpCanary)
	var tlsState *tls.ConnectionState
	var tlsVerified *bool
	transport := h.transport(nil, &tlsState, &tlsVerified)
	if transport.Proxy != nil {
		t.Fatal("HTTP canary transport must not honor ambient HTTP_PROXY/HTTPS_PROXY")
	}
}

func TestHTTPCanaryRunBypassesAmbientProxy(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		http.Error(w, "proxy should not be reached", http.StatusBadGateway)
	}))
	defer proxy.Close()

	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	c, err := NewHTTP(Config{
		Target:  target.URL,
		Timeout: time.Second,
		Params:  map[string]string{AllowPrivateParam: "true"},
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.Success {
		t.Fatalf("direct probe failed: success=%v err=%q", res.Success, res.Error)
	}
	if got := targetHits.Load(); got != 1 {
		t.Fatalf("target hits = %d, want 1", got)
	}
	if got := proxyHits.Load(); got != 0 {
		t.Fatalf("ambient proxy hits = %d, want 0", got)
	}
}

func TestNewHTTPParams(t *testing.T) {
	c, err := NewHTTP(Config{
		Target:                  "http://svc.internal:8080/ping",
		Timeout:                 3 * time.Second,
		AllowInsecureSkipVerify: true, // WIRE-004: opt-in so insecure_skip_verify is honored
		Params: map[string]string{
			"method":               "post",
			"expect_status":        "200,201",
			"follow_redirects":     "false",
			"insecure_skip_verify": "true",
			"max_body_bytes":       "2048",
			"ca_file":              "/etc/probectl/ca.pem",
			"body":                 "ping",
		},
	})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	h := c.(*httpCanary)
	if h.scheme != "http" || h.port != "8080" {
		t.Errorf("scheme=%s port=%s", h.scheme, h.port)
	}
	if h.method != "POST" {
		t.Errorf("method = %q, want POST", h.method)
	}
	if h.follow || !h.insecure {
		t.Errorf("follow=%v insecure=%v", h.follow, h.insecure)
	}
	if h.maxBody != 2048 || h.caFile != "/etc/probectl/ca.pem" || h.body != "ping" {
		t.Errorf("maxBody=%d caFile=%q body=%q", h.maxBody, h.caFile, h.body)
	}
	if h.timeout != 3*time.Second {
		t.Errorf("timeout = %s", h.timeout)
	}
	if !h.statusOK(200) || !h.statusOK(201) || h.statusOK(204) {
		t.Error("expect_status 200,201 mismatch")
	}
}

func TestNewHTTPErrors(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{"empty", Config{Target: "  "}},
		{"bad scheme", Config{Target: "ftp://example.com"}},
		{"no host", Config{Target: "http://"}},
		{"bad max_body", Config{Target: "http://x.test", Params: map[string]string{"max_body_bytes": "-5"}}},
		{"bad expect", Config{Target: "http://x.test", Params: map[string]string{"expect_status": "wat"}}},
		// WIRE-004: insecure_skip_verify=true is refused unless the agent opts in.
		{"insecure not allowed", Config{Target: "https://x.test", Params: map[string]string{"insecure_skip_verify": "true"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewHTTP(tc.cfg); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestParseExpectStatus(t *testing.T) {
	ok := []struct {
		in   string
		want []statusRange
	}{
		{"", []statusRange{{200, 399}}},
		{"200", []statusRange{{200, 200}}},
		{"2xx", []statusRange{{200, 299}}},
		{"200-204", []statusRange{{200, 204}}},
		{"200,404,5xx", []statusRange{{200, 200}, {404, 404}, {500, 599}}},
	}
	for _, tc := range ok {
		got, err := parseExpectStatus(tc.in)
		if err != nil {
			t.Errorf("parseExpectStatus(%q): %v", tc.in, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("parseExpectStatus(%q) = %v, want %v", tc.in, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseExpectStatus(%q)[%d] = %v, want %v", tc.in, i, got[i], tc.want[i])
			}
		}
	}

	for _, bad := range []string{"abc", "099", "600", "6xx", "300-200", "10-20"} {
		if _, err := parseExpectStatus(bad); err == nil {
			t.Errorf("parseExpectStatus(%q) should error", bad)
		}
	}
}

func TestStatusOK(t *testing.T) {
	c := &httpCanary{expect: mustExpect(t, "5xx")}
	if !c.statusOK(503) || c.statusOK(200) {
		t.Error("5xx matcher wrong")
	}
}

func TestDescribeExpect(t *testing.T) {
	got := describeExpect([]statusRange{{200, 200}, {500, 599}})
	if got != "200,500-599" {
		t.Errorf("describeExpect = %q", got)
	}
}

func TestTLSVersionName(t *testing.T) {
	for v, want := range map[uint16]string{
		0x0304: "1.3",
		0x0303: "1.2",
		0x0302: "1.1",
		0x0301: "1.0",
	} {
		if got := tlsVersionName(v); got != want {
			t.Errorf("tlsVersionName(%#x) = %q, want %q", v, got, want)
		}
	}
	if got := tlsVersionName(0x0300); got != "0x0300" {
		t.Errorf("unknown version = %q", got)
	}
}

func TestChainSummary(t *testing.T) {
	chain := []*x509.Certificate{
		{Subject: pkix.Name{CommonName: "leaf.example"}},
		{Subject: pkix.Name{CommonName: "Intermediate CA"}},
		{Subject: pkix.Name{CommonName: "Root CA"}},
	}
	if got := chainSummary(chain); got != "leaf.example > Intermediate CA > Root CA" {
		t.Errorf("chainSummary = %q", got)
	}
}

func TestAttachPeer(t *testing.T) {
	res := &Result{Attributes: map[string]string{}}
	attachPeer(res, "203.0.113.9:443")
	if res.Attributes["network.peer.address"] != "203.0.113.9" || res.Attributes["network.peer.port"] != "443" {
		t.Errorf("peer attrs = %v", res.Attributes)
	}

	res2 := &Result{Attributes: map[string]string{}}
	attachPeer(res2, "")
	if len(res2.Attributes) != 0 {
		t.Errorf("empty peer should add nothing, got %v", res2.Attributes)
	}
}

func TestMsf(t *testing.T) {
	if msf(time.Second) != 1000 {
		t.Errorf("msf(1s) = %v, want 1000", msf(time.Second))
	}
}

func mustExpect(t *testing.T, s string) []statusRange {
	t.Helper()
	r, err := parseExpectStatus(s)
	if err != nil {
		t.Fatalf("parseExpectStatus(%q): %v", s, err)
	}
	return r
}
