// SPDX-License-Identifier: LicenseRef-probectl-TBD

package crypto

import (
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHardenedClientTLSConfig(t *testing.T) {
	cfg := HardenedClientTLSConfig()
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %x, want TLS 1.2", cfg.MinVersion)
	}
	if cfg.InsecureSkipVerify {
		t.Error("outbound client TLS must validate certificates (InsecureSkipVerify must be false)")
	}
}

func TestHardenedHTTPClient(t *testing.T) {
	c := HardenedHTTPClient(5 * time.Second)
	if c.Timeout != 5*time.Second {
		t.Errorf("timeout = %v, want 5s", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", c.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Error("transport must use the hardened TLS policy (1.2+)")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("certificate validation must be on")
	}
	if c.CheckRedirect == nil {
		t.Fatal("hardened HTTP client must install the shared redirect policy")
	}
}

func TestHardenedHTTPClientRejectsHTTPSDowngradeRedirect(t *testing.T) {
	c := HardenedHTTPClient(5 * time.Second)
	err := c.CheckRedirect(requestFor(t, "http://feeds.example.test/next"), []*http.Request{
		requestFor(t, "https://feeds.example.test/start"),
	})
	if err == nil || !strings.Contains(err.Error(), "scheme downgrade") {
		t.Fatalf("redirect error = %v, want scheme downgrade rejection", err)
	}
}

func TestHardenedHTTPClientRejectsPrivateRedirectTarget(t *testing.T) {
	c := HardenedHTTPClient(5 * time.Second)
	for _, target := range []string{
		"https://127.0.0.1/admin",
		"https://10.0.0.7/secret",
		"https://169.254.169.254/latest/meta-data",
		"https://metadata.google.internal/computeMetadata/v1/",
		"https://localhost/debug",
	} {
		t.Run(target, func(t *testing.T) {
			err := c.CheckRedirect(requestFor(t, target), []*http.Request{
				requestFor(t, "https://feeds.example.test/start"),
			})
			if err == nil || !strings.Contains(err.Error(), "private/link-local target") {
				t.Fatalf("redirect error = %v, want private/link-local rejection", err)
			}
		})
	}
}

func TestHardenedHTTPClientRejectsCrossOriginCredentialRedirect(t *testing.T) {
	c := HardenedHTTPClient(5 * time.Second)
	first := requestFor(t, "https://vault.example.test/v1/secret/data/app")
	first.Header.Set("X-Vault-Token", "sensitive")
	first.Header.Set("X-Custom-Credential", "tenant-secret")
	err := c.CheckRedirect(requestFor(t, "https://evil.example.test/capture"), []*http.Request{first})
	if err == nil || !strings.Contains(err.Error(), "credential-bearing request crossed origin") {
		t.Fatalf("redirect error = %v, want cross-origin credential rejection", err)
	}
}

func TestHardenedHTTPClientAllowsSameOriginCredentialRedirect(t *testing.T) {
	c := HardenedHTTPClient(5 * time.Second)
	first := requestFor(t, "https://vault.example.test/v1/secret/data/app")
	first.Header.Set("X-Vault-Token", "sensitive")
	err := c.CheckRedirect(requestFor(t, "https://vault.example.test/v1/secret/data/next"), []*http.Request{first})
	if err != nil {
		t.Fatalf("same-origin credential redirect rejected: %v", err)
	}
}

func TestHardenedHTTPClientRejectsMaxHopRedirect(t *testing.T) {
	c := HardenedHTTPClient(5 * time.Second)
	via := make([]*http.Request, 0, hardenedHTTPMaxRedirects)
	for i := 0; i < hardenedHTTPMaxRedirects; i++ {
		via = append(via, requestFor(t, "https://feeds.example.test/hop"))
	}
	err := c.CheckRedirect(requestFor(t, "https://feeds.example.test/final"), via)
	if err == nil || !strings.Contains(err.Error(), "redirect rejected after") {
		t.Fatalf("redirect error = %v, want max-hop rejection", err)
	}
}

func requestFor(t *testing.T, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request %q: %v", rawURL, err)
	}
	return req
}
