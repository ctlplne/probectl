package crypto

import (
	"crypto/tls"
	"net/http"
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
}
