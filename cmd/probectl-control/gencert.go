package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// genCert writes a self-signed TLS server certificate (tls.crt + tls.key) and its
// CA (ca.crt) to a directory, for the HTTPS-by-default quickstart deploys. All
// crypto routes through internal/crypto (FIPS enabler). It is a convenience for
// getting an HTTPS listener up immediately; production operators bring their own
// CA-issued certificate.
//
//	probectl-control gen-cert [dir]      # default dir: the current directory
//	PROBECTL_CERT_HOSTS=host1,host2 ...  # SANs (default: localhost,127.0.0.1)
func genCert(args []string) error {
	dir := "."
	if len(args) > 0 && args[0] != "" {
		dir = args[0]
	}
	hosts := []string{"localhost", "127.0.0.1"}
	if env := strings.TrimSpace(os.Getenv("PROBECTL_CERT_HOSTS")); env != "" {
		hosts = splitTrim(env)
	}

	const ttl = 365 * 24 * time.Hour
	ca, err := crypto.GenerateCA("probectl quickstart CA", ttl)
	if err != nil {
		return fmt.Errorf("generate CA: %w", err)
	}
	certPEM, keyPEM, err := ca.IssueServerCert("probectl", hosts, ttl)
	if err != nil {
		return fmt.Errorf("issue server cert: %w", err)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"tls.crt", certPEM, 0o644},
		{"tls.key", keyPEM, 0o600},
		{"ca.crt", ca.CertPEM(), 0o644},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, f.mode); err != nil {
			return fmt.Errorf("write %s: %w", f.name, err)
		}
	}
	fmt.Printf("wrote tls.crt, tls.key, ca.crt to %s (SANs: %s; valid 365d)\n", dir, strings.Join(hosts, ","))
	return nil
}

func splitTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
