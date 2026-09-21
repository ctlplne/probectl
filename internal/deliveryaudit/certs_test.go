// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package deliveryaudit

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	probcrypto "github.com/ctlplne/probectl/internal/crypto"
)

func TestGenerateDisposableCertificates(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "certs")
	manifest, err := GenerateDisposableCertificates(out, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != CertificateManifestSchema || manifest.TTLSeconds != 7200 || manifest.ValidFrom.IsZero() || len(manifest.Services) != 6 {
		t.Fatalf("manifest = %#v", manifest)
	}
	if manifest.ExpiresAt.Sub(manifest.GeneratedAt) > 2*time.Hour || !manifest.ExpiresAt.After(manifest.GeneratedAt) {
		t.Fatalf("manifest lifetime = %s", manifest.ExpiresAt.Sub(manifest.GeneratedAt))
	}
	rootInfo, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if got := rootInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("root mode = %04o, want 0700", got)
	}
	caData, err := os.ReadFile(filepath.Join(out, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	caBlock, rest := pem.Decode(caData)
	if caBlock == nil || len(rest) != 0 {
		t.Fatal("CA certificate is not one PEM block")
	}
	caCert, err := probcrypto.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if validity := caCert.NotAfter.Sub(caCert.NotBefore); validity > 2*time.Hour {
		t.Fatalf("CA validity = %s, exceeds requested 2h", validity)
	}
	for _, service := range manifest.Services {
		certPath := filepath.Join(out, filepath.FromSlash(service.Certificate.Path))
		certInfo, err := os.Stat(certPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := certInfo.Mode().Perm(); got != 0o644 {
			t.Fatalf("%s mode = %04o, want 0644", certPath, got)
		}
		keyPath := filepath.Join(out, service.Name, "tls.key")
		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		keyInfo, err := os.Stat(keyPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := keyInfo.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %04o, want 0600", keyPath, got)
		}
		block, rest := pem.Decode(keyData)
		if block == nil || len(rest) != 0 {
			t.Fatalf("%s is not one PEM block", keyPath)
		}
		wantType := "EC PRIVATE KEY"
		if service.Name == "kafka" {
			wantType = "PRIVATE KEY"
		}
		if block.Type != wantType {
			t.Fatalf("%s PEM type = %q, want %q", keyPath, block.Type, wantType)
		}
		if _, err := probcrypto.ServerTLSConfig(certPath, keyPath); err != nil {
			t.Fatalf("%s certificate/key pair: %v", service.Name, err)
		}
	}
	manifestData, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(manifestData), "tls.key") || strings.Contains(string(manifestData), "PRIVATE KEY") {
		t.Fatalf("public manifest exposes private-key metadata: %s", manifestData)
	}
	var decoded CertificateManifest
	if err := json.Unmarshal(manifestData, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.CACertificate.Path != "ca.crt" {
		t.Fatalf("CA path = %q", decoded.CACertificate.Path)
	}
}

func TestGenerateDisposableCertificatesFailsClosed(t *testing.T) {
	t.Parallel()
	parent := t.TempDir()
	tooShort := filepath.Join(parent, "too-short")
	if _, err := GenerateDisposableCertificates(tooShort, minDisposableCATTL-time.Second); err == nil {
		t.Fatal("TTL below the minimum succeeded")
	}
	if _, err := os.Stat(tooShort); !os.IsNotExist(err) {
		t.Fatalf("short-TTL failure left output: %v", err)
	}
	tooLong := filepath.Join(parent, "too-long")
	if _, err := GenerateDisposableCertificates(tooLong, MaxDisposableCATTL+time.Second); err == nil {
		t.Fatal("TTL longer than six hours succeeded")
	}
	if _, err := os.Stat(tooLong); !os.IsNotExist(err) {
		t.Fatalf("failed generation left output: %v", err)
	}
	existing := filepath.Join(parent, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(existing, "keep")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateDisposableCertificates(existing, time.Hour); err == nil {
		t.Fatal("existing output directory was accepted")
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "keep" {
		t.Fatalf("existing directory changed: %q, %v", got, err)
	}
}

func TestCertificateValidityCoversCompleteReceiptWindow(t *testing.T) {
	started := time.Date(2026, time.August, 11, 12, 0, 0, 0, time.UTC)
	completed := started.Add(time.Hour)
	if !certificateCoversReceipt(started.Add(-time.Minute), completed.Add(time.Minute), started, completed) {
		t.Fatal("leaf covering the complete receipt window was rejected")
	}
	for _, test := range []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
	}{
		{name: "not yet valid", notBefore: started.Add(time.Nanosecond), notAfter: completed.Add(time.Minute)},
		{name: "expires at completion", notBefore: started.Add(-time.Minute), notAfter: completed},
		{name: "expired during audit", notBefore: started.Add(-time.Minute), notAfter: completed.Add(-time.Nanosecond)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if certificateCoversReceipt(test.notBefore, test.notAfter, started, completed) {
				t.Fatal("leaf not valid across the complete receipt window was accepted")
			}
		})
	}
}

func TestGenerateDisposableCertificatesAcceptsExactMinimumTTL(t *testing.T) {
	t.Parallel()
	out := filepath.Join(t.TempDir(), "minimum")
	manifest, err := GenerateDisposableCertificates(out, minDisposableCATTL)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.TTLSeconds != int64(minDisposableCATTL/time.Second) {
		t.Fatalf("TTL seconds = %d", manifest.TTLSeconds)
	}
	for _, service := range manifest.Services {
		if _, err := probcrypto.ServerTLSConfig(
			filepath.Join(out, filepath.FromSlash(service.Certificate.Path)),
			filepath.Join(out, service.Name, "tls.key"),
		); err != nil {
			t.Fatalf("minimum-TTL %s pair: %v", service.Name, err)
		}
	}
}
