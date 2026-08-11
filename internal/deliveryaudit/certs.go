// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package deliveryaudit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	probcrypto "github.com/ctlplne/probectl/internal/crypto"
)

const (
	MaxDisposableCATTL = 6 * time.Hour
	minDisposableCATTL = 3 * time.Minute
)

type serviceCertificateSpec struct {
	name  string
	hosts []string
}

var disposableServiceCertificates = []serviceCertificateSpec{
	{name: "control", hosts: []string{"control", "probectl-control", "localhost", "127.0.0.1", "::1"}},
	{name: "dex", hosts: []string{"dex", "localhost", "127.0.0.1", "::1"}},
	{name: "postgres", hosts: []string{"postgres", "localhost", "127.0.0.1", "::1"}},
	{name: "kafka", hosts: []string{"kafka", "localhost", "127.0.0.1", "::1"}},
	{name: "clickhouse", hosts: []string{"clickhouse", "localhost", "127.0.0.1", "::1"}},
	{name: "prometheus", hosts: []string{"prometheus", "localhost", "127.0.0.1", "::1"}},
}

// GenerateDisposableCertificates creates a fresh, private directory containing
// one short-lived CA certificate and named server leaves for the real audit
// stack. The CA private key is never exported. Leaf keys are required to start
// those local services, but neither their paths nor their bytes enter the
// public manifest. Kafka receives PKCS#8; the other Go-native services retain
// the issuer's SEC1 key format.
func GenerateDisposableCertificates(outDir string, ttl time.Duration) (CertificateManifest, error) {
	if ttl < minDisposableCATTL || ttl > MaxDisposableCATTL {
		return CertificateManifest{}, fmt.Errorf(
			"delivery audit: certificate ttl must be between %s and %s",
			minDisposableCATTL,
			MaxDisposableCATTL,
		)
	}
	abs, err := filepath.Abs(outDir)
	if err != nil {
		return CertificateManifest{}, fmt.Errorf("delivery audit: resolve certificate directory: %w", err)
	}
	if info, lerr := os.Lstat(abs); lerr == nil {
		return CertificateManifest{}, fmt.Errorf("delivery audit: certificate directory already exists (%s, mode %s)", abs, info.Mode())
	} else if !errors.Is(lerr, os.ErrNotExist) {
		return CertificateManifest{}, fmt.Errorf("delivery audit: inspect certificate directory: %w", lerr)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return CertificateManifest{}, fmt.Errorf("delivery audit: create certificate parent: %w", err)
	}
	if err := os.Mkdir(abs, 0o700); err != nil {
		return CertificateManifest{}, fmt.Errorf("delivery audit: create private certificate directory: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(abs)
		}
	}()

	generatedAt := time.Now().UTC()
	// GenerateCA backdates NotBefore by one minute for clock skew. Subtract
	// that minute from NotAfter so the certificate's total validity interval,
	// not merely its remaining lifetime, stays within the requested <=6h cap.
	ca, err := probcrypto.GenerateCA("probectl-completeness-audit", ttl-time.Minute)
	if err != nil {
		return CertificateManifest{}, fmt.Errorf("delivery audit: generate disposable CA: %w", err)
	}
	caPEM := ca.CertPEM()
	if err := writeNewFile(filepath.Join(abs, "ca.crt"), caPEM, 0o644); err != nil {
		return CertificateManifest{}, err
	}
	manifest := CertificateManifest{
		Schema:      CertificateManifestSchema,
		GeneratedAt: generatedAt,
		ValidFrom:   ca.Cert().NotBefore.UTC(),
		ExpiresAt:   ca.Cert().NotAfter.UTC(),
		TTLSeconds:  int64(ttl / time.Second),
		CACertificate: CertificateReference{
			Path:   "ca.crt",
			SHA256: digestBytes(caPEM),
		},
	}

	leafTTL := ttl - 2*time.Minute
	for _, spec := range disposableServiceCertificates {
		certPEM, keyPEM, issueErr := ca.IssueServerCert(spec.name, spec.hosts, leafTTL)
		if issueErr != nil {
			return CertificateManifest{}, fmt.Errorf("delivery audit: issue %s certificate: %w", spec.name, issueErr)
		}
		if spec.name == "kafka" {
			pkcs8PEM, convertErr := probcrypto.PrivateKeyToPKCS8PEM(keyPEM)
			probcrypto.Zeroize(keyPEM)
			if convertErr != nil {
				return CertificateManifest{}, fmt.Errorf("delivery audit: encode kafka PKCS#8 key: %w", convertErr)
			}
			keyPEM = pkcs8PEM
		}

		serviceDir := filepath.Join(abs, spec.name)
		if err := os.Mkdir(serviceDir, 0o700); err != nil {
			probcrypto.Zeroize(keyPEM)
			return CertificateManifest{}, fmt.Errorf("delivery audit: create %s certificate directory: %w", spec.name, err)
		}
		if err := writeNewFile(filepath.Join(serviceDir, "tls.key"), keyPEM, 0o600); err != nil {
			probcrypto.Zeroize(keyPEM)
			return CertificateManifest{}, err
		}
		probcrypto.Zeroize(keyPEM)
		certPath := filepath.ToSlash(filepath.Join(spec.name, "tls.crt"))
		if err := writeNewFile(filepath.Join(abs, filepath.FromSlash(certPath)), certPEM, 0o644); err != nil {
			return CertificateManifest{}, err
		}
		manifest.Services = append(manifest.Services, ServiceCertificate{
			Name:  spec.name,
			Hosts: append([]string(nil), spec.hosts...),
			Certificate: CertificateReference{
				Path:   certPath,
				SHA256: digestBytes(certPEM),
			},
		})
	}

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return CertificateManifest{}, fmt.Errorf("delivery audit: encode certificate manifest: %w", err)
	}
	manifestJSON = append(manifestJSON, '\n')
	if err := writeNewFile(filepath.Join(abs, "manifest.json"), manifestJSON, 0o644); err != nil {
		return CertificateManifest{}, err
	}
	complete = true
	return manifest, nil
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("delivery audit: create %s: %w", filepath.Base(path), err)
	}
	complete := false
	defer func() {
		_ = f.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("delivery audit: write %s: %w", filepath.Base(path), err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("delivery audit: sync %s: %w", filepath.Base(path), err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("delivery audit: close %s: %w", filepath.Base(path), err)
	}
	complete = true
	return nil
}
