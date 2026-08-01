// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// genCert writes a self-signed TLS server certificate (tls.crt + tls.key) and its
// CA (ca.crt) to a directory, for the HTTPS-by-default quickstart deploys. All
// crypto routes through internal/crypto (FIPS enabler). It is a convenience for
// getting an HTTPS listener up immediately; production operators bring their own
// CA-issued certificate.
//
//	probectl-control gen-cert [--if-missing] [dir] # default dir: current directory
//	PROBECTL_CERT_HOSTS=host1,host2 ...             # SANs (default: localhost,127.0.0.1)
func genCert(args []string) error {
	ifMissing := false
	if len(args) > 0 && args[0] == "--if-missing" {
		ifMissing = true
		args = args[1:]
	}
	if len(args) > 1 || (len(args) == 1 && strings.HasPrefix(args[0], "-")) {
		return fmt.Errorf("usage: probectl-control gen-cert [--if-missing] [dir]")
	}

	dir := "."
	if len(args) > 0 && args[0] != "" {
		dir = args[0]
	}
	if ifMissing {
		complete, err := certBundleComplete(dir)
		if err != nil {
			return err
		}
		if complete {
			fmt.Fprintf(os.Stdout, "kept existing tls.crt, tls.key, ca.crt in %s\n", dir)
			return nil
		}
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
	fmt.Fprintf(os.Stdout, "wrote tls.crt, tls.key, ca.crt to %s (SANs: %s; valid 365d)\n", dir, strings.Join(hosts, ","))
	return nil
}

func certBundleComplete(dir string) (bool, error) {
	names := []string{"tls.crt", "tls.key", "ca.crt"}
	present := 0
	for _, name := range names {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			return false, fmt.Errorf("inspect existing certificate bundle %s: %w", path, err)
		case !info.Mode().IsRegular():
			return false, fmt.Errorf("incomplete certificate bundle in %s: %s is not a regular file; refusing to replace any existing certificate material", dir, name)
		case info.Size() == 0:
			return false, fmt.Errorf("incomplete certificate bundle in %s: %s is empty; refusing to replace any existing certificate material", dir, name)
		default:
			present++
		}
	}
	if present == len(names) {
		return true, nil
	}
	if present != 0 {
		return false, fmt.Errorf("incomplete certificate bundle in %s: found %d of %d required files; repair it or remove all three before retrying", dir, present, len(names))
	}
	return false, nil
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
