// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// DPR-077: a control plane behind a private CA is the enterprise norm, and Go
// on macOS ignores SSL_CERT_FILE — so the CLI takes the CA bundle itself
// (PROBECTL_CA_FILE / --ca-file). Verification is never switched off: without
// the bundle the request fails on the certificate, and an unreadable bundle
// fails with the reason instead of falling back to "trust anything".
func TestCLITrustsAPrivateCAOnlyThroughCAFile(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/threat/rules", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"rules_running": true, "overlay_dir": "", "rules": []any{}})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	runCA := func(ca string, args ...string) (string, string, int) {
		var out, errb bytes.Buffer
		env := func(k string) string {
			switch k {
			case "PROBECTL_API_URL":
				return srv.URL
			case "PROBECTL_API_TOKEN":
				return "t"
			case "PROBECTL_CA_FILE":
				return ca
			}
			return ""
		}
		code := runCLI(args, env, &out, &errb)
		return out.String(), errb.String(), code
	}

	if out, errb, code := runCA(caFile, "threat", "rules"); code != 0 || !strings.Contains(out, "rules_running") {
		t.Fatalf("with the CA bundle the call must succeed: code=%d out=%q err=%q", code, out, errb)
	}
	if out, errb, code := runCA("", "threat", "rules"); code == 0 || (!strings.Contains(errb, "certificate") && !strings.Contains(errb, "x509")) {
		t.Fatalf("without the bundle the private CA must be REJECTED, never trusted: code=%d out=%q err=%q", code, out, errb)
	}
	if _, errb, code := runCA(filepath.Join(t.TempDir(), "missing.crt"), "threat", "rules"); code == 0 || !strings.Contains(errb, "PROBECTL_CA_FILE") {
		t.Fatalf("an unreadable bundle must fail naming the knob: code=%d err=%q", code, errb)
	}
	if _, errb, code := runCA(caFile, "--ca-file", filepath.Join(t.TempDir(), "nope.crt"), "threat", "rules"); code == 0 || !strings.Contains(errb, "PROBECTL_CA_FILE") {
		t.Fatalf("--ca-file must override the environment: code=%d err=%q", code, errb)
	}
	// The bundle is parsed as PEM certificates, nothing else.
	if _, err := x509.ParseCertificate(srv.Certificate().Raw); err != nil {
		t.Fatal(err)
	}
}
