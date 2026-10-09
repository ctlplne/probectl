// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/crypto"
)

// TestBillingExportDeliversTheSignedFeed: `probectl billing export` decoded
// the CSV (or JSON Lines) billing feed as one JSON value and failed on every
// export, so the documented CLI leg of the MSP usage export never delivered
// anything. It now writes the feed exactly as served, and only after the
// detached Ed25519 signature the server puts on every export verifies over
// those bytes. A tampered body, a missing signature, or a key that does not
// match its fingerprint is refused, and nothing is written.
func TestBillingExportDeliversTheSignedFeed(t *testing.T) {
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	const feed = "tenant_id,tenant_slug,meter,kind,period_start,period_end,value,unit\n" +
		"t-1,acme,ai_calls,counter,2026-10-01T00:00:00Z,2026-10-02T00:00:00Z,2,count\n"
	sig, err := crypto.SignEd25519(priv, []byte(feed))
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := "sha256:" + hex.EncodeToString(crypto.Hash(pub))
	for _, tc := range []struct {
		name        string
		body        string
		headers     map[string]string
		wantRefusal bool
	}{
		{name: "signed", body: feed},
		{name: "tampered body", body: strings.Replace(feed, ",2,count", ",9,count", 1), wantRefusal: true},
		{name: "unsigned", body: feed, headers: map[string]string{"X-Probectl-Usage-Signature": ""}, wantRefusal: true},
		{name: "key does not match its fingerprint", body: feed, headers: map[string]string{
			"X-Probectl-Usage-Signing-Key-Fingerprint": "sha256:" + strings.Repeat("0", 64)}, wantRefusal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/provider/v1/usage/export" || r.URL.Query().Get("format") != "csv" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "text/csv; charset=utf-8")
				w.Header().Set("Content-Disposition", `attachment; filename="probectl-usage.csv"`)
				w.Header().Set("X-Probectl-Usage-Signature-Alg", "ed25519")
				w.Header().Set("X-Probectl-Usage-Signature", base64.StdEncoding.EncodeToString(sig))
				w.Header().Set("X-Probectl-Usage-Signing-Key", base64.StdEncoding.EncodeToString(pub))
				w.Header().Set("X-Probectl-Usage-Signing-Key-Fingerprint", fingerprint)
				for k, v := range tc.headers {
					w.Header().Set(k, v)
				}
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			env := map[string]string{"PROBECTL_API_URL": srv.URL, "PROBECTL_API_TOKEN": "operator-session"}
			var stdout, stderr bytes.Buffer
			code := RunWithStdin([]string{"--json", "billing", "export", "--query", "format=csv"},
				func(k string) string { return env[k] }, strings.NewReader(""), &stdout, &stderr)
			if tc.wantRefusal {
				if code == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "refused") {
					t.Fatalf("exit %d, stdout %q, stderr %q; want the export refused and nothing written", code, stdout.String(), stderr.String())
				}
				return
			}
			if code != 0 || stdout.String() != feed {
				t.Fatalf("exit %d, stderr %q; stdout %q, want the feed exactly as served", code, stderr.String(), stdout.String())
			}
		})
	}
}
