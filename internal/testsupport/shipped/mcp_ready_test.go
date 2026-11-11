// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package shipped boots the shipped control plane and agents — the binaries
// built from this tree — on the dev stack the way a production deployment
// runs them, for real-stack receipts that must exercise the production wiring
// end to end: the bus lane supervisor, the silo router and provisioner, the
// OTLP receivers, the provider plane, the least-privilege serve login. It is a
// test harness: nothing in it is linked into a product binary.
package shipped

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMCPTransportReadinessRequiresVerifiedTLSAndBearerRefusal(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		status    int
		challenge string
		want      bool
	}{
		{"authenticated boundary", http.StatusUnauthorized, "Bearer", true},
		{"unauthenticated success", http.StatusOK, "Bearer", false},
		{"unrelated unauthorized endpoint", http.StatusUnauthorized, "", false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" {
					t.Error("readiness probe must not perform an authenticated tool call")
				}
				w.Header().Set("WWW-Authenticate", scenario.challenge)
				w.WriteHeader(scenario.status)
			}))
			defer server.Close()
			if got := mcpTransportReady(t.Context(), server.Client(), server.URL); got != scenario.want {
				t.Fatal("MCP readiness disagreed with the TLS/auth boundary", got, scenario.want)
			}
			if scenario.want && mcpTransportReady(t.Context(), http.DefaultClient, server.URL) {
				t.Fatal("untrusted server certificate qualified as ready")
			}
		})
	}
	if mcpTransportReady(t.Context(), http.DefaultClient, "http://127.0.0.1:1/") {
		t.Fatal("plaintext MCP readiness was permitted")
	}
}
