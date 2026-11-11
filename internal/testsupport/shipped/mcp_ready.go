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
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The main API can become ready before the optional MCP listener is bound.
// Wait for its TLS-verified, fail-closed authentication boundary too, rather
// than racing a functional tool call against secondary transport startup.
func (s *Stack) awaitConfiguredMCP(t *testing.T, env []string) {
	t.Helper()
	addr := ""
	for _, entry := range env {
		if value, ok := strings.CutPrefix(entry, "PROBECTL_MCP_HTTP_ADDR="); ok {
			addr = value
		}
	}
	if addr == "" {
		return
	}
	s.await(t, "the configured MCP HTTPS authentication boundary", 90*time.Second, func() bool {
		return mcpTransportReady(t.Context(), s.client, "https://"+addr+"/")
	})
}

func mcpTransportReady(ctx context.Context, client *http.Client, endpoint string) bool {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil || client == nil || request.URL.Scheme != "https" {
		return false
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusUnauthorized && response.Header.Get("WWW-Authenticate") == "Bearer"
}
