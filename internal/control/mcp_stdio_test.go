// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store/pathstore"
)

func TestMCPCompositionAppliesStdioCostPolicy(t *testing.T) {
	for _, cfg := range []*config.Config{{MCPStdioWorkers: -1}, {MCPStdioQueued: -1}} {
		paths := pathstore.NewMemory()
		t.Cleanup(func() { _ = paths.Close() })
		log := slog.New(slog.NewTextHandler(io.Discard, nil))
		server := NewMCPServer(cfg, log, nil, paths, 0, NewAIEgressGate(cfg, log, nil), nil, nil)
		var output bytes.Buffer
		if err := server.ServeStdio(t.Context(), strings.NewReader("not read"), &output, &auth.Principal{TenantID: "owned", UserID: "owner"}); err == nil || output.Len() != 0 {
			t.Fatal("shared serving/stdio constructor discarded invalid operator cost policy")
		}
	}
}

func TestMCPCompositionAppliesHTTPWorkCostBeforeAuthentication(t *testing.T) {
	for _, cfg := range []*config.Config{{MCPHTTPWorkTimeout: -time.Second}, {MCPHTTPActiveRequests: -1}} {
		paths := pathstore.NewMemory()
		t.Cleanup(func() { _ = paths.Close() })
		log := slog.New(slog.NewTextHandler(io.Discard, nil))
		server := NewMCPServer(cfg, log, nil, paths, 0, NewAIEgressGate(cfg, log, nil), nil, nil)
		probe := &controlOriginAuth{}
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "https://localhost/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		r.Header.Set("Authorization", "Bearer owned-cost-fixture")
		server.HTTPHandler(probe).ServeHTTP(w, r)
		if w.Code != http.StatusServiceUnavailable || probe.calls != 0 {
			t.Fatal("shared constructor discarded invalid HTTP work policy")
		}
	}
}
