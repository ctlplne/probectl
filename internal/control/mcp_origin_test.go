// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store/pathstore"
)

type controlOriginAuth struct{ calls int }

func (a *controlOriginAuth) Authenticate(context.Context, string) (*auth.Principal, error) {
	a.calls++
	return &auth.Principal{TenantID: "00000000-0000-0000-0000-000000000001", UserID: "owned-origin-reader"}, nil
}

func TestMCPHTTPCompositionAppliesConfiguredOrigins(t *testing.T) {
	for _, tc := range []struct {
		origins     []string
		origin      string
		want, calls int
	}{
		{[]string{"https://trusted.example"}, "https://trusted.example", 200, 1},
		{[]string{"https://trusted.example"}, "https://evil.example", 403, 0},
		{[]string{"*"}, "", 503, 0},
	} {
		cfg := &config.Config{MCPAllowedOrigins: tc.origins}
		paths := pathstore.NewMemory()
		t.Cleanup(func() { _ = paths.Close() })
		log := slog.New(slog.NewTextHandler(io.Discard, nil))
		server := NewMCPServer(cfg, log, nil, paths, 0, NewAIEgressGate(cfg, log, nil), nil, nil)
		probe := &controlOriginAuth{}
		request := httptest.NewRequest(http.MethodPost, "https://localhost/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		request.Header.Set("Authorization", "Bearer owned-composition-fixture")
		if tc.origin != "" {
			request.Header.Set("Origin", tc.origin)
		}
		w := httptest.NewRecorder()
		server.HTTPHandler(probe).ServeHTTP(w, request)
		if w.Code != tc.want || probe.calls != tc.calls {
			t.Fatal("serving/stdio shared constructor lost origin policy", w.Code, probe.calls)
		}
	}
}
