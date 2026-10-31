// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
)

type originAuthProbe struct{ calls int }

func (p *originAuthProbe) Authenticate(context.Context, string) (*auth.Principal, error) {
	p.calls++
	return principal("tenant-origin", "test.read"), nil
}

func TestHTTPOriginTrustComesOnlyFromExplicitPolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		origins   []string
		headers   http.Header
		want      int
		authCalls int
	}{
		{"absent-native-origin", nil, nil, 200, 1},
		{"default-deny-browser", nil, http.Header{"Origin": []string{"https://evil.example"}}, 403, 0},
		{"host-cannot-grant-trust", nil, http.Header{"Origin": []string{"https://evil.example"}, "Host": []string{"evil.example"}, "X-Forwarded-Host": []string{"evil.example"}}, 403, 0},
		{"explicit-canonical-origin", []string{"HTTPS://Trusted.Example:443"}, http.Header{"Origin": []string{"https://trusted.example"}}, 200, 1},
		{"lowercase-header", []string{"https://trusted.example"}, http.Header{"origin": []string{"https://evil.example"}}, 403, 0},
		{"duplicate-case-header", []string{"https://trusted.example"}, http.Header{"Origin": []string{"https://trusted.example"}, "origin": []string{"https://trusted.example"}}, 403, 0},
		{"multi-origin", []string{"https://trusted.example"}, http.Header{"Origin": []string{"https://trusted.example", "https://evil.example"}}, 403, 0},
		{"opaque-origin", nil, http.Header{"Origin": []string{"null"}}, 403, 0},
		{"empty-origin", nil, http.Header{"Origin": []string{""}}, 403, 0},
		{"invalid-programmatic-policy", []string{"*"}, nil, 503, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(&fakeBackend{}, testGate(), WithHTTPOrigins(tc.origins))
			probe := &originAuthProbe{}
			r := httptest.NewRequest(http.MethodPost, "https://localhost/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
			r.Host = "evil.example"
			for name, values := range tc.headers {
				r.Header[name] = values
			}
			r.Header.Set("Authorization", "Bearer owned-origin-fixture")
			w := httptest.NewRecorder()
			s.HTTPHandler(probe).ServeHTTP(w, r)
			if w.Code != tc.want || probe.calls != tc.authCalls {
				t.Fatal("origin policy did not precede credential/data access", w.Code, probe.calls)
			}
			if strings.Contains(w.Body.String(), "evil.example") {
				t.Fatal("origin refusal echoed untrusted header")
			}
		})
	}
}
