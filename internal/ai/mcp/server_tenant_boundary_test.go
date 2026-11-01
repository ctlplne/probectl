// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/auth"
)

func TestHandleTenantBoundaryPrecedesMalformedProtocol(t *testing.T) {
	// encoding/json accepts replacement of invalid UTF-8 inside a JSON string,
	// but the strict MCP decoder rejects it. A tenantless caller must receive
	// the same authorization result without learning which decoder rejected it.
	malformedUTF8 := append([]byte(`{"jsonrpc":"2.0","id":9,"method":"tools/list","x":"`), 0xff)
	malformedUTF8 = append(malformedUTF8, []byte(`"}`)...)
	if utf8.Valid(malformedUTF8) {
		t.Fatal("fixture must contain invalid UTF-8")
	}
	var parsed rpcRequest
	if err := json.Unmarshal(malformedUTF8, &parsed); err != nil || len(parsed.ID) == 0 {
		t.Fatalf("fixture must reproduce the fuzz precondition: %v, id=%s", err, parsed.ID)
	}
	for _, tc := range []struct {
		name      string
		principal *auth.Principal
		raw       []byte
		wantNil   bool
	}{
		{"missing tenant malformed UTF-8", &auth.Principal{UserID: "u"}, malformedUTF8, false},
		{"nil principal malformed UTF-8", nil, malformedUTF8, false},
		{"missing tenant malformed JSON", &auth.Principal{UserID: "u"}, []byte(`{bad json`), false},
		{"missing tenant invalid envelope field type", &auth.Principal{UserID: "u"}, []byte(`{"jsonrpC":0}`), false},
		{"missing tenant notification", &auth.Principal{UserID: "u"}, []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &fakeBackend{}
			server := newTestServer(backend, testGate(), WithRateLimit(0))
			response := server.Handle(context.Background(), tc.principal, tc.raw)
			if tc.wantNil {
				if response != nil {
					t.Fatalf("notification returned %s", response)
				}
			} else {
				var decoded rpcResponse
				if err := json.Unmarshal(response, &decoded); err != nil || decoded.Error == nil || decoded.Error.Code != codeUnauthorized {
					t.Fatalf("tenantless response = %s, decode error = %v", response, err)
				}
			}
			if calls := backend.seen(); len(calls) != 0 {
				t.Fatalf("tenantless caller reached backend: %v", calls)
			}
		})
	}
}
