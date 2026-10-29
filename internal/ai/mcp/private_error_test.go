// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/logging"
)

func TestMCPDependencyDetailsNeverReachLogsOrWire(t *testing.T) {
	privateMarker := "MCP-PRIVATE-ERROR-DETAIL"
	backend := &fakeBackend{listTestsErr: errors.New("postgres://qa:" + privateMarker + "@example.test/db")}
	var logs bytes.Buffer
	server := newTestServer(backend, testGate(), WithLogger(logging.New(&logs, "warn", "json")))
	principal := &auth.Principal{TenantID: "owned", UserID: "reader", Permissions: map[string]bool{"test.read": true}}
	raw := server.Handle(t.Context(), principal, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_tests","arguments":{}}}`))
	if bytes.Contains(raw, []byte(privateMarker)) {
		t.Fatal("dependency details reached MCP response")
	}
	if strings.Contains(logs.String(), privateMarker) {
		t.Fatal("private dependency error reached production logger")
	}
}

func TestMCPErrorClassDoesNotTrustArbitraryDomainCodes(t *testing.T) {
	marker := "PRIVATE-CODE-AND-MESSAGE"
	if ErrorClass(&apierror.Error{Code: marker, Message: marker}) != "dependency" {
		t.Fatal("unrecognized domain code became log metadata")
	}
	if ErrorClass(apierror.Validation(marker)) != "validation" {
		t.Fatal("known public failure lost its bounded class")
	}
}

type privateErrorAuthenticator struct{ err error }

func (a privateErrorAuthenticator) Authenticate(context.Context, string) (*auth.Principal, error) {
	return nil, a.err
}

func TestMCPPrivateErrorsAreOmittedFromEveryDependencyLogBoundary(t *testing.T) {
	marker := "MCP-PRIVATE-HOOK-DETAIL"
	private := errors.New("postgres://qa:" + marker + "@example.test/db")
	for _, kind := range []string{"authentication", "discovery-policy", "invocation-policy", "call-audit", "egress-denial-audit", "egress-result-audit"} {
		t.Run(kind, func(t *testing.T) {
			var logs bytes.Buffer
			gate := testGate()
			opts := []Option{WithLogger(logging.New(&logs, "warn", "json"))}
			switch kind {
			case "discovery-policy", "invocation-policy":
				opts = append(opts, WithPolicyLoader(func(context.Context, string) ([]auth.Policy, error) { return nil, private }))
			case "call-audit":
				opts = append(opts, WithCallAudit(func(context.Context, CallEvent) error { return private }))
			case "egress-denial-audit":
				gate = ai.NewEgressGate(func(context.Context, string) (bool, error) { return false, nil }, func(context.Context, ai.EgressEvent) error { return private }, ai.RedactionPolicy{})
			case "egress-result-audit":
				gate = ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil }, func(context.Context, ai.EgressEvent) error { return private }, ai.RedactionPolicy{})
			}
			server := newTestServer(&fakeBackend{}, gate, opts...)
			p := &auth.Principal{TenantID: "owned", UserID: "reader", Permissions: map[string]bool{"test.read": true}}
			request := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_tests","arguments":{}}}`)
			if kind == "discovery-policy" {
				request = []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
			}
			var response []byte
			if kind == "authentication" {
				r := httptest.NewRequest(http.MethodPost, "https://localhost/mcp", bytes.NewReader(request))
				r.Header.Set("Authorization", "Bearer fixture-only")
				w := httptest.NewRecorder()
				server.HTTPHandler(privateErrorAuthenticator{private}).ServeHTTP(w, r)
				response = w.Body.Bytes()
			} else {
				response = server.Handle(t.Context(), p, request)
			}
			if bytes.Contains(response, []byte(marker)) || strings.Contains(logs.String(), marker) {
				t.Fatal("private dependency detail escaped a boundary")
			}
			if !strings.Contains(logs.String(), "error_class") {
				t.Fatal("dependency refusal lost bounded diagnostic class")
			}
		})
	}
}
