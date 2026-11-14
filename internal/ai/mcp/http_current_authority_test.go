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
	"sync/atomic"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
)

func TestModernHTTPChangedAuthorityRefusesPublication(t *testing.T) {
	for _, change := range []string{"revoked", "tenant", "user", "permissions", "attributes", "mfa", "abac", "abac-unavailable"} {
		t.Run(change, func(t *testing.T) {
			var changed atomic.Bool
			backend := &legacyAuthorityBackend{nativeBackendProbe: &nativeBackendProbe{}, changed: &changed}
			backend.result.Flow.Rows = []NativeFlowRow{{Group: []NativeFlowDimension{{Field: "protocol", Value: "original-private-row"}}}}
			server := nativeProbeServer(backend, nil)
			WithPolicyLoader(func(context.Context, string) ([]auth.Policy, error) {
				if changed.Load() && change == "abac-unavailable" {
					return nil, errors.New("private policy store detail")
				}
				if changed.Load() && change == "abac" {
					return []auth.Policy{{Name: "current-denial", Enabled: true, Effect: auth.PolicyDeny, Permission: "device.read"}}, nil
				}
				return nil, nil
			})(server)
			var successes atomic.Int32
			server.gate = ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil }, func(context.Context, ai.EgressEvent) error { successes.Add(1); return nil }, ai.RedactionPolicy{})
			authn := protocolAuthFunc(func(context.Context, string) (*auth.Principal, error) {
				principal := nativePrincipal()
				if changed.Load() {
					switch change {
					case "revoked":
						return nil, errors.New("private revoked token detail")
					case "tenant":
						principal.TenantID = "sibling"
					case "user":
						principal.UserID = "sibling"
					case "permissions":
						principal.Permissions = nil
					case "attributes":
						principal.Attributes = map[string]string{"changed": "value"}
					case "mfa":
						principal.MFASatisfied = !principal.MFASatisfied
					}
				}
				return principal, nil
			})
			socket := httptest.NewTLSServer(server.HTTPHandler(authn))
			t.Cleanup(socket.Close)
			body := modernRequest("tools/call", map[string]any{"name": "flow_explorer_query", "arguments": map[string]any{"plan": map[string]any{}}})
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL, bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			for key, value := range map[string]string{"Authorization": "Bearer owned", "Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": modernProtocolVersion, "Mcp-Method": "tools/call", "Mcp-Name": "flow_explorer_query"} {
				request.Header.Set(key, value)
			}
			response, err := socket.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			raw := legacyBody(t, response)
			if !changed.Load() || bytes.Contains(raw, []byte("original-private-row")) || bytes.Contains(raw, []byte("private revoked")) || bytes.Contains(raw, []byte("private policy")) || successes.Load() != 0 || !bytes.Contains(raw, []byte(`"error"`)) {
				t.Fatal("changed credential or policy published native data or an egress success", "source_executed", changed.Load(), "private_row", bytes.Contains(raw, []byte("original-private-row")), "egress_successes", successes.Load())
			}
		})
	}
}

func TestAuthenticatedStdioChangedGrantsRefusesPublication(t *testing.T) {
	for _, change := range []string{"permissions", "attributes", "mfa", "abac", "abac-unavailable"} {
		t.Run(change, func(t *testing.T) {
			var changed atomic.Bool
			backend := &legacyAuthorityBackend{nativeBackendProbe: &nativeBackendProbe{}, changed: &changed}
			backend.result.Flow.Rows = []NativeFlowRow{{Group: []NativeFlowDimension{{Field: "protocol", Value: "original-private-row"}}}}
			server := nativeProbeServer(backend, nil)
			WithPolicyLoader(func(context.Context, string) ([]auth.Policy, error) {
				if changed.Load() && change == "abac-unavailable" {
					return nil, errors.New("private policy detail")
				}
				if changed.Load() && change == "abac" {
					return []auth.Policy{{Name: "current-denial", Enabled: true, Effect: auth.PolicyDeny, Permission: "device.read"}}, nil
				}
				return nil, nil
			})(server)
			refresh := func(context.Context) (*auth.Principal, error) {
				principal := nativePrincipal()
				if changed.Load() {
					switch change {
					case "permissions":
						principal.Permissions = nil
					case "attributes":
						principal.Attributes = map[string]string{"changed": "value"}
					case "mfa":
						principal.MFASatisfied = !principal.MFASatisfied
					}
				}
				return principal, nil
			}
			pipe := openModernStdio(t, server, nativePrincipal(), refresh)
			pipe.send(t, modernRequest("tools/call", map[string]any{"name": "flow_explorer_query", "arguments": map[string]any{"plan": map[string]any{}}}))
			raw := pipe.next(t)
			if !changed.Load() || bytes.Contains(raw, []byte("original-private-row")) || bytes.Contains(raw, []byte("private policy")) || !bytes.Contains(raw, []byte(`"error"`)) {
				t.Fatal("authenticated stdio published under changed grants", "source_executed", changed.Load(), "private_row", bytes.Contains(raw, []byte("original-private-row")))
			}
		})
	}
}
