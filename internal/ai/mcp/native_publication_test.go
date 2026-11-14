// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/auth"
)

type nativePublicationBody struct {
	onEncode func()
}

func (body nativePublicationBody) MarshalJSON() ([]byte, error) {
	body.onEncode()
	return []byte(`{"source":"operator@example.test","word":"9007199254740993"}`), nil
}

func TestNativePublicationChecksCurrentSourceAfterEncodingAndRetainsAdmission(t *testing.T) {
	for _, withdraw := range []bool{false, true} {
		for _, tenant := range []string{"tenant-a", "tenant-b"} {
			held, admitted, encoded, checked, credential := false, false, false, false, false
			releases, admissions := 0, 0
			gate := testGate()
			server := newTestServer(&fakeBackend{}, ai.NewEgressGate(gate.Policy(), gate.AuditHook(), ai.DefaultRedaction))
			server.nativeEnabled = true
			server.tools["owned_health"] = Tool{Name: "owned_health", Permission: "metrics.read", Native: true, RequiresUser: true, Query: true,
				Admit: func(context.Context, *auth.Principal) (func(), error) {
					admitted = true
					return func() { admitted = false; admissions++ }, nil
				},
				Invoke: func(ctx context.Context, p *auth.Principal, _ json.RawMessage) (any, error) {
					held = true
					err := RetainNativePublication(ctx, func(context.Context) error {
						checked = true
						if !held || !admitted || !encoded || p.TenantID != tenant {
							t.Error("publication lost encoding order, current tenant or held query admission")
						}
						if withdraw {
							return errors.New("source withdrawn")
						}
						return nil
					}, func() { held = false; releases++ })
					return nativePublicationBody{onEncode: func() {
						if !held || !admitted {
							t.Error("query released during native encoding")
						}
						encoded = true
					}}, err
				}}
			ctx := withPublicationGuard(t.Context(), func(context.Context) error {
				credential = true
				if !checked {
					t.Error("transport credential refreshed before source publication check")
				}
				return nil
			})
			p := principal(tenant, "metrics.read")
			p.UserID = "reader"
			raw := server.Handle(ctx, p, nativeRequest("owned_health", map[string]any{}))
			if !checked || held || admitted || releases != 1 || admissions != 1 {
				t.Fatal("source check or exact-once complete-response finalization missing", checked, held, admitted, releases, admissions)
			}
			if withdraw {
				if strings.Contains(string(raw), "structuredContent") || credential || !strings.Contains(string(raw), "authorization is no longer valid") {
					t.Fatal("withdrawn current source reached native publication", string(raw))
				}
			} else if !credential || !strings.Contains(string(raw), "structuredContent") || strings.Contains(string(raw), "operator@example.test") {
				t.Fatal("successful native result lost full redaction or final credential refresh", string(raw))
			}
		}
	}
	if err := RetainNativePublication(t.Context(), func(context.Context) error { return nil }, func() {}); err == nil {
		t.Fatal("unscoped caller registered a native publication grant")
	}
}
