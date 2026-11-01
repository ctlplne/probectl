// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/entity"
)

// A site-label deny applies even to an empty entity page or an unresolved
// alias. The same display label in another tenant has its own policy space.
func TestEntityContextABACAppliesAfterTenantScopedResolution(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	a, b := freshTenant(t, db, "entity-policy-route-a"), freshTenant(t, db, "entity-policy-route-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove entity policy route fixtures: %v", err)
		}
	})
	h := srv.Handler()
	create := func(tenant, site string) string {
		t.Helper()
		rec := apiReq(t, h, http.MethodPost, "/v1/entity-contexts", tenant,
			map[string]string{"site_label": site, "vrf_label": "Private"})
		var out entity.ContextRecord
		if rec.Code != http.StatusCreated || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
			t.Fatalf("create context tenant=%s site=%s: %d %s", tenant, site,
				rec.Code, rec.Body.String())
		}
		return out.ContextID
	}
	blocked, allowed, otherTenant := create(a, "West DC"), create(a, "East DC"), create(b, "West DC")
	cache := &abacCache{load: func(_ context.Context, tenant string) ([]auth.Policy, error) {
		if tenant != a {
			return nil, nil
		}
		return []auth.Policy{{Name: "deny west entity reads", Enabled: true,
			Effect: auth.PolicyDeny, Permission: "entities.read",
			Resource: map[string]string{"site_label": "West DC"}}}, nil
	}}
	srv.abac = cache
	for _, fixture := range []struct {
		tenant, contextID string
		status            int
	}{
		{a, blocked, http.StatusForbidden},
		{a, allowed, http.StatusOK},
		{b, otherTenant, http.StatusOK},
	} {
		for _, endpoint := range []string{
			"/v1/entities?context_id=" + fixture.contextID,
			"/v1/entities/resolve?context_id=" + fixture.contextID + "&kind=address&value=10.42.0.1",
		} {
			rec := apiReq(t, h, http.MethodGet, endpoint, fixture.tenant, nil)
			if rec.Code != fixture.status {
				t.Fatalf("REST context policy tenant=%s endpoint=%s: %d %s",
					fixture.tenant, endpoint, rec.Code, rec.Body.String())
			}
		}
	}
	mcpServer := NewMCPServerWithPolicyLoader(&config.Config{},
		slog.New(slog.NewTextHandler(io.Discard, nil)), db.Pool(), nil, 0,
		ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil },
			func(context.Context, ai.EgressEvent) error { return nil }, ai.RedactionPolicy{}),
		nil, nil, cache.policies)
	for _, fixture := range []struct {
		tenant, contextID string
		denied            bool
	}{
		{a, blocked, true}, {a, allowed, false}, {b, otherTenant, false},
	} {
		principal := &auth.Principal{TenantID: fixture.tenant, UserID: "entity-policy-reader",
			Permissions: map[string]bool{"entities.read": true}}
		for _, call := range []struct {
			name string
			args any
		}{
			{"entity_list", mcp.EntityListInput{ContextID: fixture.contextID}},
			{"entity_resolve", mcp.EntityResolveInput{ContextID: fixture.contextID,
				Kind: "address", Value: "10.42.0.1"}},
		} {
			_, failed := nativeControlCall(t, mcpServer, principal, call.name, call.args)
			if failed != fixture.denied {
				t.Fatalf("MCP context policy tenant=%s context=%s tool=%s denied=%v",
					fixture.tenant, fixture.contextID, call.name, failed)
			}
		}
	}
}
