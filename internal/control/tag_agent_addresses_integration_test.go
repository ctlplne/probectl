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
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestAgentCIDRTagsRESTAndMCPUseAttestedFactsAndCurrentContextGrants(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	testsupport.LockPostgresPublicCatalog(t, db.Pool())
	ctx := t.Context()
	a, b := freshTenant(t, db, "agent-cidr-api-a"), freshTenant(t, db, "agent-cidr-api-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Error(err)
		}
	})
	contextID, siteID, tagID := uuid(t), uuid(t), uuid(t)
	agents, serials := map[string]string{}, map[string]string{}
	for _, tenant := range []string{a, b} {
		agent := uuid(t)
		agents[tenant] = agent
		serials[tenant] = strings.ReplaceAll(uuid(t), "-", "")
		for _, credential := range []struct{ uri, serial string }{{crypto.AgentSPIFFEID(tenant, agent), strings.ReplaceAll(uuid(t), "-", "")}, {crypto.EntitySPIFFEID(tenant, agent), serials[tenant]}} {
			if err := store.NewAgentIdentities(db.Pool()).Record(ctx, tenant, agent, credential.uri, credential.serial, time.Now().Add(time.Hour), ""); err != nil {
				t.Fatal(err)
			}
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (store.Agents{}).Register(ctx, sc, agent, "edge-agent", "10.2.0.99", "fixture", crypto.AgentSPIFFEID(tenant, agent), nil); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES ($1,$2,$3,$4,'same-site','same-vrf')`, tenant, contextID, siteID, uuid(t)); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'site','operator-site')`, tenant, contextID, siteID); err != nil {
				return err
			}
			if err := store.NewEntityRegistry(db.Pool()).AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: agent, Kind: entity.AgentSite, SourceRef: agent}, contextID, siteID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES ($1,$2,'network')`, tenant, tagID); err != nil {
				return err
			}
			_, err := (store.TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, TagID: tagID, TargetKind: "agent", Match: "cidr", AddressSide: "agent", CIDR: "10.2.0.0/24", Value: tenant})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	h := srv.Handler()
	backend := mcpTagBackend{pool: db.Pool(), policyLoader: srv.abac.policies}
	path := func(agent string) string {
		return "/v1/entity-contexts/" + contextID + "/resolved-tags?target_kind=agent&target_id=" + agent
	}
	read := func(tenant string, want int) {
		t.Helper()
		rec := apiReq(t, h, http.MethodGet, path(agents[tenant]), tenant, nil)
		var out tags.SubjectResolution
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || len(out.Items) != want {
			t.Fatalf("agent CIDR API: %d %s", rec.Code, rec.Body.String())
		}
		if want > 0 && out.Items[0].Value != tenant {
			t.Fatal("agent rule crossed tenant values")
		}
		if strings.Contains(rec.Body.String(), "10.2.0.") {
			t.Fatal("effective projection exposed address/hostname facts")
		}
	}
	for _, tenant := range []string{a, b} {
		read(tenant, 0) // A hostname that looks like an IP is not evidence.
		item := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: agents[tenant], Kind: entity.AgentSite, SourceRef: agents[tenant]}, Alias: entity.AliasKey{Kind: entity.AgentSiteAlias, Value: "operator-site"}, SourceRef: "agent:label:site", ObservedAt: time.Now(), AgentAddresses: []netip.Addr{netip.MustParseAddr("10.2.0.7")}}
		if accepted, unresolved, err := store.NewEntityRegistry(db.Pool()).WriteEvidenceBatch(tenancy.WithTenant(ctx, tenancy.ID(tenant)), agents[tenant], serials[tenant], []entity.Observation{item}); err != nil || accepted != 1 || unresolved != 0 {
			t.Fatalf("agent source fixture %d/%d: %v", accepted, unresolved, err)
		}
		read(tenant, 1)
		p := &auth.Principal{TenantID: tenant, UserID: "agent-reader", Permissions: map[string]bool{permTagsRead: true, "agent.read": true}}
		input := mcp.TagSubjectInput{ContextID: contextID, TargetKind: "agent", TargetID: agents[tenant]}
		out, err := backend.TagSubjectResolve(ctx, p, input)
		if err != nil || len(out.Items) != 1 || out.Items[0].Value != tenant {
			t.Fatalf("MCP agent CIDR facts: %+v %v", out, err)
		}
		for _, permission := range []string{permTagsRead, "agent.read"} {
			req := httptest.NewRequest(http.MethodGet, path(agents[tenant]), nil)
			req.Header.Set("X-Probectl-Tenant", tenant)
			req.Header.Set(testWithholdPermissionsHeader, permission)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("REST missing %s returned agent facts: %d", permission, rec.Code)
			}
			delete(p.Permissions, permission)
			if _, err := backend.TagSubjectResolve(ctx, p, input); err == nil {
				t.Fatal("MCP bypassed subject/tag read grant")
			}
			p.Permissions[permission] = true
		}
	}
	srv.abac = &abacCache{load: func(_ context.Context, tenant string) ([]auth.Policy, error) {
		if tenant != a {
			return nil, nil
		}
		return []auth.Policy{{Name: "hide current agent context", Enabled: true, Effect: auth.PolicyDeny, Permission: "agent.read", Resource: map[string]string{"context_id": contextID}}}, nil
	}}
	backend.policyLoader = srv.abac.policies
	if rec := apiReq(t, h, http.MethodGet, path(agents[a]), a, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("context deny exposed current agent facts: %d", rec.Code)
	}
	if _, err := backend.TagSubjectResolve(ctx, &auth.Principal{TenantID: a, UserID: "reader", Permissions: map[string]bool{permTagsRead: true, "agent.read": true}}, mcp.TagSubjectInput{ContextID: contextID, TargetKind: "agent", TargetID: agents[a]}); err == nil {
		t.Fatal("MCP agent facts ignored current context deny")
	}
	read(b, 1)
}
