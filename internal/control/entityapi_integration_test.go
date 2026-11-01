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
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
)

// One context UUID and RFC1918 address may exist in two tenants; two VRFs in
// one tenant may also reuse that address. The HTTP edge must preserve both
// boundaries and refuse mixed-plane provenance to a partial role.
func TestEntityAPIEnforcesTenantContextAndSourcePermissions(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	a, b := freshTenant(t, db, "entity-api-a"), freshTenant(t, db, "entity-api-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove entity API fixture tenants: %v", err)
		}
	})
	sharedContext, secondContext := gouuid.NewString(), gouuid.NewString()
	entityA, entityAFlow, entityASecond, entityB :=
		gouuid.NewString(), gouuid.NewString(), gouuid.NewString(), gouuid.NewString()
	type fixture struct {
		tenant, routingContext, id, sourceKind, agent, sourceRef, label string
	}
	for _, f := range []fixture{
		{a, sharedContext, entityA, "device_target", "device-a", "10.42.0.1", "A device"},
		{a, sharedContext, entityAFlow, "flow_exporter", "flow-a", "10.42.0.1", "A flow"},
		{a, secondContext, entityASecond, "device_target", "device-a2", "10.42.0.1", "A second VRF"},
		{b, sharedContext, entityB, "device_target", "device-b", "10.42.0.1", "B device"},
	} {
		serial := strings.ReplaceAll(gouuid.NewString(), "-", "")
		if err := store.NewAgentIdentities(db.Pool()).Record(context.Background(),
			f.tenant, f.agent, crypto.EntitySPIFFEID(f.tenant, f.agent),
			serial, time.Now().Add(time.Hour), ""); err != nil {
			t.Fatalf("seed %s sender identity: %v", f.agent, err)
		}
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(f.tenant))
		err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
                VALUES ($1,$2,$3,$4,$3::uuid::text,$4::uuid::text)
				ON CONFLICT (tenant_id,id) DO NOTHING`, f.tenant, f.routingContext,
				gouuid.NewString(), gouuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
				(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
				f.tenant, f.agent, f.routingContext); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
				(tenant_id,agent_id,source_kind,source_ref,context_id)
				VALUES ($1,$2,$3,$4,$5)`, f.tenant, f.agent, f.sourceKind,
				f.sourceRef, f.routingContext); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
				(tenant_id,context_id,id,kind,label)
				VALUES ($1,$2,$3,'device',$4)`, f.tenant, f.routingContext,
				f.id, f.label); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts
				SET anchor_entity_id=$1 WHERE tenant_id=$2 AND agent_id=$3`,
				f.id, f.tenant, f.agent); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
				(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,
				 source,source_ref,agent_id,source_kind,configured_ref,observed_at,sender_serial)
				VALUES ($1,$2,$3,$3,$4,'address','10.42.0.1',
				        'fixture',$5,$6,$7,$8,$9,$10)`, f.tenant, f.routingContext,
				gouuid.NewString(), f.id, f.sourceRef, f.agent, f.sourceKind,
				f.sourceRef, time.Now(), serial)
			return err
		})
		if err != nil {
			t.Fatalf("seed %s/%s: %v", f.tenant, f.label, err)
		}
	}
	topo := topology.NewMemoryStore()
	for _, tenantID := range []string{a, b} {
		graph, err := topo.ForTenant(tenantID)
		if err != nil {
			t.Fatal(err)
		}
		graph.ObserveDevice(topology.DeviceInput{Address: "10.42.0.1", Name: "router",
			Source: "snmp"}, time.Now().UTC())
	}
	srv.WithTopology(topo)
	h := srv.Handler()

	request := func(tenant, path, withheld string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Probectl-Tenant", tenant)
		if withheld != "" {
			req.Header.Set(testWithholdPermissionsHeader, withheld)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	resolvePath := func(routingContext string) string {
		return "/v1/entities/resolve?context_id=" + routingContext +
			"&kind=address&value=10.42.0.1"
	}
	for _, tc := range []struct {
		tenant, contextID, wantStatus, wantID string
	}{
		{a, sharedContext, string(entity.Conflict), ""},
		{a, secondContext, string(entity.Resolved), entityASecond},
		{b, sharedContext, string(entity.Resolved), entityB},
	} {
		rec := request(tc.tenant, "/v1/topology?context_id="+tc.contextID, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("topology projection %s/%s: %d %s", tc.tenant, tc.contextID,
				rec.Code, rec.Body.String())
		}
		var body struct {
			Nodes     []topology.VizNode `json:"nodes"`
			ContextID string             `json:"canonical_context_id"`
			CurrentAt string             `json:"canonical_projection_current_at"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.ContextID != tc.contextID || body.CurrentAt == "" || len(body.Nodes) != 1 ||
			body.Nodes[0].CanonicalStatus != tc.wantStatus ||
			body.Nodes[0].CanonicalEntityID != tc.wantID {
			t.Fatalf("topology crossed tenant/context or hid conflict: %+v", body)
		}
	}
	for _, withheld := range []string{"entities.read", "flow.read"} {
		rec := request(a, "/v1/topology?context_id="+sharedContext, withheld)
		if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), entityAFlow) {
			t.Fatalf("topology projection with withheld %s leaked identity: %d %s",
				withheld, rec.Code, rec.Body.String())
		}
	}
	for _, tc := range []struct {
		tenant, routingContext, wantID string
		wantStatus                     entity.Status
	}{
		{a, sharedContext, "", entity.Conflict},
		{a, secondContext, entityASecond, entity.Resolved},
		{b, sharedContext, entityB, entity.Resolved},
	} {
		rec := request(tc.tenant, resolvePath(tc.routingContext), "")
		if rec.Code != http.StatusOK {
			t.Fatalf("resolve %s/%s = %d: %s", tc.tenant, tc.routingContext,
				rec.Code, rec.Body.String())
		}
		var got entity.Resolution
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Status != tc.wantStatus || got.EntityID != tc.wantID ||
			got.Scope.TenantID != tc.tenant || got.Scope.ContextID != tc.routingContext {
			t.Fatalf("wrong scoped resolution: %+v", got)
		}
		for _, claim := range got.Candidates {
			if claim.Scope != got.Scope {
				t.Fatalf("foreign candidate leaked: %+v", claim)
			}
		}
	}
	first := request(a, "/v1/entities?context_id="+sharedContext+"&limit=1", "")
	if first.Code != http.StatusOK {
		t.Fatalf("first entity page = %d: %s", first.Code, first.Body.String())
	}
	var page1 entity.Page
	if err := json.Unmarshal(first.Body.Bytes(), &page1); err != nil {
		t.Fatal(err)
	}
	if len(page1.Items) != 1 || page1.NextCursor != page1.Items[0].ID ||
		page1.Scope.TenantID != a || page1.Scope.ContextID != sharedContext {
		t.Fatalf("first entity page scope/cursor: %+v", page1)
	}
	second := request(a, "/v1/entities?context_id="+sharedContext+
		"&limit=1&cursor="+page1.NextCursor, "")
	if second.Code != http.StatusOK {
		t.Fatalf("second entity page = %d: %s", second.Code, second.Body.String())
	}
	var page2 entity.Page
	if err := json.Unmarshal(second.Body.Bytes(), &page2); err != nil {
		t.Fatal(err)
	}
	if len(page2.Items) != 1 || page2.NextCursor != "" ||
		page2.Items[0].ID == page1.Items[0].ID {
		t.Fatalf("second entity page cursor/overlap: %+v", page2)
	}
	seen := map[string]bool{page1.Items[0].ID: true, page2.Items[0].ID: true}
	if !seen[entityA] || !seen[entityAFlow] || seen[entityASecond] || seen[entityB] {
		t.Fatalf("context page leaked or lost an entity: %v", seen)
	}
	for _, tc := range []struct{ tenant, routingContext, wantID string }{
		{a, secondContext, entityASecond}, {b, sharedContext, entityB},
	} {
		rec := request(tc.tenant, "/v1/entities?context_id="+tc.routingContext, "")
		var page entity.Page
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &page) != nil ||
			len(page.Items) != 1 || page.Items[0].ID != tc.wantID {
			t.Fatalf("isolated entity page %s/%s: %d %+v %s", tc.tenant,
				tc.routingContext, rec.Code, page, rec.Body.String())
		}
	}

	for _, tc := range []struct {
		tenant, routingContext, id string
		want                       int
	}{
		{a, sharedContext, entityA, http.StatusOK},
		{a, sharedContext, entityB, http.StatusNotFound},
		{a, secondContext, entityA, http.StatusNotFound},
		{b, sharedContext, entityA, http.StatusNotFound},
	} {
		rec := request(tc.tenant, "/v1/entities/"+tc.id+"?context_id="+tc.routingContext, "")
		if rec.Code != tc.want {
			t.Fatalf("get %s/%s/%s = %d, want %d: %s", tc.tenant,
				tc.routingContext, tc.id, rec.Code, tc.want, rec.Body.String())
		}
	}
	for _, tc := range []struct{ withheld string }{
		{"entities.read"},
		{"flow.read"},
	} {
		rec := request(a, resolvePath(sharedContext), tc.withheld)
		if rec.Code != http.StatusForbidden ||
			strings.Contains(rec.Body.String(), entityA) ||
			strings.Contains(rec.Body.String(), entityAFlow) ||
			strings.Contains(rec.Body.String(), "flow-a") {
			t.Fatalf("withheld %s disclosed provenance: %d %s", tc.withheld,
				rec.Code, rec.Body.String())
		}
	}
	for _, tc := range []string{"", "not-a-uuid"} {
		rec := request(a, resolvePath(tc), "")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid context %q = %d: %s", tc, rec.Code, rec.Body.String())
		}
	}
	for _, query := range []string{"context_id=" + sharedContext + "&limit=0",
		"context_id=" + sharedContext + "&limit=101",
		"context_id=" + sharedContext + "&cursor=bad",
		"limit=1"} {
		rec := request(a, "/v1/entities?"+query, "")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid entity page %q = %d: %s", query, rec.Code, rec.Body.String())
		}
	}
	// A fourth distinct candidate is hidden behind more_candidates. A caller
	// who lacks any possible source-plane permission must not receive even
	// the first three candidates as a complete-looking conflict.
	for _, agentID := range []string{"device-overflow-c", "device-overflow-d"} {
		serial := strings.ReplaceAll(gouuid.NewString(), "-", "")
		if err := store.NewAgentIdentities(db.Pool()).Record(context.Background(),
			a, agentID, crypto.EntitySPIFFEID(a, agentID), serial,
			time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(a))
		err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			id := gouuid.NewString()
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
				(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`, a, agentID,
				sharedContext); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities
				(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'device',$4)`,
				a, sharedContext, id, agentID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
				(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
				VALUES ($1,$2,'device_target','10.42.0.1',$3,$4)`,
				a, agentID, sharedContext, id); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_evidence
				(tenant_id,context_id,id,observation_id,entity_id,alias_kind,alias_value,
				 source,source_ref,agent_id,source_kind,configured_ref,observed_at,sender_serial)
				VALUES ($1,$2,$3,$3,$4,'address','10.42.0.1',
				        'fixture','10.42.0.1',$5,'device_target','10.42.0.1',$6,$7)`,
				a, sharedContext, gouuid.NewString(), id, agentID, time.Now(), serial)
			return err
		})
		if err != nil {
			t.Fatalf("seed overflow candidate %s: %v", agentID, err)
		}
	}
	for _, path := range []string{resolvePath(sharedContext),
		"/v1/topology?context_id=" + sharedContext} {
		rec := request(a, path, "")
		if rec.Code != http.StatusOK ||
			(path == resolvePath(sharedContext) &&
				!strings.Contains(rec.Body.String(), "\"more_candidates\":true")) {
			t.Fatalf("overflow read %s = %d: %s", path, rec.Code, rec.Body.String())
		}
		rec = request(a, path, "events.read")
		if rec.Code != http.StatusForbidden ||
			strings.Contains(rec.Body.String(), "device-overflow-") {
			t.Fatalf("overflow with withheld source permission %s = %d: %s",
				path, rec.Code, rec.Body.String())
		}
	}
}
