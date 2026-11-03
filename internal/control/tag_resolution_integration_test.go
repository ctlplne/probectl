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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestEffectiveSubjectTagsAPIAndMCPKeepTenantContextAndTypedOwnership(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	testsupport.LockPostgresPublicCatalog(t, db.Pool())
	ctx := t.Context()
	a, b := freshTenant(t, db, "resolved-tags-a"), freshTenant(t, db, "resolved-tags-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove effective-tag tenants: %v", err)
		}
	})
	contextID, device, iface, prefix := gouuid.NewString(), gouuid.NewString(), gouuid.NewString(), gouuid.NewString()
	manualKey, nameKey := gouuid.NewString(), gouuid.NewString()
	testIDs := map[string]string{a: gouuid.NewString(), b: gouuid.NewString()}
	agentFor := func(tenant string) string { return "tag-api-" + tenant }
	for lane, tenant := range []string{a, b} {
		agent := agentFor(tenant)
		if err := store.NewAgentIdentities(db.Pool()).Record(ctx, tenant, agent, crypto.AgentSPIFFEID(tenant, agent),
			strings.ReplaceAll(gouuid.NewString(), "-", ""), time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (store.Agents{}).Register(ctx, sc, agent, "operator-agent", "10.2.0.99", "fixture", crypto.AgentSPIFFEID(tenant, agent), nil); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts (tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES ($1,$2,$3,$4,'same-site','same-vrf')`, tenant, contextID, gouuid.NewString(), gouuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities (tenant_id,context_id,id,kind,label) VALUES
			 ($1,$2,$3,'device','operator-device'),($1,$2,$4,'prefix','operator-prefix')`, tenant, contextID, device, prefix); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities (tenant_id,context_id,id,kind,label,parent_entity_id,source_agent_id,configured_ref,interface_index)
			 VALUES ($1,$2,$3,'interface','operator-interface',$4,$5,'target',7)`, tenant, contextID, iface, device, agent); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts (tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`, tenant, agent, contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts (tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
			 VALUES ($1,$2,'flow_exporter','192.0.2.9',$3,$4)`, tenant, agent, contextID, device); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tests (tenant_id,id,name,target) VALUES ($1,$2,'operator-test','https://10.2.0.8/health')`, tenant, testIDs[tenant]); err != nil {
				return err
			}
			if err := store.NewEntityRegistry(db.Pool()).AssignPathTestContext(ctx, sc, testIDs[tenant], contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions (tenant_id,id,key) VALUES ($1,$2,'customer'),($1,$3,'name')`, tenant, manualKey, nameKey); err != nil {
				return err
			}
			for kind, id := range map[string]string{"device": device, "interface": iface, "prefix": prefix, "agent": agent, "test": testIDs[tenant], "exporter": ""} {
				input := store.ManualTagAssignmentInput{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, TagID: manualKey,
					TargetKind: kind, TargetID: id, Value: fmt.Sprintf("%s-lane-%d", kind, lane)}
				if kind == "exporter" {
					input.ExporterAgentID, input.ExporterSourceRef = agent, "192.0.2.9"
				}
				if _, err := (store.TagAssignments{}).CreateManual(ctx, sc, input); err != nil {
					return err
				}
				if _, err := (store.TagRules{}).Create(ctx, sc, tags.Rule{Scope: input.Scope, TagID: nameKey, TargetKind: kind,
					Match: "name_pattern", NamePattern: "^operator-", Value: fmt.Sprintf("name-lane-%d", lane)}); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	handler := srv.Handler()
	request := func(tenant, path, withheld string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Probectl-Tenant", tenant)
		if withheld != "" {
			req.Header.Set(testWithholdPermissionsHeader, withheld)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	path := "/v1/entity-contexts/" + contextID + "/resolved-tags"
	backend := mcpTagBackend{pool: db.Pool(), policyLoader: srv.abac.policies}
	for lane, tenant := range []string{a, b} {
		for kind, id := range map[string]string{"device": device, "interface": iface, "prefix": prefix, "agent": agentFor(tenant), "test": testIDs[tenant], "exporter": ""} {
			query := url.Values{"target_kind": {kind}}
			input := mcp.TagSubjectInput{ContextID: contextID, TargetKind: kind, TargetID: id}
			if kind == "exporter" {
				query.Set("exporter_agent_id", agentFor(tenant))
				query.Set("exporter_source_ref", "192.0.2.9")
				input.ExporterAgentID, input.ExporterSourceRef = agentFor(tenant), "192.0.2.9"
			} else {
				query.Set("target_id", id)
			}
			rec := request(tenant, path+"?"+query.Encode(), "")
			if rec.Code != http.StatusOK {
				t.Fatalf("resolve tenant%d %s: %d %s", lane, kind, rec.Code, rec.Body.String())
			}
			var out tags.SubjectResolution
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if out.ContextID != contextID || out.TargetKind != kind || len(out.Items) != 2 || out.Items[0].Value != fmt.Sprintf("%s-lane-%d", kind, lane) || out.Items[1].Value != fmt.Sprintf("name-lane-%d", lane) {
				t.Fatalf("wrong owned resolution: %+v", out)
			}
			if kind == "exporter" && (out.TargetID != "" || strings.Contains(rec.Body.String(), agentFor(tenant)) || strings.Contains(rec.Body.String(), "192.0.2.9")) {
				t.Fatal("public projection exposed exporter identity")
			}
			permission, err := tagSubjectReadPermission(kind)
			if err != nil {
				t.Fatal(err)
			}
			p := &auth.Principal{TenantID: tenant, UserID: "reader", Permissions: map[string]bool{permTagsRead: true, permission: true}}
			mcpOut, err := backend.TagSubjectResolve(ctx, p, input)
			if err != nil || len(mcpOut.Items) != 2 || mcpOut.Items[0] != out.Items[0] || mcpOut.TagRevision != out.TagRevision {
				t.Fatalf("MCP resolution lost tenant or parity: %+v %v", mcpOut, err)
			}
			delete(p.Permissions, permission)
			if _, err := backend.TagSubjectResolve(ctx, p, input); err == nil {
				t.Fatal("MCP used tag matches to bypass the subject read grant")
			}
			if rec := request(tenant, path+"?"+query.Encode(), permission); rec.Code != http.StatusForbidden {
				t.Fatal("REST used tag matches to bypass the subject read grant")
			}
		}
	}
	valid := path + "?target_kind=device&target_id=" + device
	for _, tc := range []struct {
		query, withheld string
		want            int
	}{
		{"?target_kind=device&target_id=" + device, "tags.read", http.StatusForbidden},
		{"?target_kind=device&target_id=" + prefix, "", http.StatusNotFound},
		{"?target_kind=agent&target_id=" + agentFor(b), "", http.StatusNotFound},
		{"?target_kind=test&target_id=" + testIDs[b], "", http.StatusNotFound},
		{"?target_kind=exporter&exporter_agent_id=" + agentFor(b) + "&exporter_source_ref=192.0.2.9", "", http.StatusNotFound},
		{"?target_kind=device&target_id=" + device + "&tenant_id=" + b, "", http.StatusBadRequest},
		{"?target_kind=device&target_id=" + device + "&sys_descr=forged", "", http.StatusBadRequest},
		{"?target_kind=device&target_kind=prefix&target_id=" + device, "", http.StatusBadRequest},
	} {
		if rec := request(a, path+tc.query, tc.withheld); rec.Code != tc.want {
			t.Fatalf("subject refusal: want%d got%d %s", tc.want, rec.Code, rec.Body.String())
		}
	}
	if rec := request(a, "/v1/entity-contexts/"+gouuid.NewString()+"/resolved-tags?target_kind=device&target_id="+device, ""); rec.Code != http.StatusNotFound {
		t.Fatal("foreign context resolved a subject")
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "deny effective tags", Enabled: true,
			Effect: auth.PolicyDeny, Permission: permTagsRead, Resource: map[string]string{"context_id": contextID}, Priority: 100})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	srv.abac.invalidate(a)
	if rec := request(a, valid, ""); rec.Code != http.StatusForbidden {
		t.Fatal("current context deny did not cover effective tags")
	}
	p := &auth.Principal{TenantID: a, UserID: "reader", Permissions: map[string]bool{permTagsRead: true, permMetricsRead: true}}
	if _, err := backend.TagSubjectResolve(ctx, p, mcp.TagSubjectInput{ContextID: contextID, TargetKind: "device", TargetID: device}); err == nil {
		t.Fatal("MCP bypassed context-specific deny")
	}
	if rec := request(b, valid, ""); rec.Code != http.StatusOK {
		t.Fatal("context deny crossed tenant boundary")
	}
}
