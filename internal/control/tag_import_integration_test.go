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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	uuidx "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cmdb"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestNetBoxTagPreviewResolvesTenantTargetBeforeSourceRead(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	a, b := freshTenant(t, db, "netbox-tag-preview-a"), freshTenant(t, db, "netbox-tag-preview-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove NetBox preview fixture tenants: %v", err)
		}
	})
	contextID, tagID := uuidx.NewString(), uuidx.NewString()
	for _, tenant := range []string{a, b} {
		for _, statement := range []string{
			`INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES ($1,$2,$2,$2,'site','vrf')`,
			`INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES ($1,'collector',$2)`,
			`INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id) VALUES ($1,'collector','flow_exporter','192.0.2.10',$2)`,
		} {
			if _, err := db.Pool().Exec(context.Background(), statement, tenant, contextID); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.Pool().Exec(context.Background(), `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES ($1,$2,'site')`, tenant, tagID); err != nil {
			t.Fatal(err)
		}
	}
	var calls atomic.Int64
	var down atomic.Bool
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		tenant := r.URL.Query().Get("tenant_id")
		if tenant != "7" && tenant != "8" {
			t.Errorf("NetBox preview source read was not scoped: %s", r.URL.RawQuery)
		}
		if r.URL.Path == "/api/ipam/ip-addresses/" {
			if r.URL.Query().Get("address") != "192.0.2.10" {
				t.Errorf("preview source key was not the owned exporter: %s", r.URL.RawQuery)
			}
			fmt.Fprintf(w, `{"count":1,"results":[{"id":10,"tenant":{"id":%s},"address":"192.0.2.10/32","assigned_object":{"device":{"id":42}}}]}`, tenant)
			return
		}
		if r.URL.Path != "/api/dcim/devices/" || r.URL.Query().Get("id") != "42" {
			t.Errorf("unexpected NetBox preview source path: %s", r.URL.String())
		}
		fmt.Fprintf(w, `{"count":1,"results":[{"id":42,"tenant":{"id":%s},"name":"owned-router","site":{"name":"site-%s"}}]}`, tenant, tenant)
	}))
	defer source.Close()
	resolver := cmdb.NewResolver(cmdb.NewNetBox(source.URL, "test-token", map[string]string{a: "7", b: "8"}), time.Hour)
	srv.WithCMDB(resolver)
	path := "/v1/entity-contexts/" + contextID + "/tag-imports/netbox/preview"
	body := fmt.Sprintf(`{"tag_id":%q,"exporter_agent_id":"collector","exporter_source_ref":"192.0.2.10","field":"site"}`, tagID)
	request := func(tenant, input, withheld string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(input))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Probectl-Tenant", tenant)
		req.Header.Set(testWithholdPermissionsHeader, withheld)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	for _, row := range []struct{ tenant, value string }{{a, "site-7"}, {b, "site-8"}} {
		rec := request(row.tenant, body, "")
		var out netBoxTagPreview
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Candidate.Value != row.value ||
			out.Target.TagID != tagID || out.Target.TagRevision == "" || out.Target.ContextID != contextID {
			t.Fatalf("tenant %s preview: %d %s", row.tenant, rec.Code, rec.Body.String())
		}
	}
	backend := mcpNetBoxTagBackend{mcpTagBackend: mcpTagBackend{pool: db.Pool(),
		policyLoader: func(context.Context, string) ([]auth.Policy, error) { return nil, nil }}, source: resolver}
	previewInput := mcp.NetBoxTagPreviewInput{ContextID: contextID, TagID: tagID,
		ExporterAgentID: "collector", ExporterSourceRef: "192.0.2.10", Field: "site"}
	for _, row := range []struct{ tenant, value string }{{a, "site-7"}, {b, "site-8"}} {
		reader := &auth.Principal{TenantID: row.tenant, UserID: "tag-reader",
			Permissions: map[string]bool{permTagsRead: true, permCMDBRead: true}}
		preview, err := backend.NetBoxTagPreview(context.Background(), reader, previewInput)
		if err != nil || preview.Value != row.value || preview.TagID != tagID {
			t.Fatalf("MCP tenant %s preview: %+v, %v", row.tenant, preview, err)
		}
		delete(reader.Permissions, permCMDBRead)
		before := calls.Load()
		if _, err := backend.NetBoxTagPreview(context.Background(), reader, previewInput); err == nil || calls.Load() != before {
			t.Fatal("MCP source read survived cmdb.read revocation")
		}
	}
	deniedBackend := backend
	deniedBackend.policyLoader = func(context.Context, string) ([]auth.Policy, error) {
		return []auth.Policy{{ID: uuidx.NewString(), Enabled: true, Permission: permCMDBRead, Effect: auth.PolicyDeny}}, nil
	}
	beforePolicy := calls.Load()
	if _, err := deniedBackend.NetBoxTagPreview(context.Background(), &auth.Principal{TenantID: a, UserID: "tag-reader",
		Permissions: map[string]bool{permTagsRead: true, permCMDBRead: true}}, previewInput); err == nil || calls.Load() != beforePolicy {
		t.Fatal("MCP ABAC denial reached NetBox source")
	}
	for _, row := range []struct {
		input, withheld string
		want            int
	}{
		{body, "tags.read", http.StatusForbidden},
		{body, "cmdb.read", http.StatusForbidden},
		{strings.Replace(body, tagID, uuidx.NewString(), 1), "", http.StatusNotFound},
		{strings.Replace(body, "192.0.2.10", "192.0.2.11", 1), "", http.StatusNotFound},
		{strings.Replace(body, "collector", "other-agent", 1), "", http.StatusNotFound},
	} {
		before := calls.Load()
		if rec := request(b, row.input, row.withheld); rec.Code != row.want {
			t.Fatalf("unowned/denied preview: %d %s", rec.Code, rec.Body.String())
		}
		if calls.Load() != before {
			t.Fatal("unauthorized target reached NetBox before tenant ownership")
		}
	}
	if _, err := resolver.Lookup(tenancy.WithTenant(context.Background(), tenancy.ID(a)), "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	down.Store(true)
	if rec := request(a, body, ""); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("preview accepted stale enrichment: %d %s", rec.Code, rec.Body.String())
	}
	down.Store(false)
	for _, statement := range []string{
		`INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES ($1,'second-collector',$2)`,
		`INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id) VALUES ($1,'second-collector','flow_exporter','192.0.2.10',$2)`,
	} {
		if _, err := db.Pool().Exec(context.Background(), statement, a, contextID); err != nil {
			t.Fatal(err)
		}
	}
	before := calls.Load()
	if rec := request(a, body, ""); rec.Code != http.StatusNotFound || calls.Load() != before {
		t.Fatalf("ambiguous exporter reached source: %d %s", rec.Code, rec.Body.String())
	}
	if rec := request(b, body, ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "site-8") {
		t.Fatalf("tenant A ambiguity affected tenant B: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := db.Pool().Exec(context.Background(), `UPDATE entity_agent_contexts SET expires_at=clock_timestamp() WHERE tenant_id=$1 AND agent_id='second-collector'`, a); err != nil {
		t.Fatal(err)
	}
	if rec := request(a, body, ""); rec.Code != http.StatusOK {
		t.Fatalf("expired competing binding retained authority: %d %s", rec.Code, rec.Body.String())
	}
	var assignments int
	if err := db.Pool().QueryRow(context.Background(), `SELECT count(*) FROM tenant_tag_assignments WHERE tenant_id=ANY($1::uuid[])`, []string{a, b}).Scan(&assignments); err != nil || assignments != 0 {
		t.Fatalf("preview wrote an assignment: %d, %v", assignments, err)
	}
}
