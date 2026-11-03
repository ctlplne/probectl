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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestReviewedNetBoxImportsCoverAllOwnedKindsRESTAndMCP(t *testing.T) {
	f := newTagImportSubjectFixture(t)
	root := "/v1/entity-contexts/" + f.contextID + "/tag-imports/netbox/"
	preview := mcpNetBoxTagBackend{mcpTagBackend: mcpTagBackend{pool: f.db.Pool(), policyLoader: f.srv.abac.policies}, source: f.srv.cmdb}
	apply := mcpNetBoxTagApplyBackend{server: f.srv}
	for _, kind := range []string{"exporter", "device", "interface", "prefix", "agent", "test"} {
		for _, tenant := range []string{f.a, f.b} {
			input := f.input(tenant, kind)
			response := apiReq(t, f.srv.Handler(), http.MethodPost, root+"preview", tenant, input)
			var observed netBoxTagPreview
			want := "import-7"
			if tenant == f.b {
				want = "import-8"
			}
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &observed) != nil || observed.Candidate.Value != want || observed.Target.TargetKind != kind {
				t.Fatalf("%s owned preview: %d %s", kind, response.Code, response.Body.String())
			}
			if kind != "exporter" && strings.Contains(response.Body.String(), "192.0.2.10") {
				t.Fatal("private subject address entered public preview")
			}
			permission, err := tagSubjectReadPermission(kind)
			if err != nil {
				t.Fatal(err)
			}
			p := &auth.Principal{TenantID: tenant, UserID: "importer", Permissions: map[string]bool{permTagsRead: true, permTagsWrite: true, permCMDBRead: true, permission: true}}
			mcpInput := mcp.NetBoxTagPreviewInput{ContextID: f.contextID, TagID: f.tagID, TargetKind: kind, TargetID: input.TargetID,
				ExporterAgentID: input.ExporterAgentID, ExporterSourceRef: input.ExporterSourceRef, Field: "role"}
			for _, grant := range []string{permTagsRead, permCMDBRead, permission} {
				before := f.calls.Load()
				if rec := tagImportRequestWithoutGrant(t, f.srv, tenant, root+"preview", input, grant); rec.Code != http.StatusForbidden || f.calls.Load() != before {
					t.Fatalf("%s missing %s reached source: %d", kind, grant, rec.Code)
				}
				delete(p.Permissions, grant)
				if _, err := preview.NetBoxTagPreview(t.Context(), p, mcpInput); err == nil || f.calls.Load() != before {
					t.Fatal("MCP source projection bypassed current grant")
				}
				p.Permissions[grant] = true
			}
			before := f.calls.Load()
			other := f.a
			if tenant == f.a {
				other = f.b
			}
			cross := apiReq(t, f.srv.Handler(), http.MethodPost, root+"apply", other, netBoxTagApplyRequest{Confirmed: true, Preview: observed})
			if (cross.Code != http.StatusNotFound && cross.Code != http.StatusConflict && cross.Code != http.StatusServiceUnavailable) || f.calls.Load() != before {
				t.Fatalf("%s foreign preview reached source or wrote: %d %s", kind, cross.Code, cross.Body.String())
			}
			if rec := tagImportRequestWithoutGrant(t, f.srv, tenant, root+"apply", netBoxTagApplyRequest{Confirmed: true, Preview: observed}, permission); rec.Code != http.StatusForbidden || f.calls.Load() != before {
				t.Fatal("subject read revocation authorized apply")
			}
			applied := apiReq(t, f.srv.Handler(), http.MethodPost, root+"apply", tenant, netBoxTagApplyRequest{Confirmed: true, Preview: observed})
			var record store.TagAssignmentRecord
			if applied.Code != http.StatusOK || json.Unmarshal(applied.Body.Bytes(), &record) != nil || record.Value != want || record.TargetKind != kind || record.Source != "netbox" || record.ReviewedAt == nil {
				t.Fatalf("%s reviewed apply: %d %s", kind, applied.Code, applied.Body.String())
			}
			fresh, err := preview.NetBoxTagPreview(t.Context(), p, mcpInput)
			if err != nil || fresh.Value != want || fresh.TargetKind != kind || (kind == "exporter" && fresh.TargetID != "") {
				t.Fatalf("%s MCP preview: %+v %v", kind, fresh, err)
			}
			args := mcp.NetBoxTagApplyInput{Confirmed: true, Preview: fresh, ExporterAgentID: input.ExporterAgentID, ExporterSourceRef: input.ExporterSourceRef}
			delete(p.Permissions, permission)
			before = f.calls.Load()
			if _, err := apply.NetBoxTagApply(t.Context(), p, args); err == nil || f.calls.Load() != before {
				t.Fatal("MCP apply bypassed subject grant")
			}
			p.Permissions[permission] = true
			again, err := apply.NetBoxTagApply(t.Context(), p, args)
			if err != nil || again.AssignmentID != record.ID || again.Value != want {
				t.Fatalf("%s repeated import did not upsert its same typed annotation: %+v %v", kind, again, err)
			}
			if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
				_, err := (store.TagAssignments{}).CreateManual(ctx, sc, store.ManualTagAssignmentInput{Scope: tags.Scope{TenantID: tenant, ContextID: f.contextID}, TagID: f.tagID,
					TargetKind: kind, TargetID: input.TargetID, ExporterAgentID: input.ExporterAgentID, ExporterSourceRef: input.ExporterSourceRef, Value: "manual-" + tenant})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			query := url.Values{"target_kind": {kind}}
			if kind == "exporter" {
				query.Set("exporter_agent_id", input.ExporterAgentID)
				query.Set("exporter_source_ref", input.ExporterSourceRef)
			} else {
				query.Set("target_id", input.TargetID)
			}
			resolved := apiReq(t, f.srv.Handler(), http.MethodGet, "/v1/entity-contexts/"+f.contextID+"/resolved-tags?"+query.Encode(), tenant, nil)
			var effective tags.SubjectResolution
			if resolved.Code != http.StatusOK || json.Unmarshal(resolved.Body.Bytes(), &effective) != nil || len(effective.Items) != 1 || effective.Items[0].Source != "manual" || effective.Items[0].Value != "manual-"+tenant {
				t.Fatalf("%s manual precedence: %d %s", kind, resolved.Code, resolved.Body.String())
			}
		}
	}
	var total int
	if err := f.db.Pool().QueryRow(t.Context(), `SELECT count(*) FROM tenant_tag_assignments WHERE tenant_id=ANY($1::uuid[])`, []string{f.a, f.b}).Scan(&total); err != nil || total != 24 {
		t.Fatalf("typed imports escaped lane/upsert/precedence: %d %v", total, err)
	}
	testNetBoxImportAuditAtomicity(t, f)
	testNetBoxImportFactAndContextRecheck(t, f)
}

func testNetBoxImportAuditAtomicity(t *testing.T, f *tagImportSubjectFixture) {
	t.Helper()
	root := "/v1/entity-contexts/" + f.contextID + "/tag-imports/netbox/"
	rec := apiReq(t, f.srv.Handler(), http.MethodPost, root+"preview", f.a, f.input(f.a, "prefix"))
	var observed netBoxTagPreview
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &observed) != nil {
		t.Fatal("cannot preview audit rollback case")
	}
	snapshot := func() string {
		t.Helper()
		var state string
		if err := f.db.Pool().QueryRow(t.Context(), `SELECT jsonb_build_object('revision',r.revision,
		 'assignments',(SELECT jsonb_agg(jsonb_build_array(id,value,source_ref,reviewed_at) ORDER BY id) FROM tenant_tag_assignments WHERE tenant_id=$1 AND source='netbox'),
		 'audits',(SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='tag.assignment.imported'))::text
		 FROM tenant_tag_revisions r WHERE r.tenant_id=$1`, f.a).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	before := snapshot()
	fault := "probectl_qa_beta_import_audit_" + strings.ReplaceAll(uuid(t), "-", "")
	if _, err := f.db.Pool().Exec(t.Context(), `ALTER TABLE audit_events ADD CONSTRAINT `+fault+` CHECK (action <> 'tag.assignment.imported' OR tenant_id::text <> '`+f.a+`') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.db.Pool().Exec(context.Background(), `ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS `+fault); err != nil {
			t.Error(err)
		}
	})
	failed := apiReq(t, f.srv.Handler(), http.MethodPost, root+"apply", f.a, netBoxTagApplyRequest{Confirmed: true, Preview: observed})
	if failed.Code < 500 || snapshot() != before {
		t.Fatalf("REST audit failure committed import or revision: %d %s", failed.Code, failed.Body.String())
	}
	p := &auth.Principal{TenantID: f.a, UserID: "importer", Permissions: map[string]bool{permTagsRead: true, permTagsWrite: true, permCMDBRead: true, "entities.read": true}}
	reader := mcpNetBoxTagBackend{mcpTagBackend: mcpTagBackend{pool: f.db.Pool(), policyLoader: f.srv.abac.policies}, source: f.srv.cmdb}
	preview, err := reader.NetBoxTagPreview(t.Context(), p, mcp.NetBoxTagPreviewInput{ContextID: f.contextID, TagID: f.tagID, TargetKind: "prefix", TargetID: f.prefix, Field: "role"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = (mcpNetBoxTagApplyBackend{server: f.srv}).NetBoxTagApply(t.Context(), p, mcp.NetBoxTagApplyInput{Confirmed: true, Preview: preview})
	var refused *pgconn.PgError
	if !errors.As(err, &refused) || refused.Code != "23514" || refused.ConstraintName != fault || snapshot() != before {
		t.Fatalf("MCP did not reach the actual audit INSERT fault and roll back: %v", err)
	}
	if _, err := f.db.Pool().Exec(t.Context(), `ALTER TABLE audit_events DROP CONSTRAINT `+fault); err != nil {
		t.Fatal(err)
	}
}

func tagImportRequestWithoutGrant(t *testing.T, srv *Server, tenant, path string, input any, grant string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	req.Header.Set("X-Probectl-Tenant", tenant)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(testWithholdPermissionsHeader, grant)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func testNetBoxImportFactAndContextRecheck(t *testing.T, f *tagImportSubjectFixture) {
	t.Helper()
	root := "/v1/entity-contexts/" + f.contextID + "/tag-imports/netbox/"
	observe := func() netBoxTagPreview {
		t.Helper()
		rec := apiReq(t, f.srv.Handler(), http.MethodPost, root+"preview", f.a, f.input(f.a, "prefix"))
		var result netBoxTagPreview
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &result) != nil {
			t.Fatal("cannot preview recheck fixture")
		}
		return result
	}
	before := observe()
	f.hookMu.Lock()
	f.hook = func() {
		if _, err := f.db.Pool().Exec(t.Context(), `UPDATE entities SET network_prefix=NULL WHERE tenant_id=$1 AND id=$2`, f.a, f.prefix); err != nil {
			t.Error(err)
		}
	}
	f.hookMu.Unlock()
	changed := apiReq(t, f.srv.Handler(), http.MethodPost, root+"apply", f.a, netBoxTagApplyRequest{Confirmed: true, Preview: before})
	if changed.Code != http.StatusConflict && changed.Code != http.StatusNotFound {
		t.Fatalf("local authority removed during source I/O was admitted: %d %s", changed.Code, changed.Body.String())
	}
	if _, err := f.db.Pool().Exec(t.Context(), `UPDATE entities SET network_prefix='192.0.2.0/24'::cidr WHERE tenant_id=$1 AND id=$2`, f.a, f.prefix); err != nil {
		t.Fatal(err)
	}
	before = observe()
	var denied atomic.Bool
	f.srv.abac = &abacCache{load: func(_ context.Context, tenant string) ([]auth.Policy, error) {
		if tenant == f.a && denied.Load() {
			return []auth.Policy{{Name: "current prefix deny", Enabled: true, Effect: auth.PolicyDeny, Permission: "entities.read", Resource: map[string]string{"context_id": f.contextID}}}, nil
		}
		return nil, nil
	}}
	f.hookMu.Lock()
	f.hook = func() { denied.Store(true); f.srv.abac.invalidate(f.a) }
	f.hookMu.Unlock()
	changed = apiReq(t, f.srv.Handler(), http.MethodPost, root+"apply", f.a, netBoxTagApplyRequest{Confirmed: true, Preview: before})
	if changed.Code != http.StatusForbidden {
		t.Fatalf("context deny published during source I/O was ignored: %d %s", changed.Code, changed.Body.String())
	}
	other := apiReq(t, f.srv.Handler(), http.MethodPost, root+"preview", f.b, f.input(f.b, "prefix"))
	if other.Code != http.StatusOK {
		t.Fatal("one tenant's current deny affected the other tenant")
	}
}
