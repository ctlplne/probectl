// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Real application-role Postgres/RLS and lifecycle operations. Source bodies
// are modeled original envelopes; this does not assert physical collection.
func TestOriginalSourceSubjectExportErasurePreservesStructuralReferencesAndTenant(t *testing.T) {
	admin := itPool(t)
	t.Cleanup(admin.Close)
	testsupport.LockPostgresPublicCatalog(t, admin)
	pool := flowQueryRuntime(t, admin)
	red := mkTenant(t, admin, "source-subject-red-"+flowQueryUUID(t))
	blue := mkTenant(t, admin, "source-subject-blue-"+flowQueryUUID(t))
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{red, blue}); err != nil {
			t.Error(err)
		}
	})
	const subject = "alice\"@example.test"
	var owner string
	if err := admin.QueryRow(t.Context(), `INSERT INTO users(tenant_id,email,display_name,status,user_name) VALUES($1,$2,'Owner','active',$2) RETURNING id::text`, red, subject).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	type original struct {
		document map[string]any
		matches  bool
	}
	fixtures := map[string][]original{
		"alert_rules": {
			{map[string]any{"version": 1, "owner_user_id": owner}, true},
			{map[string]any{"version": 1, "test_id": owner, "interface_id": owner}, false},
			{map[string]any{"version": 1, "read_grants": []any{map[string]any{"scope_type": "project", "scope_id": owner}}}, false},
			{map[string]any{"version": 1, "test_id": subject}, true},
			{map[string]any{"version": 2, "test_id": owner}, true},
			{map[string]any{"version": 1, "future": map[string]any{"test_id": owner}}, true},
			{map[string]any{"version": 1, "read_grants": []any{map[string]any{"scope_type": "subject", "scope_id": owner}}}, true},
			{map[string]any{"version": 1, "future": "evilalice\"@example.test"}, false},
		},
		"change_events": {
			{map[string]any{"version": 1, "source": map[string]any{"CollectorAgentID": subject}}, true},
			{map[string]any{"version": 1, "source": map[string]any{"SourceRef": subject}}, true},
			{map[string]any{"version": 1, "source": map[string]any{"CollectorAgentID": owner}}, true},
			{map[string]any{"version": 1, "source": map[string]any{"tenant_id": owner, "context_id": owner, "RouterID": owner}}, false},
			{map[string]any{"version": 1, "view_id": owner, "generation": owner, "selection": map[string]any{
				"base_context_id": owner, "base_router_id": owner, "context_id": owner, "router_id": owner, "epoch": owner, "binding_id": owner,
				"binding": map[string]any{"id": owner, "context_id": owner, "router_id": owner}}}, false},
			{map[string]any{"version": 1, "source": map[string]any{"context_id": subject}}, true},
			{map[string]any{"version": 2, "view_id": owner}, true},
			{map[string]any{"version": 1, "selection": map[string]any{"future": map[string]any{"id": owner}}}, true},
			{map[string]any{"version": 1, "source": map[string]any{"SourceRef": "evilalice\"@example.test"}}, false},
		},
	}
	matched := map[string]map[string]bool{}
	for table, documents := range fixtures {
		matched[table] = map[string]bool{}
		for _, tenant := range []string{red, blue} {
			if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
				for _, fixture := range documents {
					id := flowQueryUUID(t)
					raw, err := json.Marshal(fixture.document)
					if err != nil {
						return err
					}
					query := `INSERT INTO change_events(tenant_id,id,title,routing_source) VALUES($1,$2,'Original',$3::jsonb)`
					if table == "alert_rules" {
						query = `INSERT INTO alert_rules(tenant_id,id,name,metric,type,comparison,threshold,path_health_source) VALUES($1,$2,'Original','probectl_device_path_error_climb','threshold','gte',1,$3::jsonb)`
					}
					if _, err := sc.Q.Exec(ctx, query, tenant, id, raw); err != nil {
						return err
					}
					if tenant == red && fixture.matches {
						matched[table][id] = true
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	engine := New(pool, nil, nil, nil, nil, "owned source fixture backups", testLog())
	var archive bytes.Buffer
	if _, err := engine.ExportSubject(t.Context(), red, subject, &archive, false); err != nil {
		t.Fatal(err)
	}
	files := readTarGz(t, archive.Bytes())
	for table, expected := range matched {
		lines := strings.Split(strings.TrimSpace(files["postgres/"+table+".jsonl"]), "\n")
		seen := map[string]bool{}
		for _, line := range lines {
			var row struct {
				ID       string          `json:"id"`
				TenantID string          `json:"tenant_id"`
				Path     json.RawMessage `json:"path_health_source"`
				Routing  json.RawMessage `json:"routing_source"`
			}
			if err := json.Unmarshal([]byte(line), &row); err != nil {
				t.Fatal("missing or invalid portable source row", table, err)
			}
			if row.TenantID != red || !expected[row.ID] || seen[row.ID] || table == "alert_rules" && len(row.Path) == 0 || table == "change_events" && len(row.Routing) == 0 {
				t.Fatal("portable source export lost an original or selected unrelated/foreign data", table, row.ID)
			}
			seen[row.ID] = true
		}
		if len(seen) != len(expected) {
			t.Fatal("portable source export omitted subject-bearing originals", table, len(seen), len(expected))
		}
	}
	appendMarker := engine.appendSubjectErasure
	injected := errors.New("owned original-source audit refusal")
	engine.appendSubjectErasure = func(context.Context, tenancy.Scope, string, string, string) (audit.Event, error) {
		return audit.Event{}, injected
	}
	if _, _, err := engine.eraseSubjectPostgres(t.Context(), red, subject, "privacy-admin", "source rollback"); !errors.Is(err, injected) {
		t.Fatal("audit refusal did not roll back source erasure", err)
	}
	for table, documents := range fixtures {
		if countRows(t, admin, `SELECT count(*) FROM `+pgIdent(table)+` WHERE tenant_id=$1`, red) != len(documents) {
			t.Fatal("audit refusal committed source loss", table)
		}
	}
	engine.appendSubjectErasure = appendMarker
	planes, _, err := engine.eraseSubjectPostgres(t.Context(), red, subject, "privacy-admin", "original source lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	byPlane := subjectPlanesByName(planes)
	for table, documents := range fixtures {
		want := len(matched[table])
		plane := byPlane["postgres:"+table]
		if plane.Deleted != int64(want) || plane.Remaining != 0 || countRows(t, admin, `SELECT count(*) FROM `+pgIdent(table)+` WHERE tenant_id=$1`, red) != len(documents)-want || countRows(t, admin, `SELECT count(*) FROM `+pgIdent(table)+` WHERE tenant_id=$1`, blue) != len(documents) {
			t.Fatal("source erasure missed personal data or removed structural/sibling rows", table, plane)
		}
	}
}
