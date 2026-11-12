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

func TestAlertQuerySubjectPostgresErasesConfigurationAndKeepsTenantBoundary(t *testing.T) {
	admin := itPool(t)
	t.Cleanup(admin.Close)
	testsupport.LockPostgresPublicCatalog(t, admin)
	pool := flowQueryRuntime(t, admin)
	red := mkTenant(t, admin, "probectl-qa-beta-alert-subject-red-"+flowQueryUUID(t))
	blue := mkTenant(t, admin, "probectl-qa-beta-alert-subject-blue-"+flowQueryUUID(t))
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{red, blue}); err != nil {
			t.Error(err)
		}
	})
	const subject = "query-owner@example.test"
	var owner string
	if err := admin.QueryRow(t.Context(), `INSERT INTO users(tenant_id,email,display_name,status,user_name)VALUES($1,$2,'Owner','active',$2) RETURNING id::text`, red, subject).Scan(&owner); err != nil {
		t.Fatal(err)
	}
	// Legacy/future configuration must remain erasable even when no current
	// source service would execute it. Only the configured subject fields match.
	for _, tenant := range []string{red, blue} {
		if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			for i := range 4 {
				id := flowQueryUUID(t)
				query, tag, dependency := any(nil), any(nil), any(nil)
				switch i {
				case 0:
					raw, err := json.Marshal(map[string]any{"owner_user_id": owner, "version": 1})
					if err != nil {
						return err
					}
					query = string(raw)
				case 1:
					tag = `{"filter":{"value":"query-owner\u0040example.test"}}`
				case 2:
					tag = `{"filter":{"value":"evilquery-owner@example.test"}}`
					if tenant == red {
						id = owner // structural UUID collision is not ownership.
					}
				case 3:
					raw, err := json.Marshal(map[string]any{"owner_user_id": owner, "version": 1})
					if err != nil {
						return err
					}
					dependency = string(raw)
				}
				if _, err := sc.Q.Exec(ctx, `INSERT INTO alert_rules(tenant_id,id,name,metric,type,comparison,threshold,query_source,tag_filter,dependency_policy)
 VALUES($1,$2,$3,'probectl_explorer_query_condition','threshold','gte',1,$4::jsonb,$5::jsonb,$6::jsonb)`, tenant, id, id, query, tag, dependency); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	engine := New(pool, nil, nil, nil, nil, "owned fixture backups", testLog())
	var archive bytes.Buffer
	if _, err := engine.ExportSubject(t.Context(), red, subject, &archive, false); err != nil {
		t.Fatal(err)
	}
	body := strings.TrimSpace(readTarGz(t, archive.Bytes())["postgres/alert_rules.jsonl"])
	if body == "" || strings.Count(body, "\n") != 2 || strings.Contains(body, blue) || strings.Contains(body, "evilquery-owner") {
		t.Fatal("subject export omitted bound alert config or included unrelated/foreign rules")
	}
	appendMarker := engine.appendSubjectErasure
	injected := errors.New("owned query-alert audit refusal")
	engine.appendSubjectErasure = func(context.Context, tenancy.Scope, string, string, string) (audit.Event, error) {
		return audit.Event{}, injected
	}
	if _, _, err := engine.eraseSubjectPostgres(t.Context(), red, subject, "privacy-admin", "owned query-alert rollback"); !errors.Is(err, injected) {
		t.Fatal("audit refusal did not fail closed", err)
	}
	if got := countRows(t, admin, `SELECT count(*) FROM alert_rules WHERE tenant_id=$1`, red); got != 4 {
		t.Fatal("failed audit committed alert configuration deletion", got)
	}
	engine.appendSubjectErasure = appendMarker
	planes, _, err := engine.eraseSubjectPostgres(t.Context(), red, subject, "privacy-admin", "owned query-alert erasure")
	if err != nil {
		t.Fatal(err)
	}
	paid := subjectPlanesByName(planes)["postgres:alert_rules"]
	if paid.Deleted != 3 || paid.Remaining != 0 || countRows(t, admin, `SELECT count(*) FROM alert_rules WHERE tenant_id=$1`, red) != 1 || countRows(t, admin, `SELECT count(*) FROM alert_rules WHERE tenant_id=$1`, blue) != 4 {
		t.Fatal("subject config survived or another tenant/unrelated rule changed", paid)
	}
	t.Log("real-integration: app-role Postgres/RLS subject export, complete config deletion and audit rollback; no scheduler or served-surface claim")
}
