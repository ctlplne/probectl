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
	"fmt"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestFlowQuerySubjectPostgresDecodedExportErasureAndRollback(t *testing.T) {
	admin := itPool(t)
	t.Cleanup(admin.Close)
	testsupport.LockPostgresPublicCatalog(t, admin)
	pool := flowQueryRuntime(t, admin)
	red := mkTenant(t, admin, "probectl-qa-beta-config-subject-red-"+flowQueryUUID(t))
	blue := mkTenant(t, admin, "probectl-qa-beta-config-subject-blue-"+flowQueryUUID(t))
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{red, blue}); err != nil {
			t.Error(err)
		}
	})
	const ownerEmail = "owned-config-subject@example.test"
	var ownerID string
	if err := admin.QueryRow(t.Context(), `INSERT INTO users(tenant_id,email,display_name,status,user_name)VALUES($1::uuid,$2,'Owned subject','active',$2) RETURNING id::text`, red, ownerEmail).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	type fixtureRow struct{ id, label, text, owner string }
	rows := []fixtureRow{}
	for i := 1; i <= 130; i++ {
		rows = append(rows, fixtureRow{fmt.Sprintf("00000000-0000-4000-8000-%012x", i), "unrelated", "unrelated configuration", "fixture"})
	}
	regexID := "00000000-0000-4000-8000-000000000131"
	ipv6ID := "00000000-0000-4000-8000-000000000132"
	nearID := "00000000-0000-4000-8000-000000000133"
	ownedID := "00000000-0000-4000-8000-000000000134"
	rows = append(rows,
		fixtureRow{regexID, "regex", `^192\.0\.2\.1$`, "fixture"},
		fixtureRow{ipv6ID, "ipv6", "https://[2001:0DB8:0000:0:0:0:0:1]:443/x", "fixture"},
		fixtureRow{nearID, "near", `^192\.0\.2\.10$`, "fixture"},
		fixtureRow{ownedID, "owned", "unrelated configuration", ownerID},
		fixtureRow{ownerID, "row-id-only", "unrelated configuration", "fixture"},
	)
	// Legacy/future JSON members are intentionally included: lifecycle must
	// scan stored data even when it cannot be executed as a current query plan.
	for _, tenant := range []string{red, blue} {
		for _, row := range rows {
			name := "owned fixture " + row.label
			expression, err := json.Marshal(map[string]any{"nested": []any{map[string]any{"value": row.text}}})
			if err != nil {
				t.Fatal(err)
			}
			definition, err := json.Marshal(map[string]any{"name": name, "visibility": "tenant", "plan": json.RawMessage(expression), "time": map[string]any{}})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := admin.Exec(t.Context(), `INSERT INTO flow_query_filters(tenant_id,id,name,expression,version,updated_by,created_at,updated_at)VALUES($1::uuid,$2::uuid,$3,$4::jsonb,1,$5,now(),now())`, tenant, row.id, name, expression, row.owner); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.Exec(t.Context(), `INSERT INTO flow_query_views(tenant_id,id,owner_id,name,visibility,definition,version,created_at,updated_at)VALUES($1::uuid,$2::uuid,$3,$4,'tenant',$5::jsonb,1,now(),now())`, tenant, row.id, row.owner, name, definition); err != nil {
				t.Fatal(err)
			}
		}
	}
	engine := New(pool, nil, nil, nil, nil, "owned fixture backups", testLog())
	for _, test := range []struct{ subject, id string }{{"192.0.2.1", regexID}, {"2001:db8::1", ipv6ID}, {ownerEmail, ownedID}, {ownerID, ownedID}} {
		var archive bytes.Buffer
		if _, err := engine.ExportSubject(t.Context(), red, test.subject, &archive, false); err != nil {
			t.Fatal("decoded configuration subject export failed", err)
		}
		files := readTarGz(t, archive.Bytes())
		for _, table := range []string{"flow_query_filters", "flow_query_views"} {
			body := strings.TrimSpace(files["postgres/"+table+".jsonl"])
			if body == "" || strings.Count(body, "\n") != 0 || !strings.Contains(body, test.id) || strings.Contains(body, blue) || test.id != ownerID && strings.Contains(body, `"id":"`+ownerID+`"`) {
				t.Errorf("decoded subject export lost a semantic match or included unrelated/foreign configuration: table=%s subject=%s", table, test.subject)
			}
		}
	}
	appendMarker := engine.appendSubjectErasure
	injected := errors.New("owned config-subject audit failure")
	sawUncommittedDeletion := false
	engine.appendSubjectErasure = func(ctx context.Context, scope tenancy.Scope, _, _, _ string) (audit.Event, error) {
		var remaining int
		if err := scope.Q.QueryRow(ctx, `SELECT count(*) FROM flow_query_filters WHERE tenant_id=$1::uuid AND id=$2::uuid`, red, regexID).Scan(&remaining); err != nil {
			return audit.Event{}, err
		}
		sawUncommittedDeletion = remaining == 0
		return audit.Event{}, injected
	}
	if _, _, err := engine.eraseSubjectPostgres(t.Context(), red, "192.0.2.1", "privacy-admin", "owned rollback proof"); !errors.Is(err, injected) || !sawUncommittedDeletion {
		t.Errorf("mandatory audit did not follow actual semantic deletion before rollback: observed=%v err=%v", sawUncommittedDeletion, err)
	}
	for _, table := range []string{"flow_query_filters", "flow_query_views"} {
		if countRows(t, admin, `SELECT count(*) FROM `+pgIdent(table)+` WHERE tenant_id=$1::uuid AND id=$2::uuid`, red, regexID) != 1 {
			t.Fatal("failed audit committed a decoded configuration deletion", table)
		}
	}
	engine.appendSubjectErasure = appendMarker
	for _, test := range []struct{ subject, id string }{{"192.0.2.1", regexID}, {"2001:db8::1", ipv6ID}, {ownerEmail, ownedID}} {
		planes, _, err := engine.eraseSubjectPostgres(t.Context(), red, test.subject, "privacy-admin", "owned decoded configuration proof")
		if err != nil {
			t.Fatal("decoded configuration erasure failed", err)
		}
		byPlane := subjectPlanesByName(planes)
		for _, table := range []string{"flow_query_filters", "flow_query_views"} {
			p := byPlane["postgres:"+table]
			if p.Deleted != 1 || p.Remaining != 0 || countRows(t, admin, `SELECT count(*) FROM `+pgIdent(table)+` WHERE tenant_id=$1::uuid AND id=$2::uuid`, red, test.id) != 0 {
				t.Errorf("semantic configuration match survived a clean erasure receipt: table=%s subject=%s deleted=%d remaining=%d", table, test.subject, p.Deleted, p.Remaining)
			}
			if countRows(t, admin, `SELECT count(*) FROM `+pgIdent(table)+` WHERE tenant_id=$1::uuid`, blue) != int64(len(rows)) {
				t.Fatal("foreign-tenant configuration changed", table)
			}
			if countRows(t, admin, `SELECT count(*) FROM `+pgIdent(table)+` WHERE tenant_id=$1::uuid AND id=ANY($2::uuid[])`, red, []string{nearID, ownerID}) != 2 {
				t.Fatal("near address or unrelated row-ID collision was erased", table)
			}
		}
	}
	// A later page that cannot be completely scanned must roll back an earlier
	// page's deletion; it cannot turn a resource refusal into a clean receipt.
	early := rows[0].id
	if _, err := admin.Exec(t.Context(), `UPDATE flow_query_filters SET expression='{"value":"192.0.2.1"}'::jsonb WHERE tenant_id=$1::uuid AND id=$2::uuid`, red, early); err != nil {
		t.Fatal(err)
	}
	badID := "ffffffff-ffff-4fff-8fff-ffffffffffff"
	deep := `{"nested":` + strings.Repeat("[", 70) + `"unrelated"` + strings.Repeat("]", 70) + `}`
	if _, err := admin.Exec(t.Context(), `INSERT INTO flow_query_filters(tenant_id,id,name,expression,version,updated_by,created_at,updated_at)VALUES($1::uuid,$2::uuid,'owned scan resource refusal',$3::jsonb,1,'fixture',now(),now())`, red, badID, deep); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engine.eraseSubjectPostgres(t.Context(), red, "192.0.2.1", "privacy-admin", "owned incomplete scan proof"); !errors.Is(err, govern.ErrSubjectDocumentBudget) {
		t.Fatal("incomplete later document scan produced a successful subject receipt", err)
	}
	if countRows(t, admin, `SELECT count(*) FROM flow_query_filters WHERE tenant_id=$1::uuid AND id=$2::uuid`, red, early) != 1 {
		t.Fatal("a later-page scan refusal committed an earlier-page deletion")
	}
}
