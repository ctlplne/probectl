// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/nmsimport"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The documented Orion SWIS and PRTG API v2 shapes reach the same FORCE-RLS
// capture and review path as live imports. They stay preview-only: source
// location, ancestry, polling and alert delivery cannot silently select a
// canonical destination or create an enabled alert.
func TestNMSImportOrionAndPRTGPreviewCaptureIsTenantIsolated(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	left, err := NewTenants(pool).Create(ctx, "nms-preview-left-"+suffix, "NMS preview left")
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewTenants(pool).Create(ctx, "nms-preview-right-"+suffix, "NMS preview right")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`,
			[]string{left.ID, right.ID}); err != nil {
			t.Errorf("remove NMS preview tenants: %v", err)
		}
	})
	contextID := uuid.NewString()
	for _, tenantID := range []string{left.ID, right.ID} {
		inTenant(ctx, t, pool, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
				VALUES ($1,$2,$3,$4,'Lab','Private')`, tenantID, contextID,
				uuid.NewString(), uuid.NewString())
			return err
		})
	}
	auditByTenant := map[string]int{}
	capturer := nmsimport.NewCaptureStore(pool,
		func(_ context.Context, sc tenancy.Scope, action, target string, data map[string]any) error {
			if target == "" || data["context_id"] != contextID || action == "" {
				return errors.New("preview audit lost its tenant context or target")
			}
			auditByTenant[sc.Tenant.String()]++
			return nil
		})
	type page struct{ resource, raw string }
	sources := []struct {
		kind  nmsimport.Kind
		pages []page
		want  []struct{ kind, id, parent string }
	}{
		{kind: nmsimport.Orion, pages: []page{
			{"nodes", `{"results":[{"NodeID":17,"Caption":"Edge R1","IPAddress":"10.42.0.1","Location":"West","PollInterval":120,"Community":"secret-orion-credential"}]}`},
			{"groups", `{"results":[{"ContainerID":23,"Name":"WAN","Definition":"secret-orion-predicate"}]}`},
			{"rules", `{"results":[{"AlertID":31,"Name":"Link down","NotifyEnabled":true,"NotificationSettings":"secret-orion-delivery"}]}`},
		}, want: []struct{ kind, id, parent string }{{"device", "17", ""}, {"group", "23", ""}, {"alert_rule", "31", ""}}},
		{kind: nmsimport.PRTG, pages: []page{
			{"devices", `[{"id":"101","parentid":"20","name":"Edge R1","basic":{"host":"10.42.0.1","credentials":"secret-prtg-credential"}}]`},
			{"groups", `[{"id":"20","parentid":"3","name":"WAN","basic":{"password":"secret-prtg-password"}}]`},
			{"probes", `[{"id":"3","parentid":"0","name":"West probe"}]`},
		}, want: []struct{ kind, id, parent string }{{"device", "101", "20"}, {"group", "20", "3"}, {"site", "3", "0"}}},
	}
	for _, source := range sources {
		t.Run(string(source.kind), func(t *testing.T) {
			var firstPlan string
			for index, tenantID := range []string{left.ID, right.ID} {
				tenantCtx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
				planID, err := capturer.StartPlan(tenantCtx, contextID, source.kind,
					"preview-"+string(source.kind), strings.Repeat("a", 64))
				if err != nil {
					t.Fatal(err)
				}
				if index == 0 {
					firstPlan = planID
				} else if _, err := capturer.AppendPage(tenantCtx, contextID, firstPlan,
					0, source.pages[0].resource, 0, strings.NewReader(source.pages[0].raw)); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
					t.Fatalf("foreign tenant captured a page: %v", err)
				}
				for pageNumber, candidate := range source.pages {
					if _, err := capturer.AppendPage(tenantCtx, contextID, planID,
						int64(pageNumber), candidate.resource, int64(pageNumber),
						strings.NewReader(candidate.raw)); err != nil {
						t.Fatalf("capture %s page %d: %v", source.kind, pageNumber, err)
					}
				}
				hash, err := capturer.Seal(tenantCtx, contextID, planID, 3, 3)
				if err != nil || len(hash) != 64 {
					t.Fatalf("seal %s preview: %q %v", source.kind, hash, err)
				}
				if index == 1 {
					foreignCtx := tenancy.WithTenant(ctx, tenancy.ID(left.ID))
					if _, err := capturer.ListSealedRows(foreignCtx, contextID, planID, -1, 10); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
						t.Fatalf("foreign tenant read preview rows: %v", err)
					}
				}
				rows, err := capturer.ListSealedRows(tenantCtx, contextID, planID, -1, 10)
				if err != nil || rows.RowCount != 3 || len(rows.Items) != 3 {
					t.Fatalf("read sealed %s rows: %+v %v", source.kind, rows, err)
				}
				choices := make([]nmsimport.ReviewChoice, 0, 3)
				for rowNumber, row := range rows.Items {
					want := source.want[rowNumber]
					if row.Kind != want.kind || row.ExternalID != want.id ||
						row.ParentID != want.parent || len(row.UnmappedCodes) == 0 ||
						row.Action != "captured" || row.Reviewed {
						t.Fatalf("source row silently mapped or lost identity: %+v", row)
					}
					choices = append(choices, nmsimport.ReviewChoice{RowNumber: row.Number, Action: "unmapped"})
				}
				wire, err := json.Marshal(rows)
				if err != nil {
					t.Fatal(err)
				}
				for _, secret := range []string{"secret-orion-credential", "secret-orion-predicate",
					"secret-orion-delivery", "secret-prtg-credential", "secret-prtg-password"} {
					if strings.Contains(string(wire), secret) {
						t.Fatalf("source secret escaped into %s preview", source.kind)
					}
				}
				if err := capturer.SetReviewChoices(tenantCtx, contextID, planID, hash, choices); err != nil {
					t.Fatalf("record explicit unmapped choices: %v", err)
				}
				reviewHash, err := capturer.FinalizeReview(tenantCtx, contextID, planID, hash)
				if err != nil {
					t.Fatalf("finalize inert preview: %v", err)
				}
				progress, err := capturer.ApplyReview(tenantCtx, contextID, planID, hash, reviewHash)
				if err != nil || progress.Applied != 0 || progress.Skipped != 3 {
					t.Fatalf("unmapped preview wrote destination: %+v %v", progress, err)
				}
				inTenant(ctx, t, pool, tenantID, func(ctx context.Context, sc tenancy.Scope) error {
					var entityCount, alertCount int
					if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entities WHERE tenant_id=$1 AND context_id=$2`,
						tenantID, contextID).Scan(&entityCount); err != nil {
						return err
					}
					if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM alert_rules WHERE tenant_id=$1`,
						tenantID).Scan(&alertCount); err != nil {
						return err
					}
					if entityCount != 0 || alertCount != 0 {
						t.Fatalf("unmapped preview changed destinations: entities=%d alerts=%d", entityCount, alertCount)
					}
					return nil
				})
			}
		})
	}
	if auditByTenant[left.ID] == 0 || auditByTenant[right.ID] == 0 {
		t.Fatalf("preview capture lost tenant audit: %+v", auditByTenant)
	}
}
