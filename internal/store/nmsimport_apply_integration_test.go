// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/nmsimport"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Two tenants can import the same source ID into independent contexts. A
// failed audit rolls back the whole destination chunk; a retry is inert.
func TestNMSImportApplyReviewTenantIsolationAndRetry(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "import-apply-a-"+suffix, "Import apply A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "import-apply-b-"+suffix, "Import apply B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`,
			[]string{a.ID, b.ID}); err != nil {
			t.Errorf("remove NMS apply fixture tenants: %v", err)
		}
	})
	contextID := uuid.NewString()
	for _, tenant := range []string{a.ID, b.ID} {
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
				VALUES ($1,$2,$3,$4,'Lab','Private')`, tenant, contextID,
				uuid.NewString(), uuid.NewString())
			return err
		})
	}
	auditFailed := false
	auditCount := 0
	auditErr := errors.New("audit append failed")
	capturer := nmsimport.NewCaptureStore(pool,
		func(_ context.Context, _ tenancy.Scope, action, _ string, _ map[string]any) error {
			if action == "nms_import.chunk_applied" {
				if auditFailed {
					return auditErr
				}
				auditCount++
			}
			return nil
		})
	type plan struct{ tenant, id, snapshot, review string }
	makePlan := func(tenant, label, generation string, choice nmsimport.ReviewChoice) plan {
		t.Helper()
		tenantCtx := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		id, err := capturer.StartPlan(tenantCtx, contextID, nmsimport.LibreNMS,
			"same-lab", strings.Repeat(generation, 64))
		if err != nil {
			t.Fatal(err)
		}
		body := `{"status":"ok","locations":[{"id":5,"location":"` + label +
			`","notes":"source-only-secret"}],"count":1}`
		if _, err := capturer.AppendPage(tenantCtx, contextID, id, 0,
			"locations", 0, strings.NewReader(body)); err != nil {
			t.Fatalf("capture source location: %v", err)
		}
		snapshot, err := capturer.Seal(tenantCtx, contextID, id, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		if err := capturer.SetReviewChoices(tenantCtx, contextID, id,
			snapshot, []nmsimport.ReviewChoice{choice}); err != nil {
			t.Fatalf("review exact source location: %v", err)
		}
		review, err := capturer.FinalizeReview(tenantCtx, contextID, id, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		return plan{tenant, id, snapshot, review}
	}
	aPlan := makePlan(a.ID, "West DC", "a", nmsimport.ReviewChoice{RowNumber: 0, Action: "create"})
	bPlan := makePlan(b.ID, "West DC", "b", nmsimport.ReviewChoice{RowNumber: 0, Action: "create"})
	aCtx := tenancy.WithTenant(ctx, tenancy.ID(a.ID))
	bCtx := tenancy.WithTenant(ctx, tenancy.ID(b.ID))
	if _, err := capturer.ApplyReview(bCtx, contextID, aPlan.id,
		aPlan.snapshot, aPlan.review); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
		t.Fatalf("foreign tenant applied a plan: %v", err)
	}
	if _, err := capturer.ApplyReview(aCtx, uuid.NewString(), aPlan.id,
		aPlan.snapshot, aPlan.review); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
		t.Fatalf("foreign routing context applied a plan: %v", err)
	}
	if _, err := capturer.ApplyReview(aCtx, contextID, aPlan.id,
		aPlan.snapshot, strings.Repeat("0", 64)); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
		t.Fatalf("wrong review hash applied a plan: %v", err)
	}
	auditFailed = true
	if _, err := capturer.ApplyReview(aCtx, contextID, aPlan.id,
		aPlan.snapshot, aPlan.review); !errors.Is(err, auditErr) {
		t.Fatalf("apply survived failed audit append: %v", err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var entities, provenance int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entities
			WHERE tenant_id=$1 AND context_id=$2`, a.ID, contextID).Scan(&entities); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_provenance
			WHERE tenant_id=$1 AND context_id=$2`, a.ID, contextID).Scan(&provenance); err != nil {
			return err
		}
		if entities != 0 || provenance != 0 {
			t.Fatalf("failed audit left destination data: entities=%d provenance=%d", entities, provenance)
		}
		return nil
	})
	auditFailed = false
	for _, candidate := range []struct {
		ctx context.Context
		p   plan
	}{{aCtx, aPlan}, {bCtx, bPlan}} {
		progress, err := capturer.ApplyReview(candidate.ctx, contextID, candidate.p.id,
			candidate.p.snapshot, candidate.p.review)
		if err != nil || progress.State != "applied" || progress.Applied != 1 ||
			progress.Skipped != 0 || progress.Remaining != 0 {
			t.Fatalf("apply bounded source site tenant=%s: %+v err=%v",
				candidate.p.tenant, progress, err)
		}
		retry, err := capturer.ApplyReview(candidate.ctx, contextID, candidate.p.id,
			candidate.p.snapshot, candidate.p.review)
		if err != nil || retry.State != "applied" || retry.Applied != 0 {
			t.Fatalf("identical apply retry wrote again tenant=%s: %+v err=%v",
				candidate.p.tenant, retry, err)
		}
	}
	if auditCount != 2 {
		t.Fatalf("apply retry duplicated actor audit: %d", auditCount)
	}
	var targetA, targetB string
	for _, candidate := range []struct {
		tenant string
		target *string
	}{
		{a.ID, &targetA}, {b.ID, &targetB},
	} {
		inTenant(ctx, t, pool, candidate.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT entity_id::text FROM nms_import_provenance
				WHERE tenant_id=$1 AND context_id=$2 AND object_kind='site' AND external_id='5'`,
				candidate.tenant, contextID).Scan(candidate.target)
		})
	}
	if targetA == "" || targetB == "" || targetA == targetB {
		t.Fatalf("paired tenants shared import provenance: A=%q B=%q", targetA, targetB)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var foreign, agentEvidence int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_provenance
			WHERE tenant_id=$1 AND context_id=$2 AND entity_id=$3`, b.ID,
			contextID, targetB).Scan(&foreign); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence
			WHERE tenant_id=$1 AND context_id=$2`, a.ID, contextID).
			Scan(&agentEvidence); err != nil {
			return err
		}
		if foreign != 0 {
			t.Fatal("tenant A read tenant B's import provenance")
		}
		if agentEvidence != 0 {
			t.Fatal("operator import created agent-attested identity evidence")
		}
		return nil
	})
	updateChoice := nmsimport.ReviewChoice{RowNumber: 0, Action: "update", TargetEntityID: targetA}
	stale := makePlan(a.ID, "East DC", "c", updateChoice)
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entities SET label='Human edit'
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, a.ID, contextID, targetA)
		return err
	})
	if _, err := capturer.ApplyReview(aCtx, contextID, stale.id,
		stale.snapshot, stale.review); !errors.Is(err, nmsimport.ErrReviewStale) {
		t.Fatalf("changed exact site target was overwritten: %v", err)
	}
	current := makePlan(a.ID, "East DC", "d", updateChoice)
	progress, err := capturer.ApplyReview(aCtx, contextID, current.id,
		current.snapshot, current.review)
	if err != nil || progress.Applied != 1 || progress.State != "applied" {
		t.Fatalf("apply current exact site target: %+v err=%v", progress, err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var label string
		if err := sc.Q.QueryRow(ctx, `SELECT label FROM entities
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, a.ID, contextID,
			targetA).Scan(&label); err != nil {
			return err
		}
		if label != "East DC" {
			t.Fatalf("exact target update did not apply: %q", label)
		}
		return nil
	})
	// The 100-row budget is per transaction, never an inventory-size cap.
	bulkPlan, err := capturer.StartPlan(aCtx, contextID, nmsimport.LibreNMS,
		"bulk-lab", strings.Repeat("e", 64))
	if err != nil {
		t.Fatal(err)
	}
	var body strings.Builder
	body.WriteString(`{"status":"ok","locations":[`)
	for id := 1; id <= 101; id++ {
		if id > 1 {
			body.WriteByte(',')
		}
		fmt.Fprintf(&body, `{"id":%d,"location":"Site %d"}`, id+100, id)
	}
	body.WriteString(`],"count":101}`)
	if _, err := capturer.AppendPage(aCtx, contextID, bulkPlan, 0,
		"locations", 0, strings.NewReader(body.String())); err != nil {
		t.Fatalf("capture 101 source sites: %v", err)
	}
	bulkSnapshot, err := capturer.Seal(aCtx, contextID, bulkPlan, 1, 101)
	if err != nil {
		t.Fatal(err)
	}
	bulkChoices := make([]nmsimport.ReviewChoice, 101)
	for index := range bulkChoices {
		bulkChoices[index] = nmsimport.ReviewChoice{RowNumber: int64(index), Action: "create"}
	}
	for _, choices := range [][]nmsimport.ReviewChoice{bulkChoices[:100], bulkChoices[100:]} {
		if err := capturer.SetReviewChoices(aCtx, contextID, bulkPlan,
			bulkSnapshot, choices); err != nil {
			t.Fatalf("review bounded source-site choices: %v", err)
		}
	}
	bulkReview, err := capturer.FinalizeReview(aCtx, contextID, bulkPlan, bulkSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	first, err := capturer.ApplyReview(aCtx, contextID, bulkPlan, bulkSnapshot, bulkReview)
	if err != nil || first.State != "applying" || first.Applied != 100 || first.Remaining != 1 {
		t.Fatalf("first bounded destination chunk: %+v err=%v", first, err)
	}
	second, err := capturer.ApplyReview(aCtx, contextID, bulkPlan, bulkSnapshot, bulkReview)
	if err != nil || second.State != "applied" || second.Applied != 1 || second.Remaining != 0 {
		t.Fatalf("last bounded destination chunk: %+v err=%v", second, err)
	}
	retry, err := capturer.ApplyReview(aCtx, contextID, bulkPlan, bulkSnapshot, bulkReview)
	if err != nil || retry.Applied != 0 || auditCount != 5 {
		t.Fatalf("bulk apply retry duplicated writes/audit: %+v audit=%d err=%v",
			retry, auditCount, err)
	}
	// A static imported set is source-keyed, scoped to the chosen routing
	// context, and backed only by device provenance from that same tenant.
	for _, tenant := range []string{a.ID, b.ID} {
		tenantCtx := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		groupPlan, err := capturer.StartPlan(tenantCtx, contextID, nmsimport.LibreNMS,
			"groups-lab", strings.Repeat("f", 64))
		if err != nil {
			t.Fatal(err)
		}
		device := `{"status":"ok","devices":[{"device_id":17,"display":"Edge A",` +
			`"ip":"10.42.0.1","location_id":5}],"count":1}`
		site := `{"status":"ok","locations":[{"id":5,"location":"West DC"}],"count":1}`
		group := `[{"status":"ok","groups":[{"id":7,"name":"WAN",` +
			`"pattern":"source-only-predicate"}],"count":1}]`
		rule := `{"status":"ok","rules":[{"id":9,"name":"Link down",` +
			`"rule":"source-only-expression"}],"count":1}`
		member := `[{"status":"ok","devices":[{"device_id":17}],"count":1}]`
		snapshot, err := capturer.CaptureLibreNMSInventory(tenantCtx, contextID,
			groupPlan, strings.NewReader(device), strings.NewReader(site),
			strings.NewReader(group), strings.NewReader(rule),
			[]nmsimport.LibreNMSMembershipList{{GroupID: "7", GroupName: "WAN",
				Raw: strings.NewReader(member)}})
		if err != nil {
			t.Fatalf("capture static group tenant=%s: %v", tenant, err)
		}
		choices := []nmsimport.ReviewChoice{
			{RowNumber: 0, Action: "create"},
			{RowNumber: 1, Action: "create"},
			{RowNumber: 2, Action: "create"},
			{RowNumber: 3, Action: "create"},
			{RowNumber: 4, Action: "unmapped"},
		}
		if err := capturer.SetReviewChoices(tenantCtx, contextID, groupPlan,
			snapshot, choices); err != nil {
			t.Fatalf("review static group tenant=%s: %v", tenant, err)
		}
		review, err := capturer.FinalizeReview(tenantCtx, contextID, groupPlan, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if tenant == a.ID {
			if _, err := capturer.ApplyReview(bCtx, contextID, groupPlan, snapshot,
				review); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
				t.Fatalf("foreign tenant applied group: %v", err)
			}
		}
		diff, err := capturer.ListReviewDiff(tenantCtx, contextID, groupPlan, review, -1, 10)
		if err != nil || len(diff.Items) != 5 ||
			strings.Join(diff.Items[2].ChangedFields, ",") != "group" ||
			strings.Join(diff.Items[3].ChangedFields, ",") != "membership" {
			t.Fatalf("group dry run tenant=%s: %+v err=%v", tenant, diff, err)
		}
		progress, err := capturer.ApplyReview(tenantCtx, contextID, groupPlan,
			snapshot, review)
		if err != nil || progress.Applied != 4 || progress.Skipped != 1 ||
			progress.State != "applied" {
			t.Fatalf("apply static group tenant=%s: %+v err=%v", tenant, progress, err)
		}
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var groups, members, foreign int
			var dynamic bool
			if err := sc.Q.QueryRow(ctx, `SELECT count(*),coalesce(bool_or(dynamic_predicate_unmapped),false)
				FROM nms_import_groups WHERE tenant_id=$1 AND context_id=$2
				  AND external_id='7'`, tenant, contextID).Scan(&groups, &dynamic); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_group_members
				WHERE tenant_id=$1 AND context_id=$2 AND group_external_id='7'
				  AND member_external_id='17'`, tenant, contextID).Scan(&members); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_groups
				WHERE tenant_id=$1 AND context_id=$2`, map[string]string{a.ID: b.ID,
				b.ID: a.ID}[tenant], contextID).Scan(&foreign); err != nil {
				return err
			}
			if groups != 1 || members != 1 || foreign != 0 || !dynamic {
				t.Fatalf("group tenant boundary tenant=%s groups=%d members=%d foreign=%d dynamic=%t",
					tenant, groups, members, foreign, dynamic)
			}
			return nil
		})
	}
}
