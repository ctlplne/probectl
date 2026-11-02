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

// One reviewed Zabbix item may propose a cadence only for an applied device
// from the same source. Concurrent reviews of the old proposal cannot silently
// overwrite the winner, and identical later captures do not advance revision.
func TestNMSImportPollProposalIsTenantScopedAndRevisionBound(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "poll-import-a-"+suffix, "Poll import A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "poll-import-b-"+suffix, "Poll import B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`,
			[]string{a.ID, b.ID}); err != nil {
			t.Errorf("remove poll importer tenants: %v", err)
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
	capturer := nmsimport.NewCaptureStore(pool,
		func(context.Context, tenancy.Scope, string, string, map[string]any) error { return nil })
	type plan struct{ id, snapshot, review string }
	makePlan := func(tenant string, seconds int, marker, hostAction, itemAction string) plan {
		t.Helper()
		tenantCtx := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		id, err := capturer.StartPlan(tenantCtx, contextID, nmsimport.Zabbix,
			"zbx-lab", strings.Repeat(marker, 64))
		if err != nil {
			t.Fatal(err)
		}
		body := fmt.Sprintf(`{"zabbix_export":{"version":"7.4","host_groups":[],
			"hosts":[{"host":"edge-r1","name":"Edge R1","interfaces":[{"ip":"10.0.0.1"}],
			"items":[{"uuid":"11111111222233334444555555555555","type":"SNMP_AGENT",
			"status":"ENABLED","delay":"%ds"}]}]}}`, seconds)
		if _, err := capturer.AppendPage(tenantCtx, contextID, id, 0,
			"hosts", 0, strings.NewReader(body)); err != nil {
			t.Fatalf("capture Zabbix host and SNMP item: %v", err)
		}
		snapshot, err := capturer.Seal(tenantCtx, contextID, id, 1, 2)
		if err != nil {
			t.Fatal(err)
		}
		if err := capturer.SetReviewChoices(tenantCtx, contextID, id, snapshot,
			[]nmsimport.ReviewChoice{{RowNumber: 0, Action: hostAction},
				{RowNumber: 1, Action: itemAction}}); err != nil {
			t.Fatalf("review exact Zabbix rows: %v", err)
		}
		review, err := capturer.FinalizeReview(tenantCtx, contextID, id, snapshot)
		if err != nil {
			t.Fatalf("freeze Zabbix cadence: %v", err)
		}
		return plan{id, snapshot, review}
	}
	aCtx := tenancy.WithTenant(ctx, tenancy.ID(a.ID))
	bCtx := tenancy.WithTenant(ctx, tenancy.ID(b.ID))
	aFirst := makePlan(a.ID, 90, "a", "create", "create")
	bFirst := makePlan(b.ID, 90, "b", "create", "create")
	if _, err := capturer.ApplyReview(bCtx, contextID, aFirst.id,
		aFirst.snapshot, aFirst.review); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
		t.Fatalf("foreign tenant applied cadence plan: %v", err)
	}
	for _, candidate := range []struct {
		ctx context.Context
		p   plan
	}{{aCtx, aFirst}, {bCtx, bFirst}} {
		progress, err := capturer.ApplyReview(candidate.ctx, contextID,
			candidate.p.id, candidate.p.snapshot, candidate.p.review)
		if err != nil || progress.State != "applied" || progress.Applied != 2 {
			t.Fatalf("apply host and cadence: %+v err=%v", progress, err)
		}
	}
	var aSource, bSource string
	for _, candidate := range []struct {
		tenant, planID string
		source         *string
	}{
		{a.ID, aFirst.id, &aSource}, {b.ID, bFirst.id, &bSource},
	} {
		inTenant(ctx, t, pool, candidate.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT source_id::text FROM nms_import_plans
				WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, candidate.tenant,
				contextID, candidate.planID).Scan(candidate.source)
		})
	}
	if aSource == "" || bSource == "" || aSource == bSource {
		t.Fatalf("source IDs crossed tenant boundary: A=%q B=%q", aSource, bSource)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var own, foreign int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_poll_proposals
			WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3
			  AND host_external_id='edge-r1' AND poll_seconds=90`, a.ID,
			contextID, aSource).Scan(&own); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_poll_proposals
			WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3`, b.ID,
			contextID, bSource).Scan(&foreign); err != nil {
			return err
		}
		if own != 1 || foreign != 0 {
			t.Fatalf("poll proposal isolation: own=%d foreign=%d", own, foreign)
		}
		return nil
	})
	aUpdate := makePlan(a.ID, 120, "c", "skip", "update")
	aStale := makePlan(a.ID, 180, "d", "skip", "update")
	diff, err := capturer.ListReviewDiff(aCtx, contextID, aUpdate.id, aUpdate.review, -1, 100)
	if err != nil || len(diff.Items) != 2 ||
		diff.Items[1].CurrentPollSeconds != 90 ||
		diff.Items[1].ProposedPollSeconds != 120 ||
		len(diff.Items[1].ChangedFields) != 1 ||
		diff.Items[1].ChangedFields[0] != "poll_seconds" {
		t.Fatalf("dry run did not disclose reviewed cadence: %+v err=%v", diff, err)
	}
	progress, err := capturer.ApplyReview(aCtx, contextID, aUpdate.id,
		aUpdate.snapshot, aUpdate.review)
	if err != nil || progress.State != "applied" || progress.Applied != 1 {
		t.Fatalf("apply reviewed interval update: %+v err=%v", progress, err)
	}
	if _, err := capturer.ApplyReview(aCtx, contextID, aStale.id,
		aStale.snapshot, aStale.review); !errors.Is(err, nmsimport.ErrReviewStale) {
		t.Fatalf("stale interval review overwrote current proposal: %v", err)
	}
	aRepeat := makePlan(a.ID, 120, "e", "skip", "create")
	repeatDiff, err := capturer.ListReviewDiff(aCtx, contextID, aRepeat.id,
		aRepeat.review, -1, 100)
	if err != nil || len(repeatDiff.Items) != 2 ||
		repeatDiff.Items[1].CurrentPollSeconds != 120 ||
		repeatDiff.Items[1].ProposedPollSeconds != 120 ||
		len(repeatDiff.Items[1].ChangedFields) != 0 {
		t.Fatalf("identical proposal did not dry-run as no-op: %+v err=%v", repeatDiff, err)
	}
	if progress, err := capturer.ApplyReview(aCtx, contextID, aRepeat.id,
		aRepeat.snapshot, aRepeat.review); err != nil || progress.State != "applied" {
		t.Fatalf("identical source item reimport: %+v err=%v", progress, err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var seconds, revision int64
		if err := sc.Q.QueryRow(ctx, `SELECT poll_seconds,revision
			FROM nms_import_poll_proposals WHERE tenant_id=$1 AND context_id=$2
			  AND source_id=$3 AND item_external_id='11111111222233334444555555555555'`,
			a.ID, contextID, aSource).Scan(&seconds, &revision); err != nil {
			return err
		}
		if seconds != 120 || revision != 2 {
			t.Fatalf("stale or identical review rewrote interval: seconds=%d revision=%d",
				seconds, revision)
		}
		return nil
	})
	const agentID, targetAddress = "poll-agent-a", "192.0.2.44"
	if _, err := capturer.PreviewPollTarget(aCtx, contextID, aSource,
		"11111111222233334444555555555555", agentID, targetAddress); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
		t.Fatalf("unbound source address selected an agent target: %v", err)
	}
	inTenant(ctx, t, pool, a.ID, func(ctx context.Context, sc tenancy.Scope) error {
		var entityID string
		if err := sc.Q.QueryRow(ctx, `SELECT entity_id::text FROM nms_import_provenance
			WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3
			  AND object_kind='device' AND external_id='edge-r1'`,
			a.ID, contextID, aSource).Scan(&entityID); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
			(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
			a.ID, agentID, contextID); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
			(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
			VALUES ($1,$2,'device_target',$3,$4,$5)`,
			a.ID, agentID, targetAddress, contextID, entityID); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO agent_identities
			(tenant_id,agent_id,spiffe_id,serial,not_after)
			VALUES ($1,$2,$3,$4,clock_timestamp()+interval '1 hour')`,
			a.ID, agentID, "spiffe://probectl/tenant/"+a.ID+"/entity/"+agentID,
			uuid.NewString())
		return err
	})
	preview, err := capturer.PreviewPollTarget(aCtx, contextID, aSource,
		"11111111222233334444555555555555", agentID, targetAddress)
	if err != nil || preview.TenantID != a.ID || preview.ContextID != contextID ||
		preview.AgentID != agentID || preview.TargetAddress != targetAddress ||
		preview.PollSeconds != 120 || preview.Revision != 2 {
		t.Fatalf("exact current agent binding did not select proposal: %+v err=%v",
			preview, err)
	}
	for _, candidate := range []struct {
		ctx    context.Context
		target string
	}{{aCtx, "10.0.0.1"}, {bCtx, targetAddress}} {
		if _, err := capturer.PreviewPollTarget(candidate.ctx, contextID, aSource,
			"11111111222233334444555555555555", agentID,
			candidate.target); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
			t.Fatalf("source IP or foreign tenant selected a target: %v", err)
		}
	}
}
