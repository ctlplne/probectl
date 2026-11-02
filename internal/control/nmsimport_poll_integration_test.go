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
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/nmsimport"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// An NMS export address cannot choose a device agent. Only the authenticated
// tenant's exact applied source item and current operator-owned device anchor
// can authorize this credential-free preview route.
func TestNMSImportPollTargetPreviewRouteIsTenantAndAgentBound(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	h := srv.Handler()
	a, b := freshTenant(t, db, "nms-poll-route-a"), freshTenant(t, db, "nms-poll-route-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove poll route tenants: %v", err)
		}
	})
	contextID := uuid.NewString()
	for _, tenant := range []string{a, b} {
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
				VALUES ($1,$2,$3,$4,'Lab','Private')`, tenant, contextID,
				uuid.NewString(), uuid.NewString())
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	capturer := nmsimport.NewCaptureStore(db.Pool(),
		func(context.Context, tenancy.Scope, string, string, map[string]any) error { return nil })
	aCtx := tenancy.WithTenant(context.Background(), tenancy.ID(a))
	planID, err := capturer.StartPlan(aCtx, contextID, nmsimport.Zabbix,
		"poll-route", strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	const itemID = "11111111222233334444555555555555"
	body := fmt.Sprintf(`{"zabbix_export":{"version":"7.4","host_groups":[],
		"hosts":[{"host":"edge-r1","name":"Edge R1","interfaces":[{"ip":"10.0.0.1"}],
		"items":[{"uuid":"%s","type":"SNMP_AGENT","status":"ENABLED","delay":"120s"}]}]}}`, itemID)
	if _, err := capturer.AppendPage(aCtx, contextID, planID, 0,
		"hosts", 0, strings.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	snapshot, err := capturer.Seal(aCtx, contextID, planID, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := capturer.SetReviewChoices(aCtx, contextID, planID, snapshot,
		[]nmsimport.ReviewChoice{{RowNumber: 0, Action: "create"},
			{RowNumber: 1, Action: "create"}}); err != nil {
		t.Fatal(err)
	}
	review, err := capturer.FinalizeReview(aCtx, contextID, planID, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := capturer.ApplyReview(aCtx, contextID, planID, snapshot, review); err != nil {
		t.Fatal(err)
	}
	const agentID, target = "poll-route-agent", "192.0.2.44"
	var sourceID string
	if err := tenancy.InTenant(aCtx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		var entityID string
		if err := sc.Q.QueryRow(ctx, `SELECT p.source_id::text,v.entity_id::text
			FROM nms_import_plans p JOIN nms_import_provenance v
			ON (v.tenant_id,v.context_id,v.source_id)=(p.tenant_id,p.context_id,p.source_id)
			WHERE p.tenant_id=$1 AND p.context_id=$2 AND p.id=$3
			AND v.object_kind='device' AND v.external_id='edge-r1'`,
			a, contextID, planID).Scan(&sourceID, &entityID); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
			(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`, a, agentID, contextID); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
			(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
			VALUES ($1,$2,'device_target',$3,$4,$5)`, a, agentID, target,
			contextID, entityID); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO agent_identities
			(tenant_id,agent_id,spiffe_id,serial,not_after)
			VALUES ($1,$2,$3,$4,clock_timestamp()+interval '1 hour')`, a,
			agentID, "spiffe://probectl/tenant/"+a+"/entity/"+agentID,
			uuid.NewString())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	selection := map[string]string{"context_id": contextID, "source_id": sourceID,
		"item_external_id": itemID, "agent_id": agentID, "target_address": target}
	preview := apiReq(t, h, http.MethodPost, "/v1/nms-imports/poll-target-preview", a, selection)
	var got nmsimport.PollTargetPreview
	if preview.Code != http.StatusOK || json.Unmarshal(preview.Body.Bytes(), &got) != nil ||
		got.TenantID != a || got.ContextID != contextID || got.EntityID == "" ||
		got.AgentID != agentID || got.PollSeconds != 120 || got.PlanID != planID ||
		strings.Contains(preview.Body.String(), "10.0.0.1") {
		t.Fatalf("own current preview: %d %s", preview.Code, preview.Body.String())
	}
	for _, candidate := range []struct {
		tenant, address string
	}{{a, "10.0.0.1"}, {b, target}} {
		selection["target_address"] = candidate.address
		denied := apiReq(t, h, http.MethodPost, "/v1/nms-imports/poll-target-preview",
			candidate.tenant, selection)
		if denied.Code != http.StatusNotFound {
			t.Fatalf("source address or foreign tenant selected agent: %d %s",
				denied.Code, denied.Body.String())
		}
	}
}
