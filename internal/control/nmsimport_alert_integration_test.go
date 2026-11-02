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
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"testing"

	googleuuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/nmsimport"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Same RFC1918 source address, rule ID, agent ID, target and routing-context
// UUID exist in two tenants. Only the principal's FORCE-RLS source, applied
// device provenance and current sender binding may make a finite preview.
func TestNMSImportAlertTargetPreviewRouteIsTenantAndAgentBound(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	h := srv.Handler()
	a, b := freshTenant(t, db, "nms-alert-route-a"), freshTenant(t, db, "nms-alert-route-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove alert preview tenants: %v", err)
		}
	})
	contextID := googleuuid.NewString()
	capturer := nmsimport.NewCaptureStore(db.Pool(),
		func(context.Context, tenancy.Scope, string, string, map[string]any) error { return nil })
	gate := ai.NewEgressGate(func(context.Context, string) (bool, error) { return true, nil },
		func(context.Context, ai.EgressEvent) error { return nil }, ai.RedactionPolicy{})
	mcpServer := NewMCPServerWithPolicyLoader(&config.Config{},
		slog.New(slog.NewTextHandler(io.Discard, nil)), db.Pool(), nil, 0,
		gate, nil, nil, nil)
	const query = `SELECT * FROM devices,ports WHERE (devices.device_id = ? AND devices.device_id = ports.device_id) AND ports.ifOperStatus != "up"`
	rule := `{"status":"ok","rules":[{"id":31,"name":"Port down","severity":"critical",` +
		`"devices":[17],"groups":[],"locations":[],"invert_map":0,"disabled":1,` +
		`"builder":{"condition":"AND","rules":[{"id":"ports.ifOperStatus",` +
		`"field":"ports.ifOperStatus","type":"string","input":"text",` +
		`"operator":"not_equal","value":"up"}],"valid":true},` +
		`"query":` + strconv.Quote(query) + `,"extra":{"options":{"override_query":false}},` +
		`"operations":[{"transport":"source-only-secret"}]}]}`
	type imported struct{ sourceID, entityID, planID, snapshotHash string }
	byTenant := map[string]imported{}
	for _, tenant := range []string{a, b} {
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
				VALUES ($1,$2,$3,$4,'Lab','Private')`, tenant, contextID,
				googleuuid.NewString(), googleuuid.NewString())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		planID, err := capturer.StartPlan(ctx, contextID, nmsimport.LibreNMS,
			"alert-route", strings.Repeat("a", 64))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := capturer.AppendPage(ctx, contextID, planID, 0, "devices", 0,
			strings.NewReader(`{"status":"ok","count":1,"devices":[{"device_id":17,"display":"Edge","ip":"10.0.0.1","location_id":5}]}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := capturer.AppendPage(ctx, contextID, planID, 1, "locations", 1,
			strings.NewReader(`{"status":"ok","count":1,"locations":[{"id":5,"location":"Lab"}]}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := capturer.AppendPage(ctx, contextID, planID, 2, "rules", 2,
			strings.NewReader(rule)); err != nil {
			t.Fatal(err)
		}
		snapshot, err := capturer.Seal(ctx, contextID, planID, 3, 3)
		if err != nil {
			t.Fatal(err)
		}
		if err := capturer.SetReviewChoices(ctx, contextID, planID, snapshot,
			[]nmsimport.ReviewChoice{{RowNumber: 0, Action: "create"},
				{RowNumber: 1, Action: "create"}, {RowNumber: 2, Action: "unmapped"}}); err != nil {
			t.Fatal(err)
		}
		review, err := capturer.FinalizeReview(ctx, contextID, planID, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := capturer.ApplyReview(ctx, contextID, planID, snapshot, review); err != nil {
			t.Fatal(err)
		}
		got := imported{planID: planID, snapshotHash: snapshot}
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			if err := sc.Q.QueryRow(ctx, `SELECT source_id::text FROM nms_import_plans
				WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, tenant, contextID,
				planID).Scan(&got.sourceID); err != nil {
				return err
			}
			return sc.Q.QueryRow(ctx, `SELECT entity_id::text FROM nms_import_provenance
				WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3
				  AND object_kind='device' AND external_id='17'`, tenant, contextID,
				got.sourceID).Scan(&got.entityID)
		}); err != nil {
			t.Fatal(err)
		}
		byTenant[tenant] = got
	}
	const agentID, target = "alert-route-agent", "192.0.2.44"
	for _, tenant := range []string{a, b} {
		owned := byTenant[tenant]
		selection := map[string]string{"context_id": contextID, "source_id": owned.sourceID,
			"rule_external_id": "31", "agent_id": agentID, "target_address": target}
		if got := apiReq(t, h, http.MethodPost, "/v1/nms-imports/alert-target-preview",
			tenant, selection); got.Code != http.StatusNotFound {
			t.Fatalf("unbound source selected an alert target: %d %s", got.Code, got.Body.String())
		}
		ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
				(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`, tenant,
				agentID, contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
				(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
				VALUES ($1,$2,'device_target',$3,$4,$5)`, tenant, agentID,
				target, contextID, owned.entityID); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO agent_identities
				(tenant_id,agent_id,spiffe_id,serial,not_after)
				VALUES ($1,$2,$3,$4,clock_timestamp()+interval '1 hour')`,
				tenant, agentID,
				"spiffe://probectl/tenant/"+tenant+"/entity/"+agentID,
				googleuuid.NewString())
			return err
		}); err != nil {
			t.Fatal(err)
		}
		response := apiReq(t, h, http.MethodPost,
			"/v1/nms-imports/alert-target-preview", tenant, selection)
		var preview nmsimport.LibreNMSAlertTargetPreview
		if response.Code != http.StatusOK ||
			json.Unmarshal(response.Body.Bytes(), &preview) != nil ||
			preview.TenantID != tenant || preview.EntityID != owned.entityID ||
			preview.DeviceID != "17" || preview.RuleID != "31" ||
			preview.RuleKind != "port_down" || preview.Enabled ||
			strings.Contains(response.Body.String(), "SELECT *") ||
			strings.Contains(response.Body.String(), "source-only-secret") {
			t.Fatalf("finite alert preview: %d %s", response.Code, response.Body.String())
		}
		principal := &auth.Principal{TenantID: tenant, UserID: "alert-importer",
			Permissions: map[string]bool{permNMSImportRead: true,
				permNMSImportWrite: true, ai.PermEntitiesRead: true, permAlertWrite: true}}
		selectionInput := mcp.NMSImportAlertTargetInput{ContextID: contextID,
			SourceID: owned.sourceID, RuleID: "31", AgentID: agentID,
			TargetAddress: target}
		mcpPreviewData, failed := nativeControlCall(t, mcpServer, principal,
			"nms_import_alert_target", selectionInput)
		var mcpPreview mcp.NMSImportAlertTargetResult
		if failed || json.Unmarshal(mcpPreviewData, &mcpPreview) != nil ||
			mcpPreview.TenantID != tenant || mcpPreview.EntityID != owned.entityID ||
			mcpPreview.PlanID != preview.PlanID || mcpPreview.Enabled ||
			strings.Contains(string(mcpPreviewData), "SELECT *") ||
			strings.Contains(string(mcpPreviewData), "source-only-secret") {
			t.Fatalf("MCP finite alert preview: %s", mcpPreviewData)
		}
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM alert_rules WHERE tenant_id=$1`,
				tenant).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				t.Fatal("read-only alert preview created a native alert")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		apply := map[string]string{"context_id": contextID, "source_id": owned.sourceID,
			"rule_external_id": "31", "agent_id": agentID, "target_address": target,
			"plan_id": owned.planID, "snapshot_hash": owned.snapshotHash,
			"entity_id": owned.entityID}
		foreign := byTenant[map[string]string{a: b, b: a}[tenant]]
		apply["source_id"] = foreign.sourceID
		if response := apiReq(t, h, http.MethodPost,
			"/v1/nms-imports/alert-target-apply", tenant, apply); response.Code != http.StatusNotFound {
			t.Fatalf("foreign source created native alert: %d %s", response.Code, response.Body.String())
		}
		apply["source_id"], apply["target_address"] = owned.sourceID, "10.0.0.1"
		if response := apiReq(t, h, http.MethodPost,
			"/v1/nms-imports/alert-target-apply", tenant, apply); response.Code != http.StatusNotFound {
			t.Fatalf("source address selected native target: %d %s", response.Code, response.Body.String())
		}
		apply["target_address"], apply["snapshot_hash"] = target, strings.Repeat("0", 64)
		if response := apiReq(t, h, http.MethodPost,
			"/v1/nms-imports/alert-target-apply", tenant, apply); response.Code != http.StatusConflict {
			t.Fatalf("stale snapshot created native alert: %d %s", response.Code, response.Body.String())
		}
		apply["snapshot_hash"] = owned.snapshotHash
		auditFailure := errors.New("alert audit unavailable")
		unavailable := nmsimport.NewCaptureStore(db.Pool(),
			func(context.Context, tenancy.Scope, string, string, map[string]any) error {
				return auditFailure
			})
		if _, err := unavailable.ApplyLibreNMSAlertTarget(ctx, contextID,
			owned.sourceID, "31", agentID, target, owned.planID,
			owned.snapshotHash, owned.entityID, nmsimport.LibreNMSFetchPolicy{}); !errors.Is(err, auditFailure) {
			t.Fatalf("alert write survived audit failure: %v", err)
		}
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM alert_rules WHERE tenant_id=$1`,
				tenant).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				t.Fatal("audit failure committed a native alert")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		var applied nmsimport.AppliedAlertTarget
		if tenant == a {
			created := apiReq(t, h, http.MethodPost,
				"/v1/nms-imports/alert-target-apply", tenant, apply)
			if created.Code != http.StatusCreated ||
				json.Unmarshal(created.Body.Bytes(), &applied) != nil {
				t.Fatalf("REST reviewed alert apply: %d %s", created.Code, created.Body.String())
			}
		} else {
			data, failed := nativeControlCall(t, mcpServer, principal,
				"nms_import_alert_apply", mcp.NMSImportAlertApplyInput{
					ContextID: contextID, SourceID: owned.sourceID, RuleID: "31",
					AgentID: agentID, TargetAddress: target,
					PlanID: owned.planID, SnapshotHash: owned.snapshotHash,
					EntityID: owned.entityID})
			if failed || json.Unmarshal(data, &applied) != nil {
				t.Fatalf("MCP reviewed alert apply: %s", data)
			}
		}
		if !applied.Created || applied.AlertRuleID == "" {
			t.Fatalf("reviewed alert did not create a rule: %+v", applied)
		}
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			var enabled bool
			var name, metric, match, channels, source, device, agent, address string
			err := sc.Q.QueryRow(ctx, `SELECT a.enabled,a.name,a.metric,a.match_labels::text,
				a.channels::text,b.source_id::text,b.device_external_id,b.agent_id,b.target_address
				FROM alert_rules a JOIN nms_import_alert_bindings b
				ON (a.tenant_id,a.id)=(b.tenant_id,b.alert_rule_id)
				WHERE a.tenant_id=$1 AND a.id=$2`, tenant, applied.AlertRuleID).
				Scan(&enabled, &name, &metric, &match, &channels, &source, &device, &agent, &address)
			if err != nil {
				return err
			}
			var labels map[string]string
			if err := json.Unmarshal([]byte(match), &labels); err != nil {
				return err
			}
			if enabled || name != "Port down" || metric != "probectl_device_if_oper_status" ||
				len(labels) != 2 || labels["agent_id"] != agentID || labels["device"] != target ||
				channels != "[]" || source != owned.sourceID || device != "17" ||
				agent != agentID || address != target {
				t.Fatalf("import created wrong native alert: enabled=%v name=%q metric=%q match=%q channels=%q source=%q device=%q agent=%q address=%q",
					enabled, name, metric, match, channels, source, device, agent, address)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		again := apiReq(t, h, http.MethodPost,
			"/v1/nms-imports/alert-target-apply", tenant, apply)
		var repeated nmsimport.AppliedAlertTarget
		if again.Code != http.StatusOK || json.Unmarshal(again.Body.Bytes(), &repeated) != nil ||
			repeated.Created || repeated.AlertRuleID != applied.AlertRuleID {
			t.Fatalf("repeated source rule wrote again: %d %s", again.Code, again.Body.String())
		}
		selection["source_id"] = foreign.sourceID
		if got := apiReq(t, h, http.MethodPost,
			"/v1/nms-imports/alert-target-preview", tenant, selection); got.Code != http.StatusNotFound {
			t.Fatalf("foreign source selected alert target: %d %s", got.Code, got.Body.String())
		}
		selection["source_id"], selection["target_address"] = owned.sourceID, "10.0.0.1"
		if got := apiReq(t, h, http.MethodPost,
			"/v1/nms-imports/alert-target-preview", tenant, selection); got.Code != http.StatusNotFound {
			t.Fatalf("source address selected agent target: %d %s", got.Code, got.Body.String())
		}
		if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET revoked_at=clock_timestamp()
				WHERE tenant_id=$1 AND agent_id=$2`, tenant, agentID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if response := apiReq(t, h, http.MethodPost,
			"/v1/nms-imports/alert-target-apply", tenant, apply); response.Code != http.StatusNotFound {
			t.Fatalf("revoked sender reused alert binding: %d %s", response.Code, response.Body.String())
		}
	}
	srv.abac = &abacCache{load: func(_ context.Context, tenant string) ([]auth.Policy, error) {
		if tenant != a {
			return nil, nil
		}
		return []auth.Policy{{Name: "deny alert write in lab", Enabled: true,
			Effect: auth.PolicyDeny, Permission: permAlertWrite,
			Resource: map[string]string{"site_label": "Lab"}}}, nil
	}}
	left := byTenant[a]
	denied := apiReq(t, h, http.MethodPost, "/v1/nms-imports/alert-target-apply", a,
		map[string]string{"context_id": contextID, "source_id": left.sourceID,
			"rule_external_id": "31", "agent_id": agentID, "target_address": target,
			"plan_id": left.planID, "snapshot_hash": left.snapshotHash,
			"entity_id": left.entityID})
	if denied.Code != http.StatusForbidden {
		t.Fatalf("alert.write ABAC denial failed: %d %s", denied.Code, denied.Body.String())
	}
}
