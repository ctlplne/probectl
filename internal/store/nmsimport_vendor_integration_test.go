// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/nmsimport"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// The dedicated CI job captures these bytes from running, digest-pinned
// LibreNMS and Zabbix containers. This test imports both source inventories
// into two real Postgres tenants. It does not treat vendor bytes as a tenant,
// routing-context, destination, credential, or alert-activation authority.
func TestNMSVendorLiveImportTwoTenants(t *testing.T) {
	dir := os.Getenv("PROBECTL_TEST_NMS_VENDOR_DIR")
	if dir == "" {
		if os.Getenv("PROBECTL_TEST_REQUIRE_NMS_VENDOR") == "1" {
			t.Fatal("required real NMS vendor fixture is unavailable")
		}
		// The broad integration lane requires its own services. This vendor
		// fixture belongs to the separate required nms-vendor-live CI job.
		testsupport.SkipOptIn(t, "PROBECTL_TEST_REQUIRE_NMS_VENDOR",
			"dedicated real NMS vendor job supplies the fixture")
	}
	read := func(name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || len(data) == 0 {
			t.Fatalf("real NMS fixture %s unavailable: %v", name, err)
		}
		return data
	}
	var manifest struct {
		LibreNMS struct {
			DeviceID   string `json:"device_id"`
			LocationID string `json:"location_id"`
			GroupID    string `json:"group_id"`
			GroupName  string `json:"group_name"`
		} `json:"librenms"`
		Zabbix struct {
			HostKey   string `json:"host_key"`
			GroupName string `json:"group_name"`
		} `json:"zabbix"`
	}
	if err := json.Unmarshal(read("manifest.json"), &manifest); err != nil {
		t.Fatalf("real NMS fixture manifest invalid: %v", err)
	}
	ctx := context.Background()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "vendor-import-a-"+suffix, "Vendor import A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "vendor-import-b-"+suffix, "Vendor import B")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`,
			[]string{a.ID, b.ID}); err != nil {
			t.Errorf("remove NMS vendor fixture tenants: %v", err)
		}
	})
	contextID := uuid.NewString()
	for _, tenant := range []string{a.ID, b.ID} {
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
				VALUES ($1,$2,$3,$4,'Vendor lab','Private')`, tenant, contextID,
				uuid.NewString(), uuid.NewString())
			return err
		})
	}
	auditEvents := 0
	capturer := nmsimport.NewCaptureStore(pool,
		func(_ context.Context, _ tenancy.Scope, _, _ string, _ map[string]any) error {
			auditEvents++
			return nil
		})
	libreFiles := map[string][]byte{}
	for _, name := range []string{"devices", "locations", "groups", "members", "rules"} {
		libreFiles[name] = read("librenms-" + name + ".json")
	}
	assertLiveLibreNMSRuleSelector(t, libreFiles["rules"], manifest.LibreNMS.DeviceID)
	zabbixExport := read("zabbix-hosts.json")
	type applied struct{ librePlan, zabbixPlan, libreRule, libreDevice, zabbixDevice, libreSource, zabbixSource string }
	byTenant := map[string]applied{}
	for _, tenant := range []string{a.ID, b.ID} {
		tenantCtx := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		librePlan, err := capturer.StartPlan(tenantCtx, contextID, nmsimport.LibreNMS,
			"vendor-librenms", strings.Repeat("a", 64))
		if err != nil {
			t.Fatal(err)
		}
		libreSnapshot, err := capturer.CaptureLibreNMSInventory(tenantCtx, contextID,
			librePlan, bytes.NewReader(libreFiles["devices"]), bytes.NewReader(libreFiles["locations"]),
			bytes.NewReader(libreFiles["groups"]), bytes.NewReader(libreFiles["rules"]),
			[]nmsimport.LibreNMSMembershipList{{GroupID: manifest.LibreNMS.GroupID,
				GroupName: manifest.LibreNMS.GroupName, Raw: bytes.NewReader(libreFiles["members"])}})
		if err != nil {
			t.Fatalf("capture live LibreNMS inventory: %v", err)
		}
		libreRows, err := capturer.ListSealedRows(tenantCtx, contextID, librePlan, -1, 100)
		if err != nil || libreRows.NextCursor != nil {
			t.Fatalf("page live LibreNMS inventory: %v", err)
		}
		libreChoices := make([]nmsimport.ReviewChoice, 0, len(libreRows.Items))
		libreSeen := map[string]bool{}
		libreRuleID := ""
		for _, row := range libreRows.Items {
			choice := nmsimport.ReviewChoice{RowNumber: row.Number, Action: "skip"}
			switch {
			case row.Kind == "device" && row.ExternalID == manifest.LibreNMS.DeviceID:
				if row.Address != "192.0.2.40" || row.LocationID != manifest.LibreNMS.LocationID {
					t.Fatalf("LibreNMS device mapped fields changed: %+v", row)
				}
				choice.Action, libreSeen["device"] = "create", true
			case row.Kind == "site" && row.ExternalID == manifest.LibreNMS.LocationID:
				if row.Label != "Fixture East" {
					t.Fatalf("LibreNMS site label changed: %q", row.Label)
				}
				choice.Action, libreSeen["site"] = "create", true
			case row.Kind == "group" && row.ExternalID == manifest.LibreNMS.GroupID:
				if row.Label != manifest.LibreNMS.GroupName {
					t.Fatalf("LibreNMS group label changed: %q", row.Label)
				}
				choice.Action, libreSeen["group"] = "create", true
			case row.Kind == "membership" && row.ExternalID == manifest.LibreNMS.GroupID+":"+manifest.LibreNMS.DeviceID:
				choice.Action, libreSeen["membership"] = "create", true
			case row.Kind == "alert_rule":
				if !strings.Contains(strings.Join(row.UnmappedCodes, ","), "expression_unmapped") {
					t.Fatal("LibreNMS rule expression was silently dropped")
				}
				if row.ParentID != manifest.LibreNMS.DeviceID {
					t.Fatal("finite LibreNMS rule did not retain its exact source device selector")
				}
				libreRuleID = row.ExternalID
				choice.Action, libreSeen["rule_unmapped"] = "unmapped", true
			}
			libreChoices = append(libreChoices, choice)
		}
		for _, key := range []string{"device", "site", "group", "membership", "rule_unmapped"} {
			if !libreSeen[key] {
				t.Fatalf("live LibreNMS %s was not captured", key)
			}
		}
		if err := capturer.SetReviewChoices(tenantCtx, contextID, librePlan,
			libreSnapshot, libreChoices); err != nil {
			t.Fatalf("review live LibreNMS rows: %v", err)
		}
		libreReview, err := capturer.FinalizeReview(tenantCtx, contextID, librePlan, libreSnapshot)
		if err != nil {
			t.Fatalf("freeze live LibreNMS review: %v", err)
		}
		if _, err := capturer.ListReviewDiff(tenantCtx, contextID, librePlan,
			libreReview, -1, 100); err != nil {
			t.Fatalf("dry-run live LibreNMS review: %v", err)
		}
		assertNoVendorWrites(ctx, t, pool, tenant, contextID)
		if tenant == a.ID {
			foreignCtx := tenancy.WithTenant(ctx, tenancy.ID(b.ID))
			if _, err := capturer.ListSealedRows(foreignCtx, contextID, librePlan, -1, 10); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
				t.Fatalf("foreign tenant read LibreNMS plan: %v", err)
			}
			if _, err := capturer.ApplyReview(foreignCtx, contextID, librePlan,
				libreSnapshot, libreReview); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
				t.Fatalf("foreign tenant applied LibreNMS plan: %v", err)
			}
		}
		libreProgress, err := capturer.ApplyReview(tenantCtx, contextID, librePlan,
			libreSnapshot, libreReview)
		if err != nil || libreProgress.State != "applied" || libreProgress.Applied != 4 {
			t.Fatalf("apply live LibreNMS inventory: %+v err=%v", libreProgress, err)
		}
		libreRetry, err := capturer.ApplyReview(tenantCtx, contextID, librePlan,
			libreSnapshot, libreReview)
		if err != nil || libreRetry.Applied != 0 {
			t.Fatalf("repeat live LibreNMS import wrote again: %+v err=%v", libreRetry, err)
		}

		zabbixPlan, err := capturer.StartPlan(tenantCtx, contextID, nmsimport.Zabbix,
			"vendor-zabbix", strings.Repeat("b", 64))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := capturer.AppendPage(tenantCtx, contextID, zabbixPlan, 0,
			"hosts", 0, bytes.NewReader(zabbixExport)); err != nil {
			t.Fatalf("capture live Zabbix export: %v", err)
		}
		var zabbixCount int64
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM nms_import_rows
				WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3`, tenant, contextID,
				zabbixPlan).Scan(&zabbixCount)
		})
		zabbixSnapshot, err := capturer.Seal(tenantCtx, contextID, zabbixPlan, 1, zabbixCount)
		if err != nil {
			t.Fatalf("seal live Zabbix export: %v", err)
		}
		zabbixRows, err := capturer.ListSealedRows(tenantCtx, contextID, zabbixPlan, -1, 100)
		if err != nil || zabbixRows.NextCursor != nil {
			t.Fatalf("page live Zabbix export: %v", err)
		}
		zabbixChoices := make([]nmsimport.ReviewChoice, 0, len(zabbixRows.Items))
		zabbixSeen := map[string]bool{}
		zabbixGroupID := ""
		for _, row := range zabbixRows.Items {
			choice := nmsimport.ReviewChoice{RowNumber: row.Number, Action: "skip"}
			switch {
			case row.Kind == "group" && row.Label == manifest.Zabbix.GroupName:
				if !strings.Contains(strings.Join(row.UnmappedCodes, ","), "group_unmapped") {
					t.Fatal("Zabbix group was not a review-only source candidate")
				}
				zabbixGroupID = row.ExternalID
				choice.Action, zabbixSeen["group"] = "create", true
			case row.Kind == "device" && row.ExternalID == manifest.Zabbix.HostKey:
				if row.Address != "192.0.2.40" || row.Label != "Fixture Edge R1" || len(row.GroupIDs) != 1 {
					t.Fatalf("Zabbix host mapped fields changed: %+v", row)
				}
				choice.Action, zabbixSeen["device"] = "create", true
			case row.Kind == "membership":
				if row.ExternalID != zabbixGroupID+":"+manifest.Zabbix.HostKey ||
					!strings.Contains(strings.Join(row.UnmappedCodes, ","), "group_unmapped") {
					t.Fatalf("Zabbix member is not the exact source pair: %+v", row)
				}
				choice.Action, zabbixSeen["membership"] = "create", true
			case row.Kind == "poll_setting" && row.ParentID == manifest.Zabbix.HostKey:
				if row.PollSeconds != 15 || !strings.Contains(strings.Join(row.UnmappedCodes, ","), "poll_proposal") {
					t.Fatalf("Zabbix SNMP cadence not retained: %+v", row)
				}
				choice.Action, zabbixSeen["poll"] = "create", true
			case row.Kind == "alert_rule":
				if !strings.Contains(strings.Join(row.UnmappedCodes, ","), "expression_unmapped") {
					t.Fatal("Zabbix trigger expression was silently dropped")
				}
				choice.Action, zabbixSeen["rule_unmapped"] = "unmapped", true
			}
			zabbixChoices = append(zabbixChoices, choice)
		}
		for _, key := range []string{"group", "device", "membership", "poll", "rule_unmapped"} {
			if !zabbixSeen[key] {
				t.Fatalf("live Zabbix %s was not captured", key)
			}
		}
		if err := capturer.SetReviewChoices(tenantCtx, contextID, zabbixPlan,
			zabbixSnapshot, zabbixChoices); err != nil {
			t.Fatalf("review live Zabbix rows: %v", err)
		}
		zabbixReview, err := capturer.FinalizeReview(tenantCtx, contextID,
			zabbixPlan, zabbixSnapshot)
		if err != nil {
			t.Fatalf("freeze live Zabbix review: %v", err)
		}
		if _, err := capturer.ListReviewDiff(tenantCtx, contextID, zabbixPlan,
			zabbixReview, -1, 100); err != nil {
			t.Fatalf("dry-run live Zabbix review: %v", err)
		}
		zabbixProgress, err := capturer.ApplyReview(tenantCtx, contextID, zabbixPlan,
			zabbixSnapshot, zabbixReview)
		if err != nil || zabbixProgress.State != "applied" || zabbixProgress.Applied != 4 {
			t.Fatalf("apply live Zabbix inventory: %+v err=%v", zabbixProgress, err)
		}
		zabbixRetry, err := capturer.ApplyReview(tenantCtx, contextID, zabbixPlan,
			zabbixSnapshot, zabbixReview)
		if err != nil || zabbixRetry.Applied != 0 {
			t.Fatalf("repeat live Zabbix import wrote again: %+v err=%v", zabbixRetry, err)
		}
		var bound applied
		bound.librePlan, bound.zabbixPlan, bound.libreRule = librePlan, zabbixPlan, libreRuleID
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, binding := range []struct {
				kind, externalID, planID string
				out                      *string
			}{
				{"device", manifest.LibreNMS.DeviceID, librePlan, &bound.libreDevice},
				{"device", manifest.Zabbix.HostKey, zabbixPlan, &bound.zabbixDevice},
			} {
				if err := sc.Q.QueryRow(ctx, `SELECT entity_id::text FROM nms_import_provenance
					WHERE tenant_id=$1 AND context_id=$2 AND plan_id=$3
					  AND object_kind=$4 AND external_id=$5`, tenant, contextID, binding.planID,
					binding.kind, binding.externalID).Scan(binding.out); err != nil {
					return err
				}
			}
			if err := sc.Q.QueryRow(ctx, `SELECT source_id::text FROM nms_import_plans
				WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, tenant, contextID,
				librePlan).Scan(&bound.libreSource); err != nil {
				return err
			}
			return sc.Q.QueryRow(ctx, `SELECT source_id::text FROM nms_import_plans
				WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, tenant, contextID,
				zabbixPlan).Scan(&bound.zabbixSource)
		})
		byTenant[tenant] = bound
	}
	left, right := byTenant[a.ID], byTenant[b.ID]
	if left.libreDevice == right.libreDevice || left.zabbixDevice == right.zabbixDevice ||
		left.libreSource == right.libreSource || left.zabbixSource == right.zabbixSource {
		t.Fatal("real vendor import shared a tenant source or canonical device")
	}
	// The source rule's one-device selector does not nominate an agent target.
	// Both tenants deliberately use the same agent name and target address;
	// only current same-tenant canonical bindings may complete the preview.
	const alertAgent, alertTarget = "vendor-alert-agent", "192.0.2.88"
	for _, tenant := range []string{a.ID, b.ID} {
		bound := byTenant[tenant]
		tenantCtx := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		if _, err := capturer.PreviewLibreNMSAlertTarget(tenantCtx, contextID,
			bound.libreSource, bound.libreRule, alertAgent, alertTarget); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
			t.Fatalf("unbound LibreNMS selector chose an agent target: %v", err)
		}
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts
				(tenant_id,agent_id,context_id) VALUES ($1,$2,$3)`,
				tenant, alertAgent, contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts
				(tenant_id,agent_id,source_kind,source_ref,context_id,anchor_entity_id)
				VALUES ($1,$2,'device_target',$3,$4,$5)`, tenant, alertAgent,
				alertTarget, contextID, bound.libreDevice); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO agent_identities
				(tenant_id,agent_id,spiffe_id,serial,not_after)
				VALUES ($1,$2,$3,$4,clock_timestamp()+interval '1 hour')`,
				tenant, alertAgent,
				"spiffe://probectl/tenant/"+tenant+"/entity/"+alertAgent,
				uuid.NewString())
			return err
		})
		preview, err := capturer.PreviewLibreNMSAlertTarget(tenantCtx, contextID,
			bound.libreSource, bound.libreRule, alertAgent, alertTarget)
		if err != nil || preview.TenantID != tenant || preview.ContextID != contextID ||
			preview.RuleID != bound.libreRule || preview.DeviceID != manifest.LibreNMS.DeviceID ||
			preview.EntityID != bound.libreDevice || preview.AgentID != alertAgent ||
			preview.TargetAddress != alertTarget || preview.PlanID != bound.librePlan ||
			preview.SnapshotHash == "" || preview.RuleKind != "port_down" || preview.Enabled ||
			preview.Severity == "" {
			t.Fatalf("real LibreNMS alert preview escaped finite binding: %+v, %v", preview, err)
		}
		wire, err := json.Marshal(preview)
		if err != nil || strings.Contains(string(wire), "SELECT *") ||
			strings.Contains(string(wire), "192.0.2.40") ||
			strings.Contains(string(wire), "operations") ||
			strings.Contains(string(wire), "community") {
			t.Fatalf("source query, address or credential escaped alert preview: %v", err)
		}
		foreignSource := map[string]string{a.ID: right.libreSource, b.ID: left.libreSource}[tenant]
		if _, err := capturer.PreviewLibreNMSAlertTarget(tenantCtx, contextID,
			foreignSource, bound.libreRule, alertAgent, alertTarget); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
			t.Fatalf("foreign LibreNMS source selected an alert target: %v", err)
		}
		if _, err := capturer.PreviewLibreNMSAlertTarget(tenantCtx, contextID,
			bound.libreSource, bound.libreRule, alertAgent, "192.0.2.40"); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
			t.Fatalf("source device address selected an unassigned alert target: %v", err)
		}
	}
	for _, tenant := range []string{a.ID, b.ID} {
		bound := byTenant[tenant]
		inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var libreGroup, libreMember, zabbixGroup, zabbixMember, pollProposal, alertRules, foreign int
			for _, item := range []struct {
				query string
				out   *int
				args  []any
			}{
				{`SELECT count(*) FROM nms_import_groups WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND external_id=$4`,
					&libreGroup, []any{tenant, contextID, bound.libreSource, manifest.LibreNMS.GroupID}},
				{`SELECT count(*) FROM nms_import_group_members WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND group_external_id=$4 AND member_external_id=$5`,
					&libreMember, []any{tenant, contextID, bound.libreSource, manifest.LibreNMS.GroupID, manifest.LibreNMS.DeviceID}},
				{`SELECT count(*) FROM nms_import_groups WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3`,
					&zabbixGroup, []any{tenant, contextID, bound.zabbixSource}},
				{`SELECT count(*) FROM nms_import_group_members WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND member_external_id=$4`,
					&zabbixMember, []any{tenant, contextID, bound.zabbixSource, manifest.Zabbix.HostKey}},
				{`SELECT count(*) FROM nms_import_poll_proposals WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3 AND host_external_id=$4 AND poll_seconds=15`,
					&pollProposal, []any{tenant, contextID, bound.zabbixSource, manifest.Zabbix.HostKey}},
				{`SELECT count(*) FROM alert_rules WHERE tenant_id=$1`, &alertRules, []any{tenant}},
				{`SELECT count(*) FROM nms_import_provenance WHERE tenant_id=$1 AND context_id=$2 AND entity_id=$3`,
					&foreign, []any{tenant, contextID, map[string]string{a.ID: right.zabbixDevice, b.ID: left.zabbixDevice}[tenant]}},
			} {
				if err := sc.Q.QueryRow(ctx, item.query, item.args...).Scan(item.out); err != nil {
					return err
				}
			}
			if libreGroup != 1 || libreMember != 1 || zabbixGroup != 1 || zabbixMember != 1 || pollProposal != 1 ||
				alertRules != 0 || foreign != 0 {
				t.Fatalf("real vendor destination tenant boundary: libreGroup=%d libreMember=%d zabbixGroup=%d zabbixMember=%d poll=%d alerts=%d foreign=%d",
					libreGroup, libreMember, zabbixGroup, zabbixMember, pollProposal, alertRules, foreign)
			}
			return nil
		})
	}
	if auditEvents == 0 {
		t.Fatal("real vendor import emitted no tenant audit events")
	}
}

// The pinned vendor version must actually serialize all three selector sets
// and the inversion bit before any future finite rule translation relies on
// one-device scope. Source expressions and delivery bodies stay in this CI
// fixture only; a failure prints no raw rule or transport field.
func assertLiveLibreNMSRuleSelector(t *testing.T, raw []byte, deviceID string) {
	t.Helper()
	var page struct {
		Rules []struct {
			Name      string            `json:"name"`
			Devices   []json.RawMessage `json:"devices"`
			Groups    []json.RawMessage `json:"groups"`
			Locations []json.RawMessage `json:"locations"`
			InvertMap json.RawMessage   `json:"invert_map"`
			Disabled  json.RawMessage   `json:"disabled"`
			Builder   json.RawMessage   `json:"builder"`
			Extra     json.RawMessage   `json:"extra"`
			Query     string            `json:"query"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(raw, &page); err != nil || page.Rules == nil {
		t.Fatalf("live LibreNMS rule selector envelope unavailable: %v", err)
	}
	selected := 0
	for _, rule := range page.Rules {
		if rule.Name != "Fixture port down" {
			continue
		}
		selected++
		oneDevice := len(rule.Devices) == 1 &&
			strings.Trim(string(bytes.TrimSpace(rule.Devices[0])), `"`) == deviceID
		if !oneDevice || rule.Groups == nil || len(rule.Groups) != 0 ||
			rule.Locations == nil || len(rule.Locations) != 0 ||
			!jsonFalse(rule.InvertMap) || !jsonTrue(rule.Disabled) ||
			len(bytes.TrimSpace(rule.Builder)) <= 2 || strings.TrimSpace(rule.Query) == "" {
			t.Fatal("live LibreNMS rule did not preserve a complete, disabled one-device selector")
		}
		var builder struct {
			Condition string `json:"condition"`
			Rules     []struct {
				Field    string `json:"field"`
				Operator string `json:"operator"`
				Value    string `json:"value"`
			} `json:"rules"`
		}
		var extra struct {
			Options struct {
				OverrideQuery json.RawMessage `json:"override_query"`
			} `json:"options"`
		}
		if json.Unmarshal(rule.Builder, &builder) != nil ||
			json.Unmarshal(rule.Extra, &extra) != nil ||
			builder.Condition != "AND" || len(builder.Rules) != 1 ||
			builder.Rules[0].Field != "ports.ifOperStatus" ||
			builder.Rules[0].Operator != "not_equal" ||
			builder.Rules[0].Value != "up" ||
			!jsonFalse(extra.Options.OverrideQuery) {
			t.Fatal("live LibreNMS rule did not preserve the finite builder and generated-query mode")
		}
	}
	if selected != 1 {
		t.Fatalf("expected one seeded LibreNMS rule, found %d", selected)
	}
}

func jsonFalse(raw json.RawMessage) bool {
	switch string(bytes.TrimSpace(raw)) {
	case "0", `"0"`, "false":
		return true
	default:
		return false
	}
}

func jsonTrue(raw json.RawMessage) bool {
	switch string(bytes.TrimSpace(raw)) {
	case "1", `"1"`, "true":
		return true
	default:
		return false
	}
}

func assertNoVendorWrites(ctx context.Context, t *testing.T, pool *pgxpool.Pool, tenant, contextID string) {
	t.Helper()
	inTenant(ctx, t, pool, tenant, func(ctx context.Context, sc tenancy.Scope) error {
		var entities, groups, members, proposals int
		if err := sc.Q.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM entities WHERE tenant_id=$1 AND context_id=$2),
			(SELECT count(*) FROM nms_import_groups WHERE tenant_id=$1 AND context_id=$2),
			(SELECT count(*) FROM nms_import_group_members WHERE tenant_id=$1 AND context_id=$2),
			(SELECT count(*) FROM nms_import_poll_proposals WHERE tenant_id=$1 AND context_id=$2)`,
			tenant, contextID).Scan(&entities, &groups, &members, &proposals); err != nil {
			return err
		}
		if entities != 0 || groups != 0 || members != 0 || proposals != 0 {
			t.Fatalf("dry run wrote destination data: entities=%d groups=%d members=%d proposals=%d",
				entities, groups, members, proposals)
		}
		return nil
	})
}
