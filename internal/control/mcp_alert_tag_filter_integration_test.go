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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The caller owns the real TLS/bearer/role/consent/call-audit transport and
// public-catalog lock. This proves metadata configuration, not telemetry senders
// or the complete release/four-store alert execution receipt.
func proveAlertTagFilterNative(t *testing.T, core *Server, pool *pgxpool.Pool, tenants []string, users, roles map[string]string,
	native func(string, string, any, bool) json.RawMessage, scoped func(string, any, bool) json.RawMessage) {
	t.Helper()
	ctx := t.Context()
	definition := uuid(t)
	ids := map[string]string{}
	inputs := map[string]alert.TagFilterInput{}
	mutate := func(tenant string, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, fn); err != nil {
			t.Fatal(err)
		}
	}
	cleanup := func() {
		for _, tenant := range tenants {
			if err := tenancy.InTenant(tenancy.WithTenant(context.Background(), tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
				if err := (store.AlertEvaluations{}).DeleteRule(ctx, sc, ids[tenant]); err != nil {
					return err
				}
				if _, err := sc.Q.Exec(ctx, `DELETE FROM alert_rules WHERE tenant_id=$1 AND id::text=$2`, tenant, ids[tenant]); err != nil {
					return err
				}
				_, err := sc.Q.Exec(ctx, `DELETE FROM tenant_tag_definitions WHERE tenant_id=$1 AND id=$2`, tenant, definition)
				return err
			}); err != nil {
				t.Error("owned native alert metadata cleanup failed")
			}
		}
	}
	t.Cleanup(cleanup)
	defer cleanup()
	for lane, tenant := range tenants {
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES($1,$2,'alert_customer')`, tenant, definition); err != nil {
				return err
			}
			rule, err := (store.AlertRules{}).Create(ctx, sc, alert.Rule{Name: "native-metadata", Metric: "probectl_probe_duration_seconds", Type: alert.Threshold, Comparison: alert.GT, Threshold: 1, Severity: alert.SeverityWarning})
			if err == nil {
				ids[tenant] = rule.ID
			}
			return err
		})
		wide := strings.Repeat("🌐", 23999) + []string{"A", "B"}[lane]
		var input alert.TagFilterInput
		if json.Unmarshal([]byte(`{"target_kind":"test","filter":{"match":"all","groups":[{"conditions":[{"field":"tag.alert_customer","op":"eq","values":[`+strconv.Quote(wide)+`]}]},{"mode":"exclude","conditions":[{"field":"tag.alert_customer","op":"eq","values":["excluded"]}]}]}}`), &input) != nil {
			t.Fatal("native alert fixture input is invalid")
		}
		inputs[tenant] = input
	}
	decode := func(raw json.RawMessage) alert.TagFilterState {
		t.Helper()
		var out alert.TagFilterState
		if json.Unmarshal(raw, &out) != nil {
			t.Fatal("native alert returned invalid metadata state")
		}
		if strings.Contains(string(raw), `"channels"`) || strings.Contains(string(raw), `"secret"`) || strings.Contains(string(raw), `"tenant_id"`) {
			t.Fatal("native alert metadata disclosed unrelated configuration")
		}
		return out
	}
	set := func(tenant string) alert.TagFilterState {
		t.Helper()
		return decode(native(tenant, "alert_tag_filter_set", map[string]any{"rule_id": ids[tenant], "input": inputs[tenant]}, true))
	}
	get := func(tenant string) alert.TagFilterState {
		t.Helper()
		return decode(native(tenant, "alert_tag_filter_get", map[string]any{"rule_id": ids[tenant]}, true))
	}
	// Explicit store fixtures over real TLS/auth/RLS; the separate source proof
	// verifies the evaluator actually used its reported snapshot.
	for lane, tenant := range tenants {
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			now := time.Now().UTC().Truncate(time.Microsecond)
			return (store.AlertEvaluations{}).Append(ctx, sc, alert.EvaluationReceipt{ContractVersion: alert.EvaluationReceiptVersion, RuleID: ids[tenant], Fingerprint: "eval:native-selection", RuleRevision: "native-fixture", State: alert.EvaluationNormal, ObservedAt: now, Expectation: alert.EvaluationExpectation{Kind: alert.Threshold}, RequiredBreaches: 1, Reason: "fixture selection", TagSelection: &alert.TagSelectionReceipt{TargetKind: "test", TagRevision: []string{"9007199254740993", "9007199254740995"}[lane], AsOf: now}})
		})
	}
	decodeReceipts := func(raw json.RawMessage) alert.EvaluationsResult {
		t.Helper()
		var out alert.EvaluationsResult
		if json.Unmarshal(raw, &out) != nil {
			t.Fatal("invalid native evaluation receipt")
		}
		return out
	}
	for lane, tenant := range tenants {
		out := decodeReceipts(native(tenant, "alert_evaluations", map[string]any{"rule_id": ids[tenant]}, true))
		if out.TagSelectionAccess != "available" || len(out.Items) != 1 || out.Items[0].TagSelection == nil || out.Items[0].TagSelection.TagRevision != []string{"9007199254740993", "9007199254740995"}[lane] || out.Items[0].RuleID != ids[tenant] {
			t.Fatal("native selection receipts lost current grants, exact revision or owned rule")
		}
		native(tenant, "alert_evaluations", map[string]any{"rule_id": ids[tenants[1-lane]]}, false)
		native(tenant, "alert_evaluations", map[string]any{"rule_id": ids[tenant], "tenant_id": tenants[1-lane]}, false)
	}
	withheld := decodeReceipts(scoped("alert_evaluations", map[string]any{"rule_id": ids[tenants[0]]}, true))
	if withheld.TagSelectionAccess != "withheld" || len(withheld.Items) != 1 || withheld.Items[0].TagSelection != nil {
		t.Fatal("native receipt source evidence widened scoped credential")
	}
	for lane, tenant := range tenants {
		if out := get(tenant); out.RuleID != ids[tenant] || out.HasTagFilter || out.TagFilter != nil {
			t.Fatal("new metric rule unexpectedly acquired tag criteria")
		}
		out := set(tenant)
		if !out.HasTagFilter || out.TagFilter == nil || out.TagFilter.OwnerUserID != users[tenant] || out.TagFilter.TagIDs["tag.alert_customer"] != definition {
			t.Fatal("native alert lost authenticated owner or immutable definition")
		}
		var revision int64
		if err := pool.QueryRow(ctx, `SELECT revision FROM tenant_tag_revisions WHERE tenant_id=$1`, tenant).Scan(&revision); err != nil || out.TagFilter.TagRevision != strconv.FormatInt(revision, 10) {
			t.Fatal("native alert changed exact current metadata revision")
		}
		fresh := get(tenant)
		if fresh.Editor == nil || len(fresh.Editor.Fields) != 1 || fresh.Editor.Fields[0].Name != "tag.alert_customer" || fresh.Editor.Fields[0].TagID != definition || fresh.Editor.TagRevision != out.TagFilter.TagRevision {
			t.Fatal("native alert read lost current root vocabulary or immutable schema identity")
		}
		actual, err := json.Marshal(fresh.TagFilter)
		if err != nil || fresh.TagFilter == nil || !strings.Contains(string(actual), inputs[tenant].Filter.Groups[0].Conditions[0].Values[0]) {
			t.Fatal("native alert lost full nested Unicode criteria")
		}
		other := tenants[1-lane]
		native(tenant, "alert_tag_filter_get", map[string]any{"rule_id": ids[other]}, false)
		native(tenant, "alert_tag_filter_set", map[string]any{"rule_id": ids[other], "input": inputs[tenant]}, false)
		native(tenant, "alert_tag_filter_clear", map[string]any{"rule_id": ids[other], "confirmed": true}, false)
		native(tenant, "alert_tag_filter_set", map[string]any{"rule_id": ids[tenant], "input": inputs[tenant], "owner_user_id": users[other]}, false)
		native(tenant, "alert_tag_filter_clear", map[string]any{"rule_id": ids[tenant]}, false)
	}
	first := tenants[0]
	args := map[string]any{"rule_id": ids[first], "input": inputs[first]}
	scoped("alert_tag_filter_get", map[string]any{"rule_id": ids[first]}, false)
	scoped("alert_tag_filter_set", args, false)
	cleared := decode(scoped("alert_tag_filter_clear", map[string]any{"rule_id": ids[first], "confirmed": true}, true))
	if cleared.HasTagFilter || cleared.TagFilter != nil || cleared.Editor != nil || get(first).HasTagFilter {
		t.Fatal("scoped explicit clear disclosed or retained old metadata")
	}
	set(first)
	mutate(first, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.RoleBindings{}).Unbind(ctx, sc, "user", users[first], roles[first])
	})
	native(first, "alert_tag_filter_get", map[string]any{"rule_id": ids[first]}, false)
	native(first, "alert_tag_filter_set", args, false)
	native(first, "alert_tag_filter_clear", map[string]any{"rule_id": ids[first], "confirmed": true}, false)
	mutate(first, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.RoleBindings{}).Bind(ctx, sc, "user", users[first], roles[first])
	})
	if !get(first).HasTagFilter || !get(tenants[1]).HasTagFilter {
		t.Fatal("refused or sibling operation changed metadata selection")
	}
	var policyID string
	mutate(first, func(ctx context.Context, sc tenancy.Scope) error {
		policy, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "native alert live MFA", Permission: "metrics.read", Effect: auth.PolicyDeny, Enabled: true, Subject: map[string]string{"mfa": "false"}})
		if err == nil {
			policyID = policy.ID
		}
		return err
	})
	core.abac.invalidate(first)
	native(first, "alert_tag_filter_get", map[string]any{"rule_id": ids[first]}, false)
	native(first, "alert_tag_filter_set", args, false)
	get(tenants[1])
	mutate(first, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.ABACPolicies{}).Delete(ctx, sc, policyID)
	})
	core.abac.invalidate(first)
	before := get(first)
	var updated time.Time
	if err := pool.QueryRow(ctx, `SELECT updated_at FROM alert_rules WHERE tenant_id=$1 AND id=$2`, first, ids[first]).Scan(&updated); err != nil {
		t.Fatal(err)
	}
	fault := "probectl_qa_beta_alert_native_audit_" + strings.ReplaceAll(uuid(t), "-", "")
	if _, err := pool.Exec(ctx, `CREATE FUNCTION public.`+fault+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
		IF NEW.tenant_id='`+first+`'::uuid AND NEW.action='alert.tag_filter.set' THEN RAISE EXCEPTION 'QA alert audit refused'; END IF;
		RETURN NEW; END $$; CREATE TRIGGER `+fault+` BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION public.`+fault+`()`); err != nil {
		t.Fatal(err)
	}
	drop := func() {
		if _, err := pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+fault+` ON audit_events; DROP FUNCTION IF EXISTS public.`+fault+`()`); err != nil {
			t.Error("owned native alert audit fault cleanup failed")
		}
	}
	t.Cleanup(drop)
	native(first, "alert_tag_filter_set", args, false)
	drop()
	after := get(first)
	var current time.Time
	if err := pool.QueryRow(ctx, `SELECT updated_at FROM alert_rules WHERE tenant_id=$1 AND id=$2`, first, ids[first]).Scan(&current); err != nil || !current.Equal(updated) || before.TagFilter.TagRevision != after.TagFilter.TagRevision {
		t.Fatal("domain audit refusal committed alert metadata or its rule version")
	}
	mutate(first, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE users SET status='disabled' WHERE tenant_id=$1 AND id=$2`, first, users[first])
		return err
	})
	native(first, "alert_tag_filter_get", map[string]any{"rule_id": ids[first]}, false)
	native(first, "alert_tag_filter_set", args, false)
	native(first, "alert_tag_filter_clear", map[string]any{"rule_id": ids[first], "confirmed": true}, false)
	get(tenants[1])
	mutate(first, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE users SET status='active' WHERE tenant_id=$1 AND id=$2`, first, users[first])
		return err
	})
}
