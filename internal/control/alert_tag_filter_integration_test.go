// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

type countedAlertTagMetrics struct {
	source alert.MetricSource
	calls  int
}

func (s *countedAlertTagMetrics) Current(ctx context.Context, metric string, match map[string]string) ([]alert.Sample, error) {
	s.calls++
	return s.source.Current(ctx, metric, match)
}

// Real PG/RLS/current-user/audit and HTTP-handler/source component proof. The
// metric store is in-process and principals are supplied after authentication;
// real credential/MCP/service/release/sender proofs remain required separately.
func TestAlertTagFiltersRecheckCurrentOwnedUserAndNeverRewriteSeries(t *testing.T) {
	core, db := setupAPIServerWithLatest(t, nil)
	testsupport.LockPostgresPublicCatalog(t, db.Pool())
	ctx := t.Context()
	var tenants []string
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error("owned alert metadata fixture cleanup failed")
		}
	})
	for _, lane := range []string{"a", "b"} {
		tenants = append(tenants, freshTenant(t, db, "alert-tags-"+lane))
	}
	contextID, tagID := uuid(t), uuid(t)
	users, roles, tests, unbound, ruleIDs := map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{}
	actors := map[string]*auth.Principal{}
	wants := map[string]string{}
	tagRules := map[string]tags.Rule{}
	mutate := func(tenant string, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), fn); err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range tenants {
		tests[tenant], unbound[tenant] = uuid(t), uuid(t)
		wants[tenant] = strings.Repeat("🌐", tags.MaxValueCharacters-1) + []string{"A", "B"}[lane]
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (store.Users{}).Create(ctx, sc, "owner@"+tenant+".invalid", "Metadata owner")
			if err != nil {
				return err
			}
			users[tenant] = user.ID
			role, err := (store.Roles{}).Create(ctx, sc, "alert-tag-owner", "Alert tag owner", "Current source proof")
			if err != nil {
				return err
			}
			roles[tenant] = role.ID
			for _, permission := range append(alertTagPermissions(), permAlertRead, permAlertWrite) {
				if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, permission); err != nil {
					return err
				}
			}
			if err := (store.RoleBindings{}).Bind(ctx, sc, "user", user.ID, role.ID); err != nil {
				return err
			}
			grants, err := (store.Permissions{}).ForSubject(ctx, sc, "user", user.ID)
			if err != nil {
				return err
			}
			actors[tenant] = auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: tenant, UserID: user.ID, Email: user.Email, MFASatisfied: true, Attributes: composeSubjectAttributes(nil, true)}, grants)
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'same-site','same-vrf')`, tenant, contextID, uuid(t), uuid(t)); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,target) VALUES($1,$2,'same-probe','https://192.0.2.10/health'),($1,$3,'unbound-probe','https://192.0.2.10/health')`, tenant, tests[tenant], unbound[tenant]); err != nil {
				return err
			}
			if err := store.NewEntityRegistry(db.Pool()).AssignPathTestContext(ctx, sc, tests[tenant], contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES($1,$2,'customer')`, tenant, tagID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES($1,$2,$3)`, tenant, uuid(t), []string{"private_a", "private_b"}[lane]); err != nil {
				return err
			}
			tag, err := (store.TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, TagID: tagID, TargetKind: "test", Match: "name_pattern", NamePattern: "^same-probe$", Value: wants[tenant]})
			if err != nil {
				return err
			}
			tagRules[tenant] = tag
			rule, err := (store.AlertRules{}).Create(ctx, sc, alert.Rule{Name: "same-rule", Enabled: true, Metric: "probectl_probe_duration_seconds", Type: alert.Threshold, Comparison: alert.GT, Threshold: 0.5, Severity: alert.SeverityWarning})
			if err != nil {
				return err
			}
			ruleIDs[tenant] = rule.ID
			return nil
		})
	}
	policy := fairness.DefaultPolicy()
	policy.QueryConcurrency = 2
	policy.QueriesPerMin = 10000
	gate := fairness.NewGate(policy, nil)
	core.WithFairness(gate)
	invoke := func(handler func(http.ResponseWriter, *http.Request) error, actor *auth.Principal, id, method string, body any) (*httptest.ResponseRecorder, error) {
		t.Helper()
		var raw []byte
		var err error
		if body != nil {
			raw, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		r := httptest.NewRequest(method, "/v1/alerts/rules/"+id+"/tag-filter", bytes.NewReader(raw))
		r.SetPathValue("id", id)
		r.Header.Set("Content-Type", "application/json")
		r = r.WithContext(auth.WithPrincipal(r.Context(), actor))
		w := httptest.NewRecorder()
		err = handler(w, r)
		return w, err
	}
	input := func(value string, op flow.QueryOperator) alert.TagFilterInput {
		return alert.TagFilterInput{TargetKind: "test", Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "tag.customer", Op: op, Values: []string{value}}}}}
	}
	getRule := func(tenant string) *alert.Rule {
		t.Helper()
		var out *alert.Rule
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			out, err = (store.AlertRules{}).Get(ctx, sc, ruleIDs[tenant])
			return err
		})
		return out
	}
	mem := tsdb.NewMemory()
	for lane, tenant := range tenants {
		foreign := tenants[1-lane]
		var series []tsdb.Series
		for _, id := range []string{tests[tenant], tests[foreign], unbound[tenant], "https://192.0.2.10/health"} {
			series = append(series, tsdb.Series{Metric: "probectl_probe_duration_seconds", Labels: map[string]string{"tenant_id": tenant, "test_id": id, "agent_id": "fixture-agent", "server_address": "192.0.2.10"}, Value: float64(lane + 1), TimeMillis: time.Now().UnixMilli()})
		}
		if err := mem.Write(ctx, series); err != nil {
			t.Fatal(err)
		}
	}
	beforeSeries := mem.Snapshot()
	for lane, tenant := range tenants {
		w, err := invoke(core.handlePutAlertTagFilter, actors[tenant], ruleIDs[tenant], http.MethodPut, input(wants[tenant], flow.QueryEqual))
		if err != nil || w.Code != http.StatusOK {
			t.Fatalf("put owned filter: %v / %d", err, w.Code)
		}
		var state alert.TagFilterState
		if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil || !state.HasTagFilter || state.TagFilter == nil || state.TagFilter.OwnerUserID != users[tenant] || state.TagFilter.TagIDs["tag.customer"] != tagID || state.TagFilter.Filter.Conditions[0].Values[0] != wants[tenant] {
			t.Fatal("metadata response lost current owner/immutable identity/full value")
		}
		if strings.Contains(w.Body.String(), `"channels"`) || strings.Contains(w.Body.String(), `"tenant_id"`) {
			t.Fatal("metadata response exposed rule channels or a tenant hint")
		}
		if state.Editor != nil {
			t.Fatal("metadata mutation unnecessarily disclosed an editor vocabulary")
		}
		read, err := readAlertTagFilter(ctx, db.Pool(), nil, actors[tenant], ruleIDs[tenant])
		if err != nil || read.Editor == nil || len(read.Editor.Fields) != 2 || read.Editor.TagRevision != state.TagFilter.TagRevision || read.Editor.AsOf == "" || read.Editor.Limits.MaxGroupEntries != flow.MaxQueryGroupEntries || read.Editor.Limits.MaxFilterDepth != flow.MaxQueryFilterDepth || read.Editor.Limits.MaxValueBytes != flow.MaxQueryValueBytes {
			t.Fatal("current alert editor lost its bounded snapshot vocabulary or shared grammar")
		}
		seenFields := map[string]bool{}
		for _, field := range read.Editor.Fields {
			if seenFields[field.Name] {
				t.Fatal("editor vocabulary duplicated a field")
			}
			seenFields[field.Name] = true
			if field.Name == "tag."+[]string{"private_b", "private_a"}[lane] || field.Type != flow.QueryText || len(field.Operators) == 0 || !strings.HasPrefix(field.Name, "tag.") {
				t.Fatal("editor schema disclosed foreign or non-test fields")
			}
			if field.Name == "tag.customer" && field.TagID != tagID {
				t.Fatal("editor schema changed immutable tag identity")
			}
		}
		if !seenFields["tag.customer"] || !seenFields["tag."+[]string{"private_a", "private_b"}[lane]] {
			t.Fatal("editor vocabulary omitted an authorized current tenant key")
		}
		counter := &countedAlertTagMetrics{source: metricSource{q: mem, tenant: tenant}}
		source := alertTagMetricSource{MetricSource: counter, pool: db.Pool(), tenant: tenant, deps: AlertTagDependencies{Gate: gate}}
		selected, err := source.CurrentRule(ctx, *getRule(tenant))
		if err != nil || len(selected.Samples) != 1 || selected.Samples[0].Labels["test_id"] != tests[tenant] || selected.Samples[0].Value != float64(lane+1) {
			t.Fatal("current metadata selection crossed ownership or changed metrics")
		}
		if selected.TagSelection == nil || selected.TagSelection.Validate() != nil || selected.TagSelection.TargetKind != "test" {
			t.Fatal("actual source selection omitted its current snapshot clock")
		}
		initialRevision := selected.TagSelection.TagRevision
		// Real source -> engine -> existing RLS receipt sink -> shared publication.
		var persisted alert.EvaluationReceipt
		engine := alert.NewEngine(source, nil, core.log, alert.WithEvaluationSink(func(ctx context.Context, receipt alert.EvaluationReceipt) error {
			persisted = receipt
			return tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
				return (store.AlertEvaluations{}).Append(ctx, sc, receipt)
			})
		}))
		if _, err := engine.Evaluate(tenancy.WithTenant(ctx, tenancy.ID(tenant)), *getRule(tenant)); err != nil || persisted.TagSelection == nil || persisted.TagSelection.TagRevision != initialRevision || persisted.Labels["test_id"] != tests[tenant] {
			t.Fatalf("actual selection did not reach the receipt sink: %v", err)
		}
		readReceipts := func(actor *auth.Principal, id string) alert.EvaluationsResult {
			t.Helper()
			w, err := invoke(core.handleListAlertEvaluations, actor, id, http.MethodGet, nil)
			var out alert.EvaluationsResult
			if err != nil || json.Unmarshal(w.Body.Bytes(), &out) != nil {
				t.Fatalf("read selection receipts: %v", err)
			}
			return out
		}
		proof := readReceipts(actors[tenant], ruleIDs[tenant])
		if proof.TagSelectionAccess != "available" || len(proof.Items) != 1 || proof.Items[0].TagSelection == nil || proof.Items[0].TagSelection.TagRevision != persisted.TagSelection.TagRevision || !proof.Items[0].TagSelection.AsOf.Equal(persisted.TagSelection.AsOf) || proof.Items[0].Fingerprint != persisted.Fingerprint {
			t.Fatal("receipt store/API lost exact actual selection clock or series identity")
		}
		readOnly := narrowPrincipalToScopes(actors[tenant], []string{permAlertRead})
		withheld := readReceipts(readOnly, ruleIDs[tenant])
		if withheld.TagSelectionAccess != "withheld" || len(withheld.Items) != 1 || withheld.Items[0].TagSelection != nil || withheld.Items[0].Fingerprint != persisted.Fingerprint {
			t.Fatal("source clock escaped live scopes or ordinary alert receipts disappeared")
		}
		mutate(tenants[1-lane], func(ctx context.Context, sc tenancy.Scope) error {
			items, _, err := (store.AlertEvaluations{}).List(ctx, sc, ruleIDs[tenant], "", 100)
			if err == nil && len(items) != 0 {
				t.Fatal("receipt query crossed paired tenant RLS")
			}
			return err
		})
		invalid := persisted
		invalid.TagSelection = persisted.TagSelection.Clone()
		invalid.TagSelection.TagRevision = "01"
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			return (store.AlertEvaluations{}).Append(ctx, sc, invalid)
		}); err == nil {
			t.Fatal("store accepted an invalid execution clock")
		}
		// Generic rule reads carry the marker without loading/exporting filter values.
		plain, err := json.Marshal(getRule(tenant))
		if err != nil || bytes.Contains(plain, []byte(wants[tenant])) || bytes.Contains(plain, []byte(`"owner_user_id"`)) {
			t.Fatal("ordinary rule projection materialized metadata configuration")
		}
		foreign := tenants[1-lane]
		if out, err := readAlertTagFilter(ctx, db.Pool(), nil, actors[tenant], ruleIDs[foreign]); err == nil || out.TagFilter != nil {
			t.Fatal("metadata read crossed tenant RLS")
		}
		if _, err := invoke(core.handlePutAlertTagFilter, actors[tenant], ruleIDs[foreign], http.MethodPut, input(wants[tenant], flow.QueryEqual)); err == nil {
			t.Fatal("metadata mutation crossed tenant RLS")
		}
		// Even a negative condition cannot select unknown/unbound foreign claims.
		if _, err := invoke(core.handlePutAlertTagFilter, actors[tenant], ruleIDs[tenant], http.MethodPut, input(wants[foreign], flow.QueryNotEqual)); err != nil {
			t.Fatal(err)
		}
		selected, err = source.CurrentRule(ctx, *getRule(tenant))
		if err != nil || len(selected.Samples) != 1 || selected.Samples[0].Labels["test_id"] != tests[tenant] {
			t.Fatal("negative metadata filter admitted an unowned claim")
		}
		if _, err := invoke(core.handlePutAlertTagFilter, actors[tenant], ruleIDs[tenant], http.MethodPut, input(wants[tenant], flow.QueryEqual)); err != nil {
			t.Fatal(err)
		}
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			rule := tagRules[tenant]
			rule.Value = "changed-" + tenant
			_, err := (store.TagRules{}).Update(ctx, sc, rule)
			return err
		})
		selected, err = source.CurrentRule(ctx, *getRule(tenant))
		if err != nil || len(selected.Samples) != 0 || selected.TagSelection == nil || selected.TagSelection.TagRevision == initialRevision {
			t.Fatal("rule edit did not retag selection over unchanged historical series")
		}
		if _, err := invoke(core.handlePutAlertTagFilter, actors[tenant], ruleIDs[tenant], http.MethodPut, input("changed-"+tenant, flow.QueryEqual)); err != nil {
			t.Fatal(err)
		}
		selected, err = source.CurrentRule(ctx, *getRule(tenant))
		if err != nil || len(selected.Samples) != 1 {
			t.Fatal("fresh current filter did not reselect unchanged series")
		}
		// A scoped credential cannot borrow the owner's current full role.
		scoped := narrowPrincipalToScopes(actors[tenant], []string{permAlertWrite, permTagsRead, "test.read"})
		if _, err := invoke(core.handlePutAlertTagFilter, scoped, ruleIDs[tenant], http.MethodPut, input("changed-"+tenant, flow.QueryEqual)); err == nil {
			t.Fatal("scoped caller borrowed current owner metrics.read")
		}
		if _, err := invoke(core.handlePutAlertTagFilter, actors[tenant], ruleIDs[tenant], http.MethodPut, map[string]any{"target_kind": "test", "filter": input("x", flow.QueryEqual).Filter, "owner_user_id": users[foreign]}); err == nil {
			t.Fatal("body owner hint was accepted")
		}
		calls := counter.calls
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.RoleBindings{}).Unbind(ctx, sc, "user", users[tenant], roles[tenant])
		})
		if partial, err := source.CurrentRule(ctx, *getRule(tenant)); err == nil || (partial.Samples != nil || partial.TagSelection != nil) || counter.calls != calls {
			t.Fatal("revoked current owner reached the metric source or yielded partial data")
		}
		revoked := readReceipts(actors[tenant], ruleIDs[tenant])
		if revoked.TagSelectionAccess != "withheld" || len(revoked.Items) != 1 || revoked.Items[0].TagSelection != nil {
			t.Fatal("stale credential borrowed a revoked current source role")
		}
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.RoleBindings{}).Bind(ctx, sc, "user", users[tenant], roles[tenant])
		})
		// An untrusted stored owner reference still resolves only inside this tenant.
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE alert_rules SET tag_filter=jsonb_set(tag_filter,'{owner_user_id}',to_jsonb($3::text)),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, tenant, ruleIDs[tenant], users[foreign])
			return err
		})
		if partial, err := source.CurrentRule(ctx, *getRule(tenant)); err == nil || (partial.Samples != nil || partial.TagSelection != nil) || counter.calls != calls {
			t.Fatal("foreign stored owner conferred source authority")
		}
		if _, err := invoke(core.handlePutAlertTagFilter, actors[tenant], ruleIDs[tenant], http.MethodPut, input("changed-"+tenant, flow.QueryEqual)); err != nil {
			t.Fatal(err)
		}
		var policyID string
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			policy, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "deny alert current metadata", Permission: permTagsRead, Effect: auth.PolicyDeny, Enabled: true, Resource: map[string]string{auth.ResourceTenantKey: tenant}})
			if err == nil {
				policyID = policy.ID
			}
			return err
		})
		callsBeforePolicy := counter.calls
		if partial, err := source.CurrentRule(ctx, *getRule(tenant)); err == nil || (partial.Samples != nil || partial.TagSelection != nil) || counter.calls != callsBeforePolicy {
			t.Fatal("current policy deny reached metrics or disclosed partial selection")
		}
		if _, err := invoke(core.handleGetAlertTagFilter, actors[tenant], ruleIDs[tenant], http.MethodGet, nil); err == nil {
			t.Fatal("current policy deny disclosed saved criteria")
		}
		var denials int
		if err := db.Pool().QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='abac.denied' AND target=$2 AND data->>'user_id'=$3`, tenant, permTagsRead, users[tenant]).Scan(&denials); err != nil || denials != 1 {
			t.Fatal("shared current-owner policy door lost its deduplicated tenant denial audit")
		}
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.ABACPolicies{}).Delete(ctx, sc, policyID)
		})
		// A pre-feature/ordinary transition stays without invented provenance.
		legacy := persisted
		legacy.TagSelection = nil
		legacy.ObservedAt = legacy.ObservedAt.Add(-time.Second)
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.AlertEvaluations{}).Append(ctx, sc, legacy)
		})
		history := readReceipts(actors[tenant], ruleIDs[tenant])
		if history.TagSelectionAccess != "available" || len(history.Items) != 2 || history.Items[0].TagSelection != nil || history.Items[1].TagSelection == nil {
			t.Fatal("legacy history acquired fabricated selection evidence")
		}
	}
	if !reflect.DeepEqual(beforeSeries, mem.Snapshot()) {
		t.Fatal("metadata selection rewrote existing metric labels or values")
	}
	// Domain audit refusal rolls back the same rule row and version.
	tenant := tenants[0]
	before := getRule(tenant)
	fault := "probectl_qa_beta_alert_audit_" + strings.ReplaceAll(uuid(t), "-", "")
	if _, err := db.Pool().Exec(ctx, `CREATE FUNCTION public.`+fault+`() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='`+tenant+`'::uuid AND NEW.action='alert.tag_filter.set' THEN RAISE EXCEPTION 'QA metadata audit refused'; END IF; RETURN NEW; END $$; CREATE TRIGGER `+fault+` BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION public.`+fault+`()`); err != nil {
		t.Fatal(err)
	}
	drop := func() {
		if _, err := db.Pool().Exec(context.Background(), `DROP TRIGGER IF EXISTS `+fault+` ON audit_events; DROP FUNCTION IF EXISTS public.`+fault+`()`); err != nil {
			t.Error("owned metadata audit fault cleanup failed")
		}
	}
	t.Cleanup(drop)
	if _, err := invoke(core.handlePutAlertTagFilter, actors[tenant], ruleIDs[tenant], http.MethodPut, input("must-not-commit", flow.QueryEqual)); err == nil {
		t.Fatal("audit refusal committed metadata")
	}
	if !getRule(tenant).UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatal("audit refusal changed the stored rule version")
	}
	drop()
	owned := tenancy.WithTenant(ctx, tenancy.ID(tenant))
	version := getRule(tenant).UpdatedAt
	if err := tenancy.InTenantReadSnapshot(owned, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		if partial, err := readAlertTagEditor(ctx, sc, 1); !errors.Is(err, store.ErrTagSnapshotBudget) || partial != nil {
			t.Fatal("editor cost refusal exposed a partial vocabulary")
		}
		partial, err := (store.AlertRules{}).GetTagFilter(ctx, sc, ruleIDs[tenant], version, 1)
		if !errors.Is(err, store.ErrTagSnapshotBudget) || partial != nil {
			t.Fatal("configuration decode budget was not atomic")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
