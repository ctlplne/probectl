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
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestAlertSavedQueryStateKeepsTenantParentsVersionsAndCompleteGroups(t *testing.T) {
	pool := setup(t.Context(), t)
	t.Cleanup(pool.Close)
	var tenants []string
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := pool.Exec(ctx, `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error("own query-alert fixtures did not erase", err)
		}
	})
	const maxBytes = 64 << 20
	// This store fixture seeds configuration authority; served source permission checks remain separate.
	publication := func(ctx context.Context, _ tenancy.Scope) error { return ctx.Err() }
	views := flow.NewPostgresQueryViewStore(pool, maxBytes, audit.TenantRecord)
	type lane struct {
		tenant, user string
		rule         *alert.Rule
		view         flow.SavedQueryView
		source       alert.QuerySource
		stored       *AlertQuerySource
		next         alert.QueryGroupState
	}
	var lanes []*lane
	for i := range 2 {
		created, err := NewTenants(pool).Create(t.Context(), fmt.Sprintf("query-alert-%d-%d", i, time.Now().UnixNano()), "Query alert fixture")
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, created.ID)
		current := &lane{tenant: created.ID}
		inTenant(t.Context(), t, pool, current.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (Users{}).Create(ctx, sc, "query-owner@example.test", "Query owner")
			if err != nil {
				return err
			}
			current.user = user.ID
			current.rule, err = (AlertRules{}).Create(ctx, sc, alert.Rule{Name: "Saved query threshold", Enabled: true, Type: alert.Threshold, Metric: alert.QueryMetric, Comparison: alert.GTE, Threshold: 1, Severity: alert.SeverityWarning})
			return err
		})
		definition := flow.QueryViewDefinition{Name: "Source AS traffic", Visibility: "private", Time: flow.QueryViewTime{Mode: "lookback", LookbackSeconds: 300}, Plan: flow.QueryPlan{GroupBy: []string{"src_asn"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}}
		current.view, err = views.SaveQueryView(t.Context(), current.tenant, current.user, flow.SaveQueryView{Definition: definition})
		if err != nil {
			t.Fatal(err)
		}
		current.source = alert.QuerySource{Version: 1, OwnerUserID: current.user, ViewID: current.view.ID, ViewVersion: current.view.Version, EverySeconds: 60,
			Condition: alert.QueryCondition{Mode: "threshold", Metric: "bytes:total", Comparison: alert.GT, Threshold: "18446744073709551616"}, ReadGrants: []alert.QueryReadGrant{{Permission: "flow.read", ScopeType: auth.ScopeTenant}}}
		inTenant(t.Context(), t, pool, current.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			current.rule, err = (AlertRules{}).SetQuerySource(ctx, sc, current.rule.ID, current.rule.UpdatedAt, &current.source, maxBytes, publication)
			if err != nil {
				return err
			}
			current.stored, err = (AlertRules{}).GetQuerySource(ctx, sc, current.rule.ID, current.rule.UpdatedAt, maxBytes)
			return err
		})
		if current.stored == nil || current.stored.State.Initialized || current.stored.StateVersion != 0 {
			t.Fatal("new binding fabricated a previous observation", current.stored)
		}
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(current.tenant))
		snapshot := alert.QueryGroupSnapshot{TenantID: current.tenant, ViewID: current.view.ID, ViewVersion: current.view.Version, At: time.Now().UTC().Truncate(time.Microsecond), Complete: true}
		for i := range 32 {
			snapshot.Groups = append(snapshot.Groups, alert.QueryGroup{Dimensions: map[string]string{"src_asn": strconv.Itoa(64512 + i)}, Value: "18446744073709551617"})
		}
		_, current.next, err = alert.EvaluateQueryGroups(ctx, current.source.Binding(current.tenant, current.rule.ID), snapshot, current.stored.State, alert.QueryGroupBudget{MemoryBytes: maxBytes, WorkUnits: maxBytes})
		if err != nil {
			t.Fatal(err)
		}
		inTenant(t.Context(), t, pool, current.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (AlertRules{}).CommitQueryState(ctx, sc, current.rule.ID, current.rule.UpdatedAt, *current.stored, current.next, maxBytes, publication)
		})
		lanes = append(lanes, current)
	}
	for _, current := range lanes {
		inTenant(t.Context(), t, pool, current.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			got, err := (AlertRules{}).GetQuerySource(ctx, sc, current.rule.ID, current.rule.UpdatedAt, maxBytes)
			if err != nil || got == nil || got.StateVersion != 1 || len(got.State.Keys) != 32 || !got.State.At.Equal(current.next.At) || got.NextAt == nil || !got.NextAt.Equal(current.next.At.Add(time.Minute)) {
				t.Fatal("stored complete state or due time did not survive a fresh read", got, err)
			}
			for _, check := range []struct {
				at  time.Time
				due bool
			}{{current.next.At.Add(30 * time.Second), false}, {current.next.At.Add(time.Minute), true}} {
				if due, err := (AlertRules{}).QuerySourceDue(ctx, sc, current.rule.ID, current.rule.UpdatedAt, check.at); err != nil || due != check.due {
					t.Fatal("stored due metadata changed schedule semantics", due, err)
				}
			}
			if err := (AlertRules{}).CommitQueryState(ctx, sc, current.rule.ID, current.rule.UpdatedAt, *current.stored, current.next, maxBytes, publication); !errors.Is(err, ErrAlertQueryChanged) {
				t.Fatal("late worker overwrote newer query state", err)
			}
			if got, err := (AlertRules{}).GetQuerySource(ctx, sc, current.rule.ID, current.rule.UpdatedAt, 8192); err == nil || got != nil {
				t.Fatal("unadmitted stored payload was transferred as a successful prefix", got, err)
			}
			current.stored = got

			for _, seconds := range []int64{60, 90} {
				configuration := current.source
				configuration.EverySeconds = seconds
				current.rule, err = (AlertRules{}).SetQuerySource(ctx, sc, current.rule.ID, current.rule.UpdatedAt, &configuration, maxBytes, publication)
				if err != nil {
					return err
				}
				preserved, err := (AlertRules{}).GetQuerySource(ctx, sc, current.rule.ID, current.rule.UpdatedAt, maxBytes)
				if err != nil || preserved == nil || preserved.StateVersion != 1 || len(preserved.State.Keys) != 32 || !preserved.State.At.Equal(current.next.At) || preserved.NextAt == nil || !preserved.NextAt.Equal(current.next.At.Add(time.Duration(seconds)*time.Second)) {
					t.Fatal("same source/cadence edit erased the complete baseline or shifted its actual read clock", preserved, err)
				}
				current.source, current.stored = configuration, preserved
			}
			following := current.next
			following.At = following.At.Add(time.Minute)
			if err := (AlertRules{}).CommitQueryState(ctx, sc, current.rule.ID, current.rule.UpdatedAt, *current.stored, following, maxBytes, nil); err == nil {
				t.Fatal("missing current source publication check advanced query state")
			}
			ordinary := *current.rule
			ordinary.Metric, ordinary.Comparison, ordinary.Threshold = "probectl_probe_loss_ratio", alert.GT, 0.5
			if changed, err := (AlertRules{}).Update(ctx, sc, current.rule.ID, ordinary); err == nil || changed != nil {
				t.Fatal("full rule edit silently replaced an attached query source", changed, err)
			}
			mixed := &alert.TagFilter{Version: 1, TargetKind: "test", OwnerUserID: current.user, TagRevision: "1", AsOf: current.next.At.Format(time.RFC3339Nano),
				Filter: &flow.QueryFilterGroup{Match: "all", Conditions: []flow.QueryPredicate{{Field: "tag.role", Op: flow.QueryEqual, Values: []string{"edge"}}}}, TagIDs: map[string]string{"tag.role": current.view.ID}}
			if changed, err := (AlertRules{}).SetTagFilter(ctx, sc, current.rule.ID, current.rule.UpdatedAt, mixed); err == nil || changed != nil {
				t.Fatal("metric metadata selection mixed with a query source", changed, err)
			}
			return nil
		})
	}
	a, b := lanes[0], lanes[1]
	if a.next.Keys[0] == b.next.Keys[0] {
		t.Fatal("two tenants shared an alert group identity")
	}
	inTenant(t.Context(), t, pool, b.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if got, err := (AlertRules{}).GetQuerySource(ctx, sc, a.rule.ID, a.rule.UpdatedAt, maxBytes); !errors.Is(err, ErrAlertQueryChanged) || got != nil {
			t.Fatal("foreign alert state bypassed tenant RLS", got, err)
		}
		foreignParent := b.source
		foreignParent.ViewID, foreignParent.OwnerUserID = a.view.ID, a.user
		if got, err := (AlertRules{}).SetQuerySource(ctx, sc, b.rule.ID, b.rule.UpdatedAt, &foreignParent, maxBytes, publication); !errors.Is(err, ErrAlertQueryChanged) || got != nil {
			t.Fatal("foreign query/owner became this tenant's alert source", got, err)
		}
		foreignState := a.next
		foreignState.At = b.next.At.Add(time.Minute)
		if err := (AlertRules{}).CommitQueryState(ctx, sc, b.rule.ID, b.rule.UpdatedAt, *b.stored, foreignState, maxBytes, publication); err == nil {
			t.Fatal("foreign state entered another tenant's rule")
		}
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM alert_rules WHERE query_group_state IS NOT NULL`).Scan(&count); err != nil || count != 1 {
			t.Fatal("predicate-free alert state escaped RLS", count, err)
		}
		return nil
	})
	changed := a.view.Definition
	changed.Description = "Explicit new saved-query revision"
	updated, err := views.SaveQueryView(t.Context(), a.tenant, a.user, flow.SaveQueryView{ID: a.view.ID, Version: a.view.Version, Definition: changed})
	if err != nil {
		t.Fatal(err)
	}
	inTenant(t.Context(), t, pool, a.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		following := a.next
		following.At = a.next.At.Add(time.Minute)
		if err := (AlertRules{}).CommitQueryState(ctx, sc, a.rule.ID, a.rule.UpdatedAt, *a.stored, following, maxBytes, publication); !errors.Is(err, ErrAlertQueryChanged) {
			t.Fatal("changed saved query retained old source publication", err)
		}
		a.source.ViewVersion = updated.Version
		a.rule, err = (AlertRules{}).SetQuerySource(ctx, sc, a.rule.ID, a.rule.UpdatedAt, &a.source, maxBytes, publication)
		if err != nil {
			return err
		}
		fresh, err := (AlertRules{}).GetQuerySource(ctx, sc, a.rule.ID, a.rule.UpdatedAt, maxBytes)
		if err != nil || fresh == nil || fresh.State.Initialized || fresh.StateVersion != 0 || fresh.NextAt != nil {
			t.Fatal("explicit rebinding revived a different revision's baseline", fresh, err)
		}
		return nil
	})
	inTenant(t.Context(), t, pool, b.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		source := b.source
		source.Condition = alert.QueryCondition{Mode: "new_group"}
		source.EverySeconds = 60
		rule, err := (AlertRules{}).SetQuerySource(ctx, sc, b.rule.ID, b.rule.UpdatedAt, &source, maxBytes, publication)
		if err != nil {
			return err
		}
		stored, err := (AlertRules{}).GetQuerySource(ctx, sc, rule.ID, rule.UpdatedAt, maxBytes)
		if err != nil {
			return err
		}
		base := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
		for i := range 2 {
			snapshot := alert.QueryGroupSnapshot{TenantID: b.tenant, ViewID: source.ViewID, ViewVersion: source.ViewVersion, At: base.Add(time.Duration(i) * time.Second), Complete: true, Groups: []alert.QueryGroup{{Dimensions: map[string]string{"src_asn": "64512"}}}}
			if i == 1 {
				snapshot.Groups = append(snapshot.Groups, alert.QueryGroup{Dimensions: map[string]string{"src_asn": "64513"}})
			}
			_, next, err := alert.EvaluateQueryGroups(ctx, source.Binding(b.tenant, rule.ID), snapshot, stored.State, alert.QueryGroupBudget{MemoryBytes: maxBytes, WorkUnits: maxBytes})
			if err != nil {
				return err
			}
			if err := (AlertRules{}).CommitQueryState(ctx, sc, rule.ID, rule.UpdatedAt, *stored, next, maxBytes, publication); err != nil {
				return err
			}
			stored, err = (AlertRules{}).GetQuerySource(ctx, sc, rule.ID, rule.UpdatedAt, maxBytes)
			if err != nil {
				return err
			}
		}
		if len(stored.State.Novel) != 1 {
			t.Fatal("fixture did not establish one actual modeled novel group")
		}
		source.EverySeconds = 90
		rule, err = (AlertRules{}).SetQuerySource(ctx, sc, rule.ID, rule.UpdatedAt, &source, maxBytes, publication)
		if err != nil {
			return err
		}
		preserved, err := (AlertRules{}).GetQuerySource(ctx, sc, rule.ID, rule.UpdatedAt, maxBytes)
		if err != nil || preserved == nil || preserved.StateVersion != 2 || len(preserved.State.Novel) != 1 || preserved.State.Novel[0] != stored.State.Novel[0] {
			t.Fatal("schedule edit invented novelty resolution", preserved, err)
		}
		source.ReadGrants = append(source.ReadGrants, alert.QueryReadGrant{Permission: "metrics.read", ScopeType: auth.ScopeTenant})
		rule, err = (AlertRules{}).SetQuerySource(ctx, sc, rule.ID, rule.UpdatedAt, &source, maxBytes, publication)
		if err != nil {
			return err
		}
		reset, err := (AlertRules{}).GetQuerySource(ctx, sc, rule.ID, rule.UpdatedAt, maxBytes)
		if err != nil || reset == nil || reset.StateVersion != 0 || reset.State.Initialized || reset.NextAt != nil {
			t.Fatal("changed credential ceiling reused an earlier read population", reset, err)
		}
		return nil
	})
	t.Log("real-integration: app-role Postgres/RLS source parents, opaque groups, restart reads and optimistic state; no sender, scheduler, notification or served-surface claim")
}
