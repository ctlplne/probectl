// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestReportPrefixTagsRetainCanonicalContextRequirements(t *testing.T) {
	f := newTagImportSubjectFixture(t)
	views := flow.NewPostgresQueryViewStore(f.db.Pool(), 0, audit.TenantRecord)
	rows := flowstore.NewMemory()
	f.srv.WithFlowStore(rows).WithFlowQueryViews(views).
		WithFlowQueryFilters(flow.NewPostgresQueryFilterStore(f.db.Pool(), 0, audit.TenantRecord)).
		WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	at := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	for lane, tenant := range []string{f.a, f.b} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		var actor *auth.Principal
		err := tenancy.InTenant(ctx, f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (store.Users{}).Create(ctx, sc, "prefix-report@"+tenant+".invalid", "Prefix report owner")
			if err != nil {
				return err
			}
			role, err := (store.Roles{}).Create(ctx, sc, "prefix-report-owner", "Prefix report owner", "Current prefix source")
			if err != nil {
				return err
			}
			for _, permission := range []string{permAIQuery, permFlowRead, permTagsRead, "entities.read"} {
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
			actor = auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: tenant, UserID: user.ID}, grants)
			_, err = (store.TagAssignments{}).CreateManual(ctx, sc, store.ManualTagAssignmentInput{
				Scope: tags.Scope{TenantID: tenant, ContextID: f.contextID}, TagID: f.tagID,
				TargetKind: "prefix", TargetID: f.prefix, Value: "PREFIX-" + tenant,
			})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := rows.Insert(t.Context(), []flowstore.Row{{TenantID: tenant, AgentID: f.agents[tenant], Exporter: "192.0.2.10", Protocol: "ipfix", TS: at, SrcAddr: "192.0.2.20", DstAddr: "203.0.113.1", Bytes: uint64(100 + lane), BytesScaled: uint64(100 + lane), Sampling: 1}}); err != nil {
			t.Fatal(err)
		}
		ctx, err = f.srv.withFlowViewVocabulary(ctx, actor)
		if err != nil {
			t.Fatal(err)
		}
		view, err := views.SaveQueryView(ctx, tenant, actor.UserID, flow.SaveQueryView{Definition: flow.QueryViewDefinition{Name: "Prefix report", Visibility: "private", Time: flow.QueryViewTime{Mode: "absolute"}, TagIDs: map[string]string{"tag.src_prefix.role": f.tagID}, Plan: flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), View: "table", GroupBy: []string{"tag.src_prefix.role"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}}})
		if err != nil {
			t.Fatal(err)
		}
		capture, err := f.srv.captureReportFlowSources(ctx, actor, []reportFlowSourceRef{{ID: view.ID, Version: view.Version}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(capture.Close)
		if !capture.ContextSources || !capture.ContextsCaptured || len(capture.Contexts) != 1 || capture.Contexts[0].Resource[auth.ResourceTenantKey] != tenant || !slices.Contains(capture.Contexts[0].Permissions, "entities.read") {
			t.Fatal("prefix report omitted its actual canonical entity/context lineage")
		}
		raw, err := marshalReportSourceRequirements(ctx, capture)
		if err != nil {
			t.Fatal("valid prefix report requirements cannot be stored", err)
		}
		if _, err := parseReportSourceRequirements(ctx, raw); err != nil {
			t.Fatal(err)
		}
		other := f.a
		if tenant == f.a {
			other = f.b
		}
		if leaked, err := parseReportSourceRequirements(tenancy.WithTenant(t.Context(), tenancy.ID(other)), raw); err == nil || leaked != nil {
			t.Fatal("prefix report requirements escaped tenant scope")
		}
		if err := f.srv.revalidateReportFlowCapture(ctx, actor, capture); err != nil {
			t.Fatal("current prefix report source access was lost", err)
		}
		capture.Close()
	}
	t.Log("real-integration: current paired PG/RLS prefix context requirements with modeled in-process flow rows; actual packet/report release cohort remains required in CI")
}
