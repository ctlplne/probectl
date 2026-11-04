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
	"maps"
	"slices"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func reportFrozenSourceReaderProof(ctx context.Context, t *testing.T, f *tagImportSubjectFixture, owner *auth.Principal, role string, views *flow.PostgresQueryViewStore, item flow.SavedQueryView, frozen *reportFlowCapture) flow.SavedQueryView {
	t.Helper()
	mutate := func(fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		if err := tenancy.InTenant(ctx, f.db.Pool(), fn); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.srv.revalidateReportFlowCapture(ctx, owner, frozen); err != nil {
		t.Fatal("current owner cannot read its frozen source after a metadata edit", err)
	}
	limited := narrowPrincipalToScopes(auth.ClonePrincipal(owner), []string{permAIQuery})
	if err := f.srv.revalidateReportFlowCapture(ctx, limited, frozen); err == nil {
		t.Fatal("frozen source reader widened its actual credential ceiling")
	}
	if err := f.srv.revalidateReportFlowCapture(t.Context(), owner, frozen); err == nil {
		t.Fatal("unbound frozen source read succeeded")
	}
	var reader *auth.Principal
	mutate(func(ctx context.Context, sc tenancy.Scope) error {
		user, err := (store.Users{}).Create(ctx, sc, "reader@"+f.a+".invalid", "Broader current reader")
		if err != nil {
			return err
		}
		if err := (store.RoleBindings{}).Bind(ctx, sc, "user", user.ID, role); err != nil {
			return err
		}
		grants, err := (store.Permissions{}).ForSubject(ctx, sc, "user", user.ID)
		reader = auth.PrincipalWithPermissionGrants(&auth.Principal{TenantID: f.a, UserID: user.ID, Email: user.Email}, grants)
		return err
	})
	if err := f.srv.revalidateReportFlowCapture(ctx, reader, frozen); err == nil {
		t.Fatal("a broad reader borrowed private source visibility")
	}
	vctx, err := f.srv.withFlowViewVocabulary(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	definition := item.Definition
	definition.Visibility = "tenant"
	item, err = views.SaveQueryView(vctx, f.a, owner.UserID, flow.SaveQueryView{ID: item.ID, Version: item.Version, Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.srv.revalidateReportFlowCapture(ctx, reader, frozen); err != nil {
		t.Fatal("current shared source access incorrectly requires creator identity or frozen version", err)
	}
	encoded, err := json.Marshal(item.Definition)
	if err != nil {
		t.Fatal(err)
	}
	mutate(func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE flow_query_views SET definition=jsonb_set(definition,'{plan,view}','"invalid"'::jsonb) WHERE tenant_id=$1 AND id=$2`, f.a, item.ID)
		return err
	})
	if _, err := views.GetQueryView(vctx, f.a, owner.UserID, item.ID); err == nil {
		t.Fatal("changed-definition fixture did not exercise the full decoder")
	}
	if err := f.srv.revalidateReportFlowCapture(ctx, reader, frozen); err != nil {
		t.Fatal("frozen source read reparsed changed source text", err)
	}
	mutate(func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE flow_query_views SET definition=$3::jsonb WHERE tenant_id=$1 AND id=$2`, f.a, item.ID, string(encoded))
		return err
	})
	definition.Visibility = "private"
	item, err = views.SaveQueryView(vctx, f.a, owner.UserID, flow.SaveQueryView{ID: item.ID, Version: item.Version, Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.srv.revalidateReportFlowCapture(ctx, reader, frozen); err == nil {
		t.Fatal("frozen source reader retained revoked sharing")
	}
	mutate(func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_contexts SET site_label='moved-site' WHERE tenant_id=$1 AND id=$2`, f.a, f.contextID)
		return err
	})
	for _, site := range []string{"same-site", "moved-site"} {
		var policy *auth.Policy
		mutate(func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			policy, err = (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "frozen-source-scope", Enabled: true, Effect: auth.PolicyDeny, Permission: permFlowRead, Resource: map[string]string{"site_label": site}, Priority: 100})
			return err
		})
		if err := f.srv.revalidateReportFlowCapture(ctx, owner, frozen); err == nil {
			t.Fatal("frozen source ignored a denied captured or current context", site)
		}
		mutate(func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM abac_policies WHERE tenant_id=$1 AND id=$2`, f.a, policy.ID)
			return err
		})
	}
	if err := f.srv.revalidateReportFlowCapture(ctx, owner, frozen); err != nil {
		t.Fatal("equivalent current authority could not read the unchanged frozen source", err)
	}
	bad := reportFlowCapture{
		TenantID: frozen.TenantID, Tables: slices.Clone(frozen.Tables), Inputs: slices.Clone(frozen.Inputs),
		Permissions: slices.Clone(frozen.Permissions), Contexts: slices.Clone(frozen.Contexts), ContextsCaptured: frozen.ContextsCaptured,
	}
	bad.Contexts[0].Resource = maps.Clone(frozen.Contexts[0].Resource)
	bad.Contexts[0].Resource[auth.ResourceTenantKey] = f.b
	if err := f.srv.revalidateReportFlowCapture(ctx, owner, &bad); err == nil {
		t.Fatal("frozen source accepted a foreign captured context")
	}
	bad.Contexts[0].Resource = maps.Clone(frozen.Contexts[0].Resource)
	delete(bad.Contexts[0].Resource, "site_label")
	if err := f.srv.revalidateReportFlowCapture(ctx, owner, &bad); err == nil {
		t.Fatal("frozen source accepted missing captured policy attributes")
	}
	assertCapturedReportDetail(ctx, t, frozen, "current", "OWN-"+f.a, "100", f.tagID)
	return item
}
