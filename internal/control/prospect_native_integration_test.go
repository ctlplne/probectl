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
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestProspectNativeEngagementCurrentTenantAndRevision(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	seedInterfaceRoleMCPConsent(f)
	owner, sibling := f.tenants[0], f.tenants[1]
	mail := &reportMailProbe{attempts: make(map[string][]string)}
	f.server.WithAlertChannelDeps(alert.ChannelDeps{Mail: mail})
	var terms [2]mcp.ProspectEngagementStart
	end := time.Now().UTC().AddDate(0, 0, 14).Truncate(time.Microsecond)
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permLifecycleErase, permLifecycleExp} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			view, err := (store.DashboardReports{}).CreateView(ctx, sc, store.DashboardViewInput{ID: []string{"north-native-prospect", "south-native-prospect"}[lane],
				OwnerID: f.users[tenant], Name: "Owned prospect assessment", Preset: "operator", Definition: []byte(`{"client_report":{"timezone":"UTC"}}`)})
			if err != nil {
				return err
			}
			terms[lane] = mcp.ProspectEngagementStart{AssessmentViewID: view.ID, AssessmentAt: view.UpdatedAt, EndsAt: end,
				Preparer: []string{"North Assessment", "South Assessment"}[lane]}
			return nil
		})
	}
	mailDestination := config.ReportEmailDestination{TenantID: owner, ID: "native-archive", Name: "Owned assessment archive", Recipients: []string{"archive@owned.invalid"}}
	f.server.cfg.ReportEmailDestinations = []config.ReportEmailDestination{mailDestination}
	slug, _, _, err := f.server.tenantSlugAndMeta(t.Context(), owner)
	if err != nil {
		t.Fatal(err)
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	callComplianceControlReport(t, socket, auditorTestSession(t, f, owner), http.MethodPost, "/v1/lifecycle/prospect", startProspectInput{
		AssessmentViewID: terms[0].AssessmentViewID, AssessmentAt: terms[0].AssessmentAt, Preparer: terms[0].Preparer, EndsAt: end,
		DestinationID: reportEmailDestinationID(mailDestination), ConfirmTenant: slug,
	}, http.StatusCreated)

	const get, start = "prospect_engagement_get", "prospect_engagement_start"
	const revoke, convert = "prospect_engagement_revoke_consent", "prospect_engagement_convert"
	decision := func(revision int, confirmed bool) map[string]any {
		return map[string]any{"revision": revision, "confirmed": confirmed}
	}
	var result json.RawMessage
	assertRead := func(lane int, revision int64, consent, revoked, converted bool) {
		t.Helper()
		var out store.ProspectEngagement
		if err := json.Unmarshal(result, &out); err != nil || out.Revision != revision ||
			out.AssessmentViewID != terms[lane].AssessmentViewID || !out.AssessmentAt.Equal(terms[lane].AssessmentAt) ||
			out.Preparer != terms[lane].Preparer || !out.EndsAt.Equal(end) || (out.ConsentedAt != nil) != consent ||
			(out.ConsentRevokedAt != nil) != revoked || (out.ConvertedAt != nil) != converted ||
			bytes.Contains(result, []byte(terms[1-lane].AssessmentViewID)) || bytes.Contains(result, []byte(`"owner_id"`)) ||
			bytes.Contains(result, []byte(`"tenant_slug"`)) || bytes.Contains(result, []byte(`"consent_revision"`)) {
			t.Fatal("MCP lost the exact owned public engagement or disclosed an internal binding", err)
		}
	}
	modern := interfaceRoleNativeTLSCaller(t, f, "2026-07-28")
	legacy := interfaceRoleNativeTLSCaller(t, f, "2025-11-25")
	modern(owner, get, struct{}{}, &result, true)
	assertRead(0, 1, true, false, false)
	modern(sibling, get, map[string]string{"tenant_id": owner}, nil, false)
	modern(sibling, get, struct{}{}, nil, false)
	modern(sibling, start, terms[0], nil, false)
	modern(sibling, start, map[string]any{"assessment_view_id": terms[1].AssessmentViewID, "assessment_view_revision": terms[1].AssessmentAt,
		"preparer": terms[1].Preparer, "ends_at": end, "destination_id": mailDestination.ID, "confirm_tenant": slug}, nil, false)
	legacy(sibling, start, terms[1], &result, true)
	assertRead(1, 1, false, false, false)
	legacy(owner, revoke, decision(1, false), nil, false)
	legacy(owner, revoke, decision(2, true), nil, false)
	legacy(sibling, revoke, decision(1, true), nil, false)

	cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
	server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, f.server.pathStore, 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil,
		f.server.MCPPolicyLoader(), f.server.aiSources())
	authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
	stdio := openInterfaceRoleStdio(t, server, authenticator, f.tokens[owner], "2026-07-28")
	stdio.call(t, "2026-07-28", get, struct{}{}, &result, true)
	assertRead(0, 1, true, false, false)
	f.in(owner, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, owner, f.roles[owner], permLifecycleErase)
		return err
	})
	stdio.call(t, "2026-07-28", revoke, decision(1, true), nil, false)
	modern(owner, get, struct{}{}, nil, false)
	f.in(owner, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.Roles{}).AddPermission(ctx, sc, f.roles[owner], permLifecycleErase)
	})
	stdio.call(t, "2026-07-28", revoke, decision(1, true), &result, true)
	assertRead(0, 2, true, true, false)
	legacy(sibling, convert, decision(1, true), &result, true)
	assertRead(1, 2, false, false, true)
	legacy(owner, get, struct{}{}, &result, true)
	assertRead(0, 2, true, true, false)
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			action := []string{prospectRevokedAudit, prospectConvertedAudit}[lane]
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND target=$1::uuid::text AND actor=$2 AND action=$3`,
				tenant, "roles@"+tenant+".invalid", action).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				t.Fatal("the exact decision did not append one stable scoped audit event")
			}
			return nil
		})
	}
	if len(mail.attempts) != 0 {
		t.Fatal("native engagement operations initiated assessment delivery")
	}
}
