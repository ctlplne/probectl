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
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestProspectEngagementConsentUsesExactOwnedTerms(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	owner, sibling := f.tenants[0], f.tenants[1]
	inputs := make(map[string]startProspectInput, len(f.tenants))
	mailer := &reportMailProbe{attempts: make(map[string][]string)}
	f.server.WithAlertChannelDeps(alert.ChannelDeps{Mail: mailer})
	end := time.Now().UTC().Truncate(time.Minute).AddDate(0, 0, 14)
	for i, tenant := range f.tenants {
		slug, _, _, err := f.server.tenantSlugAndMeta(t.Context(), tenant)
		if err != nil {
			t.Fatal(err)
		}
		destination := config.ReportEmailDestination{TenantID: tenant, ID: "prospect-" + strings.Repeat("d", 88), Name: "Owned assessment delivery", Recipients: []string{"prospect@" + tenant + ".invalid"}}
		f.server.cfg.ReportEmailDestinations = append(f.server.cfg.ReportEmailDestinations, destination)
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permLifecycleErase, permLifecycleExp} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			definition, err := json.Marshal(dashboardDefinition{ClientReport: &reporting.ClientReportDefinition{Timezone: "UTC"}})
			if err != nil {
				return err
			}
			view, err := (store.DashboardReports{}).CreateView(ctx, sc, store.DashboardViewInput{ID: []string{"prospect-a", "prospect-b"}[i],
				OwnerID: f.users[tenant], Name: "Prospect assessment", Preset: "operator", Definition: definition})
			if err != nil {
				return err
			}
			inputs[tenant] = startProspectInput{AssessmentViewID: view.ID, AssessmentAt: view.UpdatedAt, Preparer: "Example MSP",
				EndsAt: end, DestinationID: reportEmailDestinationID(destination), ConfirmTenant: slug}
			return nil
		})
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	const route = "/v1/lifecycle/prospect"
	ownedSession, siblingSession := auditorTestSession(t, f, owner), auditorTestSession(t, f, sibling)
	callSeasonalAPI(t, socket, f.tokens[owner], http.MethodPost, route, inputs[owner], http.StatusForbidden)
	wrong := inputs[sibling]
	wrong.AssessmentViewID, wrong.AssessmentAt = inputs[owner].AssessmentViewID, inputs[owner].AssessmentAt
	callComplianceControlReport(t, socket, siblingSession, http.MethodPost, route, wrong, http.StatusNotFound)
	wrong = inputs[owner]
	wrong.DestinationID = inputs[sibling].DestinationID
	callComplianceControlReport(t, socket, ownedSession, http.MethodPost, route, wrong, http.StatusUnprocessableEntity)
	wrong = inputs[owner]
	wrong.ConfirmTenant = inputs[sibling].ConfirmTenant
	callComplianceControlReport(t, socket, ownedSession, http.MethodPost, route, wrong, http.StatusUnprocessableEntity)
	read := func(raw []byte) store.ProspectEngagement {
		t.Helper()
		var out store.ProspectEngagement
		if err := json.Unmarshal(raw, &out); err != nil || out.Revision < 1 || out.OwnerID != "" {
			t.Fatal("invalid public prospect engagement", err)
		}
		return out
	}
	first := read(callComplianceControlReport(t, socket, ownedSession, http.MethodPost, route, inputs[owner], http.StatusCreated))
	if first.Revision != 1 || first.ConsentedAt == nil || !first.EndsAt.Equal(end) || !first.AssessmentAt.Equal(inputs[owner].AssessmentAt) || first.DestinationID != inputs[owner].DestinationID {
		t.Fatal("the just-recorded engagement did not preserve exact consent terms")
	}
	callSeasonalAPI(t, socket, f.tokens[sibling], http.MethodGet, route, nil, http.StatusNotFound)
	read(callComplianceControlReport(t, socket, siblingSession, http.MethodPost, route, inputs[sibling], http.StatusCreated))
	decision := func(revision int64) map[string]int64 { return map[string]int64{"revision": revision} }
	revoked := read(callSeasonalAPI(t, socket, f.tokens[owner], http.MethodPost, route+"/revoke-consent", decision(1), http.StatusOK))
	if revoked.Revision != 2 || revoked.ConsentRevokedAt == nil || revoked.ConvertedAt != nil {
		t.Fatal("the current consent was not withdrawn atomically")
	}
	callSeasonalAPI(t, socket, f.tokens[owner], http.MethodPost, route+"/convert", decision(1), http.StatusConflict)
	converted := read(callSeasonalAPI(t, socket, f.tokens[owner], http.MethodPost, route+"/convert", decision(2), http.StatusOK))
	if converted.Revision != 3 || converted.ConvertedAt == nil || converted.ConsentRevokedAt == nil {
		t.Fatal("conversion did not retain its withdrawal fence")
	}
	other := read(callSeasonalAPI(t, socket, f.tokens[sibling], http.MethodGet, route, nil, http.StatusOK))
	if other.Revision != 1 || other.ConsentRevokedAt != nil || other.ConvertedAt != nil || other.DestinationID != inputs[sibling].DestinationID || len(mailer.attempts) != 0 {
		t.Fatal("a consent mutation changed the sibling or triggered delivery")
	}
	f.in(sibling, func(ctx context.Context, sc tenancy.Scope) error {
		var rows int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM prospect_engagements WHERE tenant_id=$1`, owner).Scan(&rows); err != nil {
			return err
		}
		if rows != 0 {
			t.Fatal("sibling application role saw the owner’s engagement row")
		}
		return nil
	})
	f.in(owner, func(ctx context.Context, sc tenancy.Scope) error {
		var initiator, destination string
		err := sc.Q.QueryRow(ctx, `SELECT data->>'owner_id',data->>'destination_id' FROM audit_events
		 WHERE tenant_id=$1 AND action=$2 AND target=$1::text`, owner, prospectCreatedAudit).Scan(&initiator, &destination)
		if err != nil {
			return err
		}
		if initiator != f.users[owner] || destination != inputs[owner].DestinationID {
			t.Fatal("the audit lost the initiating account or destination binding")
		}
		return nil
	})
}

func TestProspectEngagementUsesCanonicalTenantWriteFence(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var guarded bool
			if err := sc.Q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
			 WHERE tgrelid=to_regclass('prospect_engagements') AND NOT tgisinternal
			 AND tgname='tenant_write_fence' AND tgenabled='A' AND tgtype=23
			 AND tgfoid='public.probectl_enforce_tenant_write_fence()'::regprocedure)`).Scan(&guarded); err != nil {
				return err
			}
			if !guarded {
				t.Fatal("prospect engagement storage is missing the tenant lifecycle write fence")
			}
			return nil
		})
	}
}

func TestProspectAssessmentWorkerFilesOneExactScopedArtifact(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil)).WithFlowStore(flowstore.NewMemory())
	supervisor, ok := BuildDashboardReportSupervisor(f.pool, time.Minute, f.server.log)
	if !ok {
		t.Fatal("report supervisor unavailable")
	}
	supervisor.WithReportSources(f.server)
	now := time.Now().UTC().Truncate(time.Microsecond)
	end := now.Add(-time.Minute)
	engagements := map[string]store.ProspectEngagement{}
	for _, tenant := range f.tenants {
		slug, _, _, err := f.server.tenantSlugAndMeta(t.Context(), tenant)
		if err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permTestRead, permIncidentRead, permChangeRead, "topology.read", permLifecycleErase} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			definition := dashboardDefinition{ClientReport: &reporting.ClientReportDefinition{Timezone: "UTC"},
				RedactionState: "current tenant policy", Provenance: []string{"Owned prospect fixture"}, CoverageLimitations: []string{"Controlled report configuration"}}
			if err := cleanDashboardDefinition(&definition); err != nil {
				return err
			}
			raw, err := json.Marshal(definition)
			if err != nil {
				return err
			}
			view, err := (store.DashboardReports{}).CreateView(ctx, sc, store.DashboardViewInput{ID: "prospect-view", OwnerID: f.users[tenant],
				Name: "Prospect assessment", Preset: "operator", Definition: raw})
			if err != nil {
				return err
			}
			engagements[tenant], err = (store.ProspectEngagements{}).Create(ctx, sc, store.ProspectEngagement{AssessmentViewID: view.ID,
				AssessmentAt: view.UpdatedAt, OwnerID: f.users[tenant], TenantSlug: slug,
				StartsAt: end.AddDate(0, 0, -14), EndsAt: end, Preparer: "Scope " + tenant})
			return err
		})
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	for _, tenant := range f.tenants {
		// Before the end no artifact is eligible, regardless of the ordinary
		// dashboard schedule or wall clock.
		if err := supervisor.materializeProspectAssessment(t.Context(), tenant, "Prospect", end.Add(-time.Microsecond)); err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			item, err := (store.ProspectEngagements{}).Get(ctx, sc)
			if err == nil && item.AssessmentArtifactID != "" {
				t.Fatal("prospect assessment appeared before the exact end")
			}
			return err
		})
		for range 2 {
			if err := supervisor.materializeProspectAssessment(t.Context(), tenant, "Prospect", now); err != nil {
				t.Fatal("due assessment could not be filed", err)
			}
		}
	}
	for lane, tenant := range f.tenants {
		var item store.ProspectEngagement
		var bodySHA string
		var bodySize int64
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			item, err = (store.ProspectEngagements{}).Get(ctx, sc)
			if err != nil {
				return err
			}
			artifact, err := (store.DashboardReports{}).GetArtifactMetadata(ctx, sc, item.AssessmentArtifactID, f.users[tenant])
			if err != nil {
				return err
			}
			if !artifact.AbsoluteFrom.Equal(engagements[tenant].StartsAt) || !artifact.AbsoluteTo.Equal(end) || artifact.Format != "pdf" ||
				artifact.BodyBytes < 1 || len(artifact.BodySHA256) != 64 || artifact.TenantID != tenant || artifact.EmailDelivery != nil {
				t.Fatal("the filed PDF lost its exact engagement clock or tenant scope")
			}
			bodySHA, bodySize = artifact.BodySHA256, artifact.BodyBytes
			var artifacts, audits int
			if err := sc.Q.QueryRow(ctx, `SELECT (SELECT count(*) FROM dashboard_report_artifacts WHERE tenant_id=$1),
			 (SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='lifecycle.prospect_assessment_created' AND target=$2)`, tenant, artifact.ID).Scan(&artifacts, &audits); err != nil {
				return err
			}
			if artifacts != 1 || audits != 1 {
				t.Fatal("the repeated worker run published more than one assessment")
			}
			return nil
		})
		path := "/v1/dashboard-report-artifacts/" + item.AssessmentArtifactID
		raw := callComplianceControlReport(t, socket, auditorTestSession(t, f, tenant), http.MethodGet, path, nil, http.StatusOK)
		if int64(len(raw)) != bodySize || !bytes.HasPrefix(raw, []byte("%PDF-")) || hex.EncodeToString(crypto.Hash(raw)) != bodySHA {
			t.Fatal("the released assessment did not match its own sealed bytes")
		}
		callSeasonalAPI(t, socket, f.tokens[f.tenants[1-lane]], http.MethodGet, path, nil, http.StatusNotFound)
	}
}
