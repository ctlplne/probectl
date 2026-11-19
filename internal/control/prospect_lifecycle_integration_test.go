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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
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
	verifyProspectConsentAttributeDenial(t, f, socket, ownedSession, inputs[owner])
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

func verifyProspectConsentAttributeDenial(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, cookie string, input startProspectInput) {
	t.Helper()
	owner := f.tenants[0]
	var id string
	f.in(owner, func(ctx context.Context, sc tenancy.Scope) error {
		policy, err := (store.ABACPolicies{}).Create(ctx, sc, auth.Policy{Name: "Require export permission for prospect consent",
			Permission: permLifecycleExp, Effect: auth.PolicyDeny, Enabled: true, Priority: 100})
		if err == nil {
			id = policy.ID
		}
		return err
	})
	callComplianceControlReport(t, socket, cookie, http.MethodPost, "/v1/lifecycle/prospect", input, http.StatusForbidden)
	f.in(owner, func(ctx context.Context, sc tenancy.Scope) error {
		var denials, engagements int
		if err := sc.Q.QueryRow(ctx, `SELECT (SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='abac.denied' AND target=$2),
		 (SELECT count(*) FROM prospect_engagements WHERE tenant_id=$1)`, owner, permLifecycleExp).Scan(&denials, &engagements); err != nil {
			return err
		}
		if denials != 1 || engagements != 0 {
			t.Fatal("current export denial did not audit the refusal and preserve the engagement table")
		}
		return (store.ABACPolicies{}).Delete(ctx, sc, id)
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

func TestProspectCollectionDeadlineFencesOnlyTheCompletedTenant(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	finished, collecting := f.tenants[0], f.tenants[1]
	at := time.Now().UTC().Truncate(time.Microsecond)
	neighbors := store.NewDeviceNeighbors(f.pool)
	for _, tenant := range f.tenants {
		err := neighbors.ReplaceSnapshot(t.Context(), tenant, device.NeighborSnapshot{
			TenantID: tenant, AgentID: "assessment-device", DeviceAddress: "192.0.2.10", ObservedAt: at.Add(-2 * time.Minute),
			Neighbors: []device.NeighborEvidence{{Protocol: device.NeighborProtocolLLDP,
				LocalPortID: "port1", RemotePortID: "port2", RemoteChassisID: "fixture-peer"}},
		})
		if err != nil {
			t.Fatal("could not retain the pre-expiry snapshot", tenant, err)
		}
	}
	for lane, tenant := range f.tenants {
		slug, _, _, err := f.server.tenantSlugAndMeta(t.Context(), tenant)
		if err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permLifecycleErase); err != nil {
				return err
			}
			view, err := (store.DashboardReports{}).CreateView(ctx, sc, store.DashboardViewInput{ID: "prospect-view", OwnerID: f.users[tenant],
				Name: "Prospect assessment", Preset: "operator", Definition: []byte(`{"client_report":{"timezone":"UTC"}}`)})
			if err != nil {
				return err
			}
			end := at.Add(-time.Minute)
			if lane == 1 {
				end = at.Add(time.Hour)
			}
			_, err = (store.ProspectEngagements{}).Create(ctx, sc, store.ProspectEngagement{AssessmentViewID: view.ID, AssessmentAt: view.UpdatedAt,
				OwnerID: f.users[tenant], TenantSlug: slug, Preparer: "Example MSP", StartsAt: end.AddDate(0, 0, -14), EndsAt: end})
			return err
		})
	}
	collection := tenancy.NewPostgresCollectionWriterFence(f.pool)
	control := tenancy.NewPostgresWriterFence(f.pool)
	rejected := collection.WithTenantWrites(t.Context(), []string{finished}, func(context.Context) error {
		t.Fatal("completed prospect reached the external telemetry write")
		return nil
	})
	if !errors.Is(rejected, tenancy.ErrTenantWritesFenced) || !errors.Is(rejected, tenancy.ErrProspectCollectionEnded) {
		t.Fatal("collection deadline was unavailable at the writer boundary", rejected)
	}
	if err := collection.WithPartitionedTenantWrites(t.Context(), f.tenants, func(_ context.Context, rejected map[string]error) error {
		if len(rejected) != 1 || !errors.Is(rejected[finished], tenancy.ErrProspectCollectionEnded) || rejected[collecting] != nil {
			t.Fatal("a completed prospect affected its co-batched sibling", rejected)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := control.WithTenantWrites(t.Context(), []string{finished}, func(context.Context) error { called = true; return nil }); err != nil || !called {
		t.Fatal("the collection deadline fenced the normal lifecycle writer", err)
	}
	for _, tenant := range f.tenants {
		err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO results (tenant_id) VALUES ($1)`, sc.Tenant.String())
			return err
		})
		if tenant == finished && !tenancy.IsProspectCollectionEnded(err) || tenant == collecting && err != nil {
			t.Fatal("the PostgreSQL observation trigger used the wrong deadline", tenant, err)
		}
		err = neighbors.ReplaceSnapshot(t.Context(), tenant, device.NeighborSnapshot{
			TenantID: tenant, AgentID: "assessment-device", DeviceAddress: "192.0.2.10", ObservedAt: at,
		})
		if tenant == finished && !tenancy.IsProspectCollectionEnded(err) || tenant == collecting && err != nil {
			t.Fatal("the empty observation snapshot used the wrong deadline", tenant, err)
		}
		originals, _, err := neighbors.ListNeighbors(t.Context(), tenant, device.NeighborFilter{})
		want := 0
		if tenant == finished {
			want = 1
		}
		if err != nil || len(originals) != want {
			t.Fatal("the deadline did not preserve the correct tenant's previous evidence", tenant, originals, err)
		}
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	const path = "/v1/lifecycle/prospect"
	callSeasonalAPI(t, socket, f.tokens[finished], http.MethodGet, path, nil, http.StatusOK)
	callSeasonalAPI(t, socket, f.tokens[finished], http.MethodPost, path+"/convert", map[string]int64{"revision": 1}, http.StatusOK)
	called = false
	if err := collection.WithTenantWrites(t.Context(), []string{finished}, func(context.Context) error { called = true; return nil }); err != nil || !called {
		t.Fatal("conversion did not clear the scoped collection deadline", err)
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
	owner, sibling := f.tenants[0], f.tenants[1]
	archive := t.TempDir()
	ca, tlsConfig := alertTestCA(t, "localhost")
	relay := testsupport.StartArchivingSMTPServer(t, tlsConfig, "reports", "test-only-relay-proof", archive)
	_, port, err := net.SplitHostPort(relay.Addr)
	if err != nil {
		t.Fatal(err)
	}
	mailConfig := &config.Config{AlertSMTPAddr: net.JoinHostPort("localhost", port), AlertSMTPFrom: "reports@probectl.test",
		AlertSMTPTLSMode: "starttls", AlertSMTPUsername: "reports", AlertSMTPPassword: "test-only-relay-proof", AlertSMTPCAFile: ca}
	deps, err := BuildAlertChannelDeps(mailConfig, nil, f.server.log)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := deps.Mail.(alert.AttachmentMailSender)
	if !ok {
		t.Fatal("SMTP attachment transport unavailable")
	}
	ownerAddress := "prospect@" + owner + ".invalid"
	mailProbe := &reportMailProbe{transport: transport, fail: map[string]bool{ownerAddress: true}, attempts: map[string][]string{}, sent: map[string][]reportMailReceipt{}}
	f.server.WithAlertChannelDeps(alert.ChannelDeps{Mail: mailProbe})
	inputs := make(map[string]startProspectInput, len(f.tenants))
	sessions := make(map[string]string, len(f.tenants))
	for _, tenant := range f.tenants {
		slug, _, _, err := f.server.tenantSlugAndMeta(t.Context(), tenant)
		if err != nil {
			t.Fatal(err)
		}
		destination := config.ReportEmailDestination{TenantID: tenant, ID: "prospect-archive", Name: "Prospect archive", Recipients: []string{"prospect@" + tenant + ".invalid"}}
		f.server.cfg.ReportEmailDestinations = append(f.server.cfg.ReportEmailDestinations, destination)
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permTestRead, permIncidentRead, permChangeRead, "topology.read", permLifecycleErase, permLifecycleExp} {
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
			inputs[tenant] = startProspectInput{AssessmentViewID: view.ID, AssessmentAt: view.UpdatedAt,
				ConfirmTenant: slug, Preparer: "Scope " + tenant, DestinationID: reportEmailDestinationID(destination)}
			return nil
		})
		sessions[tenant] = auditorTestSession(t, f, tenant)
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	end := time.Now().UTC().Truncate(time.Microsecond).Add(4 * time.Second)
	engagements := make(map[string]store.ProspectEngagement, len(f.tenants))
	for _, tenant := range f.tenants {
		input := inputs[tenant]
		input.EndsAt = end
		raw := callComplianceControlReport(t, socket, sessions[tenant], http.MethodPost, "/v1/lifecycle/prospect", input, http.StatusCreated)
		var engagement store.ProspectEngagement
		if err := json.Unmarshal(raw, &engagement); err != nil || engagement.Revision != 1 || !engagement.EndsAt.Equal(end) {
			t.Fatal("interactive consent did not record the exact assessment end", err)
		}
		engagements[tenant] = engagement
	}
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
	}
	select {
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	case <-time.After(time.Until(end) + time.Millisecond):
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, tenant := range f.tenants {
		for range 2 {
			if err := supervisor.materializeProspectAssessment(t.Context(), tenant, "Prospect", now); err != nil {
				t.Fatal("due assessment could not be filed", err)
			}
		}
	}
	var ownerEngagement store.ProspectEngagement
	var ownerSHA string
	var ownerSize int64
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
				artifact.BodyBytes < 1 || len(artifact.BodySHA256) != 64 || artifact.TenantID != tenant || artifact.EmailDelivery == nil ||
				artifact.EmailDelivery.State != "pending" || artifact.EmailDelivery.DestinationID != engagements[tenant].DestinationID {
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
			receipt, err := (store.ProspectEngagements{}).ErasureEvidence(ctx, sc, item, dashboardReportSchedulerActor)
			if err == nil && receipt != nil {
				t.Fatal("a report inbox copy satisfied the durable delivery boundary")
			}
			return err
		})
		path := "/v1/dashboard-report-artifacts/" + item.AssessmentArtifactID
		raw := callComplianceControlReport(t, socket, sessions[tenant], http.MethodGet, path, nil, http.StatusOK)
		if int64(len(raw)) != bodySize || !bytes.HasPrefix(raw, []byte("%PDF-")) || hex.EncodeToString(crypto.Hash(raw)) != bodySHA {
			t.Fatal("the released assessment did not match its own sealed bytes")
		}
		callSeasonalAPI(t, socket, f.tokens[f.tenants[1-lane]], http.MethodGet, path, nil, http.StatusNotFound)
		if tenant == owner {
			ownerEngagement, ownerSHA, ownerSize = item, bodySHA, bodySize
		}
	}
	callSeasonalAPI(t, socket, f.tokens[sibling], http.MethodPost, "/v1/lifecycle/prospect/revoke-consent", map[string]int{"revision": 1}, http.StatusOK)
	due := time.Now().UTC().Add(time.Second)
	if err := supervisor.deliverTenantReportEmails(t.Context(), owner, due); err == nil || len(relay.Messages()) != 0 {
		t.Fatal("the unsuccessful attempt was recorded as accepted delivery")
	}
	for _, tenant := range f.tenants {
		if err := supervisor.deliverTenantReportEmails(t.Context(), tenant, due.Add(2*time.Minute)); err != nil {
			t.Fatal("configured report delivery failed", err)
		}
	}
	accepted := relay.Messages()
	attempts := mailProbe.attempts[ownerAddress]
	if len(accepted) != 1 || !accepted[0].TLS || len(accepted[0].To) != 1 || accepted[0].To[0] != ownerAddress ||
		len(attempts) != 2 || attempts[0] != attempts[1] || len(mailProbe.attempts["prospect@"+sibling+".invalid"]) != 0 {
		t.Fatal("retry or withdrawal lost exact scoped routing")
	}
	verifyArchivedProspectPDF(t, archive, ownerSHA)
	f.in(owner, func(ctx context.Context, sc tenancy.Scope) error {
		var receipts int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id=$1 AND action='dashboard.report_email_sent'
		 AND target=$2 AND data->>'body_sha256'=$3 AND data->>'prospect_revision'='1'`, owner, ownerEngagement.AssessmentArtifactID, ownerSHA).Scan(&receipts); err != nil {
			return err
		}
		if receipts != 1 {
			t.Fatal("successful delivery did not record exactly one scoped audit event")
		}
		receipt, err := (store.ProspectEngagements{}).ErasureEvidence(ctx, sc, ownerEngagement, dashboardReportSchedulerActor)
		if err != nil {
			return err
		}
		if receipt == nil || receipt.ArtifactID != ownerEngagement.AssessmentArtifactID || receipt.BodySHA256 != ownerSHA || receipt.BodyBytes != ownerSize ||
			receipt.DestinationID != ownerEngagement.DestinationID || receipt.DeliveredAt.Before(end) || receipt.ConsentAuditSequence < 1 ||
			receipt.DeliveryAuditSequence <= receipt.ConsentAuditSequence || len(receipt.ConsentAuditHash) != 64 || len(receipt.DeliveryAuditHash) != 64 {
			t.Fatal("accepted delivery lost its original consent or exact assessment audit receipt", receipt)
		}
		return audit.TenantVerify(ctx, sc)
	})
	f.in(sibling, func(ctx context.Context, sc tenancy.Scope) error {
		receipt, err := (store.ProspectEngagements{}).ErasureEvidence(ctx, sc, ownerEngagement, dashboardReportSchedulerActor)
		if err == nil && receipt != nil {
			t.Fatal("the sibling found the owner's consent and delivery receipt")
		}
		return err
	})
}

func verifyArchivedProspectPDF(t *testing.T, archive, expected string) {
	t.Helper()
	entries, err := os.ReadDir(archive)
	if err != nil || len(entries) != 1 {
		t.Fatal("the relay archive must contain exactly one accepted report", err)
	}
	raw, err := os.ReadFile(filepath.Join(archive, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	_, parameters, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || parameters["boundary"] == "" {
		t.Fatal("archived message is missing its MIME boundary", err)
	}
	parts := multipart.NewReader(message.Body, parameters["boundary"])
	for {
		part, err := parts.NextPart()
		if err != nil {
			t.Fatal("archived message is missing the assessment PDF", err)
		}
		if !strings.HasPrefix(part.Header.Get("Content-Type"), "application/pdf") {
			continue
		}
		pdf, err := io.ReadAll(base64.NewDecoder(base64.StdEncoding, part))
		if err != nil || hex.EncodeToString(crypto.Hash(pdf)) != expected {
			t.Fatal("archived PDF differs from the sealed assessment", err)
		}
		return
	}
}
