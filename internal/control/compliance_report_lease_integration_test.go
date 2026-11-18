// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/cluster"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDirectionalComplianceScheduleStagesWithCurrentSingletonLease(t *testing.T) {
	f, _ := seedIncidentImpactFlowFixture(t)
	private, public, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	f.server.WithEvidenceSigningKey(private)
	pin := "sha256:" + hex.EncodeToString(crypto.Hash(public))
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	supervisor, ok := BuildDashboardReportSupervisor(f.pool, time.Minute, f.server.log)
	if !ok {
		t.Fatal("report supervisor unavailable")
	}
	supervisor.WithReportSources(f.server)
	lease, err := cluster.NewPGLease(f.pool, fmt.Sprintf("directional-report-%d", time.Now().UnixNano()), "directional-report-fixture")
	if err != nil {
		t.Fatal(err)
	}
	term, acquired, err := lease.Acquire(t.Context())
	if err != nil || !acquired {
		t.Fatal("could not acquire the real scheduler lease", err)
	}
	t.Cleanup(func() {
		if err := lease.Release(context.Background(), term); err != nil {
			t.Error(err)
		}
	})
	fenced := term
	fenced.Epoch++
	currentContext := tenancy.WithTxGuard(t.Context(), cluster.LeaseGuard(term))
	fencedContext := tenancy.WithTxGuard(t.Context(), cluster.LeaseGuard(fenced))
	first := time.Now().UTC().Add(time.Minute)
	due := first.Add(time.Second)
	var cookies, artifactIDs [2]string
	const zone = "protected-cde"
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{"metrics.write", permAuditRead} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		cookies[lane] = auditorTestSession(t, f, tenant)
		request := func(method, path string, body any, status int) []byte {
			return callComplianceControlReport(t, socket, cookies[lane], method, path, body, status)
		}
		control := []string{compliance.PCIInboundNetworkControl, compliance.PCIOutboundNetworkControl}[lane]
		from, to := []string{"outside", zone}[lane], []string{zone, "outside"}[lane]
		input := reporting.DashboardCreateInput{Name: "Lease-fenced directional control", Preset: "operator",
			Definition: reporting.DashboardDefinition{ComplianceControl: control, RedactionState: "selected directional evidence",
				Provenance: []string{"fixture original capture"}, CoverageLimitations: []string{"selected evidence window"},
				ComplianceFlow: &reporting.ComplianceFlowDefinition{Lookback: "24h", ProtectedZone: zone,
					Policy:  fmt.Sprintf(directionalPCIFixturePolicy, from, to, from, to),
					Sources: []reporting.ComplianceFlowSource{{ContextID: f.contextID, EntityID: f.routerID}}}}}
		var view store.DashboardView
		if err := json.Unmarshal(request(http.MethodPost, "/v1/dashboards", input, http.StatusCreated), &view); err != nil || view.ID == "" {
			t.Fatal("could not create the directional report definition", err)
		}
		request(http.MethodPost, "/v1/dashboard-report-schedules", reporting.ReportScheduleInput{DashboardID: view.ID, Name: "Lease-fenced daily review",
			Format: "csv", Cadence: "daily", DestinationID: reportInboxDestination, FirstRunAt: first}, http.StatusCreated)
		if err := supervisor.materializeTenantReports(fencedContext, tenant, due); !errors.Is(err, cluster.ErrLeaseFenced) {
			t.Fatal("a mismatched epoch reached report publication", err)
		}
		if err := supervisor.materializeTenantReports(currentContext, tenant, due); err != nil {
			t.Fatal("a current lease must stage read-only source evidence and publish", err)
		}
		assertReportLeaseStageReadOnly(t, f, currentContext, tenant)
		var inbox struct{ Items []reportArtifactView }
		if err := json.Unmarshal(request(http.MethodGet, "/v1/dashboard-report-artifacts", nil, http.StatusOK), &inbox); err != nil || len(inbox.Items) != 1 || inbox.Items[0].ScheduleID == nil {
			t.Fatal("the current epoch did not publish one scheduled artifact", err)
		}
		artifactIDs[lane] = inbox.Items[0].ID
		raw := request(http.MethodGet, "/v1/dashboard-report-artifacts/"+artifactIDs[lane], nil, http.StatusOK)
		proveDirectionalPCIReportBytes(t, raw, "csv", pin, tenant, control, zone, from, to, []string{compliance.StatusFailed, compliance.StatusObserved}[lane])
	}
	for lane, cookie := range cookies {
		callComplianceControlReport(t, socket, cookie, http.MethodGet, "/v1/dashboard-report-artifacts/"+artifactIDs[1-lane], nil, http.StatusNotFound)
	}
}

func assertReportLeaseStageReadOnly(t *testing.T, f *roleExplanationAPIFixture, ctx context.Context, tenant string) {
	t.Helper()
	ctx = tenancy.WithTenant(ctx, tenancy.ID(tenant))
	err := tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var own int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM dashboard_report_schedules`).Scan(&own); err != nil {
			return err
		}
		if own != 1 {
			t.Fatalf("the read snapshot saw %d schedules instead of the tenant's one", own)
		}
		_, err := sc.Q.Exec(ctx, `UPDATE dashboard_report_schedules SET updated_at=updated_at WHERE tenant_id=$1`, tenant)
		return err
	})
	var dbErr *pgconn.PgError
	if !errors.As(err, &dbErr) || dbErr.Code != "25006" {
		t.Fatal("the source snapshot must refuse writes in PostgreSQL", err)
	}
}
