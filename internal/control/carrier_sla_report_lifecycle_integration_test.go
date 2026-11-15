// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

func proveCarrierSLASchedule(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, tenant, foreign string, proof carrierSLAReportProof, agreement, fingerprint string) string {
	t.Helper()
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
	input := sdk.DashboardReportScheduleRequest{DashboardId: proof.View, Name: "Recorded carrier claim delivery", Cadence: "monthly", Format: "csv", DestinationId: reportInboxDestination, FirstRunAt: time.Now().UTC().Format(time.RFC3339Nano)}
	schedule, err := client.CreateDashboardReportSchedule(t.Context(), sdk.CreateDashboardReportScheduleRequest{Body: &input})
	if err != nil {
		t.Fatal("financial schedule source preflight failed", err)
	}
	supervisor, ok := BuildDashboardReportSupervisor(f.pool, time.Minute, f.server.log)
	if !ok {
		t.Fatal("shipping report supervisor unavailable")
	}
	supervisor.WithReportSources(f.server)
	now := time.Now().UTC()
	for range 2 {
		if err := supervisor.materializeTenantReports(t.Context(), tenant, now); err != nil {
			t.Fatal("financial scheduled report or retry failed", err)
		}
	}
	var id string
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*),min(id) FROM dashboard_report_artifacts WHERE tenant_id=$1 AND schedule_id=$2`, tenant, schedule.Id).Scan(&count, &id); err != nil {
			return err
		}
		if count != 1 {
			return errors.New("financial schedule omitted or duplicated its immutable artifact")
		}
		return nil
	})
	proveCarrierSLANativeArtifact(t, client, id, agreement, proof.PopulationDigest, fingerprint)
	other := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[foreign]))
	if raw, err := other.DownloadDashboardReportArtifact(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: id}); err == nil || len(raw) > 0 {
		t.Fatal("scheduled financial artifact crossed tenant")
	}
	return id
}

func proveCarrierSLAPortableBindings(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, proofs map[string]carrierSLAReportProof, agreements map[string]string) {
	t.Helper()
	for index, source := range f.tenants {
		destination := f.tenants[1-index]
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[source]))
		manifest, err := client.ExportDashboardManifest(t.Context(), sdk.ExportDashboardManifestRequest{Id: proofs[source].View})
		if err != nil || manifest == nil || manifest.Spec.Definition.CarrierClaim == nil || len(manifest.Spec.Definition.CarrierClaim.Selections) != 1 {
			t.Fatal("financial portable source slot unavailable", err)
		}
		encoded, err := json.Marshal(manifest)
		if err != nil || bytes.Contains(encoded, []byte(agreements[source])) || bytes.Contains(encoded, []byte(source)) {
			t.Fatal("portable financial template retained source tenant or agreement identity", err)
		}
		slot, ok := manifest.Spec.Definition.CarrierClaim.Selections[0]["slot"].(string)
		if !ok || slot == "" {
			t.Fatal("financial slot is not explicit")
		}
		target := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[destination]))
		input := sdk.DashboardManifestImportRequest{Manifest: *manifest, Confirm: true}
		if imported, err := target.ImportDashboardManifest(t.Context(), sdk.ImportDashboardManifestRequest{Body: &input}); err == nil || imported != nil {
			t.Fatal("financial import inferred a missing destination binding")
		}
		input.AgreementBindings = map[string]sdk.CarrierSLAReportAgreementBinding{slot: {AgreementId: agreements[source], Version: "1"}}
		if imported, err := target.ImportDashboardManifest(t.Context(), sdk.ImportDashboardManifestRequest{Body: &input}); err == nil || imported != nil {
			t.Fatal("financial import accepted a foreign tenant's recorded terms")
		}
		input.AgreementBindings[slot] = sdk.CarrierSLAReportAgreementBinding{AgreementId: agreements[destination], Version: "1"}
		input.Confirm = false
		preview, err := target.ImportDashboardManifest(t.Context(), sdk.ImportDashboardManifestRequest{Body: &input})
		if err != nil || preview == nil || preview.Preview.SourceCount != 1 || preview.Dashboard.Id != "" {
			t.Fatal("bound financial preview created state or lost its source", err)
		}
		input.Confirm = true
		imported, err := target.ImportDashboardManifest(t.Context(), sdk.ImportDashboardManifestRequest{Body: &input})
		if err != nil || imported == nil || imported.Dashboard.Id == "" || imported.Dashboard.Definition.CarrierClaim == nil || len(imported.Dashboard.Definition.CarrierClaim.Selections) != 1 {
			t.Fatal("explicit own financial import failed", err)
		}
		selection := imported.Dashboard.Definition.CarrierClaim.Selections[0]
		if selection.AgreementId != agreements[destination] || selection.Version != "1" {
			t.Fatal("financial import substituted a different recorded revision")
		}
	}
}
