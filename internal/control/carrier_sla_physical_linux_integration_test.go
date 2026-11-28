// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration && linux

package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

type physicalCarrierSLAProof struct {
	agreements  map[string]string
	paths       map[string]pathstore.Snapshot
	fingerprint string
}

// This shares the existing namespaces, collector, source assignments and issued
// mTLS transport. No second lab, fabricated receipt or shifted clock is needed.
func prepareCarrierSLAPhysical(t *testing.T, d *dependencyRoutingFixture) physicalCarrierSLAProof {
	t.Helper()
	f := d.f
	f.server.cfg.FlowQueryLibraryBytes = 256 << 20
	f.server.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	f.server.pathStore = pathstore.NewMemory()
	private, public, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	f.server.evidenceSigningKey = private
	proof := physicalCarrierSLAProof{agreements: map[string]string{}, paths: map[string]pathstore.Snapshot{}, fingerprint: "sha256:" + hex.EncodeToString(crypto.Hash(public))}
	now := time.Now().UTC()
	from := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permFlowAgreementsRead, permFlowAgreementsWrite, permTestRead, permTestWrite, "entities.read", "metrics.read", permMetricsWrite} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		source := d.graphs[tenant].Nodes[0]
		terms := flow.CapacityAgreementDefinition{Name: "Physical circuit SLA", Reference: "Operator lab terms", ValidFrom: from.Format(time.RFC3339Nano), Target: flow.CapacityTarget{Kind: "interface", ContextID: f.contextID, InterfaceID: f.interfaceID}, BillingDay: 1, Timezone: "UTC", Direction: "in", Currency: "USD", CommitBPS: "0", UnitBPS: "1", UnitPrice: "0", SLA: &flow.CarrierSLATerms{Carrier: "Lab carrier", CircuitID: "isolated routed link", Currency: "USD", MonthlyCharge: "100.125", Aggregation: "maximum", CreditCapRatio: "1", Sources: []flow.CarrierSLASource{{AgentID: source.AgentID, TestID: source.TestID}}, Rules: []flow.CarrierSLARule{
			{ID: "loss", Metric: "loss", Basis: "original_packet_ratio", GoodWhen: "at_most", Threshold: "0.01", CreditBands: []flow.CarrierSLACreditBand{{From: "0.01", CreditRatio: "0.1"}}},
			{ID: "availability", Metric: "availability", Basis: "original_execution_ratio", GoodWhen: "at_least", Threshold: "0.99", CreditBands: []flow.CarrierSLACreditBand{{From: "0", To: "0.99", CreditRatio: "0.1"}}},
			{ID: "repair", Metric: "repair_nanos", Basis: "original_failure_interval", GoodWhen: "at_most", Threshold: "1", CreditBands: []flow.CarrierSLACreditBand{{From: "1", CreditRatio: "0.1"}}},
		}}}
		repository := flow.NewPostgresCapacityAgreements(f.pool, 1<<30, 8<<20, 8<<20, audit.TenantRecord)
		item, err := repository.SaveCapacityAgreement(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.users[tenant], flow.SaveCapacityAgreement{Definition: terms})
		if err != nil {
			t.Fatal("physical source agreement refused", err)
		}
		proof.agreements[tenant] = item.ID
	}
	return proof
}

func recordPhysicalCarrierSLAPath(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, lane *dependencyPhysicalLane) pathstore.Snapshot {
	t.Helper()
	test := lane.definitions[0]
	from := f.observedAt(lane.tenant)
	body := callSeasonalAPI(t, socket, f.tokens[lane.tenant], http.MethodPost, "/v1/tests/"+test.ID+"/path", nil, http.StatusOK)
	var observed path.Path
	if err := json.Unmarshal(body, &observed); err != nil || observed.TargetIP != test.Target || !observed.DestinationReached ||
		observed.Vantage != path.VantageControlPlane || observed.MeasurementFidelity == nil || observed.MeasurementFidelity.AcquisitionMode != "raw_icmp" {
		t.Fatal("physical SLA path did not reach the owned routed interface", err)
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(lane.tenant))
	rows, err := f.server.pathStore.History(ctx, lane.tenant, test.Target, pathstore.HistoryQuery{
		From: from, To: f.observedAt(lane.tenant), TestID: test.ID, MaxBytes: 8 << 20,
	})
	if err != nil || len(rows) != 1 || rows[0].ID == "" || !rows[0].TrustedDiscoveryTime || rows[0].CompletedAt == nil {
		t.Fatal("the physical discovery did not retain one original round under the tenant", err)
	}
	return rows[0]
}

func proveCarrierSLAPhysical(t *testing.T, d *dependencyRoutingFixture, socket *httptest.Server, lanes []*dependencyPhysicalLane, proof physicalCarrierSLAProof) {
	t.Helper()
	for index, lane := range lanes {
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(d.f.tokens[lane.tenant]))
		input := sdk.CarrierSLAInput{Version: "1", At: time.Now().UTC().Format(time.RFC3339Nano)}
		statement, err := client.CalculateCarrierSla(t.Context(), sdk.CalculateCarrierSlaRequest{Id: proof.agreements[lane.tenant], Body: &input})
		if err != nil || statement == nil || len(statement.Sources) != 1 {
			t.Fatal("physical carrier population unavailable", err)
		}
		transmitted, lost, replies := 0, 0, 0
		for _, batch := range lane.measured {
			m := batch[0].Measurement
			transmitted += m.Transmitted
			replies += m.Replies
			lost += m.Transmitted - m.Replies
		}
		source := statement.Sources[0]
		if source.Originals != strconv.Itoa(len(lane.measured)) || source.Transmitted != strconv.Itoa(transmitted) || source.Lost != strconv.Itoa(lost) || source.RttSamples != strconv.Itoa(replies) || lost <= 0 || replies <= 0 {
			t.Fatal("carrier statement changed actual injected loss or recovered samples", source)
		}
		if statement.Credit.Complete || statement.Credit.ExactCredit != "" || !statement.HumanReviewRequired {
			t.Fatal("brief physical proof invented a complete month's legal credit")
		}
		definition := sdk.DashboardCreateRequest{Name: "Physical carrier claim", Preset: "operator", Definition: sdk.DashboardDefinition{CarrierClaim: &sdk.CarrierSLAReportDefinition{Selections: []sdk.CarrierSLAReportSelection{{AgreementId: proof.agreements[lane.tenant], Version: "1", At: input.At}}}, Provenance: []string{"actual routed ICMP and issued mTLS originals"}, RedactionState: "tenant policy", CoverageLimitations: []string{"current month incomplete; observed samples only"}}}
		view, err := client.CreateDashboard(t.Context(), sdk.CreateDashboardRequest{Body: &definition})
		if err != nil {
			t.Fatal(err)
		}
		request := map[string]any{"dashboard_id": view.Id, "format": "csv"}
		artifact, err := client.GenerateDashboardReport(t.Context(), sdk.GenerateDashboardReportRequest{Body: &request})
		if err != nil {
			t.Fatal("physical signed claim refused", err)
		}
		var downloaded bytes.Buffer
		if _, err := client.DownloadDashboardReportArtifactTo(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: artifact.Id}, &downloaded, 1<<30); err != nil {
			t.Fatal(err)
		}
		signed := physicalCarrierCSVPackage(t, downloaded.Bytes())
		checkPhysicalCarrierOriginals(t, signed, lane, proof.paths[lane.tenant], proof.fingerprint)
		foreign := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(d.f.tokens[lanes[1-index].tenant]))
		if body, err := foreign.DownloadDashboardReportArtifact(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: artifact.Id}); err == nil || len(body) > 0 {
			t.Fatal("physical signed claim crossed storage tenant")
		}
		if _, err := foreign.CalculateCarrierSla(t.Context(), sdk.CalculateCarrierSlaRequest{Id: proof.agreements[lane.tenant], Body: &input}); err == nil {
			t.Fatal("physical financial source crossed tenant")
		}
		t.Logf("real-integration carrier originals=%d transmitted=%d lost=%d recovered_reply_samples=%d; current month explicitly incomplete", len(lane.measured), transmitted, lost, replies)
	}
}

func physicalCarrierCSVPackage(t *testing.T, body []byte) []byte {
	t.Helper()
	reader := csv.NewReader(bytes.NewReader(body))
	reader.FieldsPerRecord = -1
	var signed bytes.Buffer
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(row) == 6 && len(row[0]) > 4 && row[0][:4] == "pkg_" {
			raw, err := base64.StdEncoding.DecodeString(row[5])
			if err != nil {
				t.Fatal(err)
			}
			signed.Write(raw)
		}
	}
	return signed.Bytes()
}

type physicalCarrierOriginal struct {
	EvidenceID string    `json:"evidence_id"`
	ObservedAt time.Time `json:"observed_at"`
	ICMP       struct {
		Version                         int       `json:"version"`
		StartedAt                       time.Time `json:"started_at"`
		CompletedAt                     time.Time `json:"completed_at"`
		Requested, Transmitted, Replies uint32
		RoundTrips                      struct {
			Nanos          []string `json:"nanos"`
			ExecutionNanos string   `json:"execution_nanos"`
		} `json:"round_trips"`
	} `json:"icmp"`
}

func checkPhysicalCarrierOriginals(t *testing.T, raw []byte, lane *dependencyPhysicalLane, recordedPath pathstore.Snapshot, fingerprint string) {
	t.Helper()
	manifest, err := evidence.Verify(raw)
	if err != nil || manifest.Profile != "carrier-sla" {
		t.Fatal("physical signed originals do not verify offline", err)
	}
	var pkg evidence.Package
	if err := json.Unmarshal(raw, &pkg); err != nil || pkg.Signing.Fingerprint != fingerprint || len(pkg.Attachments) != 2 {
		t.Fatal("physical claim signer or complete attachment set changed", err)
	}
	var originals struct {
		Selections []struct {
			Measurements []physicalCarrierOriginal `json:"measurements"`
			PathCoverage string                    `json:"path_coverage"`
			Paths        []carrierSLAPathOriginal  `json:"path_rounds"`
		} `json:"selections"`
	}
	if err := json.Unmarshal(pkg.Attachments[1].Content, &originals); err != nil || len(originals.Selections) != 1 || len(originals.Selections[0].Measurements) != len(lane.measured) {
		t.Fatal("signed package lost actual original observations", err)
	}
	selection := originals.Selections[0]
	if recordedPath.CompletedAt == nil || selection.PathCoverage != "control_plane_context" || len(selection.Paths) != 1 {
		t.Fatal("signed package did not retain the actual circuit path")
	}
	trace := selection.Paths[0]
	if trace.TestID != lane.definitions[0].ID || trace.RoundID != recordedPath.ID ||
		!trace.StartedAt.Equal(recordedPath.ObservedAt) || !trace.CompletedAt.Equal(*recordedPath.CompletedAt) ||
		trace.Path.Vantage != path.VantageControlPlane || !trace.Path.DestinationReached ||
		trace.Path.MeasurementFidelity == nil || trace.Path.MeasurementFidelity.AcquisitionMode != "raw_icmp" {
		t.Fatal("signed path changed the original observation or substituted a different circuit")
	}
	expected := map[string]*dependencyPhysicalMeasurement{}
	for i := range lane.measured {
		item := &lane.measured[i][0]
		expected[item.EvidenceID] = item
	}
	for _, original := range originals.Selections[0].Measurements {
		item, ok := expected[original.EvidenceID]
		if !ok {
			t.Fatal("signed physical claim substituted a duplicate or foreign original")
		}
		delete(expected, original.EvidenceID)
		m := item.Measurement
		if original.ICMP.Version != 3 || original.ICMP.Requested != uint32(m.Expected) || original.ICMP.Transmitted != uint32(m.Transmitted) || original.ICMP.Replies != uint32(m.Replies) || !original.ObservedAt.Equal(m.CompletedAt.UTC().Truncate(time.Microsecond)) || !original.ICMP.StartedAt.Equal(m.StartedAt) || !original.ICMP.CompletedAt.Equal(m.CompletedAt) || len(original.ICMP.RoundTrips.Nanos) != len(m.RoundTripNanos) || original.ICMP.RoundTrips.ExecutionNanos != strconv.FormatUint(m.ExecutionNanos, 10) {
			t.Fatal("signed original changed physical packet counters, clock or monotonic duration")
		}
		for i, nanos := range m.RoundTripNanos {
			if original.ICMP.RoundTrips.Nanos[i] != strconv.FormatUint(nanos, 10) {
				t.Fatal("signed original changed an actual RTT")
			}
		}
	}
	if len(expected) != 0 {
		t.Fatal("signed physical claim omitted an original")
	}
	file := filepath.Join(t.TempDir(), "physical-claim.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var output, errors bytes.Buffer
	code := cli.RunWithStdin([]string{"incident", "verify", file, "--trusted-key-fingerprint", fingerprint}, func(string) string { return "" }, nil, &output, &errors)
	if code != 0 || !bytes.Contains(output.Bytes(), []byte("VERIFIED probectl-evidence/v1")) {
		t.Fatal("actual offline CLI did not verify physical claim", code, errors.String())
	}
	originalAttachment := pkg.Attachments[1].Content
	pkg.Attachments[1].Content = bytes.Replace(originalAttachment, []byte(trace.RoundID), []byte("00000000000000000000000000000000"), 1)
	if bytes.Equal(pkg.Attachments[1].Content, originalAttachment) {
		t.Fatal("could not plant a changed physical path round in the signed claim")
	}
	tampered, err := json.Marshal(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.Verify(tampered); err == nil {
		t.Fatal("the offline verifier accepted a changed path round in the physical claim")
	}
}
