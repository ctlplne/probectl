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
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Real issued mTLS, PostgreSQL/RLS, session credentials, production SPA and
// Chromium/axe in both themes. Packet observations are modeled; the separate
// Linux fault proof supplies physical loss/outage evidence.
func TestCarrierClaimServedSignedReportsKeepTwoTenantsAndBothThemes(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.cfg.FlowQueryLibraryBytes = 256 << 20
	f.server.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	private, public, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	f.server.evidenceSigningKey = private
	fingerprint := "sha256:" + hex.EncodeToString(crypto.Hash(public))
	sender := newVerdictEvidenceSender(t, f)
	now := time.Now().UTC()
	from := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	names := []string{"Carrier alpha private terms", "Carrier beta private terms"}
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permFlowRead, permFlowAgreementsRead, permFlowAgreementsWrite, permTestRead, permMetricsWrite, permAgentRead, permAlertRead, permIncidentRead, permThreatRead, "topology.read"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			return nil
		})
		agent := gouuid.NewString()
		definition := seedVerdictCarrierTest(t, f, tenant, agent, "198.51.100.10")
		client := sender(tenant, agent)
		digest, err := testspec.DefinitionHash(definition)
		if err != nil {
			t.Fatal(err)
		}
		at := f.observedAt(tenant)
		measurement := &entity.ICMPMeasurement{Version: 3, DefinitionHash: digest, StartedAt: at, CompletedAt: at.Add(time.Microsecond), Requested: 3, Attempted: 3, Transmitted: 3, Replies: uint32(lane + 1), Responders: []string{definition.Target}, ReadComplete: true, RoundTrips: &entity.ICMPRoundTrips{Nanos: []uint64{100}, ExecutionNanos: 1000}}
		if lane == 1 {
			measurement.RoundTrips.Nanos = append(measurement.RoundTrips.Nanos, 300)
		}
		observation := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: agent, Kind: entity.PathAgent, SourceRef: definition.ID}, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: definition.Target}, SourceRef: "icmp:configured-test", ObservedAt: measurement.CompletedAt, ICMP: measurement}
		if n, unresolved, err := client.Submit(t.Context(), []entity.Observation{observation}); err != nil || n != 1 || unresolved != 0 {
			t.Fatal("served claim original source refused", n, unresolved, err)
		}
		terms := flow.CapacityAgreementDefinition{Name: names[lane], Reference: "operator contract", ValidFrom: from.Format(time.RFC3339Nano), Target: flow.CapacityTarget{Kind: "interface", ContextID: f.contextID, InterfaceID: f.interfaceID}, BillingDay: 1, Timezone: "UTC", Direction: "in", Currency: "USD", CommitBPS: "0", UnitBPS: "1", UnitPrice: "0", SLA: &flow.CarrierSLATerms{Carrier: names[lane], CircuitID: "recorded circuit", Currency: "USD", MonthlyCharge: "100.125", CreditCapRatio: "1", Aggregation: "maximum", Sources: []flow.CarrierSLASource{{AgentID: agent, TestID: definition.ID}}, Rules: []flow.CarrierSLARule{{ID: "loss", Metric: "loss", Basis: "original_packet_ratio", GoodWhen: "at_most", Threshold: "0.01", CreditBands: []flow.CarrierSLACreditBand{{From: "0.01", CreditRatio: "0.1"}}}}}}
		repository := flow.NewPostgresCapacityAgreements(f.pool, 1<<30, 8<<20, 8<<20, audit.TenantRecord)
		if _, err := repository.SaveCapacityAgreement(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.users[tenant], flow.SaveCapacityAgreement{Definition: terms}); err != nil {
			t.Fatal(err)
		}
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "served-carrier-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range f.tenants {
		for _, theme := range []string{"light", "dark"} {
			t.Run(strconv.Itoa(lane)+"/"+theme, func(t *testing.T) {
				proveCarrierClaimRendered(t, f, socket, ca, tenant, names[lane], names[1-lane], theme, now, fingerprint)
			})
		}
	}
}

func proveCarrierClaimRendered(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, ca, tenant, name, foreign, theme string, now time.Time, fingerprint string) {
	t.Helper()
	var grants []auth.PermissionGrant
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
		return err
	})
	cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: f.users[tenant], Email: "carrier@local.invalid", DisplayName: "Carrier reviewer", MFASatisfied: true, AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
	if err != nil {
		t.Fatal(err)
	}
	reportName := name + " " + theme
	spec := testsupport.RenderSpec{URL: socket.URL + "/ui/capacity", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}}, TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 90000, Expect: []string{"Capacity planning", name}, Absent: []string{foreign}}
	spec.Steps = []testsupport.RenderStep{
		{Click: "Open " + name, Expect: []string{"Monthly carrier SLA", name}, Absent: []string{foreign}},
		{Fill: "[data-capacity-sla] input", Value: now.Format(time.RFC3339Nano)},
		{Click: "Calculate monthly SLA", ExpectWithin: "[aria-label='Monthly SLA result']", Expect: []string{"1 / 0 / 0", "3", "No — unknown coverage or an unfinished period withholds exact credit"}},
		{Click: "Add selected agreement to claim"},
		{Fill: "[data-capacity-sla-claim] input >> nth=0", Value: now.Format(time.RFC3339Nano)},
		{Click: "Prepare grouped claim draft", ExpectWithin: "[aria-label='Grouped carrier claim draft']", Expect: []string{name, "Human review required.", "Unavailable"}, Absent: []string{foreign}},
		{Fill: "[data-capacity-sla-claim] input >> nth=1", Value: reportName},
		{Click: "Save signed claim report", Expect: []string{"Report saved."}},
	}
	spec.Controls = []testsupport.RenderControl{{Role: "link", Name: "Generate or schedule the signed claim"}}
	testsupport.RenderUI(t, spec)
	var view string
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT id FROM dashboard_views WHERE tenant_id=$1 AND owner_id=$2 AND name=$3`, tenant, f.users[tenant], reportName).Scan(&view)
	})
	spec.URL = socket.URL + "/ui/dashboards?view=" + view + "#saved-dashboard"
	spec.Expect = []string{"Saved views and report delivery", reportName}
	spec.Controls = nil
	spec.Steps = []testsupport.RenderStep{
		{Click: "Generate PDF", Within: "#saved-dashboard", Expect: []string{"PDF generated"}},
		{Select: "#saved-dashboard select >> nth=1", Value: "csv"},
		{Click: "Generate CSV", Within: "#saved-dashboard", Expect: []string{"CSV generated"}},
		{Select: "#saved-dashboard select >> nth=2", Value: "monthly"},
		{Click: "Schedule delivery", Within: "#saved-dashboard", Expect: []string{"Report scheduled"}},
	}
	testsupport.RenderUI(t, spec)
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
	for _, format := range []string{"csv", "pdf"} {
		var artifact string
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT id FROM dashboard_report_artifacts WHERE tenant_id=$1 AND generated_by=$2 AND dashboard_id=$3 AND format=$4`, tenant, f.users[tenant], view, format).Scan(&artifact)
		})
		var body bytes.Buffer
		if _, err := client.DownloadDashboardReportArtifactTo(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: artifact}, &body, 1<<30); err != nil {
			t.Fatal(err)
		}
		signed := carrierMonthWorkloadPackage(t, format, body.Bytes())
		manifest, err := evidence.Verify(signed)
		if err != nil || manifest.Profile != "carrier-sla" || manifest.TenantScopeDigest != hex.EncodeToString(crypto.Hash([]byte("probectl.carrier-sla.tenant.v1:"+tenant))) {
			t.Fatal("browser-generated claim lost its signed complete body", err)
		}
		var pkg evidence.Package
		if err := json.Unmarshal(signed, &pkg); err != nil || pkg.Signing.Fingerprint != fingerprint {
			t.Fatal("browser-generated claim changed its deployment signer", err)
		}
	}
}
