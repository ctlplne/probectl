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
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Real issued mTLS, application-role PostgreSQL/RLS, session authentication,
// production SPA and Chromium/axe. One modeled execution lies in a selected
// fourteen-day interval; this does not claim a full engagement or offboarding.
func TestAssessmentServedConfigurationReportsKeepTwoTenantsAndBothThemes(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	private, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	f.server.WithEvidenceSigningKey(private)
	sender := newVerdictEvidenceSender(t, f)
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permTestRead, permChangeRead, permMetricsWrite, permIncidentRead, permFlowRead, permAgentRead, permAlertRead, permThreatRead, "topology.read"} {
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
		measurement := &entity.ICMPMeasurement{Version: 3, DefinitionHash: digest, StartedAt: at, CompletedAt: at.Add(time.Microsecond), Requested: 3, Attempted: 3, Transmitted: 3, ReadComplete: true, RoundTrips: &entity.ICMPRoundTrips{Nanos: []uint64{}, ExecutionNanos: 1000}, Responders: []string{}}
		if lane == 0 {
			measurement.Replies, measurement.RoundTrips.Nanos, measurement.Responders = 1, []uint64{100}, []string{definition.Target}
		}
		observation := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: agent, Kind: entity.PathAgent, SourceRef: definition.ID}, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: definition.Target}, SourceRef: "icmp:configured-test", ObservedAt: measurement.CompletedAt, ICMP: measurement}
		if accepted, unresolved, err := client.Submit(t.Context(), []entity.Observation{observation}); err != nil || accepted != 1 || unresolved != 0 {
			t.Fatal("served assessment original source refused", accepted, unresolved, err)
		}
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	ca := filepath.Join(t.TempDir(), "assessment-ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	to := time.Now().UTC()
	from := to.AddDate(0, 0, -14)
	for lane, tenant := range f.tenants {
		for _, theme := range []string{"light", "dark"} {
			t.Run(strconv.Itoa(lane)+"/"+theme, func(t *testing.T) {
				proveAssessmentRendered(t, f, socket, ca, tenant, f.tenants[1-lane], theme, from, to)
			})
		}
	}
}

func proveAssessmentRendered(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, ca, tenant, foreign, theme string, from, to time.Time) {
	t.Helper()
	var grants []auth.PermissionGrant
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
		return err
	})
	cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: f.users[tenant], Email: "assessment@local.invalid", DisplayName: "Assessment preparer", MFASatisfied: true, AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
	if err != nil {
		t.Fatal(err)
	}
	name, preparer := "Prospect assessment "+theme, "Example MSP "+theme
	spec := testsupport.RenderSpec{URL: socket.URL + "/ui/dashboards", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}}, TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true, TimeoutMs: 90000, Expect: []string{"Saved views and report delivery"}}
	spec.Steps = []testsupport.RenderStep{
		{Click: "Build a client report (preview)", Expect: []string{"Report period"}},
		{Select: "[aria-label='Client report configuration'] select >> nth=0", Value: "assessment"},
		{Fill: "label:text-is('Assessment start') + div input", Value: from.Format(time.RFC3339Nano)},
		{Fill: "label:text-is('Assessment end') + div input", Value: to.Format(time.RFC3339Nano)},
		{Fill: "label:text-is('Assessment prepared by') + div input", Value: preparer},
		{Fill: "label:text-is('Dashboard name') + div input", Value: name},
		{Click: "Save dashboard", Within: "#saved-dashboard", Expect: []string{"Dashboard saved", preparer}},
		{Click: "Generate PDF", Within: "#saved-dashboard", Expect: []string{"PDF generated"}},
		{Select: "#saved-dashboard label:text-is('Format') + div select", Value: "csv"},
		{Click: "Generate CSV", Within: "#saved-dashboard", Expect: []string{"CSV generated"}},
	}
	testsupport.RenderUI(t, spec)
	var view store.DashboardView
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT id,definition FROM dashboard_views WHERE tenant_id=$1 AND owner_id=$2 AND name=$3`, tenant, f.users[tenant], name).Scan(&view.ID, &view.Definition)
	})
	var definition reporting.DashboardDefinition
	if json.Unmarshal(view.Definition, &definition) != nil || definition.ClientReport == nil || definition.ClientReport.Assessment == nil || definition.ClientReport.Assessment.From != from.Format(time.RFC3339Nano) || definition.ClientReport.Assessment.To != to.Format(time.RFC3339Nano) || definition.ClientReport.Assessment.Preparer != preparer {
		t.Fatal("browser-saved assessment changed its explicit period or preparer")
	}
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
	var tenantName string
	var inventoryIDs []string
	f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		tenantName, err = dashboardTenantName(ctx, sc)
		if err != nil {
			return err
		}
		rows, err := sc.Q.Query(ctx, `SELECT id::text FROM entities WHERE tenant_id=$1 ORDER BY id`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			inventoryIDs = append(inventoryIDs, id)
		}
		return rows.Err()
	})
	for _, format := range []string{"csv", "pdf"} {
		var id string
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT id FROM dashboard_report_artifacts WHERE tenant_id=$1 AND generated_by=$2 AND dashboard_id=$3 AND format=$4`, tenant, f.users[tenant], view.ID, format).Scan(&id)
		})
		var output bytes.Buffer
		if _, err := client.DownloadDashboardReportArtifactTo(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: id}, &output, 1<<30); err != nil {
			t.Fatal(err)
		}
		text := output.String()
		if format == "pdf" {
			text, err = staticDocumentSemanticText(output.Bytes(), reporting.Document{TenantName: tenantName, TenantScope: tenant, AbsoluteFrom: from, AbsoluteTo: to})
			if err != nil {
				t.Fatal("served assessment PDF changed its complete pages or tenant header", err)
			}
			for _, id := range inventoryIDs {
				if !strings.Contains(text, id) {
					t.Fatal("served PDF omitted a canonical inventory identity")
				}
			}
		} else if err := checkServedAssessmentCSV(output.Bytes(), tenant, inventoryIDs); err != nil {
			t.Fatal(err)
		}
		for _, expected := range []string{preparer, "Canonical inventory at report capture", "Observed physical adjacency at report capture", "Assessment measurement coverage and gaps", "Observed assessment risks and capacity hot spots"} {
			if !strings.Contains(text, expected) {
				t.Fatal("browser-generated assessment omitted a complete section or preparer", format, expected)
			}
		}
		if strings.Contains(text, foreign) {
			t.Fatal("served assessment contains the sibling tenant's data")
		}
		other := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[foreign]))
		if written, err := other.DownloadDashboardReportArtifactTo(t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: id}, io.Discard, 1<<30); err == nil || written != 0 {
			t.Fatal("served assessment body crossed tenant storage authority", err)
		}
	}
}

func checkServedAssessmentCSV(body []byte, tenant string, expectedInventory []string) error {
	reader := csv.NewReader(bytes.NewReader(body))
	reader.FieldsPerRecord = -1
	rows, err := reader.ReadAll()
	if err != nil {
		return err
	}
	inventory, availability := map[string]bool{}, 0
	for _, row := range rows {
		if len(row) == 14 && row[0] == tenant {
			if inventory[row[6]] {
				return fmt.Errorf("served inventory duplicated a canonical entity")
			}
			inventory[row[6]] = true
		}
		if len(row) == 18 && row[0] == tenant {
			if row[16] != "1" || row[17] == "" {
				return fmt.Errorf("served assessment lost the independently known original count or digest")
			}
			availability++
		}
	}
	if len(inventory) != len(expectedInventory) || availability != 1 {
		return fmt.Errorf("served assessment populations differ: inventory=%d/%d availability=%d/1", len(inventory), len(expectedInventory), availability)
	}
	for _, id := range expectedInventory {
		if !inventory[id] {
			return fmt.Errorf("served assessment omitted a canonical inventory identity")
		}
	}
	return nil
}
