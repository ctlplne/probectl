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
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

type clientReportNativeProof struct {
	t             *testing.T
	fixture       *roleExplanationAPIFixture
	rest, native  *httptest.Server
	caFile        string
	artifacts     map[string]string
	server        *mcp.Server
	authenticator mcp.Authenticator
	stdio         map[string]map[string]*interfaceRoleStdioClient
}

func newClientReportNativeProof(t *testing.T, f *roleExplanationAPIFixture, rest *httptest.Server) *clientReportNativeProof {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "report-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rest.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permAIQuery)
		})
		policies := govern.NewPolicyStore(f.pool)
		policy, found, err := policies.TenantPolicy(t.Context(), tenant)
		if err != nil {
			t.Fatal(err)
		}
		policy.AIRemoteEgress, policy.RedactExport = true, true
		actor := "core-operator:" + f.users[tenant]
		if err := policies.SetTenantPolicy(t.Context(), tenant, policy, actor, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := audit.TenantAppend(ctx, sc, actor, "governance.policy_set", tenant, map[string]any{"ai_remote_egress": true, "redact_export": true, "prior_policy_existed": found, "fixture": "documented-core-operator"})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{}
	server := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, pathstore.NewMemory(), 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), AISources{NativeFlow: f.server})
	socket := httptest.NewTLSServer(server.HTTPHandler(NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)))
	t.Cleanup(socket.Close)
	return &clientReportNativeProof{t: t, fixture: f, rest: rest, native: socket, caFile: caFile, artifacts: map[string]string{}, server: server, authenticator: NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false), stdio: map[string]map[string]*interfaceRoleStdioClient{}}
}
func (p *clientReportNativeProof) invokeCLI(tenant string, input []byte, args ...string) ([]byte, int) {
	p.t.Helper()
	var output, errors bytes.Buffer
	code := cli.RunWithStdin(append([]string{"--json"}, args...), func(key string) string {
		switch key {
		case "PROBECTL_API_URL":
			return p.rest.URL
		case "PROBECTL_API_TOKEN":
			return p.fixture.tokens[tenant]
		case "PROBECTL_CA_FILE":
			return p.caFile
		}
		return ""
	}, bytes.NewReader(input), &output, &errors)
	if code != 0 && output.Len() != 0 {
		p.t.Fatal("refused CLI monthly request leaked a response body")
	}
	return output.Bytes(), code
}
func (p *clientReportNativeProof) prove(ctx context.Context, tenant, foreign, view, incident, public string, tables []reporting.CSVTable) {
	p.t.Helper()
	caller := reportMCPClient{t: p.t, socket: p.native, foreignTenant: foreign}
	var selected mcp.ReportDashboard
	caller.call(p.fixture.tokens[tenant], "report_dashboard", map[string]any{"id": view}, &selected, true, "monthly native view failed")
	proveLegacyMCPInitializationTLS(p.t, p.native, p.fixture.tokens[tenant])
	legacy := reportMCPClient{t: p.t, socket: p.native, foreignTenant: foreign, protocolVersion: "2025-11-25"}
	var legacyView mcp.ReportDashboard
	legacy.call(p.fixture.tokens[tenant], "report_dashboard", map[string]any{"id": view}, &legacyView, true, "legacy monthly native view failed")
	if legacyView.ID != selected.ID || legacyView.TenantID != selected.TenantID {
		p.t.Fatal("monthly native protocol projections differ")
	}
	if selected.TenantID != tenant || selected.Definition.ClientReport == nil || len(selected.Definition.ClientReport.CapacityTargets) != 1 {
		p.t.Fatal("native view lost tenant monthly capacity configuration")
	}
	manifest, code := p.invokeCLI(tenant, nil, "dashboard", "export", view)
	if code != 0 {
		p.t.Fatal("CLI monthly manifest export failed", code)
	}
	var exported reporting.DashboardManifest
	if err := json.Unmarshal(manifest, &exported); err != nil || exported.Spec.Definition.ClientReport == nil || len(exported.Spec.Definition.ClientReport.CapacityTargets) != 1 {
		p.t.Fatal("CLI monthly export lost source configuration", err)
	}
	var artifact mcp.ReportArtifact
	caller.call(p.fixture.tokens[tenant], "report_generate", reporting.ReportGenerateInput{DashboardID: view, Format: "csv"}, &artifact, true, "complete monthly native generation failed")
	client := sdk.NewClient(p.rest.URL, sdk.WithHTTPClient(p.rest.Client()), sdk.WithToken(p.fixture.tokens[tenant]), sdk.WithTenant(tenant))
	body, err := client.DownloadDashboardReportArtifact(ctx, sdk.DownloadDashboardReportArtifactRequest{Id: artifact.ID})
	if err != nil {
		p.t.Fatal("SDK complete native-generated monthly download failed", err)
	}
	conflicting := sdk.NewClient(p.rest.URL, sdk.WithHTTPClient(p.rest.Client()), sdk.WithToken(p.fixture.tokens[tenant]), sdk.WithTenant(foreign))
	if leaked, err := conflicting.DownloadDashboardReportArtifact(ctx, sdk.DownloadDashboardReportArtifactRequest{Id: artifact.ID}); err == nil || len(leaked) != 0 {
		p.t.Fatal("SDK conflicting tenant header did not fail closed")
	}
	proveClientReportNativeCSV(ctx, p.t, body, tables, tenant, foreign, incident, public)
	downloaded, code := p.invokeCLI(tenant, nil, "dashboard-report", "download", artifact.ID)
	if code != 0 || !bytes.Equal(downloaded, body) {
		p.t.Fatal("CLI changed the complete SDK monthly download", code)
	}
	p.artifacts[tenant] = artifact.ID
	request := map[string]any{"dashboard_id": view, "format": "csv"}
	generated, err := client.GenerateDashboardReport(ctx, sdk.GenerateDashboardReportRequest{Body: &request})
	if err != nil {
		p.t.Fatal("SDK monthly generation failed", err)
	}
	sdkBody, err := client.DownloadDashboardReportArtifact(ctx, sdk.DownloadDashboardReportArtifactRequest{Id: generated.Id})
	if err != nil {
		p.t.Fatal(err)
	}
	proveClientReportNativeCSV(ctx, p.t, sdkBody, tables, tenant, foreign, incident, public)
	var legacyArtifact mcp.ReportArtifact
	legacy.call(p.fixture.tokens[tenant], "report_generate", reporting.ReportGenerateInput{DashboardID: view, Format: "csv"}, &legacyArtifact, true, "legacy complete monthly generation failed")
	legacyBody, err := client.DownloadDashboardReportArtifact(ctx, sdk.DownloadDashboardReportArtifactRequest{Id: legacyArtifact.ID})
	if err != nil {
		p.t.Fatal(err)
	}
	proveClientReportNativeCSV(ctx, p.t, legacyBody, tables, tenant, foreign, incident, public)
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		if p.stdio[wire] == nil {
			p.stdio[wire] = map[string]*interfaceRoleStdioClient{}
		}
		stream := openInterfaceRoleStdio(p.t, p.server, p.authenticator, p.fixture.tokens[tenant], wire, 5*time.Minute)
		p.stdio[wire][tenant] = stream
		var generated mcp.ReportArtifact
		stream.call(p.t, wire, "report_generate", reporting.ReportGenerateInput{DashboardID: view, Format: "csv"}, &generated, true)
		body, err := client.DownloadDashboardReportArtifact(ctx, sdk.DownloadDashboardReportArtifactRequest{Id: generated.ID})
		if err != nil {
			p.t.Fatal(err)
		}
		proveClientReportNativeCSV(ctx, p.t, body, tables, tenant, foreign, incident, public)
	}

	encoded, err := json.Marshal(request)
	if err != nil {
		p.t.Fatal(err)
	}
	raw, code := p.invokeCLI(tenant, encoded, "dashboard-report", "generate", "--body-file", "-")
	if code != 0 {
		p.t.Fatal("CLI complete monthly generation failed", code)
	}
	var fromCLI reportArtifactView
	if err := json.Unmarshal(raw, &fromCLI); err != nil || fromCLI.ID == "" {
		p.t.Fatal("CLI monthly metadata is incomplete", err)
	}
	body, err = client.DownloadDashboardReportArtifact(ctx, sdk.DownloadDashboardReportArtifactRequest{Id: fromCLI.ID})
	if err != nil {
		p.t.Fatal(err)
	}
	proveClientReportNativeCSV(ctx, p.t, body, tables, tenant, foreign, incident, public)
	caller.call(p.fixture.tokens[tenant], "report_generate", map[string]any{"dashboard_id": view, "format": "csv", "tenant_id": foreign}, nil, false, "monthly native call accepted a tenant override")
}
func (p *clientReportNativeProof) crossTenant() {
	p.t.Helper()
	for i, tenant := range p.fixture.tenants {
		foreign := p.fixture.tenants[1-i]
		caller := reportMCPClient{t: p.t, socket: p.native, foreignTenant: foreign}
		caller.call(p.fixture.tokens[tenant], "report_artifact_link", map[string]any{"id": p.artifacts[foreign]}, nil, false, "monthly native artifact crossed tenants")
		for wire, streams := range p.stdio {
			streams[tenant].call(p.t, wire, "report_artifact_link", map[string]any{"id": p.artifacts[foreign]}, nil, false)
		}
		client := sdk.NewClient(p.rest.URL, sdk.WithHTTPClient(p.rest.Client()), sdk.WithToken(p.fixture.tokens[tenant]))
		if body, err := client.DownloadDashboardReportArtifact(p.t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: p.artifacts[foreign]}); err == nil || len(body) != 0 {
			p.t.Fatal("SDK downloaded foreign monthly artifact")
		}
		if body, code := p.invokeCLI(tenant, nil, "dashboard-report", "download", p.artifacts[foreign]); code == 0 || len(body) != 0 {
			p.t.Fatal("CLI downloaded foreign monthly artifact")
		}
	}
}

// Read all six native-generated CSV sections independently, then reconcile
// every canonical identity and exact numeric cell against complete source rows.
func proveClientReportNativeCSV(ctx context.Context, t *testing.T, body []byte, tables []reporting.CSVTable, tenant, foreign, incident, public string) {
	t.Helper()
	if bytes.Contains(body, []byte(foreign)) {
		t.Fatal("monthly native CSV exposed another tenant")
	}
	reader := csv.NewReader(bytes.NewReader(body))
	reader.FieldsPerRecord = -1
	rows, err := reader.ReadAll()
	if err != nil {
		t.Fatal("monthly native CSV is incomplete", err)
	}
	byID := map[string][][]string{}
	var id string
	for _, row := range rows {
		if len(row) == 2 && row[0] == "table_id" {
			id = row[1]
			if _, ok := byID[id]; ok {
				t.Fatal("monthly native CSV duplicated a section")
			}
			byID[id] = nil
		}
		if id != "" {
			byID[id] = append(byID[id], row)
		}
	}
	if len(byID) != 6 || len(tables) != 6 {
		t.Fatal("monthly native CSV lost a source section")
	}
	for _, table := range tables {
		section := byID[table.ID]
		header := make([]string, len(table.Columns))
		for i, column := range table.Columns {
			header[i] = reporting.CSVText(column.Name)
		}
		offset := -1
		for i, row := range section {
			if reflect.DeepEqual(row, header) {
				offset = i + 1
				break
			}
		}
		if offset < 0 || int64(len(section)-offset) != table.ExpectedRows {
			t.Fatal("monthly native CSV lost a schema or complete rows", table.ID)
		}
		n := 0
		if err := table.WalkRows(ctx, func(source []string) error {
			actual := section[offset+n]
			if len(actual) != len(source) {
				t.Fatal("monthly native CSV lost columns", table.ID)
			}
			for i, value := range source {
				column := table.Columns[i]
				identity := strings.HasSuffix(column.Name, "_id") && column.Name != "package_id" && column.Name != "evidence_package_id"
				if column.Numeric || identity || strings.HasSuffix(column.Name, "_numerator") || strings.HasSuffix(column.Name, "_denominator") {
					expected := value
					if !column.Numeric {
						expected = reporting.CSVText(value)
					}
					if actual[i] != expected {
						t.Fatal("monthly native CSV changed an exact source cell", table.ID, column.Name)
					}
				}
			}
			n++
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	section := byID["client-evidence"]
	record := section[len(section)-1]
	if len(record) != 9 {
		t.Fatal("monthly native CSV lost its signed evidence row")
	}
	raw, err := base64.StdEncoding.DecodeString(record[8])
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := evidence.Verify(raw)
	if err != nil || manifest.Incident.ID != incident || manifest.TenantScopeDigest != "sha256:"+hex.EncodeToString(crypto.Hash([]byte(tenant))) {
		t.Fatal("monthly native CSV failed offline evidence verification", err)
	}
	var signed evidence.Package
	if err := json.Unmarshal(raw, &signed); err != nil || signed.Signing.PublicKey != public || record[2] != manifest.PackageID || record[3] != hex.EncodeToString(crypto.Hash(raw)) {
		t.Fatal("monthly native CSV changed trusted evidence identity", err)
	}
}

func (p *clientReportNativeProof) withdrawnSource(tenant, sibling string) {
	p.t.Helper()
	caller := reportMCPClient{t: p.t, socket: p.native, foreignTenant: sibling}
	caller.call(p.fixture.tokens[tenant], "report_artifact_link", map[string]any{"id": p.artifacts[tenant]}, nil, false, "monthly native metadata retained a withdrawn source grant")
	for wire, streams := range p.stdio {
		streams[tenant].call(p.t, wire, "report_artifact_link", map[string]any{"id": p.artifacts[tenant]}, nil, false)
		var link mcp.ReportArtifactLink
		streams[sibling].call(p.t, wire, "report_artifact_link", map[string]any{"id": p.artifacts[sibling]}, &link, true)
	}
	client := sdk.NewClient(p.rest.URL, sdk.WithHTTPClient(p.rest.Client()), sdk.WithToken(p.fixture.tokens[tenant]))
	if body, err := client.DownloadDashboardReportArtifact(p.t.Context(), sdk.DownloadDashboardReportArtifactRequest{Id: p.artifacts[tenant]}); err == nil || len(body) != 0 {
		p.t.Fatal("SDK retained withdrawn monthly source access")
	}
	if body, code := p.invokeCLI(tenant, nil, "dashboard-report", "download", p.artifacts[tenant]); code == 0 || len(body) != 0 {
		p.t.Fatal("CLI retained withdrawn monthly source access")
	}
	other := reportMCPClient{t: p.t, socket: p.native, foreignTenant: tenant}
	var link mcp.ReportArtifactLink
	other.call(p.fixture.tokens[sibling], "report_artifact_link", map[string]any{"id": p.artifacts[sibling]}, &link, true, "monthly source withdrawal blocked sibling native access")
}
