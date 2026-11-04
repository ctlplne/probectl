// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type nativeReportLane struct {
	lane      *nativeLane
	source    flow.SavedQueryView
	dashboard mcp.ReportDashboard
	manifest  reporting.DashboardManifest
	artifact  mcp.ReportArtifact
	body      []byte
	token     string
}

// This extends the existing real-service receipt, including its explicitly
// disclosed development bus/TSDB transport and protocol-fixture provenance.
// It is not the separate TLS/SASL exact release-image acceptance.
func proveNativeSourceReports(t *testing.T, st *shipped.Stack, addr string, lanes []*nativeLane) {
	t.Helper()
	binary := st.Binary(t, "probectl")
	proofs := make([]nativeReportLane, len(lanes))
	for i, lane := range lanes {
		p := &proofs[i]
		// Keep the original Explorer reader token unchanged. This separate
		// report writer credential authorizes only the new CLI generation leg.
		reportLane := *lane
		reportLane.apiToken = st.APIToken(t, lane.cookie, "read", "ai.query", "metrics.write")
		p.lane = &reportLane
		lane.do(t, st, http.MethodGet, "/v1/explorer/flow-views/"+lane.view, nil, &p.source, http.StatusOK)
		input := reporting.DashboardCreateInput{Name: "Wire source report " + lane.name, Preset: "operator",
			Definition: reporting.DashboardDefinition{FlowSources: []reporting.FlowSourceRef{{ID: p.source.ID, Version: p.source.Version}},
				Provenance:     []string{"Shipped collector; generated protocol datagrams; development CI service transports"},
				RedactionState: "tenant-scoped", CoverageLimitations: []string{"No hardware-exporter or production-transport claim"}}}
		lane.do(t, st, http.MethodPost, "/v1/dashboards", input, &p.dashboard, http.StatusCreated)
		if p.dashboard.TenantID != lane.id || len(p.dashboard.Definition.FlowSources) != 1 {
			t.Fatal("native report lost current tenant or selected source")
		}
		lane.do(t, st, http.MethodPost, "/v1/dashboard-reports",
			reporting.ReportGenerateInput{DashboardID: p.dashboard.ID, Format: "csv"}, &p.artifact, http.StatusCreated)
		p.body = p.download(t, st, lane, p.artifact, http.StatusOK)
		p.verifyCSV(t, p.body)
		cliBody, code := nativeReportCLI(t, st, binary, p.lane, "dashboard-report", "download", p.artifact.ID)
		if code != 0 || !bytes.Equal(cliBody, p.body) {
			t.Fatal("built CLI differs from complete authenticated source CSV")
		}
		generate := st.SecretFile(t, reporting.ReportGenerateInput{DashboardID: p.dashboard.ID, Format: "pdf"})
		raw, code := nativeReportCLI(t, st, binary, p.lane, "dashboard-report", "generate", "--body-file", generate)
		var pdf mcp.ReportArtifact
		if code != 0 || json.Unmarshal(raw, &pdf) != nil || pdf.Format != "pdf" {
			t.Fatal("built CLI failed to generate a source PDF")
		}
		pdfBody := p.download(t, st, lane, pdf, http.StatusOK)
		if !bytes.HasPrefix(pdfBody, []byte("%PDF-")) {
			t.Fatal("native source PDF has no PDF document")
		}
		lane.do(t, st, http.MethodGet, "/v1/dashboards/"+p.dashboard.ID+"/manifest", nil, &p.manifest, http.StatusOK)
		manifest, err := json.Marshal(p.manifest)
		if err != nil {
			t.Fatal(err)
		}
		for _, identity := range []string{lane.id, p.source.ID, p.dashboard.OwnerID, p.dashboard.ID} {
			if bytes.Contains(manifest, []byte(identity)) {
				t.Fatal("native portable recipe retained local identity")
			}
		}
		var me struct {
			UserID string `json:"user_id"`
		}
		lane.do(t, st, http.MethodGet, "/v1/me", nil, &me, http.StatusOK)
		issued := strings.Split(strings.TrimSpace(st.Subcommand(t, "mcp-token", "--tenant", lane.id, "--user", me.UserID,
			"--scope", "read,ai.query", "--expires-days", "1")), "\n")
		p.token = issued[len(issued)-1]
	}
	for i := range proofs {
		p, other := &proofs[i], &proofs[1-i]
		p.download(t, st, other.lane, p.artifact, http.StatusNotFound)
		var link mcp.ReportArtifactLink
		if p.mcpLink(t, st, addr, other.lane.id, p.artifact.ID, &link) || !link.AuthenticationRequired ||
			link.Artifact.ID != p.artifact.ID || link.Artifact.BodySHA256 != hex.EncodeToString(crypto.Hash(p.body)) ||
			link.Artifact.BodyBytes != int64(len(p.body)) {
			t.Fatal("native report MCP lost current authority or expected body metadata")
		}
		if !p.mcpLink(t, st, addr, other.lane.id, other.artifact.ID, &link) {
			t.Fatal("foreign source report link escaped current MCP credential")
		}
		for _, theme := range []string{"light", "dark"} {
			p.render(t, st, other, theme)
		}
		// New UI work must not mutate earlier artifact bytes.
		if !bytes.Equal(p.body, p.download(t, st, p.lane, p.artifact, http.StatusOK)) {
			t.Fatal("later native/UI reports changed a frozen artifact")
		}
	}
	for i := range proofs {
		p := &proofs[i]
		p.lane.do(t, st, http.MethodDelete, "/v1/explorer/flow-views/"+p.source.ID+"?version="+p.source.Version, nil, nil, http.StatusNoContent)
		p.download(t, st, p.lane, p.artifact, http.StatusNotFound)
		if output, code := nativeReportCLI(t, st, binary, p.lane, "dashboard-report", "download", p.artifact.ID); code == 0 || bytes.Contains(output, p.body) {
			t.Fatal("built CLI retained a report grant after source removal")
		}
		var link mcp.ReportArtifactLink
		if !p.mcpLink(t, st, addr, p.lane.id, p.artifact.ID, &link) {
			t.Fatal("native MCP retained a report grant after source removal")
		}
	}
	t.Log("native source report services: paired collector-derived CSV/PDF, built CLI, current TLS MCP links, actual source-selection/binding Chromium both themes, frozen bytes and source removal passed; protocol fixtures and development service transports remain disclosed")
}

func nativeReportCLI(t *testing.T, st *shipped.Stack, binary string, lane *nativeLane, args ...string) ([]byte, int) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), binary, append([]string{"--json"}, args...)...)
	cmd.Env = append(os.Environ(), "PROBECTL_API_URL="+st.BaseURL, "PROBECTL_CA_FILE="+st.CAFile, "PROBECTL_API_TOKEN="+lane.apiToken)
	var output bytes.Buffer
	cmd.Stdout = &output
	// Error output can carry source data; keep it private, never print credentials.
	err := cmd.Run()
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal("built report CLI could not execute")
		}
		return output.Bytes(), exit.ExitCode()
	}
	return output.Bytes(), 0
}

func (p *nativeReportLane) download(t *testing.T, st *shipped.Stack, actor *nativeLane, artifact mcp.ReportArtifact, want int) []byte {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, st.BaseURL+"/v1/dashboard-report-artifacts/"+artifact.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+actor.apiToken)
	req.Header.Set("X-Probectl-Tenant", p.lane.id) // never overrides actor credential
	response, err := st.Client().Do(req)
	if err != nil {
		t.Fatal("native report TLS download failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(body) > 4<<20 || response.StatusCode != want {
		t.Fatal("native report download status or bounded body mismatch", response.StatusCode, want)
	}
	if want == http.StatusOK {
		if response.Header.Get("X-Report-SHA256") != hex.EncodeToString(crypto.Hash(body)) ||
			response.Header.Get("Content-Length") != strconv.Itoa(len(body)) || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("native report download lost complete integrity/length/private-cache headers")
		}
	} else if response.Header.Get("X-Report-SHA256") != "" || bytes.Contains(body, []byte("table_tenant_scope")) {
		t.Fatal("refused native report exposed body bytes or body metadata")
	}
	return body
}

func (p *nativeReportLane) verifyCSV(t *testing.T, body []byte) {
	t.Helper()
	reader := csv.NewReader(bytes.NewReader(body))
	reader.FieldsPerRecord = -1
	detail := false
	address, quantity := -1, -1
	seen := map[string]string{}
	totals := 0
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("native source report CSV is incomplete")
		}
		if len(row) == 0 {
			continue
		}
		if row[0] == "table_tenant_scope" && (len(row) != 2 || row[1] != p.lane.id) {
			t.Fatal("native report CSV crossed tenant")
		}
		if row[0] == "table_id" {
			if len(row) != 2 || !strings.HasPrefix(row[1], p.source.ID+"/") {
				t.Fatal("native report CSV changed selected source")
			}
			detail = strings.HasSuffix(row[1], "/detail")
		}
		if !detail {
			continue
		}
		if row[0] == "record_type" {
			for i, key := range row {
				if key == "src_addr" {
					address = i
				}
				if key == "bytes:total" {
					quantity = i
				}
			}
			continue
		}
		if row[0] != "detail" && row[0] != "totals" {
			continue
		}
		if address < 0 || quantity < 0 || address >= len(row) || quantity >= len(row) {
			t.Fatal("native report detail schema missing")
		}
		if row[0] == "totals" {
			if row[quantity] != strconv.FormatUint(uint64(p.lane.bytes)+10800, 10) {
				t.Fatal("native report lost exact wire total")
			}
			totals++
			continue
		}
		ip := row[address]
		if _, exists := seen[ip]; exists {
			t.Fatal("native report duplicated a source detail")
		}
		seen[ip] = row[quantity]
	}
	wantBytes := []uint64{uint64(p.lane.bytes), 2000, 3000, 5800}
	for n := 1; n <= 4; n++ {
		if seen[fmt.Sprintf("10.%d.%d.1", p.lane.octet, n)] != strconv.FormatUint(wantBytes[n-1], 10) {
			t.Fatal("native report omitted or changed an actual collector detail quantity")
		}
	}
	if len(seen) != 4 || totals != 1 {
		t.Fatal("native source report changed complete selected detail cardinality")
	}
}

func (p *nativeReportLane) mcpLink(t *testing.T, st *shipped.Stack, addr, hint, id string, out *mcp.ReportArtifactLink) bool {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{
		"name": "report_artifact_link", "arguments": map[string]string{"id": id},
		"_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": map[string]any{}}}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+addr+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"Authorization": "Bearer " + p.token, "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
		"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "report_artifact_link", "X-Probectl-Tenant": hint} {
		req.Header.Set(key, value)
	}
	response, err := st.Client().Do(req)
	if err != nil {
		t.Fatal("native report MCP TLS request failed")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 || response.StatusCode != http.StatusOK {
		t.Fatal("native report MCP transport or output bound failed")
	}
	var result struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError    bool            `json:"isError"`
			Structured json.RawMessage `json:"structuredContent"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Error) != 0 {
		t.Fatal("native report MCP protocol failed")
	}
	if result.Result.IsError && (bytes.Contains(raw, []byte(id)) || bytes.Contains(raw, []byte("body_sha256")) || bytes.Contains(raw, []byte("download_url"))) {
		t.Fatal("refused native MCP report exposed artifact metadata")
	}
	if !result.Result.IsError && json.Unmarshal(result.Result.Structured, out) != nil {
		t.Fatal("native report MCP output invalid")
	}
	return result.Result.IsError
}

func (p *nativeReportLane) render(t *testing.T, st *shipped.Stack, foreign *nativeReportLane, theme string) {
	t.Helper()
	t.Run(p.lane.name+"/"+theme, func(t *testing.T) {
		card := "#saved-dashboard"
		name := "Browser " + p.lane.name + " " + theme
		manifest, err := json.Marshal(foreign.manifest)
		if err != nil {
			t.Fatal(err)
		}
		spec := testsupport.RenderSpec{URL: st.BaseURL + "/ui/dashboards", Cookies: []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: p.lane.cookie}},
			TrustCertFiles: st.TrustCerts(), CAFile: st.CAFile, TimeoutMs: 60000,
			Expect:   []string{"Saved views and report delivery", "Native " + p.lane.name},
			Absent:   []string{"Native golden " + foreign.lane.name, foreign.dashboard.Name},
			Controls: []testsupport.RenderControl{{Role: "button", Name: "Switch theme (current: " + theme + ")"}}}
		if theme == "dark" {
			spec.Steps = append(spec.Steps, testsupport.RenderStep{Click: "Switch theme (current: light)"})
		}
		spec.Steps = append(spec.Steps,
			testsupport.RenderStep{Click: "Build from saved flow queries", Role: "checkbox"},
			testsupport.RenderStep{Click: "Open " + p.source.Definition.Name, Within: card + " [aria-label='Report saved flow sources']", Expect: []string{p.source.Definition.Name + " · version " + p.source.Version}},
			testsupport.RenderStep{Fill: card + " input[maxlength='120']", Value: name},
			testsupport.RenderStep{Click: "Save dashboard", Within: card, Expect: []string{"Dashboard saved", name}},
			testsupport.RenderStep{Select: card + " label:text-is('Format') + div select", Value: "csv"},
			testsupport.RenderStep{Click: "Generate CSV", Within: card, Expect: []string{"CSV generated"}},
			testsupport.RenderStep{Fill: card + " textarea", Value: string(manifest)},
			testsupport.RenderStep{Click: "Open " + p.source.Definition.Name, Within: card + " [aria-label='Destination report source bindings']", Expect: []string{"flow-1: " + p.source.Definition.Name + " · version " + p.source.Version}},
			testsupport.RenderStep{Click: "Preview import", Within: card, Expect: []string{"Manifest validated", "1 explicitly bound saved flow sources"}},
			testsupport.RenderStep{Click: "Confirm import", Within: card, Expect: []string{"Dashboard imported"}},
		)
		// The imported recipe deliberately uses a foreign display name; only
		// its explicit destination source binding determines telemetry.
		spec.Absent = []string{"Native golden " + foreign.lane.name}
		testsupport.RenderUI(t, spec)
		var views mcp.ReportDashboardList
		p.lane.do(t, st, http.MethodGet, "/v1/dashboards", nil, &views, http.StatusOK)
		var dashboardID string
		for _, view := range views.Items {
			if view.Name == name {
				dashboardID = view.ID
				if len(view.Definition.FlowSources) != 1 || view.Definition.FlowSources[0].ID != p.source.ID || view.Definition.FlowSources[0].Version != p.source.Version {
					t.Fatal("actual browser saved a changed source")
				}
			}
		}
		if dashboardID == "" {
			t.Fatal("actual browser did not save source dashboard")
		}
		var artifacts mcp.ReportArtifactList
		p.lane.do(t, st, http.MethodGet, "/v1/dashboard-report-artifacts", nil, &artifacts, http.StatusOK)
		found := false
		for _, artifact := range artifacts.Items {
			if artifact.DashboardID == dashboardID {
				found = true
				p.verifyCSV(t, p.download(t, st, p.lane, artifact, http.StatusOK))
			}
		}
		if !found {
			t.Fatal("actual browser did not generate complete source CSV")
		}
		var imported bool
		for _, view := range views.Items {
			if view.Name == foreign.dashboard.Name {
				imported = true
				if view.TenantID != p.lane.id || len(view.Definition.FlowSources) != 1 || view.Definition.FlowSources[0].ID != p.source.ID || view.Definition.FlowSources[0].Version != p.source.Version {
					t.Fatal("actual browser imported a foreign source binding")
				}
			}
		}
		if !imported {
			t.Fatal("actual browser did not confirm the native template")
		}
	})
}
