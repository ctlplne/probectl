// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func proveReleaseReportSurfaces(t *testing.T, root string, cli func(...string) string, mcpBase, cert string, sessions []releaseSession, reports []releaseFlowReport, consent *releaseCoreReportConsent) {
	t.Helper()
	manifests := make([]json.RawMessage, len(reports))
	for i := range reports {
		p := &reports[i]
		manifests[i] = p.api.json(t, http.StatusOK, http.MethodGet, "/v1/dashboards/"+p.dashboard+"/manifest", nil, nil)
		var me struct {
			UserID string `json:"user_id"`
		}
		p.api.json(t, http.StatusOK, http.MethodGet, "/v1/me", nil, &me)
		output := cli("mcp-token", "--tenant", p.tenant, "--user", me.UserID, "--scope", "read,ai.query", "--expires-days", "1")
		lines := strings.Split(strings.TrimSpace(output), "\n")
		token := lines[len(lines)-1]
		if !p.mcpReportLink(t, mcpBase, token, reports[1-i].tenant, p.artifact) {
			t.Fatal("release reporting native tool bypassed explicit tenant consent")
		}
		consent.set(t, p, true)
		if p.mcpReportLink(t, mcpBase, token, reports[1-i].tenant, p.artifact) {
			t.Fatal("release reporting native tool refused its current owned artifact")
		}
		if !p.mcpReportLink(t, mcpBase, token, p.tenant, reports[1-i].artifact) {
			t.Fatal("release reporting native tool disclosed a foreign artifact")
		}
		if p.packet {
			p.provePacketImpactNative(t, mcpBase, token, &reports[1-i])
		}
	}
	for i := range reports {
		for _, theme := range []string{"light", "dark"} {
			if !t.Run(strconv.Itoa(i)+"/"+theme, func(t *testing.T) {
				reports[i].renderReport(t, root, cert, sessions[i].Cookie, theme, manifests[1-i], &reports[1-i])
			}) {
				t.FailNow()
			}
		}
	}
	t.Log("release image reporting surfaces: real Dex cookies, actual API/native services, TLS MCP consent/credential/foreign controls and pinned Chromium source selection, complete CSV generation and destination-bound native import in both tenant/theme lanes passed")
}

func (p *releaseFlowReport) mcpReportLink(t *testing.T, base, token, hint, id string) bool {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{
		"name": "report_artifact_link", "arguments": map[string]string{"id": id},
		"_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": map[string]any{}}}})
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json, text/event-stream",
		"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "report_artifact_link", "X-Probectl-Tenant": hint} {
		req.Header.Set(key, value)
	}
	response, err := p.api.client.Do(req)
	if err != nil {
		t.Fatal("release native report TLS request failed")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil || len(raw) > 2<<20 || response.StatusCode != http.StatusOK {
		t.Fatal("release native report bounded transport failed", response.StatusCode)
	}
	var result struct {
		Error  json.RawMessage `json:"error"`
		Result struct {
			IsError bool `json:"isError"`
			Link    struct {
				AuthenticationRequired bool `json:"authentication_required"`
				Artifact               struct {
					ID    string `json:"id"`
					Bytes int64  `json:"body_bytes"`
					Hash  string `json:"body_sha256"`
					URL   string `json:"download_url"`
				} `json:"artifact"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Error) != 0 && string(result.Error) != "null" {
		t.Fatal("release native report protocol failed")
	}
	if result.Result.IsError {
		if bytes.Contains(raw, []byte(id)) || bytes.Contains(raw, []byte("body_sha256")) || bytes.Contains(raw, []byte("download_url")) {
			t.Fatal("refused release native report exposed artifact metadata")
		}
		return true
	}
	link := result.Result.Link
	digest, decode := hex.DecodeString(link.Artifact.Hash)
	if !link.AuthenticationRequired || link.Artifact.ID != p.artifact || link.Artifact.ID != id ||
		link.Artifact.Bytes != int64(len(p.body)) || decode != nil || len(digest) != 32 ||
		link.Artifact.URL != "/v1/dashboard-report-artifacts/"+id {
		t.Fatal("release native link changed current artifact identity, metadata or authentication requirement")
	}
	return false
}

func (p *releaseFlowReport) renderReport(t *testing.T, root, cert, cookie, theme string, manifest json.RawMessage, foreign *releaseFlowReport) {
	t.Helper()
	card := "#saved-dashboard"
	name := "Release browser " + p.tenant + " " + theme + " " + p.sourceName
	step := func(click string, expect ...string) map[string]any {
		return map[string]any{"click": click, "within": card, "expect": expect}
	}
	steps := []map[string]any{}
	if theme == "dark" {
		steps = append(steps, map[string]any{"click": "Switch theme (current: light)"})
	}
	steps = append(steps,
		map[string]any{"click": "Build from saved flow queries", "role": "checkbox"},
		map[string]any{"click": "Open " + p.sourceName, "within": card + " [aria-label='Report saved flow sources']", "expect": []string{p.sourceName + " · version " + p.version}},
		map[string]any{"fill": card + " input[maxlength='120']", "value": name},
		step("Save dashboard", "Dashboard saved", name),
		map[string]any{"select": card + " label:text-is('Format') + div select", "value": "csv"},
		step("Generate CSV", "CSV generated"),
		map[string]any{"fill": card + " textarea", "value": string(manifest)},
		map[string]any{"click": "Open " + p.sourceName, "within": card + " [aria-label='Destination report source bindings']", "expect": []string{"flow-1: " + p.sourceName + " · version " + p.version}},
		step("Preview import", "Manifest validated", "1 explicitly bound saved flow sources"),
		step("Confirm import", "Dashboard imported"),
	)
	absent := []string{foreign.address, foreign.sourceName}
	if p.packet {
		absent = append(absent, foreign.packetValue)
	}
	spec := map[string]any{"url": p.api.base + "/ui/dashboards", "cookies": []map[string]string{{"name": "probectl_session", "value": cookie}},
		"trustCertFiles": []string{cert}, "timeoutMs": 60000, "expect": []string{"Saved views and report delivery", p.tenant},
		"absent": absent, "steps": steps,
		"controls": []map[string]string{{"role": "button", "name": "Switch theme (current: " + theme + ")"}}}
	raw, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "node", filepath.Join(root, "scripts", "realstack_render.mjs"))
	command.Dir = root
	command.Stdin = bytes.NewReader(raw)
	output, err := command.Output()
	if err != nil {
		t.Fatal("release-source Chromium process failed; no fixture/browser skip is allowed")
	}
	var rendered struct{ Missing, Present []string }
	if json.Unmarshal(output, &rendered) != nil || len(rendered.Missing) != 0 || len(rendered.Present) != 0 {
		t.Fatal("actual release-source Chromium did not satisfy required owned/foreign controls", rendered.Missing, rendered.Present)
	}
	var views struct {
		Items []struct {
			ID, Name   string
			TenantID   string `json:"tenant_id"`
			Definition struct {
				Sources []struct{ ID, Version string } `json:"flow_sources"`
			} `json:"definition"`
		} `json:"items"`
	}
	p.api.json(t, http.StatusOK, http.MethodGet, "/v1/dashboards", nil, &views)
	var saved string
	imported := false
	var foreignRecipe struct {
		Metadata struct{ Name string } `json:"metadata"`
	}
	if json.Unmarshal(manifest, &foreignRecipe) != nil {
		t.Fatal("release native manifest invalid")
	}
	for _, view := range views.Items {
		if view.Name != name && view.Name != foreignRecipe.Metadata.Name {
			continue
		}
		if view.TenantID != p.tenant || len(view.Definition.Sources) != 1 || view.Definition.Sources[0].ID != p.source || view.Definition.Sources[0].Version != p.version {
			t.Fatal("release browser saved/imported a changed or foreign source binding")
		}
		if view.Name == name {
			saved = view.ID
		}
		if view.Name == foreignRecipe.Metadata.Name {
			imported = true
		}
	}
	if saved == "" || !imported {
		t.Fatal("release browser did not save and explicitly import its source recipe")
	}
	var artifacts struct {
		Items []struct {
			ID          string
			DashboardID string `json:"dashboard_id"`
		} `json:"items"`
	}
	p.api.json(t, http.StatusOK, http.MethodGet, "/v1/dashboard-report-artifacts", nil, &artifacts)
	found := false
	for _, item := range artifacts.Items {
		if item.DashboardID != saved {
			continue
		}
		found = true
		code, body := p.api.do(t, http.MethodGet, "/v1/dashboard-report-artifacts/"+item.ID, nil)
		if code != http.StatusOK {
			t.Fatal("release browser generated artifact is not readable", code)
		}
		p.verify(t, body)
	}
	if !found {
		t.Fatal("release browser did not publish complete selected source output")
	}
}
