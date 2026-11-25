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
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// The local Ollama protocol and observations are modeled. HTTPS, credentials,
// current application-role source reads, signing and scope checks are real.
func TestIncidentDraftRechecksCredentialAndIsolatesTenantEvidence(t *testing.T) {
	fixture := seedCarrierExportFixture(t)
	f := fixture.path.fixture
	left, right := f.tenants[0], f.tenants[1]
	labels := map[string]string{left: "left probe timed out", right: "right probe recovered"}
	general := map[string]string{}
	correlator := BuildCorrelator(f.pool, time.Minute, f.server.log)
	for _, tenant := range f.tenants {
		inc, err := correlator.Ingest(t.Context(), incident.Signal{TenantID: tenant, Plane: "network", Kind: "draft-fixture",
			Title: labels[tenant], Target: "192.0.2.7", Severity: incident.SeverityWarning, OccurredAt: time.Now().UTC().Add(-time.Second)})
		if err != nil {
			t.Fatal(err)
		}
		general[tenant] = inc.ID
	}
	var calls atomic.Int64
	var withdraw, unsupported atomic.Bool
	local := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if r.URL.Path != "/api/chat" || json.NewDecoder(r.Body).Decode(&request) != nil || len(request.Messages) != 2 || request.Messages[1].Role != "user" {
			t.Error("local model did not receive the draft selection contract")
			http.Error(w, "bad model request", http.StatusBadRequest)
			return
		}
		var choices []evidence.DraftChoice
		if err := json.Unmarshal([]byte(request.Messages[1].Content), &choices); err != nil || len(choices) == 0 {
			t.Error("no eligible signed facts were given to the local model", err)
			http.Error(w, "bad draft facts", http.StatusBadRequest)
			return
		}
		calls.Add(1)
		ids := make([]int, len(choices))
		for i, choice := range choices {
			ids[i] = choice.ID
		}
		if unsupported.Swap(false) {
			ids[0] = len(choices) + 1
		}
		if withdraw.Swap(false) {
			if err := store.NewMCPTokens(f.pool).RevokeForUser(r.Context(), left, f.users[left]); err != nil {
				t.Errorf("withdraw originating credential during completion: %v", err)
			}
		}
		body, _ := json.Marshal(map[string]any{"ids": ids})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"message": map[string]string{"role": "assistant", "content": string(body)}, "done": true, "done_reason": "stop"})
	}))
	t.Cleanup(local.Close)
	anchor := filepath.Join(t.TempDir(), "local-fixture.pem")
	if err := os.WriteFile(anchor, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: local.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	f.server.cfg.AIModelProvider = "ollama"
	f.server.cfg.AIModelName = "draft-fixture"
	f.server.cfg.AIModelEndpoint = local.URL
	f.server.cfg.AIModelCAFile = anchor
	f.server.cfg.AIModelTimeout = 10 * time.Second

	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	apiCA := filepath.Join(t.TempDir(), "draft-api-ca.pem")
	if err := os.WriteFile(apiCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: socket.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	read := func(tenant, id string, input incidentDraftRequest) (int, []byte) {
		t.Helper()
		body, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/incidents/"+id+"/drafts", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		request.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode == http.StatusOK && response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("signed draft response must not be cached")
		}
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, raw
	}
	check := func(tenant, id, want string, input incidentDraftRequest) {
		t.Helper()
		status, raw := read(tenant, id, input)
		var result incidentDraftResponse
		if status != http.StatusOK || json.Unmarshal(raw, &result) != nil {
			t.Fatalf("local draft unavailable with status %d: %s", status, raw)
		}
		assertDraftFixtureResult(t, result, tenant, id, fixture.signer, want)
		for _, viewer := range f.tenants {
			f.in(viewer, func(ctx context.Context, sc tenancy.Scope) error {
				var count, invalidMetadata int
				err := sc.Q.QueryRow(ctx, `SELECT count(*), count(*) FILTER (
					WHERE data->>'incident_id' IS DISTINCT FROM $3
					OR data ?| ARRAY['evidence_package', 'sections', 'prompt'])
					FROM audit_events WHERE action = $1 AND target = $2`,
					incidentDraftAuditAction, result.PackageID, id).Scan(&count, &invalidMetadata)
				if err != nil {
					return err
				}
				expected := 0
				if viewer == tenant {
					expected = 1
				}
				if count != expected {
					t.Fatalf("draft audit visibility mismatch: got %d, want %d", count, expected)
				}
				if invalidMetadata != 0 {
					t.Fatal("draft audit metadata is missing the incident or includes private draft content")
				}
				return nil
			})
		}
	}
	review := incidentDraftRequest{Kind: evidence.DraftReview}
	for i, tenant := range f.tenants {
		check(tenant, general[tenant], labels[tenant], review)
		window := fixture.windows[tenant]
		check(tenant, fixture.ids[tenant], []string{"3 packets sent and received 1 in reply", "3 packets sent and received 2 in reply"}[i],
			incidentDraftRequest{Kind: evidence.DraftCarrier, incidentEvidenceExportInput: incidentEvidenceExportInput{Carrier: &window}})
	}
	before := calls.Load()
	foreignStatus, foreign := read(right, general[left], review)
	missingStatus, _ := read(right, "00000000-0000-4000-8000-000000000025", review)
	if foreignStatus != http.StatusNotFound || missingStatus != foreignStatus || calls.Load() != before || bytes.Contains(foreign, []byte(general[left])) {
		t.Fatal("foreign incident reached the draft model or disclosed incident identity", foreignStatus, missingStatus)
	}
	seedInterfaceRoleMCPConsent(f)
	native := interfaceRoleNativeTLSCaller(t, f, "2026-07-28")
	for lane, tenant := range f.tenants {
		other := f.tenants[1-lane]
		args := map[string]any{"incident_id": general[tenant], "kind": evidence.DraftReview}
		var result incidentDraftResponse
		native(tenant, "incident_draft", args, &result, true)
		assertDraftFixtureResult(t, result, tenant, general[tenant], fixture.signer, labels[tenant])
		// The native fixture enables the IP mask even though the REST fixture's
		// deployment config leaves it off. The transport policy must apply before
		// serialization makes the signed package opaque to text redaction.
		if bytes.Contains(result.EvidencePackage, []byte("192.0.2.7")) {
			t.Fatal("native signed bytes escaped the active transport's IP mask")
		}
		args["incident_id"] = general[other]
		native(tenant, "incident_draft", args, nil, false)
		assertDraftCLIAndSDK(t, f, socket, apiCA, tenant, general[tenant], general[other], fixture.signer, labels[tenant])
	}
	t.Run("served", func(t *testing.T) {
		assertDraftBrowser(t, f, socket.URL, apiCA, general, labels, fixture.signer)
	})
	unsupported.Store(true)
	if status, body := read(left, general[left], review); status != http.StatusUnprocessableEntity || bytes.Contains(body, []byte("evidence_package")) {
		t.Fatal("unsupported claim reached the draft response", status)
	}
	withdraw.Store(true)
	if status, body := read(left, general[left], review); status != http.StatusUnauthorized || bytes.Contains(body, []byte("evidence_package")) {
		t.Fatal("withdrawn credential received draft evidence", status)
	}
	if withdraw.Load() {
		t.Fatal("authorizing credential was never withdrawn during local model processing")
	}
	check(right, general[right], labels[right], incidentDraftRequest{Kind: evidence.DraftExecutive})
}

func assertDraftFixtureResult(t *testing.T, result incidentDraftResponse, tenant, id, signer, want string) {
	t.Helper()
	if result.Model != "ollama:draft-fixture" || result.Degraded {
		t.Fatal("draft did not execute the configured local model", result.Model, result.Degraded)
	}
	source, err := evidence.OpenDraftSource(result.EvidencePackage, tenant, id, signer)
	if err != nil || source.PackageID() != result.PackageID {
		t.Fatalf("draft source did not match the signed result: %v", err)
	}
	if bytes.Contains(result.EvidencePackage, []byte(tenant)) || bytes.Contains(result.EvidencePackage, []byte("carrier-fixture-only")) {
		t.Fatal("signed draft source disclosed private tenant or customer values")
	}
	found := false
	for _, section := range result.Sections {
		for _, sentence := range section.Sentences {
			found = found || strings.Contains(sentence.Text, want)
			if len(sentence.Citations) == 0 {
				t.Fatalf("sentence has no evidence: %q", sentence.Text)
			}
			for _, citation := range sentence.Citations {
				if _, ok := source.Resolve(citation); !ok {
					t.Fatalf("citation did not resolve in the signed source: %+v", citation)
				}
			}
		}
	}
	if !found {
		t.Fatalf("draft omitted fixture value %q", want)
	}
}

func assertDraftCLIAndSDK(t *testing.T, f *roleExplanationAPIFixture, socket *httptest.Server, ca, tenant, id, foreign, signer, want string) {
	t.Helper()
	env := func(key string) string {
		return map[string]string{"PROBECTL_API_URL": socket.URL, "PROBECTL_API_TOKEN": f.tokens[tenant], "PROBECTL_CA_FILE": ca}[key]
	}
	run := func(id string) ([]byte, int) {
		var stdout, stderr bytes.Buffer
		code := cli.RunWithStdin([]string{"--json", "incident", "draft", id, "--body-file", "-"}, env, strings.NewReader(`{"kind":"postmortem"}`), &stdout, &stderr)
		if code != 0 && len(stderr.Bytes()) == 0 {
			t.Fatal("CLI refused without an error")
		}
		return stdout.Bytes(), code
	}
	var result incidentDraftResponse
	if raw, code := run(id); code != 0 || json.Unmarshal(raw, &result) != nil {
		t.Fatal("CLI could not read the current tenant draft", code)
	}
	assertDraftFixtureResult(t, result, tenant, id, signer, want)
	if raw, code := run(foreign); code == 0 || bytes.Contains(raw, []byte("evidence_package")) {
		t.Fatal("CLI published a foreign draft", code)
	}
	client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
	response, err := client.GenerateIncidentDraft(t.Context(), sdk.GenerateIncidentDraftRequest{Id: id, Body: &sdk.IncidentDraftRequest{Kind: "postmortem"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(response)
	if err != nil || json.Unmarshal(raw, &result) != nil {
		t.Fatal("generated SDK changed the draft result shape", err)
	}
	assertDraftFixtureResult(t, result, tenant, id, signer, want)
}

func assertDraftBrowser(t *testing.T, f *roleExplanationAPIFixture, base, ca string, incidents, labels map[string]string, signer string) {
	t.Helper()
	for lane, tenant := range f.tenants {
		foreign := f.tenants[1-lane]
		var grants []auth.PermissionGrant
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			grants, err = (store.Permissions{}).ForSubject(ctx, sc, "user", f.users[tenant])
			return err
		})
		cookie, err := f.server.sessions.Issue(t.Context(), auth.Session{TenantID: tenant, UserID: f.users[tenant], Email: "draft@local.invalid", DisplayName: "Incident operator", AuthorizationHash: auth.PermissionGrantFingerprint(grants)})
		if err != nil {
			t.Fatal(err)
		}
		for _, theme := range []string{"light", "dark"} {
			t.Run(theme+"/"+labels[tenant], func(t *testing.T) {
				download := filepath.Join(t.TempDir(), "signed-draft-source.json")
				testsupport.RenderUI(t, testsupport.RenderSpec{
					URL:            base + "/ui/incidents?incident=" + url.QueryEscape(incidents[tenant]),
					Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: cookie}},
					TrustCertFiles: []string{ca}, CAFile: ca, Theme: theme, Accessibility: true,
					Expect: []string{"Incident drafts", labels[tenant]}, Absent: []string{labels[foreign], incidents[foreign]},
					Steps: []testsupport.RenderStep{
						{Click: "Generate draft", Expect: []string{"Draft ready.", "Download signed source"}},
						{Click: "View cited evidence", Summary: true, Within: `section:has(> h3:text-is("Timeline"))`, Expect: []string{"/title"}},
						{Click: "Download signed source", Download: download},
					},
				})
				raw, err := os.ReadFile(download)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := evidence.OpenDraftSource(raw, tenant, incidents[tenant], signer); err != nil || bytes.Contains(raw, []byte(labels[foreign])) {
					t.Fatalf("browser download selected a different source: %v", err)
				}
			})
		}
	}
}
