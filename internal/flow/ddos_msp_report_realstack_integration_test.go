// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flow_test

import (
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type shippedDDoSArtifact struct {
	ID         string `json:"id"`
	ScheduleID string `json:"schedule_id"`
	BodySHA256 string `json:"body_sha256"`
}

func assertShippedDDoSProviderReport(t *testing.T, stack *shipped.Stack, owner, sibling *nativeLane, operator string, observation remediation.PrefixImpactInput) {
	t.Helper()
	var receipt alert.DDoSEvaluationEvidence
	owner.do(t, stack, http.MethodGet, "/v1/alerts/rules/"+observation.RuleID+"/ddos-receipt?fingerprint="+observation.ReceiptFingerprint, nil, &receipt, http.StatusOK)
	selection := reporting.DDoSReportDefinition{IncidentID: receipt.IncidentID, RuleID: observation.RuleID, ReceiptFingerprint: observation.ReceiptFingerprint}
	name := "Observed tenant DDoS response"
	viewInput := reporting.DashboardCreateInput{Name: name, Preset: "operator", Definition: reporting.DashboardDefinition{
		DDoSReport: &selection, Provenance: []string{"Original protected traffic receipt"}, RedactionState: "Tenant source data",
		CoverageLimitations: []string{"Only retained observed traffic windows"},
	}}
	var view struct{ ID string }
	owner.do(t, stack, http.MethodPost, "/v1/dashboards", viewInput, &view, http.StatusCreated)
	sibling.do(t, stack, http.MethodPost, "/v1/dashboards", viewInput, nil, http.StatusNotFound)
	var manual shippedDDoSArtifact
	owner.do(t, stack, http.MethodPost, "/v1/dashboard-reports", map[string]string{"dashboard_id": view.ID, "format": "csv"}, &manual, http.StatusCreated)
	assertDDoSPackArtifact(t, stack, owner, sibling, operator, manual, "ddos-decisions", "diversion_preview_start", "diversion_preview_stop")

	const schedules = "/v1/dashboard-report-schedules"
	var schedule struct{ ID string }
	owner.do(t, stack, http.MethodPost, schedules, map[string]any{
		"dashboard_id": view.ID, "name": name, "format": "csv", "cadence": "daily", "destination_id": "tenant-report-inbox",
		"first_run_at": time.Now().UTC().Add(8 * time.Hour).Format(time.RFC3339Nano),
	}, &schedule, http.StatusCreated)
	ref := schedules + "/" + schedule.ID
	sibling.do(t, stack, http.MethodPatch, ref, map[string]bool{"provider_trigger_allowed": true}, nil, http.StatusNotFound)
	before := ddosProviderQueue(t, stack, operator, owner.id, newDDoSReportRequest(t))
	if before.Eligible != 0 || before.Queued != 0 {
		t.Fatalf("provider advanced a schedule before opt-in: %+v", before)
	}
	owner.do(t, stack, http.MethodPatch, ref, map[string]bool{"provider_trigger_allowed": true}, nil, http.StatusOK)
	owner.do(t, stack, http.MethodPatch, ref, map[string]bool{"provider_trigger_allowed": false}, nil, http.StatusOK)
	if revoked := ddosProviderQueue(t, stack, operator, owner.id, newDDoSReportRequest(t)); revoked.Eligible != 0 || revoked.Queued != 0 {
		t.Fatalf("provider queued revoked consent: %+v", revoked)
	}
	owner.do(t, stack, http.MethodPatch, ref, map[string]bool{"provider_trigger_allowed": true}, nil, http.StatusOK)
	request := newDDoSReportRequest(t)
	queued := ddosProviderQueue(t, stack, operator, owner.id, request)
	if queued.TenantID != owner.id || queued.Eligible != 1 || queued.Queued != 1 {
		t.Fatalf("provider did not queue exactly the consented owned report: %+v", queued)
	}
	if foreign := ddosProviderQueue(t, stack, operator, sibling.id, request); foreign.TenantID != sibling.id || foreign.Eligible != 0 || foreign.Queued != 0 {
		t.Fatalf("the same provider request crossed the tenant boundary: %+v", foreign)
	}
	if retry := ddosProviderQueue(t, stack, operator, owner.id, request); !retry.Replay || retry.Queued != 1 {
		t.Fatalf("approved provider trigger did not replay as one operation: %+v", retry)
	}
	assertShippedDDoSScheduledArtifact(t, stack, owner, sibling, operator, schedule.ID, request)
}

func newDDoSReportRequest(t *testing.T) string {
	t.Helper()
	id, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func ddosProviderQueue(t *testing.T, stack *shipped.Stack, operator, tenant, request string) reporting.ProviderReportQueueResult {
	t.Helper()
	var progress reporting.ProviderReportQueueResult
	stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &progress, "provider", "ddos-reports", tenant,
		"--body-file", stack.SecretFile(t, map[string]string{"request_id": request}))
	return progress
}

func assertShippedDDoSScheduledArtifact(t *testing.T, stack *shipped.Stack, owner, sibling *nativeLane, operator, scheduleID, request string) {
	t.Helper()
	env := map[string]string{"PROBECTL_API_TOKEN": operator}
	shipped.Await(t, "the tenant report worker delivers the provider-triggered DDoS report", 85*time.Second, func() bool {
		var progress reporting.ProviderReportQueueResult
		stack.MustCLI(t, env, &progress, "provider", "ddos-report-progress", owner.id, request)
		return progress.Delivered == 1 && progress.Pending == 0
	})
	var inbox struct{ Items []shippedDDoSArtifact }
	owner.do(t, stack, http.MethodGet, "/v1/dashboard-report-artifacts", nil, &inbox, http.StatusOK)
	for _, artifact := range inbox.Items {
		if artifact.ScheduleID == scheduleID {
			assertDDoSPackArtifact(t, stack, owner, sibling, operator, artifact, "ddos-summary", "ddos-top-sources", "ddos-decisions", "diversion_preview_stop")
			return
		}
	}
	t.Fatal("delivered report did not enter the owned inbox")
}

func assertDDoSPackArtifact(t *testing.T, stack *shipped.Stack, owner, sibling *nativeLane, operator string, artifact shippedDDoSArtifact, extra ...string) {
	t.Helper()
	if artifact.ID == "" {
		t.Fatal("the owned report artifact has no ID")
	}
	path := "/v1/dashboard-report-artifacts/" + artifact.ID
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, stack.BaseURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: auth.SessionCookie, Value: owner.cookie})
	response, err := stack.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("owned report artifact download status %d", response.StatusCode)
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	digest := hex.EncodeToString(crypto.Hash(content))
	if response.Header.Get("X-Report-SHA256") != digest || artifact.BodySHA256 != "" && artifact.BodySHA256 != digest {
		t.Fatal("owned report download does not match its stored digest")
	}
	for _, marker := range append([]string{"8000.000", "600000", "13.333"}, extra...) {
		if !strings.Contains(string(content), marker) {
			t.Fatalf("owned report omitted expected evidence %q", marker)
		}
	}
	sibling.do(t, stack, http.MethodGet, path, nil, nil, http.StatusNotFound)
	if status, _ := stack.Get(t, operator, path); status != http.StatusUnauthorized && status != http.StatusForbidden {
		t.Fatalf("provider credential directly accessed tenant report: status %d", status)
	}
}

func assertDDoSProviderReportConsole(t *testing.T, stack *shipped.Stack, operator string) {
	t.Helper()
	for _, theme := range []string{"light", "dark"} {
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL: stack.BaseURL + "/ui/provider", TrustCertFiles: stack.TrustCerts(), CAFile: stack.CAFile,
			Theme: theme, Accessibility: true, Cookies: []testsupport.RenderCookie{{Name: auth.ProviderSessionCookie, Value: operator}},
			Expect: []string{"Monthly client reports", "Tenant consent required"},
			Steps:  []testsupport.RenderStep{{Select: "label:text-is('Report family') + div select", Value: "ddos", Expect: []string{"DDoS incident reports", "Queue DDoS reports"}}},
		})
	}
}
