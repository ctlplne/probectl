// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type governanceExportLane struct {
	id, name, email, cookie, marker, testID, class, floor string
	retention                                             int
	token                                                 map[string]string
}

type governanceView struct {
	Classes        map[string]string `json:"classifications"`
	Forced         bool              `json:"redact_export"`
	Egress         bool              `json:"ai_remote_egress"`
	Floor          string            `json:"redact_from"`
	IsolationModel string            `json:"isolation_model"`
	RetentionDays  *int              `json:"retention_days"`
}

// TestShippedGovernanceAppliesScopedExportPolicy uses disabled synthetic tests
// as export evidence. Policies and tests enter through the shipped HTTPS API
// and provider console. The fixture has no remote inference or probe activity.
func TestShippedGovernanceAppliesScopedExportPolicy(t *testing.T) {
	stack := shipped.Start(t, shipped.Options{Name: "governance", TenantBand: 4})
	operator := stack.OnboardOperator(t, "root@msp-governance.example")
	operatorEnv := map[string]string{"PROBECTL_API_TOKEN": operator}
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := [2]governanceExportLane{
		{name: "Governance Red", email: "ada@acme.example", marker: "192.0.2.11", class: "restricted", floor: "restricted", retention: 21},
		{name: "Governance Blue", email: "bob@globex.example", marker: "198.51.100.27", class: "pii", floor: "pii", retention: 42},
	}
	for i := range lanes {
		lane := &lanes[i]
		provision := map[string]any{"name": lane.name, "slug": fmt.Sprintf("governance-%d-%s", i, stamp), "isolation_model": "pooled"}
		var tenant struct {
			ID string `json:"id"`
		}
		stack.MustCLI(t, operatorEnv, &tenant, "provider", "create-tenant", "--body-file", stack.SecretFile(t, provision))
		if tenant.ID == "" {
			t.Fatal("provider enrollment returned no tenant ID")
		}
		lane.id = tenant.ID
		lane.cookie = stack.SignIn(t, lane.id, lane.email, lane.name)
		lane.token = map[string]string{"PROBECTL_API_TOKEN": stack.APIToken(t, lane.cookie, "audit.read", "governance.read", "lifecycle.export", "tenant.read")}
		lane.request(t, stack, http.MethodPut, "/v1/governance/policy", map[string]any{
			"classifications": map[string]string{"ip_address": lane.class},
			"redact_from":     lane.floor, "redact_export": false, "ai_remote_egress": false,
		}, http.StatusOK)
		lane.request(t, stack, http.MethodPut, "/v1/lifecycle/retention", map[string]int{"flow_retention_days": lane.retention}, http.StatusOK)
		raw := lane.request(t, stack, http.MethodPost, "/v1/tests", map[string]any{
			"name": lane.name + " documentation target", "type": "icmp", "target": lane.marker,
			"enabled": false, "interval_seconds": 60, "timeout_seconds": 5,
		}, http.StatusCreated)
		var created struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		}
		if err := json.Unmarshal(raw, &created); err != nil || created.ID == "" || created.Enabled {
			t.Fatalf("expected a disabled export fixture: %+v, %v", created, err)
		}
		lane.testID = created.ID
	}
	for i := range lanes {
		lane, peer := &lanes[i], &lanes[1-i]
		assertGovernanceBundle(t, lane, peer, lane.request(t, stack, http.MethodGet, "/v1/lifecycle/export", nil, http.StatusOK), false, lane.marker)
	}

	for i := range lanes {
		lane, peer := &lanes[i], &lanes[1-i]
		const card = "#provider-governance"
		testsupport.RenderUI(t, testsupport.RenderSpec{
			URL: stack.BaseURL + "/ui/provider", Theme: [2]string{"light", "dark"}[i], Accessibility: true,
			Cookies:        []testsupport.RenderCookie{{Name: auth.ProviderSessionCookie, Value: operator}},
			TrustCertFiles: stack.TrustCerts(), CAFile: stack.CAFile,
			Expect: []string{"Data governance"},
			Absent: []string{lane.marker, peer.marker},
			Steps: []testsupport.RenderStep{
				{Fill: card + " form input", Value: lane.id},
				{Click: "Load", Within: card, ExpectWithin: card, Expect: []string{"Redact from " + lane.floor, fmt.Sprintf("Retention: %dd", lane.retention)}},
				{Click: "Force redacted export", Within: card, Role: "checkbox"},
				{Click: "Save governance", Within: card, ExpectWithin: card, Expect: []string{"Governance policy saved."}},
			},
		})
		var composed governanceView
		stack.MustCLI(t, operatorEnv, &composed, "governance", "tenant", lane.id)
		if !composed.Forced || composed.Egress || composed.Floor != lane.floor ||
			composed.Classes["ip_address"] != lane.class || composed.IsolationModel != "pooled" ||
			composed.RetentionDays == nil || *composed.RetentionDays != lane.retention {
			t.Fatalf("provider view lost the tenant's persisted policy or posture: %+v", composed)
		}
		// The first provider edit cannot change the still-unmodified sibling.
		if i == 0 {
			assertGovernanceBundle(t, peer, lane, peer.request(t, stack, http.MethodGet, "/v1/lifecycle/export", nil, http.StatusOK), false, peer.marker)
		}
	}

	wants := [2]string{"", "198.51.100.0/24"}
	for i := range lanes {
		lane, peer := &lanes[i], &lanes[1-i]
		var policy governanceView
		stack.MustCLI(t, lane.token, &policy, "governance", "policy")
		if !policy.Forced || policy.Egress || policy.Floor != lane.floor || policy.Classes["ip_address"] != lane.class {
			t.Fatalf("tenant CLI disclosed the wrong effective policy: %+v", policy)
		}
		var retention struct {
			Days int `json:"flow_retention_days"`
		}
		stack.MustCLI(t, lane.token, &retention, "lifecycle", "retention")
		if retention.Days != lane.retention {
			t.Fatalf("tenant CLI saw the wrong retention period: %d", retention.Days)
		}
		assertGovernanceBundle(t, lane, peer, lane.request(t, stack, http.MethodGet, "/v1/lifecycle/export", nil, http.StatusOK), true, wants[i])
		stack.MustCLI(t, lane.token, nil, "audit", "verify")
		var events struct {
			Items []audit.Event `json:"items"`
		}
		stack.MustCLI(t, lane.token, &events, "audit", "list", "--query", "action=governance.policy_set")
		if len(events.Items) != 1 || events.Items[0].Target != lane.id || events.Items[0].Action != "governance.policy_set" || events.Items[0].Hash == "" ||
			events.Items[0].Data["redact_from"] != lane.floor || events.Items[0].Data["redact_export"] != false {
			t.Fatalf("tenant audit policy receipt is missing or unscoped: %+v", events.Items)
		}
		lane.request(t, stack, http.MethodGet, "/v1/tests/"+peer.testID, nil, http.StatusNotFound)
	}

	uiDownload := filepath.Join(t.TempDir(), "governed-red.tar.gz")
	testsupport.RenderUI(t, testsupport.RenderSpec{
		URL: stack.BaseURL + "/ui/admin", Theme: "light",
		Cookies:        []testsupport.RenderCookie{{Name: auth.SessionCookie, Value: lanes[0].cookie}},
		TrustCertFiles: stack.TrustCerts(), CAFile: stack.CAFile,
		Expect: []string{"Data lifecycle"},
		Steps:  []testsupport.RenderStep{{Click: "Export my data (tar.gz)", Role: "link", Download: uiDownload}},
	})
	uiBundle, err := os.ReadFile(uiDownload)
	if err != nil {
		t.Fatal(err)
	}
	assertGovernanceBundle(t, &lanes[0], &lanes[1], uiBundle, true, wants[0])
	stdout, stderr, exit := stack.CLI(lanes[1].token, "lifecycle", "export")
	if exit != 0 {
		t.Fatalf("tenant CLI export failed: %s", stderr)
	}
	assertGovernanceBundle(t, &lanes[1], &lanes[0], []byte(stdout), true, wants[1])

	var operatorAudit struct {
		Items []audit.Event `json:"items"`
	}
	stack.MustCLI(t, operatorEnv, &operatorAudit, "provider", "audit", "--query", "action=provider.governance_set")
	targets := map[string]string{lanes[0].id: lanes[0].floor, lanes[1].id: lanes[1].floor}
	for _, event := range operatorAudit.Items {
		floor, known := targets[event.Target]
		redaction, _ := event.Data["redact_export"].(map[string]any)
		consent, _ := event.Data["ai_remote_egress"].(map[string]any)
		classification, _ := event.Data["redact_from"].(map[string]any)
		if !known || event.Action != "provider.governance_set" || event.Hash == "" || redaction["old"] != false || redaction["new"] != true ||
			consent["old"] != false || consent["new"] != false || classification["old"] != floor || classification["new"] != floor {
			t.Fatalf("unexpected provider policy receipt: %+v", event)
		}
		delete(targets, event.Target)
	}
	if len(targets) != 0 {
		t.Fatalf("missing provider receipts for %d edited tenant policies", len(targets))
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, stack.BaseURL+"/v1/lifecycle/export", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+operator)
	req.Header.Set("X-Probectl-Tenant", lanes[0].id)
	res, err := stack.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized && res.StatusCode != http.StatusForbidden {
		t.Fatalf("provider-only session obtained tenant export status %d", res.StatusCode)
	}
}

func (lane *governanceExportLane) request(t *testing.T, stack *shipped.Stack, method, path string, body any, want int) []byte {
	t.Helper()
	status, data := stack.Do(t, lane.cookie, method, path, body)
	if status != want {
		t.Fatalf("%s %s as %s: status %d, want %d: %.300s", method, path, lane.name, status, want, data)
	}
	return data
}

func assertGovernanceBundle(t *testing.T, owner, peer *governanceExportLane, archive []byte, redacted bool, want string) {
	t.Helper()
	files := untar(t, archive)
	var manifest tenantlife.Manifest
	if err := json.Unmarshal([]byte(files["manifest.json"]), &manifest); err != nil || manifest.TenantID != owner.id ||
		manifest.Redacted != redacted || manifest.Tables["tests"] != 1 {
		t.Fatalf("export scope or redaction state differs from the owning policy: %+v, %v", manifest, err)
	}
	var row struct{ ID, Target string }
	if err := json.Unmarshal([]byte(files["postgres/tests.jsonl"]), &row); err != nil || row.ID != owner.testID || row.Target != want {
		t.Fatalf("export failed to preserve the owned test and apply its policy: %+v, %v", row, err)
	}
	for name, data := range files {
		if strings.Contains(data, peer.testID) || strings.Contains(data, peer.marker) || (redacted && strings.Contains(data, owner.marker)) {
			t.Fatalf("export member %s contains a raw PII marker or sibling test", name)
		}
	}
}
