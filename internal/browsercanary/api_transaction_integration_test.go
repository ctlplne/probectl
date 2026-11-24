// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package browsercanary_test

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/browser"
	"github.com/ctlplne/probectl/internal/browsercanary"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type apiTenant struct {
	renderedBrowserTenant
	password, bearer string
	agentLog         string
}

func TestShippedAPITransactionsKeepTenantCredentialsAndResultsIsolated(t *testing.T) {
	var lanes [2]apiTenant
	for i := range lanes {
		lanes[i].password = "fixture-credential-" + uuid.NewString()
		lanes[i].bearer = "fixture-bearer-" + uuid.NewString()
		t.Setenv(apiFixtureCredentialKey(i), lanes[i].password)
	}
	var foreignRequests atomic.Uint64
	var ownedLogouts [2]atomic.Uint64
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(segments) != 3 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		lane, err := strconv.Atoi(segments[1])
		if err != nil || lane < 0 || lane >= len(lanes) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if segments[0] == "foreign" {
			foreignRequests.Add(1)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch {
		case r.Method == http.MethodPost && segments[2] == "login":
			var body struct{ Password string }
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password != lanes[lane].password {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"bearer": lanes[lane].bearer})
		case r.Method == http.MethodDelete && segments[2] == "logout":
			if r.Header.Get("Authorization") != "Bearer "+lanes[lane].bearer {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			ownedLogouts[lane].Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fixture.Close)
	caFile := filepath.Join(t.TempDir(), "app-ca.pem")
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.Certificate().Raw})
	if err := os.WriteFile(caFile, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	stack := shipped.Start(t, shipped.Options{Name: "apitransactions", TenantBand: 3, Env: map[string]string{
		"PROBECTL_TESTSYNC_SIGNING_KEY_FILE": filepath.Join(t.TempDir(), "testsync-key.pem"),
	}})
	operator := stack.OnboardOperator(t, "owner@msp-api-transaction.example")
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	for i := range lanes {
		lane := &lanes[i]
		lane.slug = fmt.Sprintf("api-%s-%d", stamp, i)
		var created struct{ ID string }
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &created, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":"pooled"}`, lane.slug, lane.slug))
		lane.id = created.ID
		lane.cookie = stack.SignIn(t, lane.id, fmt.Sprintf("editor-%d@tenant-api.example", i), lane.slug)
		lane.good = createAPITransactionTest(t, stack, lane, fixture.URL, i, false)
		lane.rejected = createAPITransactionTest(t, stack, lane, fixture.URL, i, true)
		lane.agent = uuid.NewString()
	}
	for i := range lanes {
		lane, other := &lanes[i], &lanes[1-i]
		identity := stack.EnrollAgent(t, lane.id, lane.agent, lane.slug)
		lane.agentLog = stack.StartAgent(t, identity, lane.slug, []string{"browser"}, fmt.Sprintf(`artifact_store:
  dir: %q
browser:
  driver: http
  api:
    ca_file: %q
    secrets:
      - tenant_id: %q
        origin: %q
        alias: login
        ref: %q
      - tenant_id: %q
        origin: %q
        alias: foreign
        ref: %q
test_sync:
  enabled: true
  interval: 2s
  allowed_types: [browser]
  allow_private_targets: true
`, stack.ObjectDir, caFile, lane.id, fixture.URL, "env:"+apiFixtureCredentialKey(i),
			other.id, fixture.URL, "env:"+apiFixtureCredentialKey(1-i)))
	}
	for i := range lanes {
		lane, other := &lanes[i], &lanes[1-i]
		shipped.Await(t, lane.slug+"'s authenticated logout and refused sibling credential", 100*time.Second, func() bool {
			var success, refused bool
			for _, result := range readRenderedBrowserHistory(t, stack, &lane.renderedBrowserTenant, &other.renderedBrowserTenant) {
				if result.AgentID != lane.agent || result.Type != "browser" {
					continue
				}
				testID := result.Attributes["probectl.test.id"]
				if (testID == lane.good || testID == lane.rejected) &&
					(result.Target != fixture.URL || result.Attributes["browser.transaction_kind"] != "api") {
					t.Fatal("the result did not retain its transaction kind and origin-only target")
				}
				switch testID {
				case lane.good:
					success = success || (result.Success && result.Attributes["browser.step.3.success"] == "true")
				case lane.rejected:
					refused = refused || (!result.Success && result.Attributes["browser.step.0.detail"] == "transaction secret is unavailable")
				}
			}
			return success && refused && ownedLogouts[i].Load() > 0
		})
	}
	if foreignRequests.Load() != 0 {
		t.Fatal("an agent attempted a request with a sibling tenant's secret alias")
	}
	for i := range lanes {
		lane, other := &lanes[i], &lanes[1-i]
		results := readRenderedBrowserHistory(t, stack, &lane.renderedBrowserTenant, &other.renderedBrowserTenant)
		for _, result := range results {
			if result.Attributes["browser.screenshot.key"] != "" {
				t.Fatal("an API transaction created a response artifact")
			}
		}
		if code, _ := stack.Do(t, other.cookie, http.MethodGet, "/v1/tests/"+lane.good, nil); code != http.StatusNotFound {
			t.Fatal("a sibling can read the other tenant's API test", code)
		}
		if _, err := os.ReadDir(filepath.Join(stack.ObjectDir, "tenant", lane.id, "browser")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("a response artifact directory was created for API transactions")
		}
		_, raw := stack.Do(t, lane.cookie, http.MethodGet, "/v1/results/history?window=1h", nil)
		log, err := os.ReadFile(lane.agentLog)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "fixture-credential-") || strings.Contains(string(raw), "fixture-bearer-") ||
			strings.Contains(string(log), "fixture-credential-") || strings.Contains(string(log), "fixture-bearer-") {
			t.Fatal("a captured or resolved credential reached API results or agent logs")
		}
	}
}

func apiFixtureCredentialKey(lane int) string {
	return "PROBECTL_TEST_FX31_LOGIN_" + strconv.Itoa(lane)
}

func createAPITransactionTest(t *testing.T, stack *shipped.Stack, lane *apiTenant, origin string, index int, sibling bool) string {
	t.Helper()
	path, alias := "owned", "login"
	if sibling {
		path, alias = "foreign", "foreign"
	}
	target := fmt.Sprintf("%s/%s/%d/", origin, path, index)
	body := json.RawMessage(fmt.Sprintf(`{"password":"${secret.%s}"}`, alias))
	steps := []browser.Step{{Name: "login", Action: browser.Request, URL: "login", APIRequest: &browser.APIRequestStep{Method: http.MethodPost, JSONBody: body}}}
	if !sibling {
		steps = append(steps,
			browser.Step{Name: "capture bearer", Action: browser.Capture, APICapture: &browser.APICaptureStep{Name: "bearer", JSONPath: "$.bearer"}},
			browser.Step{Name: "logout", Action: browser.Request, URL: "logout", APIRequest: &browser.APIRequestStep{Method: http.MethodDelete,
				Headers: map[string][]string{"Authorization": {"Bearer ${capture.bearer}"}}}},
			browser.Step{Name: "verify logout", Action: browser.AssertStatus, Status: http.StatusNoContent})
	}
	name := lane.slug + "-" + path
	script, err := browsercanary.MarshalScript(browser.Script{Name: name, StartURL: target, Steps: steps})
	if err != nil {
		t.Fatal(err)
	}
	status, raw := stack.Do(t, lane.cookie, http.MethodPost, "/v1/tests", map[string]any{
		"name": name, "type": "browser", "target": target, "interval_seconds": 20, "timeout_seconds": 15, "enabled": true,
		"params": map[string]string{"browser_driver": "http", "script": script, "allow_private_targets": "true"},
	})
	var result struct{ ID string }
	if status != http.StatusCreated || json.Unmarshal(raw, &result) != nil || result.ID == "" {
		t.Fatalf("create API transaction returned HTTP %d", status)
	}
	return result.ID
}
