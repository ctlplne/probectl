// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package browsercanary_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/browser"
	"github.com/ctlplne/probectl/internal/browsercanary"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

type renderedBrowserTenant struct {
	id, slug, cookie, agent string
	good, rejected          string
}

func TestRenderedBrowserCanariesReachOnlyTheirShippedTenant(t *testing.T) {
	worker := os.Getenv("PROBECTL_TEST_SHIPPED_BROWSER_WORKER")
	if worker == "" {
		if os.Getenv("PROBECTL_TEST_REQUIRE_SHIPPED_BROWSER_WORKER") == "1" {
			t.Fatal("required pinned browser worker path is missing")
		}
		testsupport.SkipOptIn(t, "PROBECTL_TEST_SHIPPED_BROWSER_WORKER", "set the absolute path to worker.mjs beside a pinned Playwright install")
	}
	if !filepath.IsAbs(worker) {
		t.Fatal("the shipped browser worker path must be absolute")
	}
	stack := shipped.Start(t, shipped.Options{Name: "renderedbrowser", TenantBand: 3, Env: map[string]string{
		"PROBECTL_TESTSYNC_SIGNING_KEY_FILE": filepath.Join(t.TempDir(), "testsync-signing-key.pem"),
	}})
	operator := stack.OnboardOperator(t, "root@msp-browser-receipt.example")
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path != "/journey" {
			http.NotFound(w, r)
			return
		}
		// The text exists only after Chromium runs page JavaScript.
		_, _ = fmt.Fprint(w, `<h1 id="welcome">Before rendering</h1><script>document.querySelector('#welcome').textContent = 'Rendered ' + new URLSearchParams(location.search).get('lane')</script>`)
	}))
	t.Cleanup(page.Close)
	stamp := strconv.FormatInt(time.Now().UnixNano(), 36)
	lanes := [2]renderedBrowserTenant{}
	for i, email := range []string{"ada@acme.example", "bob@globex.example"} {
		lane := &lanes[i]
		lane.slug = fmt.Sprintf("rendered-%s-%d", stamp, i)
		var tenant struct{ ID string }
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &tenant, "provider", "create-tenant", "--body",
			fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":"pooled"}`, lane.slug, lane.slug))
		lane.id = tenant.ID
		lane.cookie = stack.SignIn(t, lane.id, email, lane.slug)
		target := page.URL + "/journey?lane=" + lane.slug
		lane.good = createRenderedBrowserTest(t, stack, lane, target, lane.slug+"-good", "Rendered "+lane.slug)
		lane.rejected = createRenderedBrowserTest(t, stack, lane, target, lane.slug+"-failure", "Text absent from the rendered page")
		lane.agent = uuid.NewString()
		identity := stack.EnrollAgent(t, lane.id, lane.agent, lane.slug)
		if _, err := os.Stat(filepath.Join(identity, "testsync.pub")); err != nil {
			t.Fatal("the enrolled agent omitted the signed browser bundle trust key", err)
		}
		stack.StartAgent(t, identity, lane.slug, []string{"browser"}, fmt.Sprintf(`artifact_store:
  dir: %q
browser:
  driver: browser
  worker:
    command: node
    path: %q
    step_timeout: 6s
test_sync:
  enabled: true
  interval: 2s
  allowed_types: [browser]
  allow_private_targets: true
`, stack.ObjectDir, worker))
	}
	for i := range lanes {
		checkRenderedBrowserDelivery(t, stack, &lanes[i], &lanes[1-i])
	}
	// Re-read both histories after both have emitted their positive result and
	// failure artifact. A quiet sibling at the first poll cannot prove isolation.
	for i := range lanes {
		_ = readRenderedBrowserHistory(t, stack, &lanes[i], &lanes[1-i])
	}
}

func createRenderedBrowserTest(t *testing.T, stack *shipped.Stack, lane *renderedBrowserTenant, target, name, text string) string {
	t.Helper()
	script, err := browsercanary.MarshalScript(browser.Script{Name: name, StartURL: target, Steps: []browser.Step{
		{Name: "load", Action: browser.Goto},
		{Name: "rendered text", Action: browser.AssertText, Selector: "#welcome", Value: text},
	}})
	if err != nil {
		t.Fatal(err)
	}
	status, body := stack.Do(t, lane.cookie, http.MethodPost, "/v1/tests", map[string]any{
		"name": name, "type": "browser", "target": target, "interval_seconds": 20, "timeout_seconds": 15, "enabled": true,
		"params": map[string]string{"browser_driver": "browser", "script": script, "allow_private_targets": "true"},
	})
	var result struct{ ID string }
	if status != http.StatusCreated || json.Unmarshal(body, &result) != nil || result.ID == "" {
		t.Fatalf("could not create the tenant's browser test: status %d, %.300s", status, body)
	}
	return result.ID
}

func checkRenderedBrowserDelivery(t *testing.T, stack *shipped.Stack, lane, other *renderedBrowserTenant) {
	t.Helper()
	const testID = "probectl.test.id"
	const screenshot = "browser.screenshot.key"
	var key string
	shipped.Await(t, lane.slug+"'s rendered success and PNG failure", 100*time.Second, func() bool {
		success := false
		for _, result := range readRenderedBrowserHistory(t, stack, lane, other) {
			if result.Type != "browser" || result.AgentID != lane.agent || result.Attributes["browser.driver"] != "browser" {
				continue
			}
			switch result.Attributes[testID] {
			case lane.good:
				_, hasDOM := result.Metrics["dom.load_ms"]
				success = success || (result.Success && hasDOM && result.Attributes["browser.step.1.success"] == "true")
			case lane.rejected:
				if !result.Success && result.Attributes["browser.step.0.detail"] == "200" &&
					result.Attributes["browser.step.1.success"] == "false" &&
					result.Attributes["browser.screenshot.content_type"] == "image/png" &&
					result.Metrics["transaction.failed_steps"] == 1 {
					key = result.Attributes[screenshot]
				}
			}
		}
		return success && key != ""
	})
	if key != filepath.ToSlash(filepath.Clean(key)) || !strings.HasPrefix(key, "tenant/"+lane.id+"/browser/") {
		t.Fatal("browser artifact was not stored under the authenticated tenant's namespace")
	}
	file, err := os.ReadFile(filepath.Join(stack.ObjectDir, key))
	if err != nil || !bytes.HasPrefix(file, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("the reported failure artifact is not the rendered PNG", err)
	}
	if code, _ := stack.Do(t, other.cookie, http.MethodGet, "/v1/tests/"+lane.good, nil); code != http.StatusNotFound {
		t.Fatal("a sibling can read the other tenant's browser test", code)
	}

	shipped.Await(t, lane.slug+"'s successful and failed Prometheus samples", 30*time.Second, func() bool {
		good := readRenderedBrowserMetrics(t, stack, lane.cookie, lane.good)
		failure := readRenderedBrowserMetrics(t, stack, lane.cookie, lane.rejected)
		return len(good) > 0 && len(failure) > 0
	})
	for _, probe := range []struct{ id, value string }{{lane.good, "1"}, {lane.rejected, "0"}} {
		samples := readRenderedBrowserMetrics(t, stack, lane.cookie, probe.id)
		if len(samples) != 1 || samples[0].Metric["tenant_id"] != lane.id || samples[0].Metric["agent_id"] != lane.agent ||
			samples[0].Metric["test_id"] != probe.id || len(samples[0].Value) != 2 || string(samples[0].Value[1]) != strconv.Quote(probe.value) {
			t.Fatalf("tenant %s did not receive its exact browser metric for test %s: %+v", lane.slug, probe.id, samples)
		}
		if foreign := readRenderedBrowserMetrics(t, stack, other.cookie, probe.id); len(foreign) != 0 {
			t.Fatal("a sibling can read the other tenant's rendered browser metrics")
		}
	}
}

type renderedBrowserResult struct {
	AgentID    string             `json:"agent_id"`
	Type       string             `json:"type"`
	Target     string             `json:"target"`
	Success    bool               `json:"success"`
	Metrics    map[string]float64 `json:"metrics"`
	Attributes map[string]string  `json:"attributes"`
}

func readRenderedBrowserHistory(t *testing.T, stack *shipped.Stack, lane, other *renderedBrowserTenant) []renderedBrowserResult {
	t.Helper()
	var history struct{ Items []renderedBrowserResult }
	code, raw := stack.Do(t, lane.cookie, http.MethodGet, "/v1/results/history?window=1h", nil)
	if code != http.StatusOK || json.Unmarshal(raw, &history) != nil {
		t.Fatalf("could not read the tenant's browser results: status %d", code)
	}
	for _, result := range history.Items {
		testID := result.Attributes["probectl.test.id"]
		key := result.Attributes["browser.screenshot.key"]
		if result.AgentID == other.agent || testID == other.good || testID == other.rejected || strings.HasPrefix(key, "tenant/"+other.id+"/") {
			t.Fatal("browser history disclosed a sibling tenant's result or object reference")
		}
	}
	return history.Items
}

type renderedBrowserSample struct {
	Metric map[string]string `json:"metric"`
	Value  []json.RawMessage `json:"value"`
}

func readRenderedBrowserMetrics(t *testing.T, stack *shipped.Stack, cookie, testID string) []renderedBrowserSample {
	t.Helper()
	query := fmt.Sprintf(`probectl_probe_success{test_id=%q}`, testID)
	code, raw := stack.Do(t, cookie, http.MethodGet, "/v1/grafana/api/v1/query?query="+url.QueryEscape(query), nil)
	var out struct {
		Status string `json:"status"`
		Data   struct {
			Result []renderedBrowserSample `json:"result"`
		} `json:"data"`
	}
	if code != http.StatusOK || json.Unmarshal(raw, &out) != nil || out.Status != "success" {
		t.Fatalf("could not read rendered browser metrics for %s: status %d, %.300s", testID, code, raw)
	}
	return out.Data.Result
}
