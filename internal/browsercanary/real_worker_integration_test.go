// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package browsercanary

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/browser"
	"github.com/imfeelingtheagi/probectl/internal/canary"
)

// TestAgentFactoryRunsRealPlaywrightWorker is W2's agent-driven smoke: the
// exact factory registered by probectl-agent selects ExecDriver, invokes the
// real worker, and returns rendered DOM timings. The browser-worker CI job sets
// PROBECTL_BROWSER_WORKER_PATH after installing the pinned Playwright lock.
func TestAgentFactoryRunsRealPlaywrightWorker(t *testing.T) {
	worker := os.Getenv("PROBECTL_BROWSER_WORKER_PATH")
	if worker == "" {
		t.Skip("PROBECTL_BROWSER_WORKER_PATH is required for the real worker smoke")
	}
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.URL.Path != "/login" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<form method="post"><input name="username"><button type="submit">Sign in</button></form>`))
			return
		}
		_, _ = w.Write([]byte(`<h1>Welcome rendered agent</h1>`))
	}))
	defer app.Close()

	script, err := MarshalScript(browser.Script{
		Name:     "agent-rendered-login",
		StartURL: app.URL + "/login",
		Steps: []browser.Step{
			{Name: "open", Action: browser.Goto},
			{Name: "username", Action: browser.Fill, Selector: `[name="username"]`, Value: "alice"},
			{Name: "submit", Action: browser.Click, Selector: `button[type="submit"]`},
			{Name: "welcome", Action: browser.AssertText, Value: "Welcome rendered agent"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewFactory(DriverConfig{
		Driver: DriverBrowser, WorkerCommand: "node", WorkerPath: worker, StepTimeout: 15 * time.Second,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := factory(canary.Config{
		Type: Type, Target: app.URL + "/login", Timeout: 45 * time.Second,
		Params: map[string]string{
			DriverParam:              DriverBrowser,
			ScriptParam:              script,
			canary.AllowPrivateParam: "true",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.Run(context.Background())
	if err != nil {
		t.Fatalf("real worker run: %v", err)
	}
	if !result.Success || result.Attributes["browser.driver"] != DriverBrowser {
		t.Fatalf("rendered result = %+v", result)
	}
	if _, ok := result.Metrics["dom.load_ms"]; !ok {
		t.Fatalf("real worker emitted no DOM timings: %+v", result.Metrics)
	}
}
