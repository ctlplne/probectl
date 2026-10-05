// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package browsercanary

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"time"

	"github.com/ctlplne/probectl/internal/testsupport"

	"github.com/ctlplne/probectl/internal/browser"
	"github.com/ctlplne/probectl/internal/canary"
)

// TestAgentFactoryRunsRealPlaywrightWorker is W2's agent-driven smoke: the
// exact factory registered by probectl-agent selects ExecDriver, invokes the
// real worker, and returns rendered DOM timings. The browser-worker CI job sets
// PROBECTL_BROWSER_WORKER_PATH after installing the pinned Playwright lock.
//
// DPR-222: that lane is an opt-in, not a required service. The worker is
// worker.mjs plus a Chromium install, which is why it runs inside the pinned
// Playwright image in its own job; the general integration job has neither and
// under PROBECTL_TEST_REQUIRE_SERVICES=1 was failing permanently on their
// absence. The browser-worker job is the lane, and it now fails if this test
// reports a skip, so an unset path there is still caught.
func TestAgentFactoryRunsRealPlaywrightWorker(t *testing.T) {
	worker := os.Getenv("PROBECTL_BROWSER_WORKER_PATH")
	if worker == "" {
		// SkipOptIn's message says "=1"; this one takes a path, so say so.
		testsupport.SkipOptIn(t, "PROBECTL_BROWSER_WORKER_PATH",
			"set it to the worker path (browser-worker/worker.mjs) next to a Chromium install, as the browser-worker CI job does")
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

// TestAgentFactoryRunsRealPlaywrightWorkerOverSocket is the SUP-02/D-36 sidecar
// runtime proof: the real worker runs as a long-lived SOCKET SERVER (as it does
// in the split pod's browser-worker sidecar) and the agent drives it over a UNIX
// socket via SocketDriver — no child process, no shared container. It also proves
// the per-transaction allow_private_targets flag travels IN-BAND: the httptest
// app is on 127.0.0.1, which the worker's SSRF guard denies by default, so a
// successful render means the flag reached the shared worker over the socket.
func TestAgentFactoryRunsRealPlaywrightWorkerOverSocket(t *testing.T) {
	worker := os.Getenv("PROBECTL_BROWSER_WORKER_PATH")
	if worker == "" {
		testsupport.SkipOptIn(t, "PROBECTL_BROWSER_WORKER_PATH",
			"set it to the worker path (browser-worker/worker.mjs) next to a Chromium install, as the browser-worker CI job does")
	}

	sock := filepath.Join(t.TempDir(), "worker.sock")
	cmd := exec.Command("node", worker)
	cmd.Env = append(os.Environ(), "PROBECTL_BROWSER_WORKER_SOCKET="+sock)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start worker in socket mode: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// Wait for the worker to be listening on the socket.
	deadline := time.Now().Add(30 * time.Second)
	for {
		c, derr := net.Dial("unix", sock)
		if derr == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker never listened on %s: %v", sock, derr)
		}
		time.Sleep(100 * time.Millisecond)
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
		_, _ = w.Write([]byte(`<h1>Welcome sidecar agent</h1>`))
	}))
	defer app.Close()

	script, err := MarshalScript(browser.Script{
		Name:     "agent-rendered-login-over-socket",
		StartURL: app.URL + "/login",
		Steps: []browser.Step{
			{Name: "open", Action: browser.Goto},
			{Name: "username", Action: browser.Fill, Selector: `[name="username"]`, Value: "alice"},
			{Name: "submit", Action: browser.Click, Selector: `button[type="submit"]`},
			{Name: "welcome", Action: browser.AssertText, Value: "Welcome sidecar agent"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Sidecar transport: WorkerSocket, no WorkerCommand/WorkerPath.
	factory, err := NewFactory(DriverConfig{
		Driver: DriverBrowser, WorkerSocket: sock, StepTimeout: 15 * time.Second,
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
		t.Fatalf("real worker run over socket: %v", err)
	}
	if !result.Success || result.Attributes["browser.driver"] != DriverBrowser {
		t.Fatalf("rendered result over socket = %+v", result)
	}
	if _, ok := result.Metrics["dom.load_ms"]; !ok {
		t.Fatalf("socket worker emitted no DOM timings: %+v", result.Metrics)
	}
}
