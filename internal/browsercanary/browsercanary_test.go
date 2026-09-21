// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package browsercanary

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/browser"
	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/objectstore"
)

func TestBrowserCanaryRunsTransactionAndEmitsStepTimings(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			_, _ = w.Write([]byte("Welcome"))
			return
		}
		http.NotFound(w, r)
	}))
	defer app.Close()

	script, err := MarshalScript(browser.Script{
		Name:     "login",
		StartURL: app.URL + "/login",
		Steps: []browser.Step{
			{Name: "open", Action: browser.Goto},
			{Name: "welcome", Action: browser.AssertText, Value: "Welcome"},
			{Name: "status", Action: browser.AssertStatus, Status: 200},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(canary.Config{
		Type:    Type,
		Target:  app.URL + "/login",
		Timeout: time.Second,
		Params: map[string]string{
			canary.AllowPrivateParam: "true",
			ScriptParam:              script,
		},
	})
	if err != nil {
		t.Fatalf("new browser canary: %v", err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Type != Type || !res.Success || res.Target != app.URL+"/login" {
		t.Fatalf("result = %+v", res)
	}
	if _, ok := res.Metrics["transaction.step.0.duration_ms"]; !ok {
		t.Fatalf("missing per-step timing metrics: %v", res.Metrics)
	}
	if res.Attributes["browser.step.1.name"] != "welcome" ||
		res.Attributes["browser.step.1.action"] != "assert_text" ||
		res.Attributes["browser.step.1.success"] != "true" {
		t.Fatalf("missing per-step attributes: %v", res.Attributes)
	}
}

func TestBrowserCanaryStoresFailureArtifactWithTenantObjectStore(t *testing.T) {
	app := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("Welcome"))
			return
		}
		http.NotFound(w, r)
	}))
	defer app.Close()

	script, err := MarshalScript(browser.Script{
		Name:     "login",
		StartURL: app.URL + "/login",
		Steps: []browser.Step{
			{Name: "open", Action: browser.Goto},
			{Name: "missing", Action: browser.AssertText, Value: "never-here"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	store := objectstore.NewMemory()
	c, err := newWithObjectStore(store, nil)(canary.Config{
		Type:     Type,
		Target:   app.URL + "/login",
		Timeout:  time.Second,
		TenantID: "tnA",
		Params: map[string]string{
			canary.AllowPrivateParam: "true",
			ScriptParam:              script,
		},
	})
	if err != nil {
		t.Fatalf("new browser canary: %v", err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Success {
		t.Fatalf("result should fail to trigger artifact storage: %+v", res)
	}
	key := res.Attributes["browser.screenshot.key"]
	if !strings.HasPrefix(key, "tenant/tnA/browser/") {
		t.Fatalf("screenshot key = %q, want tenant/tnA/browser/ prefix", key)
	}
	obj, err := store.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("stored artifact %q: %v", key, err)
	}
	if string(obj.Data) != "Welcome" || obj.ContentType != "text/html" {
		t.Fatalf("stored artifact = %q / %q", obj.Data, obj.ContentType)
	}
}

func TestBrowserCanaryArtifactStoreRequiresTenant(t *testing.T) {
	_, err := newWithObjectStore(objectstore.NewMemory(), nil)(canary.Config{
		Type:   Type,
		Target: "https://example.com/login",
	})
	if err == nil || !strings.Contains(err.Error(), "tenant id is required") {
		t.Fatalf("configured artifact store without tenant should fail closed, got %v", err)
	}
}

func TestBrowserCanaryEnforcesSSRFGuardAtConstruction(t *testing.T) {
	for _, target := range []string{
		"http://127.0.0.1:8080/login",
		"http://169.254.169.254/latest/meta-data",
		"http://2130706433/",
	} {
		if _, err := New(canary.Config{Type: Type, Target: target}); err == nil {
			t.Fatalf("target %s should be denied", target)
		} else if !strings.Contains(err.Error(), canary.AllowPrivateParam) && !strings.Contains(err.Error(), "denied") {
			t.Fatalf("error should explain SSRF guard/override, got %v", err)
		}
	}
}

func TestBrowserCanaryEnforcesSSRFGuardOnScriptStepURLs(t *testing.T) {
	script, err := MarshalScript(browser.Script{
		Name:     "login",
		StartURL: "https://example.com/login",
		Steps: []browser.Step{
			{Name: "open", Action: browser.Goto},
			{Name: "metadata", Action: browser.Goto, URL: "http://169.254.169.254/latest"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(canary.Config{
		Type:   Type,
		Target: "https://example.com/login",
		Params: map[string]string{ScriptParam: script},
	}); err == nil {
		t.Fatal("private step URL should be denied")
	}
}

func TestBrowserFactorySelectsExecDriverWithoutSilentFallback(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is required for the exec-driver selection test")
	}
	worker := filepath.Join(t.TempDir(), "worker.mjs")
	if err := os.WriteFile(worker, []byte(`
import { readFileSync } from "node:fs";
readFileSync(0, "utf8");
process.stdout.write(JSON.stringify({success:true,total_ms:7,steps:[],waterfall:[],dom:{load_ms:3}}));
`), 0o600); err != nil {
		t.Fatal(err)
	}
	factory, err := NewFactory(DriverConfig{
		Driver: DriverBrowser, WorkerCommand: "node", WorkerPath: worker,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := factory(canary.Config{
		// DPR-202: not one second. This spawns `node`, and a cold Node start on a
		// loaded machine takes longer than that — the worker is killed at the
		// deadline, res.Success goes false, and the test fails with
		// "browser worker: signal: killed" for a reason that has nothing to do
		// with what it asserts. Observed exactly once during a full gate run on a
		// saturated host, and it passed twice immediately afterwards, which is
		// the signature of a deadline rather than a defect. The test measures
		// driver selection and output parsing, not latency, so a generous budget
		// costs nothing when things are fast.
		Type: Type, Target: "https://example.com/", Timeout: 30 * time.Second,
		Params: map[string]string{DriverParam: DriverBrowser},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success || res.Attributes["browser.driver"] != DriverBrowser || res.Metrics["dom.load_ms"] != 3 {
		t.Fatalf("rendered result = %+v", res)
	}

	httpFactory, err := NewFactory(DriverConfig{Driver: DriverHTTP}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = httpFactory(canary.Config{
		Type: Type, Target: "https://example.com/",
		Params: map[string]string{DriverParam: DriverBrowser},
	})
	if err == nil || !strings.Contains(err.Error(), "requires browser driver") {
		t.Fatalf("HTTP agent silently accepted rendered test: %v", err)
	}

	_, err = factory(canary.Config{Type: Type, Target: "https://example.com/"})
	if err == nil || !strings.Contains(err.Error(), "requires http driver") {
		t.Fatalf("browser agent silently upgraded legacy HTTP transaction: %v", err)
	}
}

func TestBrowserFactoryFailsClosedWhenWorkerMissing(t *testing.T) {
	_, err := NewFactory(DriverConfig{
		Driver: DriverBrowser, WorkerCommand: "definitely-not-a-probectl-worker", WorkerPath: "/missing/worker.mjs",
	}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "command") {
		t.Fatalf("missing worker command accepted: %v", err)
	}
}

func TestRenderedBrowserPreservesScriptTargetGuard(t *testing.T) {
	factory, err := NewFactory(DriverConfig{
		Driver: DriverBrowser, WorkerCommand: os.Args[0], WorkerPath: os.Args[0],
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = factory(canary.Config{
		Type: Type, Target: "http://169.254.169.254/latest/meta-data",
		Params: map[string]string{DriverParam: DriverBrowser},
	})
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("rendered driver accepted metadata target: %v", err)
	}
}
