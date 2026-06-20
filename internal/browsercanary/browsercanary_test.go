// SPDX-License-Identifier: LicenseRef-probectl-TBD

package browsercanary

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/browser"
	"github.com/imfeelingtheagi/probectl/internal/canary"
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
