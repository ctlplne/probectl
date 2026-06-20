// SPDX-License-Identifier: LicenseRef-probectl-TBD

package browser

import (
	"testing"
	"time"
)

const loginScript = `{
  "name": "login",
  "start_url": "http://app.test/login",
  "steps": [
    {"action": "goto"},
    {"action": "fill", "field": "username", "value": "alice"},
    {"action": "fill", "field": "password", "value": "secret"},
    {"action": "submit", "url": "http://app.test/login"},
    {"action": "assert_text", "value": "Welcome"},
    {"action": "assert_status", "status": 200}
  ]
}`

func TestParseValidScript(t *testing.T) {
	s, err := Parse([]byte(loginScript))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Name != "login" || len(s.Steps) != 6 || s.Steps[1].Field != "username" {
		t.Fatalf("parsed: %+v", s)
	}
}

func TestParseRejectsBad(t *testing.T) {
	cases := map[string]string{
		"no name":           `{"steps":[{"action":"goto","url":"http://x"}]}`,
		"no steps":          `{"name":"x","steps":[]}`,
		"unknown action":    `{"name":"x","steps":[{"action":"teleport"}]}`,
		"fill no field":     `{"name":"x","start_url":"http://x","steps":[{"action":"fill","value":"v"}]}`,
		"assert no text":    `{"name":"x","start_url":"http://x","steps":[{"action":"assert_text"}]}`,
		"bad status":        `{"name":"x","start_url":"http://x","steps":[{"action":"assert_status","status":42}]}`,
		"first goto no url": `{"name":"x","steps":[{"action":"goto"}]}`,
		"unknown field":     `{"name":"x","steps":[{"action":"goto","url":"http://x"}],"bogus":1}`,
	}
	for name, js := range cases {
		if _, err := Parse([]byte(js)); err == nil {
			t.Fatalf("%s: expected a parse/validate error", name)
		}
	}
}

func TestToCanaryResult(t *testing.T) {
	r := Result{
		Script: "login", Target: "http://app.test/login", Success: false,
		Error: "step 5 failed", StartedAt: time.Now(), TotalMs: 1234,
		Steps: []StepResult{
			{Action: Goto, Success: true, DurationMs: 41},
			{Action: AssertText, Success: false, Detail: "text not found", DurationMs: 42},
		},
		Waterfall: []ResourceTiming{{URL: "http://app.test/login", TotalMs: 40}},
		DOM:       DOMTimings{DOMContentLoadedMs: 120, LoadMs: 300, FirstContentfulPaintMs: 150},
		Screenshot: &ScreenshotRef{
			Key: "tenant/t1/browser/login-1.png", ContentType: "image/png", SizeBytes: 9,
		},
	}
	cr := r.ToCanaryResult()
	if cr.Type != "browser" || cr.Target != "http://app.test/login" || cr.Success {
		t.Fatalf("envelope: %+v", cr)
	}
	if cr.Metrics["transaction.total_ms"] != 1234 || cr.Metrics["transaction.failed_steps"] != 1 {
		t.Fatalf("metrics: %v", cr.Metrics)
	}
	if cr.Metrics["transaction.step.1.duration_ms"] != 42 {
		t.Fatalf("step metrics: %v", cr.Metrics)
	}
	if cr.Metrics["dom.content_loaded_ms"] != 120 || cr.Metrics["paint.first_contentful_ms"] != 150 {
		t.Fatalf("dom metrics: %v", cr.Metrics)
	}
	if cr.Attributes["browser.script"] != "login" ||
		cr.Attributes["browser.step.1.action"] != "assert_text" ||
		cr.Attributes["browser.step.1.success"] != "false" ||
		cr.Attributes["browser.screenshot.key"] != "tenant/t1/browser/login-1.png" ||
		cr.Attributes["browser.error"] != "step 5 failed" {
		t.Fatalf("attrs: %v", cr.Attributes)
	}
	if cr.Duration != 1234*time.Millisecond {
		t.Fatalf("duration: %v", cr.Duration)
	}
}
