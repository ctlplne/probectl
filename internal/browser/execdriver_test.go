package browser

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/objectstore"
)

// writeStub writes a node script to a temp dir and returns its path. node is
// available in CI; the test skips if not (the real Playwright worker runs in its
// own CI job).
func writeStub(t *testing.T, body string) string {
	t.Helper()
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}
	p := filepath.Join(t.TempDir(), "stub.mjs")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The exec driver passes the script to the worker, parses its JSON result, and
// decodes the base64 screenshot — exercised with a stub standing in for the real
// Playwright worker.
func TestExecDriverParsesWorkerResult(t *testing.T) {
	pngB64 := base64.StdEncoding.EncodeToString([]byte("\x89PNGDATA"))
	stub := writeStub(t, `
import { readFileSync } from "node:fs";
readFileSync(0, "utf8"); // consume the script on stdin
const result = {
  success: false,
  error: 'step "welcome" (assert_text): text not found',
  total_ms: 842,
  steps: [
    { name: "open", action: "goto", success: true, duration_ms: 100, detail: "200" },
    { name: "welcome", action: "assert_text", success: false, duration_ms: 50, detail: "text not found" }
  ],
  waterfall: [ { url: "http://app/login", method: "GET", status: 200, start_ms: 0, ttfb_ms: 30, total_ms: 40 } ],
  dom: { dom_content_loaded_ms: 120, load_ms: 300, first_contentful_paint_ms: 150 },
  screenshot_b64: "`+pngB64+`",
  screenshot_content_type: "image/png"
};
process.stdout.write(JSON.stringify(result));
`)

	s := Script{Name: "login", StartURL: "http://app/login", Steps: []Step{{Action: Goto, URL: "http://app/login"}}}
	out, err := NewExecDriver("node", stub).Run(context.Background(), s)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	r := out.Result
	if r.Success || r.Script != "login" || r.Target != "http://app/login" || r.TotalMs != 842 {
		t.Fatalf("result envelope: %+v", r)
	}
	if len(r.Steps) != 2 || r.Steps[1].Action != AssertText || r.Steps[1].Success {
		t.Fatalf("steps: %+v", r.Steps)
	}
	if len(r.Waterfall) != 1 || r.Waterfall[0].Status != 200 {
		t.Fatalf("waterfall: %+v", r.Waterfall)
	}
	if r.DOM.DOMContentLoadedMs != 120 || r.DOM.FirstContentfulPaintMs != 150 {
		t.Fatalf("dom: %+v", r.DOM)
	}
	if string(out.Screenshot) != "\x89PNGDATA" || out.ScreenshotType != "image/png" {
		t.Fatalf("screenshot: %q %q", out.Screenshot, out.ScreenshotType)
	}
	if r.StartedAt.IsZero() {
		t.Fatal("driver should stamp StartedAt")
	}
}

// A worker that overruns is killed by ctx cancellation (the Fleet's isolation).
func TestExecDriverContextKillsWorker(t *testing.T) {
	stub := writeStub(t, `await new Promise(r => setTimeout(r, 5000)); process.stdout.write("{}");`)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := NewExecDriver("node", stub).Run(ctx, Script{Name: "x", StartURL: "http://x", Steps: []Step{{Action: Screenshot}}})
	if err == nil {
		t.Fatal("an overrunning worker should be killed and return an error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("worker was not killed promptly (%s)", time.Since(start))
	}
}

func TestExecDriverRejectsMalformedOutput(t *testing.T) {
	stub := writeStub(t, `process.stdout.write("not json");`)
	_, err := NewExecDriver("node", stub).Run(context.Background(), Script{Name: "x", StartURL: "http://x", Steps: []Step{{Action: Screenshot}}})
	if err == nil {
		t.Fatal("malformed worker output should error")
	}
}

// The Fleet drives the exec driver end-to-end through a stub, storing the artifact.
func TestFleetWithExecDriverStub(t *testing.T) {
	pngB64 := base64.StdEncoding.EncodeToString([]byte("PNG"))
	stub := writeStub(t, `
import { readFileSync } from "node:fs";
try { readFileSync(0, "utf8"); } catch {}
process.stdout.write(JSON.stringify({ success:false, error:"boom", total_ms:5, steps:[], waterfall:[], dom:{}, screenshot_b64:"`+pngB64+`", screenshot_content_type:"image/png" }));
`)
	store := objectstore.NewMemory()
	fleet := NewFleet(Config{MaxConcurrency: 1}, func() Driver { return NewExecDriver("node", stub) }, store, quiet())
	defer fleet.Close()
	res, err := fleet.Run(context.Background(), "t1", Script{Name: "x", StartURL: "http://x", Steps: []Step{{Action: Screenshot}}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Success || res.Screenshot == nil {
		t.Fatalf("expected failure with artifact: %+v", res)
	}
	if store.Len() != 1 {
		t.Fatalf("artifact not stored (len=%d)", store.Len())
	}
}
