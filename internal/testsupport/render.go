// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testsupport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// RenderSpec is one page of a live control plane to render in a real
// Chromium as a signed-in user (scripts/realstack_render.mjs).
type RenderSpec struct {
	URL       string         `json:"url"`
	Cookies   []RenderCookie `json:"cookies"`
	Expect    []string       `json:"expect"`
	Absent    []string       `json:"absent"`
	Steps     []RenderStep   `json:"steps,omitempty"`
	TimeoutMs int            `json:"timeoutMs"`
}

// RenderStep clicks the one control with Role (default "button") and the exact
// accessible name Click, then waits for every Expect text and, when Gone is
// set, for that control to leave the page (the UI re-rendered from the
// server's answer). An ambiguous or missing control fails the render instead
// of clicking a guess.
type RenderStep struct {
	Click  string   `json:"click"`
	Role   string   `json:"role,omitempty"`
	Expect []string `json:"expect,omitempty"`
	Gone   bool     `json:"gone,omitempty"`
}

// RenderCookie is a cookie set on the page's origin before it loads.
type RenderCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// RenderResult is what the browser saw: expected text that never rendered,
// forbidden text that did, and the page's rendered body text.
type RenderResult struct {
	Missing []string `json:"missing"`
	Present []string `json:"present"`
	Title   string   `json:"title"`
	URL     string   `json:"url"`
	Errors  []string `json:"errors"`
	Text    string   `json:"text"`
}

// placeholderMarker identifies the ARCH-004 placeholder index.html the control
// plane embeds when the web bundle was not built into internal/webui/dist.
const placeholderMarker = "ARCH-004 placeholder"

// RenderUI renders spec.URL in a real Chromium against the live server and
// fails the test unless every Expect text renders and no Absent text does.
// It needs the real web bundle embedded in the control plane (CI overlays
// web/dist onto internal/webui/dist before the integration build, as the
// release image does), node, and the browser-worker's pinned Playwright with a
// Chromium; a missing piece is SkipOrFatal, so the integration lane fails
// rather than silently skipping a rendered-UI receipt.
func RenderUI(t testing.TB, spec RenderSpec) RenderResult {
	t.Helper()
	if embedsPlaceholderUI(t, spec.URL) {
		SkipOrFatal(t, "the control plane embeds the placeholder UI: build web/ and overlay web/dist onto internal/webui/dist before compiling (CI does this; locally: npm --prefix web run build && cp -R web/dist/. internal/webui/dist/)")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		SkipOrFatal(t, "node is unavailable for the rendered-UI receipt: %v", err)
	}
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	if spec.TimeoutMs == 0 {
		spec.TimeoutMs = 30000
	}
	in, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(spec.TimeoutMs)*time.Millisecond+90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, filepath.Join(root, "scripts", "realstack_render.mjs"))
	cmd.Stdin = bytes.NewReader(in)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := stderr.String()
		if strings.Contains(msg, "Executable doesn't exist") || strings.Contains(msg, "is not installed") || strings.Contains(msg, "Cannot find module") {
			SkipOrFatal(t, "no Chromium for the rendered-UI receipt (CI: npx playwright install --with-deps chromium in browser-worker; locally set PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH): %s", msg)
		}
		t.Fatalf("render %s: %v\n%s", spec.URL, err, msg)
	}
	var res RenderResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		t.Fatalf("decode render result: %v\n%s", err, stdout.String())
	}
	if len(res.Missing) > 0 || len(res.Present) > 0 {
		t.Fatalf("rendered %s (%q): missing %q, must-not-render %q present, page errors %q\nrendered text:\n%s",
			spec.URL, res.Title, res.Missing, res.Present, res.Errors, res.Text)
	}
	return res
}

// embedsPlaceholderUI reports whether the page the receipt is about to render
// is the placeholder, not the real single-page app.
func embedsPlaceholderUI(t testing.TB, pageURL string) bool {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, pageURL, nil)
	if err != nil {
		t.Fatalf("render url %s: %v", pageURL, err)
	}
	resp, err := crypto.HardenedHTTPClient(30 * time.Second).Do(req)
	if err != nil {
		t.Fatalf("fetch %s: %v", pageURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return strings.Contains(string(body), placeholderMarker)
}

// repoRoot is the module root (the directory holding go.mod).
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
