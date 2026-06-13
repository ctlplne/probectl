// SPDX-License-Identifier: LicenseRef-probectl-TBD

package webui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ARCH-004: the embedded UI handler serves index.html at the prefix root and
// falls back to it for unknown (client-routed) paths, so a deep link loads the
// app instead of 404ing.
func TestHandlerServesEmbeddedUI(t *testing.T) {
	h := Handler("/ui/")

	for _, path := range []string{"/ui/", "/ui/incidents/42"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "<html") {
			t.Fatalf("%s: did not serve the SPA index", path)
		}
	}
}

// UX-002: Built() must be HONEST — it returns true iff a REAL Vite bundle is
// embedded. We no longer t.Skip() the assertion (a skip let the stub pass as if
// it were the UI). Instead we assert each branch concretely:
//   - placeholder embedded → Built() is false AND index.html says so plainly;
//   - real bundle embedded → Built() is true AND a hashed assets/ file exists
//     AND index.html references it (proving it is not just a renamed stub).
//
// The release build (docker, `release` tag) makes Built() true; see
// TestRealBundleRequiredInReleaseBuild (embed_release_test.go).
func TestBuiltIsHonestAboutTheBundle(t *testing.T) {
	entries, err := fs.ReadDir(dist, "dist")
	if err != nil {
		t.Fatalf("read dist: %v", err)
	}

	idx, err := fs.ReadFile(dist, "dist/index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	index := string(idx)

	if !Built() {
		// Placeholder path: exactly index.html, and it must openly declare it is
		// not the real UI (no silently-served stub pretending to be the app).
		if len(entries) != 1 || entries[0].Name() != "index.html" {
			t.Fatalf("Built()==false but dist has %d entries (%v) — a non-placeholder asset is present; Built() is lying", len(entries), names(entries))
		}
		if !strings.Contains(index, "not bundled in this build") {
			t.Error("the placeholder index.html must plainly state the UI is not bundled (no silent stub)")
		}
		if strings.Contains(index, `<div id="root">`) {
			t.Error("placeholder must NOT masquerade as the real SPA shell (#root mount point present)")
		}
		return
	}

	// Real-bundle path: a hashed asset under assets/ must exist and index.html
	// must reference it — that is what distinguishes a real Vite build from a
	// stub that merely set Built()==true.
	assets, err := fs.ReadDir(dist, "dist/assets")
	if err != nil || len(assets) == 0 {
		t.Fatalf("Built()==true but dist/assets is empty/missing (%v) — not a real Vite bundle", err)
	}
	referenced := false
	for _, a := range assets {
		if strings.Contains(index, "/assets/"+a.Name()) {
			referenced = true
			break
		}
	}
	if !referenced {
		t.Error("Built()==true but index.html references no /assets/<hashed> file — bundle looks fake")
	}
	if !strings.Contains(index, `id="root"`) {
		t.Error("real bundle index.html should mount the SPA at #root")
	}
}

func names(entries []fs.DirEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}
