// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package webui

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

// WEB-17: a real Vite build writes dist/.vite/manifest.json; with all:dist it
// was embedded and served at GET /ui/.vite/manifest.json, leaking build
// metadata. The handler must fall back to the SPA shell for any dot-prefixed
// path segment, and normal assets must still be served.
func TestDotfilePathsFallBackToSPA(t *testing.T) {
	sub := fs.FS(fstest.MapFS{
		"index.html":          {Data: []byte("<!doctype html><html>app shell</html>")},
		"assets/index-abc.js": {Data: []byte("console.log('real asset')")},
		".vite/manifest.json": {Data: []byte(`{"index.html":{"file":"assets/index-abc.js"}}`)},
	})
	h := handlerFS("/ui/", sub)

	// The build-metadata dotfile must NOT be served — SPA fallback instead.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/.vite/manifest.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ui/.vite/manifest.json = %d, want 200 fallback", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("manifest path served as %q, want the HTML SPA shell", ct)
	}
	if strings.Contains(rec.Body.String(), "assets/index-abc.js") && strings.Contains(rec.Body.String(), "\"file\"") {
		t.Fatalf("manifest JSON leaked at /ui/.vite/manifest.json: %s", rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "app shell") {
		t.Fatalf("expected the SPA shell, got: %s", rec.Body)
	}

	// A normal hashed asset is still served as itself.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ui/assets/index-abc.js", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "real asset") {
		t.Fatalf("normal asset must be served, got %d %s", rec.Code, rec.Body)
	}
}
