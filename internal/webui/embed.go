// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package webui embeds the built web UI (web/dist) into the control-plane
// binary so the documented quickstart serves a SCREEN, not just an API
// (ARCH-004). The control plane previously shipped no UI serving path at all —
// the getting-started doc implied a UI that nothing served. The Vite build
// (web/) outputs to web/dist; the release image's `web` stage runs `npm run
// build` and overlays that bundle onto internal/webui/dist BEFORE compiling the
// control plane (deploy/docker/Dockerfile), so shipped binaries embed the REAL
// UI and serve it behind the existing CSP. The committed placeholder keeps the
// embed (and the from-source build) green when the UI has not been bundled —
// and says so honestly rather than 404ing or masquerading as the app. A release
// build that still has only the placeholder fails the build-tagged guard
// TestRealBundleRequiredInReleaseBuild (UX-002), so the stub can never ship.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Built reports whether a REAL UI bundle is embedded (a built asset other than
// the placeholder index.html is present). The release build makes this true.
func Built() bool {
	entries, err := fs.ReadDir(dist, "dist")
	if err != nil {
		return false
	}
	for _, e := range entries {
		// The placeholder ships only index.html; any other asset (the Vite
		// build emits hashed assets/) means a real bundle is present.
		if e.Name() != "index.html" {
			return true
		}
	}
	return false
}

// Handler serves the embedded SPA with history-API fallback (unknown paths
// return index.html so client-side routing works). It is mounted behind the
// server's CSP + security headers, so it inherits the no-third-party-calls
// posture (guardrail 11). Mount it under a prefix (e.g. "/ui/").
func Handler(prefix string) http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return http.NotFoundHandler()
	}
	fileServer := http.StripPrefix(prefix, http.FileServer(http.FS(sub)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SPA fallback: serve index.html for paths that aren't real files, so a
		// deep link (/ui/incidents/42) loads the app instead of 404ing.
		rel := strings.TrimPrefix(r.URL.Path, prefix)
		if rel == "" || rel == "/" {
			serveIndex(w, r, sub)
			return
		}
		if _, err := fs.Stat(sub, strings.TrimPrefix(rel, "/")); err != nil {
			serveIndex(w, r, sub)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, sub fs.FS) {
	b, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.Error(w, "ui not available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}
