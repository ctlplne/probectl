// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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

// WEB-17: embed `dist`, NOT `all:dist`. The `all:` prefix pulls in dotfiles,
// which in a real Vite build includes dist/.vite/manifest.json — a build-metadata
// file that then became reachable at GET /ui/.vite/manifest.json. The SPA needs
// only its normal-named assets under dist/assets/, so dropping `all:` keeps the
// manifest out of the binary entirely (the handler's dot-segment guard is the
// defense in depth).
//
//go:embed dist
var dist embed.FS

// built reports whether a REAL UI bundle is embedded (a built asset other than
// the placeholder index.html is present). The release build makes this true.
func built() bool {
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
	return handlerFS(prefix, sub)
}

// handlerFS is the serving logic over an arbitrary file system, so the fallback
// and dot-segment rules are testable without a real embedded build.
func handlerFS(prefix string, sub fs.FS) http.Handler {
	fileServer := http.StripPrefix(prefix, http.FileServer(http.FS(sub)))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SPA fallback: serve index.html for paths that aren't real files, so a
		// deep link (/ui/incidents/42) loads the app instead of 404ing.
		rel := strings.TrimPrefix(r.URL.Path, prefix)
		if rel == "" || rel == "/" {
			serveIndex(w, r, sub)
			return
		}
		clean := strings.TrimPrefix(rel, "/")
		// WEB-17: never serve a dot-prefixed path segment (build metadata such as
		// .vite/manifest.json, or any future dotfile) — fall back to the SPA shell.
		// A real SPA asset path never starts a segment with a dot.
		if hasDotSegment(clean) {
			serveIndex(w, r, sub)
			return
		}
		if _, err := fs.Stat(sub, clean); err != nil {
			serveIndex(w, r, sub)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

// hasDotSegment reports whether any path segment begins with a dot.
func hasDotSegment(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if strings.HasPrefix(seg, ".") {
			return true
		}
	}
	return false
}

func serveIndex(w http.ResponseWriter, _ *http.Request, sub fs.FS) {
	b, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.Error(w, "ui not available", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// WEB-16: the app shell is per-session and must not be cached; isolate the
	// browsing context (COOP) and refuse cross-origin embedding of the document
	// (CORP). The RUM script and beacon ingest are served elsewhere and stay
	// cross-origin by design.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	_, _ = w.Write(b)
}
