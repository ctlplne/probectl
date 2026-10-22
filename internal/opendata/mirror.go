// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Mirror rewrites a feed's canonical public endpoint to an operator-hosted or
// file:// mirror, so threat-intel and outage feeds load on an air-gapped
// deployment with NO outbound internet call (docs/guardrails.md G7-2). The
// zero value is DISABLED — canonical URLs are used unchanged, behavior is
// identical to before. A mirrored body is still UNTRUSTED (parsed defensively
// by each feed), cached by the refresher, and degrades gracefully (G7-10); an
// http(s) mirror is fetched over the hardened, certificate-validating client
// (G7-12), while a file:// mirror is read from the local filesystem.
type Mirror struct {
	base string // "" = disabled; file:///dir, /abs/dir (→ file://), or https://host/path
}

// NewMirror builds a mirror from an operator-configured base location. base is
// empty (disabled), a file:// URL or absolute local directory path (air-gap,
// fully offline), or an operator-hosted http(s) base URL. A bare absolute path
// is normalised to a file:// URL.
func NewMirror(base string) Mirror {
	base = strings.TrimSpace(base)
	if base == "" {
		return Mirror{}
	}
	if !strings.Contains(base, "://") {
		// A bare local directory path → file:// URL (absolute expected).
		base = "file://" + base
	}
	return Mirror{base: strings.TrimRight(base, "/")}
}

// Enabled reports whether a mirror is configured.
func (m Mirror) Enabled() bool { return m.base != "" }

// Resolve returns the mirror endpoint for a named source (mirrored at
// <base>/<source>), or the canonical URL unchanged when the mirror is
// disabled. source is the stable feed name (e.g. "spamhaus_drop", "ioda").
func (m Mirror) Resolve(source, canonical string) string {
	if m.base == "" {
		return canonical
	}
	return m.base + "/" + source
}

// Client wraps a network Doer so a file:// mirror URL is served from the local
// filesystem (no network) while an http(s) mirror URL goes through the
// hardened client. When the mirror is disabled it returns net unchanged (a nil
// net stays nil, so the caller applies its own hardened default — behavior is
// identical to before).
func (m Mirror) Client(net Doer) Doer {
	if !m.Enabled() {
		return net
	}
	if net == nil {
		net = defaultIntelClient()
	}
	return mirrorDoer{net: net, root: m.fileRoot()}
}

// fileRoot is the local directory a file:// mirror serves, cleaned, or "" when
// the mirror is an http(s) base and so has no local files.
func (m Mirror) fileRoot() string {
	u, err := url.Parse(m.base)
	if err != nil || !strings.EqualFold(u.Scheme, "file") || u.Path == "" {
		return ""
	}
	return filepath.Clean(filepath.FromSlash(u.Path))
}

// mirrorDoer serves file:// requests from the mirror directory and delegates
// everything else to a hardened HTTP Doer. It holds no bare http.Client — the
// network side is the injected hardened client (U-036 egress ratchet).
type mirrorDoer struct {
	net  Doer
	root string // the file:// mirror directory; "" for an http(s) mirror
}

func (d mirrorDoer) Do(req *http.Request) (*http.Response, error) {
	if req != nil && req.URL != nil && strings.EqualFold(req.URL.Scheme, "file") {
		return readFileResponse(d.root, req)
	}
	return d.net.Do(req)
}

// readFileResponse serves a file:// request from the mirror directory root.
// Any query string (the feed adapters append one) is ignored — a static mirror
// file holds the whole dataset. The request path must resolve inside root: a
// path that climbs out with "..", or names a file elsewhere on the host, is
// refused before anything is opened, so a mirror request reads only the
// operator's mirror. The body stays UNTRUSTED and is size-capped by the
// caller's LimitReader; a missing file returns a transport-shaped error so the
// refresher records the failure and keeps last-good (graceful degradation,
// docs/guardrails.md G7-10).
func readFileResponse(root string, req *http.Request) (*http.Response, error) {
	rel, err := mirrorRelPath(root, req.URL.Path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(root, rel))
	if err != nil {
		return nil, fmt.Errorf("opendata mirror: open %q: %w", req.URL.Path, err)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       f,
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// mirrorRelPath resolves a file:// request path against the mirror directory
// and returns it relative to that directory. The cleaned path is made relative
// with filepath.Rel, so anything outside root comes back as a ".." path (or an
// error) and fails filepath.IsLocal, which also refuses absolute and empty
// paths. Without a local directory every file:// request is refused.
func mirrorRelPath(root, reqPath string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("opendata mirror: refusing %q: the mirror has no local directory", reqPath)
	}
	rel, err := filepath.Rel(root, filepath.Clean(filepath.FromSlash(reqPath)))
	if err != nil || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("opendata mirror: refusing %q: outside the mirror directory", reqPath)
	}
	return rel, nil
}
