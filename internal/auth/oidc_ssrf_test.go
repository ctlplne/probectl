// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// TestNewOIDCProviderRefusesLoopbackIssuerBeforeConnect proves INJ-04: OIDC
// discovery against an issuer whose host resolves into reserved space (here a
// real loopback listener) is refused by the SSRF guard BEFORE the socket opens.
// The listener stands in for any issuer DNS that resolves to loopback/link-local/
// RFC1918/metadata; the load-bearing assertion is that no connection is ever
// accepted. On 72e7a2b discovery used http.DefaultClient, which connects (the
// listener accepts) — RED; with crypto.GuardedHTTPClient wired into discovery the
// RESOLVED loopback address is refused at dial time — GREEN.
func TestNewOIDCProviderRefusesLoopbackIssuerBeforeConnect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var accepted atomic.Bool
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Store(true)
			_ = c.Close()
		}
	}()

	issuer := "https://" + ln.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := NewOIDCProvider(ctx, OIDCConfig{Issuer: issuer, ClientID: "probectl-client"}); err == nil {
		t.Fatal("discovery to a loopback issuer must fail closed")
	}
	// Give any erroneously-dialed connection time to land before asserting.
	time.Sleep(100 * time.Millisecond)
	if accepted.Load() {
		t.Fatal("OIDC discovery opened a socket to the loopback issuer: the SSRF dial guard was bypassed")
	}
}

// TestNewOIDCProviderRefusesDiscoveryRedirectToReserved proves the redirect leg
// of INJ-04: discovery that is 302-redirected into link-local/metadata space is
// refused at the redirect hop, before the redirected request is dialed. The
// origin is a loopback httptest server, so discovery is pointed at the
// loopback-capable hardened client — which shares the exact redirect policy that
// crypto.GuardedHTTPClient enforces in production — and the hop into
// 169.254.169.254 must be rejected. (Pre-connect refusal of a reserved issuer
// itself is covered by TestNewOIDCProviderRefusesLoopbackIssuerBeforeConnect.)
//
// Existing-symbol RED overlay (on 72e7a2b, which has no discoveryHTTPClient seam
// and discovers via http.DefaultClient): drop the two seam-override lines; the
// default client follows the redirect and the error is a bare dial failure to
// 169.254.169.254 ("context deadline exceeded"), not a "redirect rejected"
// refusal — so the assertion fails RED.
func TestNewOIDCProviderRefusesDiscoveryRedirectToReserved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254"+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()

	prev := discoveryHTTPClient
	discoveryHTTPClient = func() *http.Client { return crypto.HardenedHTTPClient(oidcDiscoveryTimeout) }
	defer func() { discoveryHTTPClient = prev }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := NewOIDCProvider(ctx, OIDCConfig{Issuer: srv.URL, ClientID: "probectl-client"})
	if err == nil {
		t.Fatal("discovery following a redirect into link-local space must fail closed")
	}
	if !strings.Contains(err.Error(), "redirect rejected") {
		t.Fatalf("discovery error = %v, want the redirect-hop SSRF refusal (\"redirect rejected\")", err)
	}
}

// TestOIDCDiscoveryClientGuardsResolvedIP proves the production discovery client
// (crypto.GuardedHTTPClient, the default discoveryHTTPClient()) refuses a
// connection whose RESOLVED address is reserved, and leaves a public destination
// alone — the "normal public issuer path is unaffected" half of the acceptance.
func TestOIDCDiscoveryClientGuardsResolvedIP(t *testing.T) {
	c := discoveryHTTPClient()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	var accepted atomic.Bool
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Store(true)
			_ = conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+ln.Addr().String()+"/.well-known/openid-configuration", nil)
	if resp, err := c.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatal("guarded discovery client reached a loopback destination")
	}
	time.Sleep(50 * time.Millisecond)
	if accepted.Load() {
		t.Fatal("guarded discovery client opened a socket to the loopback destination")
	}

	// A public hostname is NOT refused by the dial guard itself: the guard only
	// inspects the resolved address, so the redirect policy must leave a
	// public→public hop alone (no false positive on the normal issuer path).
	target, _ := http.NewRequest(http.MethodGet, "https://login.example.net/jwks", nil)
	origin, _ := http.NewRequest(http.MethodGet, "https://idp.example.com/.well-known/openid-configuration", nil)
	if err := c.CheckRedirect(target, []*http.Request{origin}); err != nil {
		t.Fatalf("public→public redirect must be allowed, got %v", err)
	}
}
