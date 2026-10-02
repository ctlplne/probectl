// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"context"
	stdcrypto "crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/ctlplne/probectl/internal/crypto"
)

// mockIDP is a minimal OIDC identity provider for tests: it serves a discovery
// document, a JWKS built from the test key, and a token endpoint that returns a
// signed ID token. The signing key is GENERATED at test setup via
// internal/crypto.GenerateRSAKeyPEM (CODE-006: no committed key fixture, ever),
// so this file still imports no crypto primitive (x509 + go-jose only — the
// FIPS guard stays green).
type mockIDP struct {
	srv      *httptest.Server
	signer   jose.Signer
	clientID string
	issuer   string
	// claims overrides for the next minted token.
	sub, email, name, zoneinfo, locale string
	tokenCodeVerifier                  string
	// emailVerified, when non-nil, is emitted as the email_verified claim
	// (AUTHZ-03). nil omits the claim entirely.
	emailVerified *bool
}

func newMockIDP(t *testing.T, clientID string) *mockIDP {
	t.Helper()
	pemBytes, err := crypto.GenerateRSAKeyPEM(2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("decode generated PEM")
	}
	// x509 is allowed by the crypto guard; the parsed type reaches go-jose
	// without this file importing crypto/rsa.
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: priv, KeyID: "test"}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	idp := &mockIDP{
		signer:   signer,
		clientID: clientID,
		sub:      "user-123",
		email:    "alice@example.com",
		name:     "Alice Example",
		zoneinfo: "America/New_York",
		locale:   "en-US",
	}

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: priv.(stdcrypto.Signer).Public(), KeyID: "test", Use: "sig", Algorithm: "RS256",
	}}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResp(w, map[string]any{
			"issuer":                                idp.issuer,
			"authorization_endpoint":                idp.issuer + "/authorize",
			"token_endpoint":                        idp.issuer + "/token",
			"jwks_uri":                              idp.issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) { writeJSONResp(w, jwks) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse token form: %v", err)
		}
		idp.tokenCodeVerifier = r.Form.Get("code_verifier")
		writeJSONResp(w, map[string]any{
			"access_token": "at",
			"token_type":   "Bearer",
			"id_token":     idp.mintIDToken(t),
		})
	})

	idp.srv = httptest.NewServer(mux)
	idp.issuer = idp.srv.URL
	t.Cleanup(idp.srv.Close)

	// The mock IdP binds to loopback (httptest), which the production SSRF guard
	// (INJ-04) refuses at dial time. For these behavioral tests, point OIDC
	// discovery/exchange at the loopback-capable — but still certificate-hardened
	// and redirect-guarded — client; the SSRF dial guard itself is exercised by
	// the dedicated tests in oidc_ssrf_test.go.
	prev := discoveryHTTPClient
	discoveryHTTPClient = func() *http.Client { return crypto.HardenedHTTPClient(oidcDiscoveryTimeout) }
	t.Cleanup(func() { discoveryHTTPClient = prev })
	return idp
}

func (m *mockIDP) mintIDToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss":      m.issuer,
		"sub":      m.sub,
		"aud":      m.clientID,
		"exp":      now.Add(time.Hour).Unix(),
		"iat":      now.Unix(),
		"email":    m.email,
		"name":     m.name,
		"zoneinfo": m.zoneinfo,
		"locale":   m.locale,
		"nonce":    "nonce-abc", // SEC-004: surfaced as Identity.Nonce
	}
	if m.emailVerified != nil {
		claims["email_verified"] = *m.emailVerified // AUTHZ-03
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := m.signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	tok, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return tok
}

func writeJSONResp(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestOIDCProviderExchange(t *testing.T) {
	idp := newMockIDP(t, "probectl-client")
	ctx := context.Background()

	prov, err := NewOIDCProvider(ctx, OIDCConfig{
		Issuer:      idp.issuer,
		ClientID:    "probectl-client",
		RedirectURL: "https://probectl.example/auth/callback",
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	// RFC 7636 Appendix B vector: authorization carries only the S256
	// challenge, while token exchange carries the original verifier.
	const codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const codeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	u := prov.AuthCodeURL("state-xyz", "nonce-abc", codeVerifier)
	for _, want := range []string{"state=state-xyz", "nonce=nonce-abc", "client_id=probectl-client", "response_type=code"} {
		if !strings.Contains(u, want) {
			t.Errorf("auth URL missing %q: %s", want, u)
		}
	}
	if !strings.Contains(u, "code_challenge="+codeChallenge) || !strings.Contains(u, "code_challenge_method=S256") {
		t.Fatalf("auth URL missing RFC 7636 S256 challenge: %s", u)
	}
	if strings.Contains(u, "code_verifier") || strings.Contains(u, codeVerifier) {
		t.Fatalf("authorization URL leaked the PKCE verifier: %s", u)
	}

	// Exchange a code → verified identity from the signed ID token.
	id, err := prov.Exchange(ctx, "any-code", codeVerifier)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if id.Subject != "user-123" || id.Email != "alice@example.com" || id.DisplayName != "Alice Example" {
		t.Fatalf("wrong identity: %+v", id)
	}
	if id.TimeZone != "America/New_York" || id.Locale != "en-US" {
		t.Fatalf("wrong preferences: timezone=%q locale=%q", id.TimeZone, id.Locale)
	}
	// SEC-004: the ID token's nonce claim surfaces on the identity so the
	// callback can enforce it against the login-minted value.
	if id.Nonce != "nonce-abc" {
		t.Fatalf("Identity.Nonce = %q, want the token's nonce claim", id.Nonce)
	}
	if idp.tokenCodeVerifier != codeVerifier {
		t.Fatalf("token endpoint code_verifier = %q, want login verifier", idp.tokenCodeVerifier)
	}
}

// AUTHZ-03: Exchange surfaces the verified issuer and the email_verified claim
// so the callback can bind on the stable (iss, sub) pair and refuse an
// IdP-unverified email. go-oidc already verifies `iss` against discovery.
func TestOIDCProviderSurfacesIssuerAndEmailVerified(t *testing.T) {
	ctx := context.Background()

	t.Run("verified_true", func(t *testing.T) {
		idp := newMockIDP(t, "probectl-client")
		idp.emailVerified = func(b bool) *bool { return &b }(true)
		prov, err := NewOIDCProvider(ctx, OIDCConfig{Issuer: idp.issuer, ClientID: "probectl-client"})
		if err != nil {
			t.Fatal(err)
		}
		id, err := prov.Exchange(ctx, "code", "verifier")
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if id.Issuer != idp.issuer {
			t.Fatalf("Identity.Issuer = %q, want the verified issuer %q", id.Issuer, idp.issuer)
		}
		if id.EmailVerified == nil || !*id.EmailVerified {
			t.Fatalf("Identity.EmailVerified = %v, want true", id.EmailVerified)
		}
	})

	t.Run("verified_false", func(t *testing.T) {
		idp := newMockIDP(t, "probectl-client")
		idp.emailVerified = func(b bool) *bool { return &b }(false)
		prov, err := NewOIDCProvider(ctx, OIDCConfig{Issuer: idp.issuer, ClientID: "probectl-client"})
		if err != nil {
			t.Fatal(err)
		}
		id, err := prov.Exchange(ctx, "code", "verifier")
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if id.EmailVerified == nil || *id.EmailVerified {
			t.Fatalf("Identity.EmailVerified = %v, want false", id.EmailVerified)
		}
	})

	t.Run("absent_is_nil", func(t *testing.T) {
		idp := newMockIDP(t, "probectl-client") // no email_verified claim
		prov, err := NewOIDCProvider(ctx, OIDCConfig{Issuer: idp.issuer, ClientID: "probectl-client"})
		if err != nil {
			t.Fatal(err)
		}
		id, err := prov.Exchange(ctx, "code", "verifier")
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if id.EmailVerified != nil {
			t.Fatalf("Identity.EmailVerified = %v, want nil for an absent claim", *id.EmailVerified)
		}
	})
}

func TestOIDCProviderRejectsWrongAudience(t *testing.T) {
	idp := newMockIDP(t, "someone-else") // token aud != our client ID
	ctx := context.Background()
	prov, err := NewOIDCProvider(ctx, OIDCConfig{Issuer: idp.issuer, ClientID: "probectl-client"})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	if _, err := prov.Exchange(ctx, "code", "verifier"); err == nil {
		t.Fatal("expected verification failure for mismatched audience")
	}
}

func TestOIDCProviderRejectsMissingPKCEVerifier(t *testing.T) {
	idp := newMockIDP(t, "probectl-client")
	prov, err := NewOIDCProvider(context.Background(), OIDCConfig{Issuer: idp.issuer, ClientID: "probectl-client"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prov.Exchange(context.Background(), "code", ""); err == nil || !strings.Contains(err.Error(), "PKCE") {
		t.Fatalf("missing verifier must fail closed, got %v", err)
	}
}
