package auth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// mockIDP is a minimal OIDC identity provider for tests: it serves a discovery
// document, a JWKS built from the test key, and a token endpoint that returns a
// signed ID token. The signing key comes from a static PEM fixture, so the test
// performs no key generation and imports no crypto primitive (x509 + go-jose
// only — the FIPS guard stays green).
type mockIDP struct {
	srv      *httptest.Server
	signer   jose.Signer
	clientID string
	issuer   string
	// claims overrides for the next minted token.
	sub, email, name string
}

func newMockIDP(t *testing.T, clientID string) *mockIDP {
	t.Helper()
	pemBytes, err := os.ReadFile("testdata/oidc_test_key.pem")
	if err != nil {
		t.Fatalf("read key fixture: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("decode PEM fixture")
	}
	// x509 is allowed by the crypto guard; the returned type is *rsa.PrivateKey
	// without this file importing crypto/rsa.
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
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
	}

	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: "test", Use: "sig", Algorithm: "RS256",
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
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResp(w, map[string]any{
			"access_token": "at",
			"token_type":   "Bearer",
			"id_token":     idp.mintIDToken(t),
		})
	})

	idp.srv = httptest.NewServer(mux)
	idp.issuer = idp.srv.URL
	t.Cleanup(idp.srv.Close)
	return idp
}

func (m *mockIDP) mintIDToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	claims := map[string]any{
		"iss":   m.issuer,
		"sub":   m.sub,
		"aud":   m.clientID,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
		"email": m.email,
		"name":  m.name,
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
	idp := newMockIDP(t, "netctl-client")
	ctx := context.Background()

	prov, err := NewOIDCProvider(ctx, OIDCConfig{
		Issuer:      idp.issuer,
		ClientID:    "netctl-client",
		RedirectURL: "https://netctl.example/auth/callback",
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	// AuthCodeURL carries the CSRF state, the nonce, and the client config.
	u := prov.AuthCodeURL("state-xyz", "nonce-abc")
	for _, want := range []string{"state=state-xyz", "nonce=nonce-abc", "client_id=netctl-client", "response_type=code"} {
		if !strings.Contains(u, want) {
			t.Errorf("auth URL missing %q: %s", want, u)
		}
	}

	// Exchange a code → verified identity from the signed ID token.
	id, err := prov.Exchange(ctx, "any-code")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if id.Subject != "user-123" || id.Email != "alice@example.com" || id.DisplayName != "Alice Example" {
		t.Fatalf("wrong identity: %+v", id)
	}
}

func TestOIDCProviderRejectsWrongAudience(t *testing.T) {
	idp := newMockIDP(t, "someone-else") // token aud != our client ID
	ctx := context.Background()
	prov, err := NewOIDCProvider(ctx, OIDCConfig{Issuer: idp.issuer, ClientID: "netctl-client"})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}
	if _, err := prov.Exchange(ctx, "code"); err == nil {
		t.Fatal("expected verification failure for mismatched audience")
	}
}
