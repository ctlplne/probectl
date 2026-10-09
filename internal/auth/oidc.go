// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/ctlplne/probectl/internal/crypto"
)

// oidcDiscoveryTimeout bounds each outbound IdP round-trip (the discovery
// document fetch, the JWKS fetch, and the token exchange).
const oidcDiscoveryTimeout = 20 * time.Second

// discoveryHTTPClient builds the HTTP client used for every outbound call to a
// tenant-configured IdP. The issuer URL is tenant-controlled and the discovery
// document's token_endpoint/jwks_uri are IdP-returned, so this fetched content
// is untrusted (docs/guardrails.md G7-10): the default is the SSRF-guarded,
// certificate-hardened client from internal/crypto. Its dialer refuses a
// connection whose RESOLVED address is loopback/link-local/metadata/RFC1918/ULA/
// CGNAT/unspecified/multicast BEFORE the socket opens and re-checks every
// redirect hop over the hardened TLS policy, so a tenant-set issuer that
// resolves into reserved space cannot drive the control plane into SSRF (INJ-04;
// missing/forbidden target → fail closed, docs/guardrails.md G7-12). It is a
// package var only so a test can point discovery at a loopback mock IdP;
// production never reassigns it.
var discoveryHTTPClient = func() *http.Client { return crypto.GuardedHTTPClient(oidcDiscoveryTimeout) }

// OIDCConfig configures one tenant's OIDC identity provider.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	// HTTPClient carries every outbound call to the IdP (discovery, JWKS, the
	// code exchange). Nil — always the case for a tenant-configured issuer —
	// means the SSRF-guarded client. Only the operator's own deployment IdP
	// sets it, to DeploymentIDPClient (see there).
	HTTPClient *http.Client
}

// DeploymentIDPClient is the outbound client for the DEPLOYMENT IdP
// (PROBECTL_OIDC_ISSUER): hardened, certificate-validating TLS that trusts the
// operator's optional CA bundle (PROBECTL_OIDC_CA_FILE), without the private-
// address refusal of the SSRF-guarded client. That guard exists because a
// tenant-configured issuer is tenant input (INJ-04); the deployment issuer is
// the operator's own configuration, and a self-hosted, air-gapped IdP lives on
// the operator's own network — loopback, RFC1918 or in-cluster DNS. Tenant
// issuers never get this client.
func DeploymentIDPClient(caFile string) (*http.Client, error) {
	return crypto.HardenedHTTPClientWithCAFile(oidcDiscoveryTimeout, caFile)
}

// oidcProvider runs the OIDC authorization-code flow and verifies the ID token.
// All cryptographic verification lives inside go-oidc / go-jose (a FIPS Go build
// swaps their primitives), so this package imports no crypto primitive directly.
type oidcProvider struct {
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
	client   *http.Client
}

// NewOIDCProvider discovers the IdP metadata and builds a provider. It touches the
// network at construction (fetching the discovery document + JWKS).
func NewOIDCProvider(ctx context.Context, c OIDCConfig) (Provider, error) {
	// INJ-04: a tenant-controlled issuer must be discovered through the
	// SSRF-guarded, certificate-hardened client — not http.DefaultClient — or an
	// issuer that resolves to a private/loopback/link-local/metadata address would
	// let the control plane be driven into SSRF (docs/guardrails.md G7-10, G7-12).
	// Only the operator's deployment IdP arrives with its own client.
	client := c.HTTPClient
	if client == nil {
		client = discoveryHTTPClient()
	}
	ctx = oidc.ClientContext(ctx, client)
	idp, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc: discover issuer %q: %w", c.Issuer, err)
	}
	scopes := c.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	return &oidcProvider{
		oauth: &oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			RedirectURL:  c.RedirectURL,
			Endpoint:     idp.Endpoint(),
			Scopes:       scopes,
		},
		verifier: idp.Verifier(&oidc.Config{ClientID: c.ClientID}),
		client:   client,
	}, nil
}

// AuthCodeURL returns the IdP authorization URL carrying CSRF state, nonce, and
// an RFC 7636 S256 PKCE challenge. Challenge derivation stays behind
// internal/crypto so the FIPS-swappable provider owns SHA-256.
func (p *oidcProvider) AuthCodeURL(state, nonce, codeVerifier string) string {
	return p.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", crypto.PKCEChallengeS256(codeVerifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange swaps the authorization code for tokens, verifies the ID token, and
// returns the end-user identity.
func (p *oidcProvider) Exchange(ctx context.Context, code, codeVerifier string) (*Identity, error) {
	if codeVerifier == "" {
		return nil, fmt.Errorf("oidc: PKCE code verifier is required")
	}
	// INJ-04: the token and JWKS endpoints are taken from the (untrusted) discovery
	// document, so the code exchange and ID-token verification use the same
	// client as discovery — SSRF-guarded for a tenant issuer (oidc.ClientContext
	// sets the oauth2 HTTP client, which both the token exchange and the
	// verifier's JWKS fetch read).
	ctx = oidc.ClientContext(ctx, p.client)
	tok, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(codeVerifier))
	if err != nil {
		return nil, fmt.Errorf("oidc: code exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("oidc: response had no id_token")
	}
	idToken, err := p.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("oidc: verify id_token: %w", err)
	}
	var claims struct {
		Subject           string   `json:"sub"`
		Email             string   `json:"email"`
		EmailVerified     *bool    `json:"email_verified"` // AUTHZ-03: nil when absent
		Name              string   `json:"name"`
		PreferredUsername string   `json:"preferred_username"`
		ZoneInfo          string   `json:"zoneinfo"`
		Locale            string   `json:"locale"`
		AMR               []string `json:"amr"` // RFC 8176 authentication methods
		ACR               string   `json:"acr"` // authentication context class
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: parse claims: %w", err)
	}
	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}
	return &Identity{
		Subject: claims.Subject,
		// AUTHZ-03: idToken.Issuer is the `iss` the verifier already checked
		// against the configured issuer, so it is the trustworthy binding key.
		Issuer:        idToken.Issuer,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		DisplayName:   name,
		TimeZone:      claims.ZoneInfo,
		Locale:        claims.Locale,
		MFASatisfied:  mfaFromAuthContext(claims.AMR, claims.ACR),
		Nonce:         idToken.Nonce,
	}, nil
}

// secondFactorAMR is the set of RFC 8176 amr values that assert a SECOND factor
// (SEC-005) — "mfa" itself, plus the strong-factor methods (a one-time code,
// hardware/software key, biometric, SMS/phone, proof-of-possession). "pwd",
// "pin", "kba", "geo", "rba", "user" alone are NOT a second factor.
var secondFactorAMR = map[string]bool{
	"mfa": true, "otp": true, "hwk": true, "swk": true, "sms": true, "tel": true,
	"phr": true, "phrh": true, "fpt": true, "face": true, "iris": true, "retina": true,
	"vbm": true, "pop": true, "mca": true, "sc": true,
}

// mfaFromAuthContext reports whether the ID token's authentication-context
// claims assert multi-factor authentication. amr (RFC 8176) is authoritative:
// any second-factor method (or the explicit "mfa") satisfies it. acr is a
// secondary hint — a level-of-assurance naming mfa/aal2+/loa2+.
func mfaFromAuthContext(amr []string, acr string) bool {
	for _, m := range amr {
		if secondFactorAMR[strings.ToLower(strings.TrimSpace(m))] {
			return true
		}
	}
	la := strings.ToLower(strings.TrimSpace(acr))
	return strings.Contains(la, "mfa") || strings.Contains(la, "aal2") ||
		strings.Contains(la, "aal3") || strings.Contains(la, "loa2") || strings.Contains(la, "loa3")
}
