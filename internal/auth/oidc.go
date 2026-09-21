// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/ctlplne/probectl/internal/crypto"
)

// OIDCConfig configures one tenant's OIDC identity provider.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// oidcProvider runs the OIDC authorization-code flow and verifies the ID token.
// All cryptographic verification lives inside go-oidc / go-jose (a FIPS Go build
// swaps their primitives), so this package imports no crypto primitive directly.
type oidcProvider struct {
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewOIDCProvider discovers the IdP metadata and builds a provider. It touches the
// network at construction (fetching the discovery document + JWKS).
func NewOIDCProvider(ctx context.Context, c OIDCConfig) (Provider, error) {
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
		Subject:      claims.Subject,
		Email:        claims.Email,
		DisplayName:  name,
		TimeZone:     claims.ZoneInfo,
		Locale:       claims.Locale,
		MFASatisfied: mfaFromAuthContext(claims.AMR, claims.ACR),
		Nonce:        idToken.Nonce,
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
