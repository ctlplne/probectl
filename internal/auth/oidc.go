package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
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

// AuthCodeURL returns the IdP authorization URL carrying the CSRF state + nonce.
func (p *oidcProvider) AuthCodeURL(state, nonce string) string {
	return p.oauth.AuthCodeURL(state, oidc.Nonce(nonce))
}

// Exchange swaps the authorization code for tokens, verifies the ID token, and
// returns the end-user identity.
func (p *oidcProvider) Exchange(ctx context.Context, code string) (*Identity, error) {
	tok, err := p.oauth.Exchange(ctx, code)
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
		Subject           string `json:"sub"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("oidc: parse claims: %w", err)
	}
	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}
	return &Identity{Subject: claims.Subject, Email: claims.Email, DisplayName: name}, nil
}
