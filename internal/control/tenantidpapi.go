// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type tenantIDPResponse struct {
	Source                 string          `json:"source"`
	Configured             bool            `json:"configured"`
	Valid                  bool            `json:"valid"`
	Issuer                 string          `json:"issuer"`
	ClientID               string          `json:"client_id"`
	ClientSecretConfigured bool            `json:"client_secret_configured"`
	RedirectURL            string          `json:"redirect_url"`
	Scopes                 []string        `json:"scopes"`
	Enabled                bool            `json:"enabled"`
	Flags                  map[string]bool `json:"flags"`
}

type tenantIDPRequest struct {
	Issuer       string          `json:"issuer"`
	ClientID     string          `json:"client_id"`
	ClientSecret string          `json:"client_secret"`
	RedirectURL  string          `json:"redirect_url"`
	Scopes       []string        `json:"scopes"`
	Enabled      *bool           `json:"enabled"`
	Flags        map[string]bool `json:"flags"`
}

// handleTenantIDPGet returns only public configuration metadata. Neither the
// sealed value nor its plaintext is loaded on this admin read path.
func (s *Server) handleTenantIDPGet(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.NotFound("identity settings not available")
	}
	var settings *store.TenantIDP
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var getErr error
		settings, getErr = (store.TenantIDPs{}).GetScoped(ctx, sc, false)
		return getErr
	})
	if err == nil {
		writeJSON(w, http.StatusOK, tenantIDPResponseFromSettings(settings))
		return nil
	}
	if !errors.Is(err, store.ErrTenantIDPNotFound) {
		return apierror.Internal("failed to read tenant identity settings").Wrap(err)
	}
	writeJSON(w, http.StatusOK, s.environmentIDPResponse())
	return nil
}

// handleTenantIDPPut creates or replaces the caller tenant's IdP override. The
// secret is write-only; an empty value preserves an existing sealed secret.
func (s *Server) handleTenantIDPPut(w http.ResponseWriter, r *http.Request) error {
	if s.pool == nil {
		return apierror.NotFound("identity settings not available")
	}
	var in tenantIDPRequest
	if err := decodeJSON(r, &in); err != nil {
		return err
	}
	in.Issuer = strings.TrimSpace(in.Issuer)
	in.ClientID = strings.TrimSpace(in.ClientID)
	in.RedirectURL = strings.TrimSpace(in.RedirectURL)
	if in.ClientSecret != "" && strings.TrimSpace(in.ClientSecret) == "" {
		return apierror.Validation("client_secret cannot be blank")
	}
	in.Scopes = normalizeOIDCScopes(in.Scopes)
	if len(in.Scopes) == 0 {
		in.Scopes = []string{"openid", "email", "profile"}
	}
	if in.Flags == nil {
		in.Flags = map[string]bool{}
	}
	if len(in.Flags) > 32 {
		return apierror.Validation("OIDC flags cannot contain more than 32 entries")
	}
	if err := validateOIDCConfig(auth.OIDCConfig{
		Issuer: in.Issuer, ClientID: in.ClientID, ClientSecret: "preserved-or-new",
		RedirectURL: in.RedirectURL, Scopes: in.Scopes,
	}); err != nil {
		return apierror.Validation(err.Error())
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}

	var settings *store.TenantIDP
	err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		var upsertErr error
		settings, upsertErr = (store.TenantIDPs{}).UpsertScoped(ctx, sc, store.TenantIDPInput{
			Issuer: in.Issuer, ClientID: in.ClientID, ClientSecret: in.ClientSecret,
			RedirectURL: in.RedirectURL, Scopes: in.Scopes, Enabled: enabled, Flags: in.Flags,
		})
		if upsertErr != nil {
			return upsertErr
		}
		return s.recordAudit(ctx, sc, r, "identity.idp_update", sc.Tenant.String(), map[string]any{
			"issuer": in.Issuer, "enabled": enabled, "scopes": in.Scopes,
			"client_secret_rotated": in.ClientSecret != "",
		})
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrTenantIDPSecretRequired):
			return apierror.Validation("client_secret is required when creating a tenant IdP override")
		case errors.Is(err, store.ErrTenantIDPEncryptionRequired):
			return apierror.Unavailable("at-rest envelope encryption is required before storing an IdP client secret")
		default:
			return apierror.Internal("failed to persist tenant identity settings").Wrap(err)
		}
	}
	writeJSON(w, http.StatusOK, tenantIDPResponseFromSettings(settings))
	return nil
}

func normalizeOIDCScopes(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, raw := range in {
		scope := strings.TrimSpace(raw)
		if scope == "" || seen[scope] {
			continue
		}
		seen[scope] = true
		out = append(out, scope)
	}
	return out
}

func tenantIDPResponseFromSettings(settings *store.TenantIDP) tenantIDPResponse {
	resp := tenantIDPResponse{
		Source: "tenant", Configured: true, Issuer: settings.Issuer,
		ClientID: settings.ClientID, ClientSecretConfigured: settings.ClientSecretConfigured,
		RedirectURL: settings.RedirectURL, Scopes: settings.Scopes,
		Enabled: settings.Enabled, Flags: settings.Flags,
	}
	resp.Valid = validateOIDCConfig(auth.OIDCConfig{
		Issuer: resp.Issuer, ClientID: resp.ClientID, ClientSecret: "configured",
		RedirectURL: resp.RedirectURL, Scopes: resp.Scopes,
	}) == nil && resp.ClientSecretConfigured
	return resp
}

func (s *Server) environmentIDPResponse() tenantIDPResponse {
	configured := s.cfg.OIDCIssuer != "" || s.cfg.OIDCClientID != "" ||
		s.cfg.OIDCClientSecret != "" || s.cfg.OIDCRedirectURL != ""
	resp := tenantIDPResponse{
		Source: "none", Configured: configured, Issuer: s.cfg.OIDCIssuer,
		ClientID: s.cfg.OIDCClientID, ClientSecretConfigured: s.cfg.OIDCClientSecret != "",
		RedirectURL: s.cfg.OIDCRedirectURL, Scopes: []string{"openid", "email", "profile"},
		Enabled: configured, Flags: map[string]bool{},
	}
	if configured {
		resp.Source = "environment"
		resp.Valid = validateOIDCConfig(auth.OIDCConfig{
			Issuer: s.cfg.OIDCIssuer, ClientID: s.cfg.OIDCClientID,
			ClientSecret: s.cfg.OIDCClientSecret, RedirectURL: s.cfg.OIDCRedirectURL,
		}) == nil
	}
	return resp
}
