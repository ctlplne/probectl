// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

var (
	// ErrTenantIDPNotFound means the tenant has no database override; callers
	// may deliberately fall back to the deployment-wide environment IdP.
	ErrTenantIDPNotFound = errors.New("store: tenant identity provider not configured")
	// ErrTenantIDPSecretRequired prevents creation of an unusable override.
	ErrTenantIDPSecretRequired = errors.New("store: tenant identity provider client secret is required")
	// ErrTenantIDPEncryptionRequired prevents client secrets from being stored
	// by the keyless-development passthrough mode.
	ErrTenantIDPEncryptionRequired = errors.New("store: tenant identity provider requires at-rest envelope encryption")
)

const tenantIDPSecretAAD = "tenant_idp.client_secret:v1"

// TenantIDPs persists one RLS-enforced OIDC configuration per tenant.
type TenantIDPs struct{ pool *pgxpool.Pool }

// NewTenantIDPs binds the repository to the writer pool.
func NewTenantIDPs(pool *pgxpool.Pool) TenantIDPs { return TenantIDPs{pool: pool} }

// Get resolves and decrypts a tenant's IdP through an explicit tenant-scoped
// transaction. It is used before user authentication, after the login host or
// tenant hint has already selected exactly one tenant.
func (s TenantIDPs) Get(ctx context.Context, tenantID string) (*TenantIDP, error) {
	var out *TenantIDP
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			var getErr error
			out, getErr = s.GetScoped(ctx, sc, true)
			return getErr
		})
	return out, err
}

// GetScoped returns the caller tenant's only row. The query intentionally has
// no tenant predicate: forced RLS is the outer isolation boundary. openSecret
// is false for admin reads so ciphertext is never decrypted unnecessarily.
func (TenantIDPs) GetScoped(ctx context.Context, sc tenancy.Scope, openSecret bool) (*TenantIDP, error) {
	var out TenantIDP
	var sealed string
	var flagsJSON []byte
	err := sc.Q.QueryRow(ctx, `
SELECT tenant_id::text, issuer, client_id, client_secret_sealed, redirect_url,
       scopes, enabled, flags, created_at, updated_at
FROM tenant_idp
LIMIT 1`).Scan(&out.TenantID, &out.Issuer, &out.ClientID, &sealed, &out.RedirectURL,
		&out.Scopes, &out.Enabled, &flagsJSON, &out.CreatedAt, &out.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTenantIDPNotFound
	}
	if err != nil {
		return nil, err
	}
	if len(flagsJSON) > 0 {
		if err := json.Unmarshal(flagsJSON, &out.Flags); err != nil {
			return nil, fmt.Errorf("store: decode tenant identity provider flags: %w", err)
		}
	}
	if out.Flags == nil {
		out.Flags = map[string]bool{}
	}
	out.ClientSecretConfigured = sealed != ""
	if !openSecret {
		return &out, nil
	}
	plain, err := tenantcrypto.Open(ctx, sc.Tenant.String(), sealed, []byte(tenantIDPSecretAAD))
	if err != nil {
		return nil, fmt.Errorf("store: open tenant identity provider client secret: %w", err)
	}
	defer crypto.Zeroize(plain)
	out.ClientSecret = string(plain)
	return &out, nil
}

// UpsertScoped writes configuration and its audit receipt in the caller's
// surrounding tenant transaction. A blank secret preserves an existing sealed
// value; a new row always requires a freshly envelope-sealed secret.
func (TenantIDPs) UpsertScoped(ctx context.Context, sc tenancy.Scope, in TenantIDPInput) (*TenantIDP, error) {
	var storedSecret string
	err := sc.Q.QueryRow(ctx, `SELECT client_secret_sealed FROM tenant_idp LIMIT 1`).Scan(&storedSecret)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if in.ClientSecret != "" {
		sealed, sealErr := tenantcrypto.Seal(ctx, sc.Tenant.String(), []byte(in.ClientSecret), []byte(tenantIDPSecretAAD))
		if sealErr != nil {
			return nil, fmt.Errorf("store: seal tenant identity provider client secret: %w", sealErr)
		}
		if !tenantcrypto.HasScheme(sealed) {
			return nil, ErrTenantIDPEncryptionRequired
		}
		storedSecret = sealed
	}
	if storedSecret == "" {
		return nil, ErrTenantIDPSecretRequired
	}
	if len(in.Scopes) == 0 {
		in.Scopes = []string{"openid", "email", "profile"}
	}
	if in.Flags == nil {
		in.Flags = map[string]bool{}
	}
	flagsJSON, err := json.Marshal(in.Flags)
	if err != nil {
		return nil, fmt.Errorf("store: encode tenant identity provider flags: %w", err)
	}
	_, err = sc.Q.Exec(ctx, `
INSERT INTO tenant_idp
    (tenant_id, issuer, client_id, client_secret_sealed, redirect_url, scopes, enabled, flags)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
ON CONFLICT (tenant_id) DO UPDATE SET
    issuer = EXCLUDED.issuer,
    client_id = EXCLUDED.client_id,
    client_secret_sealed = EXCLUDED.client_secret_sealed,
    redirect_url = EXCLUDED.redirect_url,
    scopes = EXCLUDED.scopes,
    enabled = EXCLUDED.enabled,
    flags = EXCLUDED.flags,
    updated_at = clock_timestamp()`,
		sc.Tenant.String(), in.Issuer, in.ClientID, storedSecret, in.RedirectURL,
		in.Scopes, in.Enabled, flagsJSON)
	if err != nil {
		return nil, mapWriteErr("tenant identity provider", err)
	}
	return (TenantIDPs{}).GetScoped(ctx, sc, false)
}
