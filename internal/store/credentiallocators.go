// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/tenancy"
)

const (
	credentialSession     = "session"
	credentialMCP         = "mcp"
	credentialSCIM        = "scim"
	credentialOTLP        = "otlp"
	credentialAgentEnroll = "agent_enroll"
)

var errCredentialStateChanged = errors.New("store: credential state changed concurrently")

func resolveCredential(
	ctx context.Context,
	pool *pgxpool.Pool,
	kind string,
	tokenHash []byte,
) (string, error) {
	var tenantID string
	err := pool.QueryRow(ctx,
		`SELECT tenant_id::text
		   FROM pretenant_resolve_credential($1, $2)`,
		kind, tokenHash,
	).Scan(&tenantID)
	return tenantID, err
}

func resolveCredentialID(
	ctx context.Context,
	pool *pgxpool.Pool,
	kind, credentialID string,
) (string, error) {
	var tenantID string
	err := pool.QueryRow(ctx,
		`SELECT tenant_id::text
		   FROM pretenant_resolve_credential_id($1, $2::uuid)`,
		kind, credentialID,
	).Scan(&tenantID)
	return tenantID, err
}

func registerCredential(
	ctx context.Context,
	sc tenancy.Scope,
	kind, credentialID string,
	tokenHash []byte,
) error {
	var registered bool
	if err := sc.Q.QueryRow(ctx,
		`SELECT pretenant_register_credential($1, $2::uuid, $3, $4::uuid)`,
		kind, credentialID, tokenHash, sc.Tenant.String(),
	).Scan(&registered); err != nil {
		return err
	}
	if !registered {
		return tenancy.ErrNoTenant
	}
	return nil
}

func revokeCredential(
	ctx context.Context,
	sc tenancy.Scope,
	kind string,
	tokenHash []byte,
) error {
	var revoked bool
	if err := sc.Q.QueryRow(ctx,
		`SELECT pretenant_revoke_credential($1, $2, $3::uuid)`,
		kind, tokenHash, sc.Tenant.String(),
	).Scan(&revoked); err != nil {
		return err
	}
	if !revoked {
		return errCredentialStateChanged
	}
	return nil
}

func consumeCredential(
	ctx context.Context,
	sc tenancy.Scope,
	kind string,
	tokenHash []byte,
) error {
	var consumed bool
	if err := sc.Q.QueryRow(ctx,
		`SELECT pretenant_consume_credential($1, $2, $3::uuid)`,
		kind, tokenHash, sc.Tenant.String(),
	).Scan(&consumed); err != nil {
		return err
	}
	if !consumed {
		return errCredentialStateChanged
	}
	return nil
}

func rotateCredential(
	ctx context.Context,
	sc tenancy.Scope,
	kind string,
	oldHash, newHash []byte,
) error {
	var rotated bool
	if err := sc.Q.QueryRow(ctx,
		`SELECT pretenant_rotate_credential($1, $2, $3, $4::uuid)`,
		kind, oldHash, newHash, sc.Tenant.String(),
	).Scan(&rotated); err != nil {
		return err
	}
	if !rotated {
		return errCredentialStateChanged
	}
	return nil
}

// DeleteSubjectCredentialLocatorsScoped removes the hash-only global locators
// corresponding to session and MCP detail rows captured by subject erasure.
// The SECURITY DEFINER boundary checks sc.Tenant against the transaction's
// tenant GUC; ids belonging to another tenant do not match. The returned count
// lets the lifecycle receipt verify how many global records were erased.
func DeleteSubjectCredentialLocatorsScoped(
	ctx context.Context,
	sc tenancy.Scope,
	sessionIDs, mcpTokenIDs []string,
) (int64, error) {
	var total int64
	for _, item := range []struct {
		kind string
		ids  []string
	}{
		{credentialSession, sessionIDs},
		{credentialMCP, mcpTokenIDs},
	} {
		if len(item.ids) == 0 {
			continue
		}
		var deleted int64
		if err := sc.Q.QueryRow(ctx,
			`SELECT pretenant_delete_credential_locators(
				$1, $2::uuid[], $3::uuid
			 )`,
			item.kind, item.ids, sc.Tenant.String(),
		).Scan(&deleted); err != nil {
			return total, err
		}
		total += deleted
	}
	return total, nil
}

func invalidCredential(err error, invalid error) error {
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, errCredentialStateChanged) {
		return invalid
	}
	return err
}

// touchCredential stamps a credential's last-used activity as a best-effort
// side effect of authentication (DPR-096). Authentication itself is a read:
// while the writer endpoint is a read-only standby or the writer pool is
// fenced, the stamp fails with a read-only error and MUST NOT fail the
// login — the documented failover promise is that reads keep serving. The
// update runs under a savepoint so a refused stamp leaves the surrounding
// tenant transaction usable; every error is swallowed by design.
func touchCredential(ctx context.Context, q tenancy.Querier, sql string, args ...any) {
	if _, err := q.Exec(ctx, "SAVEPOINT credential_touch"); err != nil {
		return
	}
	if _, err := q.Exec(ctx, sql, args...); err != nil {
		_, _ = q.Exec(ctx, "ROLLBACK TO SAVEPOINT credential_touch")
		return
	}
	_, _ = q.Exec(ctx, "RELEASE SAVEPOINT credential_touch")
}
