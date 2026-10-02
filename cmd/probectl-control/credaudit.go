// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"fmt"
	"os"
	"os/user"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// cliActor identifies the control-host operator who ran a one-shot command, as
// `cli:<os-user>@<host>`, so a credential minted or revoked from the CLI is
// attributable in the audit trail the same way an API caller is (AUD-09).
func cliActor() string {
	name := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	} else if env := os.Getenv("USER"); env != "" {
		name = env
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return "cli:" + name + "@" + host
}

// auditCredentialOneShot records a CLI credential mint/revoke in BOTH the
// tenant's hash-chained audit stream and the provider stream (AUD-09). The
// equivalent /v1 and /provider routes already audit; the one-shot
// probectl-control commands (scim-token, mcp-token, enroll-token,
// register-collector, revoke-agent) did not, so a credential could be created
// or revoked from the control host with no record. target is the token/agent
// id — never the secret. data must not carry the secret either.
func auditCredentialOneShot(ctx context.Context, pool *pgxpool.Pool, tenantID, action, target string, data map[string]any) error {
	if data == nil {
		data = map[string]any{}
	}
	actor := cliActor()
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, e := audit.TenantAppend(ctx, sc, actor, action, target, data)
		return e
	}); err != nil {
		return fmt.Errorf("audit %s: %w", action, err)
	}
	pdata := map[string]any{"tenant_id": tenantID}
	for k, v := range data {
		pdata[k] = v
	}
	if _, err := audit.ProviderAppend(ctx, pool, actor, action, target, pdata); err != nil {
		return fmt.Errorf("provider audit %s: %w", action, err)
	}
	return nil
}

// auditProviderOneShot records a deployment-global one-shot (no tenant) in the
// provider stream only (AUD-09). The agent CA init/renew mint the fleet trust
// root and issuing intermediate — the highest-value credential material, with
// no tenant and no API equivalent — so they belong in the provider/system
// stream rather than any tenant chain. target is an identifier, never key bytes.
func auditProviderOneShot(ctx context.Context, pool *pgxpool.Pool, action, target string, data map[string]any) error {
	if data == nil {
		data = map[string]any{}
	}
	if _, err := audit.ProviderAppend(ctx, pool, cliActor(), action, target, data); err != nil {
		return fmt.Errorf("provider audit %s: %w", action, err)
	}
	return nil
}
