// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// runSCIMToken mints a per-tenant SCIM bearer token and prints it once to stdout.
// The IdP (Okta/Entra) presents this token to /scim/v2 to provision the tenant's
// users + groups. Only the token's hash is stored, so this is the one chance to
// copy it. Mirrors mcp-token.
func runSCIMToken(log *slog.Logger, db *store.DB, args []string) error {
	fs := flag.NewFlagSet("scim-token", flag.ContinueOnError)
	tenant := fs.String("tenant", tenancy.DefaultTenantID.String(), "tenant id the token provisions")
	name := fs.String("name", "scim", "a label for the token")
	if err := fs.Parse(args); err != nil {
		return err
	}
	token, err := auth.RandomToken()
	if err != nil {
		return err
	}
	ctx := context.Background()
	id, err := store.NewScimTokens(db.Pool()).Create(ctx, *tenant, *name, crypto.Hash([]byte(token)))
	if err != nil {
		return fmt.Errorf("create scim token: %w", err)
	}
	// AUD-09: audit the mint (token id, never the secret) in the tenant and
	// provider streams, matching the /v1/directory/scim-tokens route.
	if err := auditCredentialOneShot(ctx, db.Pool(), *tenant, "directory.scim_token_create", id, map[string]any{"name": *name}); err != nil {
		return err
	}
	log.Info("created scim token", "id", id, "tenant", *tenant, "name", *name)
	fmt.Println(token) // the secret is shown once
	return nil
}
