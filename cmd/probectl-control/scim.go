package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"

	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
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
	id, err := store.NewScimTokens(db.Pool()).Create(context.Background(), *tenant, *name, crypto.Hash([]byte(token)))
	if err != nil {
		return fmt.Errorf("create scim token: %w", err)
	}
	log.Info("created scim token", "id", id, "tenant", *tenant, "name", *name)
	fmt.Println(token) // the secret is shown once
	return nil
}
