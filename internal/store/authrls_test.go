// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store_test

import (
	"strings"
	"testing"

	"github.com/ctlplne/probectl/migrations"
)

// TestPreTenantAuthMigrationContract was removed: it grepped 0070's SQL text,
// so it passed under any reformat and proved nothing about the running DB. The
// strict pre-tenant RLS it checked and the provider-only EXECUTE grants are now
// exercised end to end against real catalogs by
// TestStrictPreTenantAuthPoliciesAreEnforced in
// pretenant_auth_rls_integration_test.go (TQ-10).

func TestPreTenantSessionRotationPreservesSourceAuthority(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0070_strict_pretenant_auth_rls.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	start := strings.Index(sql, "CREATE OR REPLACE FUNCTION pretenant_rotate_session")
	if start < 0 {
		t.Fatal("pretenant_rotate_session definition missing")
	}
	endOffset := strings.Index(sql[start:], "ALTER FUNCTION pretenant_rotate_session")
	if endOffset < 0 {
		t.Fatal("pretenant_rotate_session ownership boundary missing")
	}
	rotation := sql[start : start+endOffset]

	for _, want := range []string{
		"p_old_hash bytea",
		"p_new_hash bytea",
		"p_tenant_id uuid",
		"p_user_id uuid",
		"p_authorization_hash bytea",
		"UPDATE public.sessions AS s",
		"SET token_hash = p_new_hash",
		"last_activity_at = now()",
		"authorization_hash = COALESCE(p_authorization_hash",
		"s.tenant_id = p_tenant_id",
		"s.user_id = p_user_id",
	} {
		if !strings.Contains(rotation, want) {
			t.Errorf("narrow rotation missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"p_email",
		"p_display_name",
		"p_mfa_satisfied",
		"p_time_zone",
		"p_locale",
		"p_tenant_time_zone",
		"p_tenant_locale",
		"p_expires_at",
		"p_created_at",
		"p_last_activity_at",
		"INSERT INTO public.sessions",
		"DELETE FROM public.sessions",
	} {
		if strings.Contains(rotation, forbidden) {
			t.Errorf("rotation accepts or rewrites database-authoritative field %q", forbidden)
		}
	}
}

func TestAuthenticatedLoginReplacementMigrationContract(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0072_authenticated_login_session_replacement.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)

	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS replaced_at timestamptz",
		"CREATE OR REPLACE FUNCTION pretenant_replace_authenticated_session",
		"p_old_hash bytea",
		"p_legacy_old_hash bytea",
		"p_new_hash bytea",
		"FOR UPDATE",
		"SET replaced_at = COALESCE(s.replaced_at, now())",
		"IF already_consumed THEN",
		"INSERT INTO public.sessions",
		"p_tenant_id",
		"p_user_id",
		"p_email",
		"p_display_name",
		"p_mfa_satisfied",
		"p_time_zone",
		"p_locale",
		"p_tenant_time_zone",
		"p_tenant_locale",
		"p_expires_at",
		"p_created_at",
		"p_last_activity_at",
		"p_authorization_hash",
		"GRANT INSERT ON sessions TO probectl_pretenant_auth",
		"REVOKE ALL ON FUNCTION pretenant_replace_authenticated_session",
		"GRANT EXECUTE ON FUNCTION pretenant_replace_authenticated_session",
		"REVOKE CREATE ON SCHEMA public FROM probectl_pretenant_auth",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("authenticated-login replacement migration missing %q", want)
		}
	}
	if got := strings.Count(sql, "AND s.replaced_at IS NULL"); got != 3 {
		t.Errorf("inactive-predecessor filters = %d, want lookup + permission rotation + logout", got)
	}
	start := strings.Index(sql, "CREATE OR REPLACE FUNCTION pretenant_replace_authenticated_session")
	if start < 0 {
		t.Fatal("authenticated-login replacement function definition missing")
	}
	end := strings.Index(sql[start:], "ALTER FUNCTION pretenant_replace_authenticated_session")
	if end < 0 {
		t.Fatal("authenticated-login replacement ownership boundary missing")
	}
	replacement := sql[start : start+end]
	for _, forbidden := range []string{
		"s.tenant_id = p_tenant_id",
		"s.user_id = p_user_id",
	} {
		if strings.Contains(replacement, forbidden) {
			t.Errorf("authenticated login incorrectly preserves predecessor authority via %q", forbidden)
		}
	}
}

func TestSiloPreTenantLocatorMigrationContract(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0073_silo_pretenant_credential_locators.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS credential_locators",
		"credential_kind text",
		"credential_id   uuid",
		"token_hash      bytea",
		"tenant_id       uuid",
		"CREATE TABLE IF NOT EXISTS agent_identity_revocations",
		"CREATE POLICY tenant_isolation ON credential_locators",
		"CREATE POLICY tenant_isolation ON agent_identity_revocations",
		"pretenant_resolve_credential",
		"pretenant_replace_session_locator",
		"pretenant_sync_agent_revocation",
		"provider_list_revoked_agent_identities",
		"ON CONFLICT DO NOTHING",
		"to_jsonb(s)->>''replaced_at''",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("silo pre-tenant migration missing %q", want)
		}
	}

	start := strings.Index(sql, "CREATE TABLE IF NOT EXISTS credential_locators")
	end := strings.Index(sql[start:], ");")
	if start < 0 || end < 0 {
		t.Fatal("credential locator table definition missing")
	}
	locator := sql[start : start+end]
	for _, pii := range []string{
		"email", "display_name", "mfa_satisfied", "time_zone", "locale",
		"user_id", "agent_id", "spiffe_id", "name",
	} {
		if strings.Contains(locator, pii) {
			t.Errorf("global credential locator stores detailed identity field %q", pii)
		}
	}
}
