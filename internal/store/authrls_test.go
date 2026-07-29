// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package store_test

import (
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/migrations"
)

func TestPreTenantAuthMigrationContract(t *testing.T) {
	raw, err := migrations.FS.ReadFile("0070_strict_pretenant_auth_rls.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)

	for _, table := range []string{
		"sessions",
		"mcp_tokens",
		"scim_tokens",
		"agent_enroll_tokens",
		"agent_identities",
		"break_glass_grants",
	} {
		for _, want := range []string{
			"DROP POLICY IF EXISTS tenant_isolation ON " + table,
			"CREATE POLICY tenant_isolation ON " + table,
		} {
			if !strings.Contains(sql, want) {
				t.Errorf("strict pre-tenant migration missing %q", want)
			}
		}
	}

	for _, function := range []string{
		"pretenant_lookup_session",
		"pretenant_rotate_session",
		"pretenant_delete_session",
		"pretenant_authenticate_mcp_token",
		"pretenant_authenticate_scim_token",
		"pretenant_consume_agent_enroll_token",
		"provider_revoke_agent_enroll_token",
		"provider_list_revoked_agent_identities",
	} {
		if !strings.Contains(sql, "FUNCTION "+function) {
			t.Errorf("strict pre-tenant migration missing narrow function %s", function)
		}
	}

	for _, want := range []string{
		"TO probectl_app",
		"TO probectl_pretenant_auth",
		"TO probectl_provider",
		"REVOKE ALL ON FUNCTION",
		"GRANT EXECUTE ON FUNCTION",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("strict pre-tenant migration missing role/function boundary %q", want)
		}
	}
	if strings.Contains(sql, "IS NULL\n") && strings.Contains(sql, "OR tenant_id") {
		t.Fatal("strict pre-tenant migration preserves an unset-GUC allow-all policy")
	}
	for _, want := range []string{
		"GRANT EXECUTE ON FUNCTION provider_revoke_agent_enroll_token(uuid) TO probectl_provider",
		"GRANT EXECUTE ON FUNCTION provider_list_revoked_agent_identities() TO probectl_provider",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("provider operation is not provider-only: missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"GRANT EXECUTE ON FUNCTION provider_revoke_agent_enroll_token(uuid) TO probectl_app",
		"GRANT EXECUTE ON FUNCTION provider_list_revoked_agent_identities() TO probectl_app",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("application role received provider-only operation: %q", forbidden)
		}
	}

	definers := strings.Count(sql, "\nSECURITY DEFINER\n")
	if definers == 0 {
		t.Fatal("strict pre-tenant migration defines no security boundary functions")
	}
	if pinned := strings.Count(sql, "SET search_path = pg_catalog, public"); pinned != definers {
		t.Fatalf("SECURITY DEFINER search paths pinned = %d, want %d", pinned, definers)
	}
	if revoked := strings.Count(sql, "REVOKE ALL ON FUNCTION"); revoked != definers {
		t.Fatalf("SECURITY DEFINER PUBLIC execute revocations = %d, want %d", revoked, definers)
	}
}

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
