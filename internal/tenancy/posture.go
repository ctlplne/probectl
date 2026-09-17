// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tenancy

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TENANT-104: pooled tenant isolation is enforced at the storage layer by
// Postgres RLS — but RLS is only a boundary if the role the app actually runs
// as cannot bypass it AND every tenant-owned table FORCES row security (so the
// table OWNER is bound too). migrations/0007 creates probectl_app as
// NOLOGIN NOSUPERUSER NOBYPASSRLS, but nothing verified that the role the app
// ASSUMES at runtime (after SET LOCAL ROLE probectl_app) is actually that
// role and is actually constrained. This self-check runs at boot and FATALs
// the control plane if the posture is wrong — a misconfigured deployment must
// never serve traffic with RLS silently off (guardrail 1, fail closed).

// AssertIsolationPosture verifies, inside a real AppRole-scoped transaction,
// that the effective role is non-superuser and cannot bypass RLS, and that
// every tenant-owned table (one carrying a tenant_id column) has FORCE ROW
// LEVEL SECURITY. Canonical physical-silo tables must additionally carry the
// exact schema-bound RESTRICTIVE guard. It returns a non-nil error describing
// the first violation; the caller (main) treats that as fatal.
func AssertIsolationPosture(ctx context.Context, pool *pgxpool.Pool) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("isolation posture: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Assume the same restricted role InTenant uses, so the check reflects the
	// ACTUAL runtime posture, not the connection's login role.
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{AppRole}.Sanitize()); err != nil {
		return fmt.Errorf("isolation posture: cannot assume %s (is the role provisioned? migrations/0007): %w", AppRole, err)
	}
	return AssertPostureTx(ctx, tx)
}

// postureQuerier is the minimal surface AssertPostureTx needs (a pgx tx).
type postureQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// AssertPostureTx runs the role + FORCE-RLS checks on an already-role-scoped
// querier. AssertIsolationPosture wraps it (begin + SET ROLE); the isolation
// test suite calls it directly to prove the check is not vacuous.
func AssertPostureTx(ctx context.Context, q postureQuerier) error {
	// 1. The effective role must be non-super, non-bypassrls. current_user is
	// the assumed role after SET LOCAL ROLE.
	var roleName string
	var isSuper, canBypass bool
	if err := q.QueryRow(ctx,
		`SELECT rolname, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`,
	).Scan(&roleName, &isSuper, &canBypass); err != nil {
		return fmt.Errorf("isolation posture: read effective role: %w", err)
	}
	if isSuper {
		return fmt.Errorf("isolation posture: the app role %q is a SUPERUSER — RLS is bypassed; tenant isolation is OFF (refusing to start)", roleName)
	}
	if canBypass {
		return fmt.Errorf("isolation posture: the app role %q has BYPASSRLS — tenant isolation is OFF (refusing to start)", roleName)
	}

	// 2. Every tenant-owned table (has a tenant_id column) must FORCE row
	// security — otherwise the table owner (and any future grant) reads across
	// tenants. Every ordinary table in a canonical t_<32hex> silo schema must
	// also carry tenant_id uuid NOT NULL: physical silos contain tenant data
	// only, and an unscoped restored table is a startup-fatal boundary failure.
	//
	// TENANT-008: this scans EVERY non-system schema, not just public. Siloed
	// tenants' tables live in per-tenant schemas (ee/silo provisions them with
	// ENABLE+FORCE RLS); the boot guard must inspect those too, so a
	// partially-provisioned or hand-edited silo schema with RLS enabled-but-not-
	// forced can never pass boot. We report schema.table so an offender in a
	// silo schema is identifiable.
	rows, err := q.Query(ctx, `
		SELECT n.nspname,
		       c.relname,
		       c.relrowsecurity,
		       c.relforcerowsecurity,
		       a.attname IS NOT NULL,
		       COALESCE(a.atttypid = 'uuid'::regtype, false),
		       COALESCE(a.attnotnull, false)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		LEFT JOIN LATERAL (
		    SELECT attname, atttypid, attnotnull
		      FROM pg_attribute
		     WHERE attrelid = c.oid
		       AND attname = 'tenant_id'
		       AND NOT attisdropped
		     LIMIT 1
		) AS a ON true
		WHERE c.relkind = 'r'
		  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		  AND n.nspname NOT LIKE 'pg_toast%'
		  AND n.nspname NOT LIKE 'pg_temp%'`)
	if err != nil {
		return fmt.Errorf("isolation posture: enumerate tenant tables: %w", err)
	}
	defer rows.Close()

	var offenders []string
	var invalidSiloTables []string
	var siloTables []siloPostureTable
	var checked int
	for rows.Next() {
		var schema, name string
		var enabled, forced, hasTenantID, tenantIDUUID, tenantIDNotNull bool
		if err := rows.Scan(
			&schema,
			&name,
			&enabled,
			&forced,
			&hasTenantID,
			&tenantIDUUID,
			&tenantIDNotNull,
		); err != nil {
			return fmt.Errorf("isolation posture: scan: %w", err)
		}
		schemaTenant, canonicalSilo := canonicalSiloTenantID(schema)
		if canonicalSilo && (!hasTenantID || !tenantIDUUID || !tenantIDNotNull) {
			invalidSiloTables = append(
				invalidSiloTables,
				fmt.Sprintf(
					"%s.%s(tenant_id=%t,uuid=%t,not_null=%t)",
					schema,
					name,
					hasTenantID,
					tenantIDUUID,
					tenantIDNotNull,
				),
			)
		}
		if !hasTenantID {
			continue
		}
		checked++
		if !enabled || !forced {
			offenders = append(offenders, fmt.Sprintf("%s.%s(rls=%t,force=%t)", schema, name, enabled, forced))
		}
		if canonicalSilo {
			siloTables = append(siloTables, siloPostureTable{
				schema:   schema,
				table:    name,
				tenantID: schemaTenant,
			})
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("isolation posture: iterate: %w", err)
	}
	if checked == 0 {
		return fmt.Errorf("isolation posture: found NO tenant-owned tables to verify — migrations not applied? (refusing to start)")
	}
	if len(invalidSiloTables) > 0 {
		return fmt.Errorf(
			"isolation posture: canonical silo table(s) without tenant_id uuid NOT NULL: %s (refusing to start)",
			strings.Join(invalidSiloTables, ", "),
		)
	}
	if len(offenders) > 0 {
		return fmt.Errorf("isolation posture: %d tenant table(s) without FORCE ROW LEVEL SECURITY: %s (refusing to start)",
			len(offenders), strings.Join(offenders, ", "))
	}
	if err := assertSiloSchemaGuards(ctx, q, siloTables); err != nil {
		return err
	}
	if err := assertStrictPreTenantPolicies(ctx, q); err != nil {
		return err
	}
	if err := assertProviderPoliciesAreScoped(ctx, q); err != nil {
		return err
	}
	return assertAppGrantsMatchPolicies(ctx, q)
}

type siloPostureTable struct {
	schema   string
	table    string
	tenantID string
}

type siloPolicyPosture struct {
	count                  int
	restrictive, allPublic bool
	usingExpr, checkExpr   *string
}

func canonicalSiloTenantID(schema string) (string, bool) {
	const prefix = "t_"
	schema = strings.ToLower(schema)
	if !strings.HasPrefix(schema, prefix) || len(schema) != len(prefix)+32 {
		return "", false
	}
	compact := schema[len(prefix):]
	for _, ch := range compact {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return "", false
		}
	}
	return compact[:8] + "-" + compact[8:12] + "-" + compact[12:16] + "-" +
		compact[16:20] + "-" + compact[20:], true
}

// assertSiloSchemaGuards verifies the policy property FORCE RLS cannot express:
// every physical silo table has one exact RESTRICTIVE policy that AND-binds
// rows to both the caller GUC and the immutable tenant encoded by its schema.
// Extra permissive policies may survive a legacy restore, but cannot bypass
// this guard.
func assertSiloSchemaGuards(
	ctx context.Context,
	q postureQuerier,
	tables []siloPostureTable,
) error {
	if len(tables) == 0 {
		return nil
	}
	rows, err := q.Query(ctx, `
		SELECT schemaname,
		       tablename,
		       permissive = 'RESTRICTIVE',
		       cmd = 'ALL' AND roles = ARRAY['public'::name],
		       qual,
		       with_check
		  FROM pg_policies
		 WHERE policyname = 'tenant_schema_isolation'
		 ORDER BY schemaname, tablename`)
	if err != nil {
		return fmt.Errorf("isolation posture: enumerate silo schema guards: %w", err)
	}
	defer rows.Close()

	policies := make(map[string]siloPolicyPosture, len(tables))
	for rows.Next() {
		var schema, table string
		var policy siloPolicyPosture
		if err := rows.Scan(
			&schema,
			&table,
			&policy.restrictive,
			&policy.allPublic,
			&policy.usingExpr,
			&policy.checkExpr,
		); err != nil {
			return fmt.Errorf("isolation posture: scan silo schema guard: %w", err)
		}
		key := schema + "." + table
		policy.count = policies[key].count + 1
		policies[key] = policy
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("isolation posture: iterate silo schema guards: %w", err)
	}

	var unsafe []string
	for _, table := range tables {
		key := table.schema + "." + table.table
		policy := policies[key]
		if policy.count != 1 || !policy.restrictive || !policy.allPublic ||
			!strictSiloSchemaPolicyExpression(policy.usingExpr, table.tenantID) ||
			!strictSiloSchemaPolicyExpression(policy.checkExpr, table.tenantID) {
			unsafe = append(unsafe, fmt.Sprintf(
				"%s(count=%d,restrictive=%t,all_public=%t)",
				key,
				policy.count,
				policy.restrictive,
				policy.allPublic,
			))
		}
	}
	if len(unsafe) > 0 {
		return fmt.Errorf(
			"isolation posture: silo tables have missing or non-exact schema tenant guards: %s (refusing to start)",
			strings.Join(unsafe, ", "),
		)
	}
	return nil
}

func strictSiloSchemaPolicyExpression(expr *string, tenantID string) bool {
	if expr == nil {
		return false
	}
	normalized, ok := normalizeTenantPolicyExpression(*expr)
	if !ok {
		return false
	}
	for _, strict := range []string{
		`tenant_id = '` + tenantID + `'::uuid AND ` +
			`tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid`,
		`(tenant_id = '` + tenantID + `'::uuid) AND ` +
			`(tenant_id = (NULLIF(current_setting('probectl.tenant_id'::text, true), ''::text))::uuid)`,
	} {
		want, valid := normalizeTenantPolicyExpression(strict)
		if valid && normalized == want {
			return true
		}
	}
	return false
}

var strictPreTenantPolicyTables = []string{
	"sessions",
	"mcp_tokens",
	"scim_tokens",
	"agent_enroll_tokens",
	"agent_identities",
	"credential_locators",
	"agent_identity_revocations",
	"break_glass_grants",
}

// assertStrictPreTenantPolicies verifies the policy semantics that ENABLE/FORCE
// alone cannot prove. These tables resolve authentication or provider metadata
// before a tenant GUC exists, so a permissive "GUC unset => all rows" policy
// would turn the storage boundary off while still passing the generic RLS check.
func assertStrictPreTenantPolicies(ctx context.Context, q postureQuerier) error {
	rows, err := q.Query(ctx, `
		SELECT tablename, policyname, cmd, qual, with_check
		  FROM pg_policies
		 WHERE schemaname = current_schema()
		   AND tablename = ANY($1::text[])
		   AND EXISTS (
		       SELECT 1
		         FROM unnest(roles) AS applicable(policy_role)
		        WHERE CASE
		                  WHEN applicable.policy_role = 'public'::name THEN true
		                  ELSE pg_has_role(current_user, applicable.policy_role, 'MEMBER')
		              END
		   )
		 ORDER BY tablename, policyname`, strictPreTenantPolicyTables)
	if err != nil {
		return fmt.Errorf("isolation posture: enumerate pre-tenant app policies: %w", err)
	}
	defer rows.Close()

	seen := make(map[string]int, len(strictPreTenantPolicyTables))
	var unsafe []string
	for rows.Next() {
		var table, policy, command string
		var usingExpr, checkExpr *string
		if err := rows.Scan(&table, &policy, &command, &usingExpr, &checkExpr); err != nil {
			return fmt.Errorf("isolation posture: scan pre-tenant app policy: %w", err)
		}
		seen[table]++
		if policy != "tenant_isolation" || command != "ALL" ||
			!strictTenantPolicyExpression(usingExpr) ||
			!strictTenantPolicyExpression(checkExpr) {
			unsafe = append(unsafe, table+"."+policy)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("isolation posture: iterate pre-tenant app policies: %w", err)
	}
	for _, table := range strictPreTenantPolicyTables {
		if seen[table] != 1 {
			unsafe = append(unsafe, fmt.Sprintf("%s(applicable_policies=%d)", table, seen[table]))
		}
	}
	if len(unsafe) > 0 {
		return fmt.Errorf("isolation posture: pre-tenant tables have non-strict application policies: %s (unset tenant context must match zero rows; refusing to start)",
			strings.Join(unsafe, ", "))
	}
	return nil
}

// providerManagedTables are the tenant_id-carrying tables the provider plane
// legitimately operates ACROSS tenants, each with the reason. These hold
// provider-plane control state — the tenant's configuration and the MSP's
// metering — not the tenant's telemetry or operational data, and managing them
// cross-tenant IS the provider console's job (CLAUDE.md §2, §3). Every OTHER
// tenant-owned table defaults to "the provider may not read it unscoped", so a
// new table is refused at boot until someone classifies it.
//
// An entry that no longer carries a provider policy is stale and fails too, so
// this cannot rot into a list of yesterday's exceptions.
var providerManagedTables = map[string]string{
	"tenant_branding":            "deployment theming the provider console administers per tenant",
	"tenant_fairness":            "per-tenant admission policy the provider sets and displays",
	"tenant_governance":          "data-governance policy the provider administers per tenant",
	"tenant_keys":                "BYOK key metadata the provider rotates on the tenant's behalf",
	"tenant_quotas":              "MSP quota configuration, provider-owned by definition",
	"tenant_retention":           "retention policy the provider administers per tenant",
	"usage_records":              "consumption metering: the MSP's own billing input, aggregated across tenants",
	"credential_locators":        "pre-tenant credential routing the provider maintains during lifecycle operations",
	"agent_identity_revocations": "deployment-wide revocation list the provider maintains for the handshake deny-list",
	"break_glass_grants":         "the provider plane's own break-glass ledger: who was granted time-bounded access to which tenant, which the provider console issues, displays and expires. It records the audited cross-tenant capability rather than any tenant telemetry (DPR-122 — it was invisible to this guard until the catalog query replaced the privilege-filtered one)",
}

// assertProviderPoliciesAreScoped refuses to start when the PROVIDER role
// holds an unconstrained cross-tenant read on a table holding TENANT DATA
// (Foundation-Loop S-1612260f).
//
// Provider operators get no implicit telemetry read (CLAUDE.md §7 guardrail
// 1): cross-tenant access is explicit, time-bounded, consented break-glass —
// which runs through the TENANT role and a GUC, never the provider role.
// Migration 0045 tightened exactly this for audit_events and named the shape
// it removed: a `FOR SELECT ... USING (true)` provider policy. 0088 removed
// the surviving one on agents. This assertion makes the shape unable to come
// back: any provider-role SELECT/ALL policy on a table that has a tenant_id
// column must constrain rows by the tenant GUC. A DELETE-only policy (the
// erase mutation, which deletes by an explicit WHERE tenant_id = $1) is not a
// read capability and is left alone.
func assertProviderPoliciesAreScoped(ctx context.Context, q postureQuerier) error {
	// DPR-122, two corrections that changed what this guard actually sees:
	//
	//  1. The tenant_id test reads the CATALOG, not information_schema.
	//     information_schema.columns is filtered by the CONNECTED ROLE's
	//     privileges, so any table the app role happened to lack a grant on
	//     was invisible here and its provider policy went unchecked. On the QA
	//     lab that hid break_glass_grants, which carries a `USING (true)`
	//     provider policy — the exact shape this guard exists to refuse. A
	//     safety check whose reach depends on a GRANT is not a safety check.
	//
	//  2. Only PERMISSIVE policies grant access. A RESTRICTIVE policy further
	//     CONSTRAINS what a permissive one allows, so reading one as an
	//     unconstrained grant is backwards: it would refuse to start on a
	//     database that is more locked down, not less. ir_attribution_records'
	//     public-route policy is exactly that — a restrictive guard keeping
	//     siloed tenants out of the pooled table.
	rows, err := q.Query(ctx, `
		SELECT p.tablename, p.policyname, p.cmd, p.qual
		  FROM pg_policies p
		 WHERE p.schemaname = current_schema()
		   AND p.cmd IN ('SELECT', 'ALL')
		   AND p.permissive = 'PERMISSIVE'
		   AND 'probectl_provider' = ANY(p.roles)
		   AND EXISTS (
		       SELECT 1
		         FROM pg_catalog.pg_attribute a
		         JOIN pg_catalog.pg_class     c ON c.oid = a.attrelid
		         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		        WHERE n.nspname  = p.schemaname
		          AND c.relname  = p.tablename
		          AND a.attname  = 'tenant_id'
		          AND a.attnum   > 0
		          AND NOT a.attisdropped
		   )
		 ORDER BY p.tablename, p.policyname`)
	if err != nil {
		return fmt.Errorf("isolation posture: enumerate provider policies: %w", err)
	}
	defer rows.Close()

	var unscoped []string
	seenManaged := map[string]bool{}
	for rows.Next() {
		var table, policy, command string
		var usingExpr *string
		if err := rows.Scan(&table, &policy, &command, &usingExpr); err != nil {
			return fmt.Errorf("isolation posture: scan provider policy: %w", err)
		}
		if _, managed := providerManagedTables[table]; managed {
			seenManaged[table] = true
			continue
		}
		if !providerPolicyIsTenantScoped(usingExpr) {
			unscoped = append(unscoped, fmt.Sprintf("%s.%s (%s)", table, policy, command))
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("isolation posture: iterate provider policies: %w", err)
	}
	if len(unscoped) > 0 {
		return fmt.Errorf("isolation posture: the provider role holds unconstrained cross-tenant read policies on tenant-owned tables: %s — scope them to the tenant GUC, expose an aggregate-only view, or classify the table in providerManagedTables with a reason (refusing to start)",
			strings.Join(unscoped, ", "))
	}
	var stale []string
	for table := range providerManagedTables {
		if !seenManaged[table] {
			stale = append(stale, table)
		}
	}
	if len(stale) > 0 {
		sort.Strings(stale)
		return fmt.Errorf("isolation posture: providerManagedTables lists %s, which no longer carries a provider policy — remove the stale classification (refusing to start)",
			strings.Join(stale, ", "))
	}
	return nil
}

// assertAppGrantsMatchPolicies refuses to start when a table's row-level
// policy says the APPLICATION role may use it and the role has no privilege to
// (DPR-122).
//
// Migration 0007 grants DML on future tables through ALTER DEFAULT PRIVILEGES,
// and Postgres records that for the ROLE THAT RAN IT. Run a later migration as
// a different role — a rotated migration user, a restore into a scratch
// database under another login, a partially-applied bootstrap — and every table
// created from then on carries its policy without the grant the policy assumes.
// Nothing complains at migration time. The deployment then fails much later and
// somewhere else: a confusing isolation-posture error, or a runtime "permission
// denied for table" on a path nobody associated with the database user.
//
// This says it once, at boot, in the operator's words: these tables, this
// cause, this fix.
//
// DPR-135: provider-managed tables are exempt. Migration 0044 added a
// defense-in-depth tenant policy to break_glass_grants targeting probectl_app,
// but the application role has no grant on the provider plane's break-glass
// ledger and must not have one — the policy there is inert by construction, not
// a missing grant. Requiring one refused every FRESH install, and the only way
// to satisfy it would have been to hand the app role a privilege §7.1 says it
// should never hold. The exemption reads from providerManagedTables, whose own
// staleness check keeps it from rotting into a list of yesterday's exceptions.
func assertAppGrantsMatchPolicies(ctx context.Context, q postureQuerier) error {
	rows, err := q.Query(ctx, `
		SELECT DISTINCT p.tablename
		  FROM pg_policies p
		 WHERE p.schemaname = current_schema()
		   AND p.permissive = 'PERMISSIVE'
		   AND p.cmd IN ('ALL', 'SELECT')
		   AND 'probectl_app' = ANY(p.roles)
		   AND NOT has_table_privilege('probectl_app', format('%I.%I', p.schemaname, p.tablename), 'SELECT')
		 ORDER BY 1`)
	if err != nil {
		return fmt.Errorf("isolation posture: enumerate application grants: %w", err)
	}
	defer rows.Close()
	var ungranted []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return fmt.Errorf("isolation posture: scan application grant: %w", err)
		}
		if _, providerOwned := providerManagedTables[table]; providerOwned {
			continue // DPR-135: the app role neither has nor needs a grant here.
		}
		ungranted = append(ungranted, table)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("isolation posture: iterate application grants: %w", err)
	}
	if len(ungranted) > 0 {
		return fmt.Errorf("isolation posture: probectl_app has a row-level policy but no privilege on %s — "+
			"migration 0007 grants DML on later tables through ALTER DEFAULT PRIVILEGES, which Postgres records for the role that RAN it, "+
			"so these tables were created by a different database user than the one that bootstrapped the schema. "+
			"Re-run the migrations as that user, or GRANT SELECT, INSERT, UPDATE, DELETE on those tables to probectl_app (refusing to start)",
			strings.Join(ungranted, ", "))
	}
	return nil
}

// providerPolicyIsTenantScoped reports whether a provider policy's USING
// expression constrains rows to the tenant GUC. An absent or `true` predicate
// is precisely the unconstrained shape.
func providerPolicyIsTenantScoped(expr *string) bool {
	if expr == nil {
		return false
	}
	e := strings.ToLower(strings.Join(strings.Fields(*expr), " "))
	if e == "true" || e == "" {
		return false
	}
	return strings.Contains(e, "probectl.tenant_id") && strings.Contains(e, "tenant_id")
}

func strictTenantPolicyExpression(expr *string) bool {
	if expr == nil {
		return false
	}
	normalized, ok := normalizeTenantPolicyExpression(*expr)
	if !ok {
		return false
	}

	// pg_policies returns pg_get_expr's canonical form, which adds explicit
	// ::text casts to string literals. Keep the migration-source form as a
	// second exact shape for unit/fake catalog queriers. Parentheses and
	// whitespace are deliberately ignored by the normalizer, but every
	// identifier, literal, function, cast, comma, and operator must otherwise
	// match. In particular, COALESCE(..., tenant_id), tautological AND clauses,
	// or any future policy embellishment fail closed instead of trying to grow a
	// keyword blacklist around SQL's many equivalent spellings.
	for _, strict := range []string{
		`(tenant_id = (NULLIF(current_setting('probectl.tenant_id'::text, true), ''::text))::uuid)`,
		`tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid`,
	} {
		want, valid := normalizeTenantPolicyExpression(strict)
		if valid && normalized == want {
			return true
		}
	}
	return false
}

// normalizeTenantPolicyExpression removes only semantically irrelevant
// whitespace and grouping parentheses from PostgreSQL's already-parsed policy
// expression. Quoted literal bytes remain exact; identifier case is folded like
// unquoted PostgreSQL identifiers. The result is compared against a closed
// allowlist above, so retaining any extra SQL token causes rejection.
func normalizeTenantPolicyExpression(expr string) (string, bool) {
	var out strings.Builder
	out.Grow(len(expr))
	inLiteral := false
	for i := 0; i < len(expr); i++ {
		ch := expr[i]
		if ch == '\'' {
			out.WriteByte(ch)
			if inLiteral && i+1 < len(expr) && expr[i+1] == '\'' {
				out.WriteByte(expr[i+1])
				i++
				continue
			}
			inLiteral = !inLiteral
			continue
		}
		if inLiteral {
			out.WriteByte(ch)
			continue
		}
		switch ch {
		case ' ', '\t', '\r', '\n', '(', ')':
			continue
		default:
			if ch >= 'A' && ch <= 'Z' {
				ch += 'a' - 'A'
			}
			out.WriteByte(ch)
		}
	}
	return out.String(), !inLiteral
}

// profileCountQuerier is the minimal surface AssertDeploymentProfilePosture
// needs (a pgxpool.Pool satisfies it; the unit test passes a fake).
type profileCountQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// AssertDeploymentProfilePosture (RED-001) fails closed at boot when the control
// plane is running the single-tenant profile — which leaves ClickHouse
// row-policies AND the bus strict-lane OFF by default (chScopeDefault=false in
// config) — but Postgres actually holds more than one tenant. Postgres-resident
// data stays isolated by always-on FORCE-RLS (AssertIsolationPosture above), but
// the high-cardinality CH planes (flow/eBPF/path/threat) would serve many
// tenants with their storage-layer tenant scoping degraded. An MSP that forgets
// PROBECTL_DEPLOYMENT_PROFILE must not silently serve multiple tenants with that
// defense-in-depth off (guardrail 1, fail closed). If the operator has
// explicitly enabled CH tenant scoping (chTenantScoped), the posture is not
// degraded and the check is a no-op.
func AssertDeploymentProfilePosture(ctx context.Context, q profileCountQuerier, profile string, chTenantScoped bool) error {
	if profile != "single" || chTenantScoped {
		return nil
	}
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM tenants`).Scan(&n); err != nil {
		return fmt.Errorf("profile posture: count tenants: %w", err)
	}
	if n > 1 {
		return fmt.Errorf("deployment posture: PROBECTL_DEPLOYMENT_PROFILE=single leaves ClickHouse "+
			"row-policies and the bus strict-lane OFF, but Postgres holds %d tenants — set "+
			"PROBECTL_DEPLOYMENT_PROFILE=multi-tenant (or regulated), or enable PROBECTL_*_TENANT_SCOPING, "+
			"before serving multiple tenants (refusing to start; RED-001, fail closed)", n)
	}
	return nil
}
