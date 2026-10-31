// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenancy

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// FlowHistoryOwnerPredicate is a RESTRICTIVE storage guard, including the outer
// tenant boundary so an extra permissive policy cannot bypass either scope.
// The private lifecycle binding is only for separately authorized maintenance;
// neither a setting nor a stored owner ID grants caller permissions.
const FlowHistoryOwnerPredicate = `tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid
    AND (owner_id = NULLIF(current_setting('probectl.flow_history_owner', true), '')::uuid
         OR current_setting('probectl.flow_history_lifecycle', true) = 'authorized')`

// FlowHistoryOwnerTable names source/job/activity tables in the private history family.
// Operational tenant epochs remain protected by the ordinary tenant policy.
func FlowHistoryOwnerTable(table string) bool {
	return table == "flow_conversation_messages" || table == "flow_conversation_jobs" || table == "flow_conversation_activity"
}

// FlowHistoryOwnerBoundaryPlan installs the same owner guard on initial and restored silos.
// The planner supplies catalog identifiers, never user SQL; quote both even
// though the table name must belong to the fixed private-history family.
func FlowHistoryOwnerBoundaryPlan(schema, table string) []string {
	if !FlowHistoryOwnerTable(table) {
		return nil
	}
	identifier := pgx.Identifier{table}
	if schema != "" {
		identifier = pgx.Identifier{schema, table}
	}
	quoted := identifier.Sanitize()
	plan := []string{
		"DROP POLICY IF EXISTS flow_history_owner ON " + quoted,
		"CREATE POLICY flow_history_owner ON " + quoted + " AS RESTRICTIVE\n" +
			"  FOR ALL TO PUBLIC\n  USING (" + FlowHistoryOwnerPredicate + ")\n" +
			"  WITH CHECK (" + FlowHistoryOwnerPredicate + ")",
	}
	if table == "flow_conversation_activity" {
		plan = append(plan, "DROP POLICY IF EXISTS flow_history_drained_delete ON "+quoted,
			"CREATE POLICY flow_history_drained_delete ON "+quoted+" AS RESTRICTIVE FOR DELETE TO PUBLIC USING (drained_at IS NOT NULL)")
	}
	return plan
}

// PostgreSQL deparses the fixed policy with explicit text casts and grouping.
// Keep that grouping: (tenant AND owner) OR lifecycle is not tenant AND
// (owner OR lifecycle), even though removing parentheses gives equal tokens.
const postgresHistoryOwnerPredicate = `((tenant_id = (NULLIF(current_setting('probectl.tenant_id'::text, true), ''::text))::uuid) AND ((owner_id = (NULLIF(current_setting('probectl.flow_history_owner'::text, true), ''::text))::uuid) OR (current_setting('probectl.flow_history_lifecycle'::text, true) = 'authorized'::text)))`

func exactHistoryOwnerExpression(expr *string) bool {
	if expr == nil {
		return false
	}
	value, ok := historyOwnerExpressionKey(*expr)
	if !ok {
		return false
	}
	for _, expected := range []string{FlowHistoryOwnerPredicate, postgresHistoryOwnerPredicate} {
		key, valid := historyOwnerExpressionKey(expected)
		if valid && key == value {
			return true
		}
	}
	return false
}

// Remove only whitespace outside literals and fold unquoted SQL case. Every
// operator, cast, grouping parenthesis and literal byte remains significant.
func historyOwnerExpressionKey(expr string) (string, bool) {
	var key strings.Builder
	key.Grow(len(expr))
	literal := false
	for index := 0; index < len(expr); index++ {
		value := expr[index]
		if value == '\'' {
			key.WriteByte(value)
			if literal && index+1 < len(expr) && expr[index+1] == '\'' {
				key.WriteByte(expr[index+1])
				index++
				continue
			}
			literal = !literal
			continue
		}
		if !literal {
			if value == ' ' || value == '\n' || value == '\r' || value == '\t' {
				continue
			}
			if value >= 'A' && value <= 'Z' {
				value += 'a' - 'A'
			}
		}
		key.WriteByte(value)
	}
	return key.String(), !literal
}

// AssertFlowHistoryOwnerGuard reads only catalog metadata. Startup and the
// private repository can refuse a missing/restored/widened owner boundary
// before source access; no source table or caller grant is inferred from this.
func AssertFlowHistoryOwnerGuard(ctx context.Context, q postureQuerier, schema, table string) error {
	if !FlowHistoryOwnerTable(table) || schema == "" {
		return fmt.Errorf("isolation posture: invalid private history guard target")
	}
	var columns, forced, policy, providerDenied bool
	var using, check *string
	err := q.QueryRow(ctx, `SELECT
        COALESCE(t.atttypid='uuid'::regtype AND t.attnotnull AND o.atttypid='uuid'::regtype AND o.attnotnull,false),
        c.relrowsecurity AND c.relforcerowsecurity,
        COALESCE(NOT p.polpermissive AND p.polcmd='*' AND p.polroles=ARRAY[0::oid],false),
        NOT has_table_privilege('probectl_provider',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'),
        pg_get_expr(p.polqual,p.polrelid),pg_get_expr(p.polwithcheck,p.polrelid)
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      LEFT JOIN pg_attribute t ON t.attrelid=c.oid AND t.attname='tenant_id' AND NOT t.attisdropped
      LEFT JOIN pg_attribute o ON o.attrelid=c.oid AND o.attname='owner_id' AND NOT o.attisdropped
      LEFT JOIN pg_policy p ON p.polrelid=c.oid AND p.polname='flow_history_owner'
      WHERE n.nspname=$1 AND c.relname=$2 AND c.relkind IN ('r','p')`, schema, table).Scan(&columns, &forced, &policy, &providerDenied, &using, &check)
	if err != nil || !columns || !forced || !policy || !providerDenied || !exactHistoryOwnerExpression(using) || !exactHistoryOwnerExpression(check) {
		return fmt.Errorf("isolation posture: private history guard refused for %q.%q (refusing to start)", schema, table)
	}
	if table == "flow_conversation_activity" {
		return assertHistoryActivityDeleteGuard(ctx, q, schema)
	}
	return nil
}
