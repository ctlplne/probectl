// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenancy

import (
	"context"
	"fmt"
)

// Restrictive DELETE remains in force under the private lifecycle owner mode.
// Neither generic cleanup nor a job/user cascade may erase an active proof.
func assertHistoryActivityDeleteGuard(ctx context.Context, q postureQuerier, schema string) error {
	var column, policy, truncateDenied bool
	var using *string
	err := q.QueryRow(ctx, `SELECT COALESCE(a.atttypid='timestamptz'::regtype AND NOT a.attnotnull,false),
   COALESCE(NOT p.polpermissive AND p.polcmd='d' AND p.polroles=ARRAY[0::oid] AND p.polwithcheck IS NULL,false),pg_get_expr(p.polqual,p.polrelid),NOT has_table_privilege('probectl_app',c.oid,'TRUNCATE')
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   LEFT JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='drained_at' AND NOT a.attisdropped
   LEFT JOIN pg_policy p ON p.polrelid=c.oid AND p.polname='flow_history_drained_delete'
   WHERE n.nspname=$1 AND c.relname='flow_conversation_activity' AND c.relkind IN ('r','p')`, schema).Scan(&column, &policy, &using, &truncateDenied)
	if err != nil || !column || !policy || !truncateDenied || !exactActivityDeleteExpression(using) {
		return fmt.Errorf("isolation posture: active history operation deletion guard refused for %q (refusing to start)", schema)
	}
	return nil
}

func exactActivityDeleteExpression(expr *string) bool {
	if expr == nil {
		return false
	}
	key, ok := historyOwnerExpressionKey(*expr)
	return ok && (key == "drained_atisnotnull" || key == "(drained_atisnotnull)")
}
