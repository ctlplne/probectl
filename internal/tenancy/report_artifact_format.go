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
)

// ReportArtifactFormatPredicate is an additional format guard. Tenant and
// physical-schema policies remain mandatory and independent of this marker.
const ReportArtifactFormatPredicate = "public.probectl_report_artifact_format_allowed(tenant_id, body_storage, source_capture)"

func reportArtifactFormatExpression(value string) string {
	value = strings.Join(strings.Fields(value), "")
	value = strings.ReplaceAll(value, "public.", "")
	for strings.HasPrefix(value, "(") && strings.HasSuffix(value, ")") {
		value = value[1 : len(value)-1]
	}
	return value
}

func assertReportArtifactFormatGuards(ctx context.Context, q postureQuerier) error {
	rows, err := q.Query(ctx, `SELECT n.nspname,
        COALESCE(p.permissive='RESTRICTIVE',false),
        COALESCE(p.cmd='ALL' AND p.roles=ARRAY['public'::name],false),
        COALESCE(p.qual,''),COALESCE(p.with_check,'')
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      LEFT JOIN pg_policies p ON p.schemaname=n.nspname AND p.tablename=c.relname
        AND p.policyname='report_artifact_format'
     WHERE c.relname='dashboard_report_artifacts' AND c.relkind IN ('r','p')
       AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid
         AND a.attname='body_storage' AND a.attnum>0 AND NOT a.attisdropped)`)
	if err != nil {
		return fmt.Errorf("isolation posture: enumerate report format guards: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var schema, using, check string
		var restrictive, allPublic bool
		if err := rows.Scan(&schema, &restrictive, &allPublic, &using, &check); err != nil {
			return fmt.Errorf("isolation posture: read report format guard: %w", err)
		}
		// Only the public template and managed silo namespaces belong to us.
		if schema != "public" {
			if _, managed := canonicalSiloTenantID(schema); !managed {
				continue
			}
		}
		want := reportArtifactFormatExpression(ReportArtifactFormatPredicate)
		if !restrictive || !allPublic || reportArtifactFormatExpression(using) != want || reportArtifactFormatExpression(check) != want {
			return fmt.Errorf("isolation posture: missing or unsafe report format guard in %s (refusing to start)", schema)
		}
	}
	return rows.Err()
}
