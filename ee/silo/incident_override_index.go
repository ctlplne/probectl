// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ensureIncidentOverrideIdentityIndex completes the FX-2 override migration
// for a pre-existing physical silo. CREATE TABLE LIKE already copies the new
// public index for new silos, but an old silo retains the raw-address-only
// unique index. Index builds and drops must run outside execPlan's transaction
// so active incident writers keep working during catch-up.
func (p *Provisioner) ensureIncidentOverrideIdentityIndex(ctx context.Context, schema string) error {
	var ready bool
	err := p.ddlPool().QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM pg_class t
		JOIN pg_namespace n ON n.oid=t.relnamespace
		JOIN pg_attribute a ON a.attrelid=t.oid
		WHERE n.nspname=$1 AND t.relname='incident_correlation_overrides'
		  AND a.attname='identity_lookup_attempted' AND NOT a.attisdropped
	)`, schema).Scan(&ready)
	if err != nil {
		return fmt.Errorf("silo: inspect incident override identity column: %w", err)
	}
	if !ready {
		return errors.New("silo: incident override identity column is missing after catch-up")
	}
	const newIndex = "fx2_incident_override_identity_uidx"
	var equivalent bool
	const scopedIndexSQL = `SELECT EXISTS (
		SELECT 1 FROM pg_index i
		JOIN pg_class t ON t.oid=i.indrelid
		JOIN pg_namespace n ON n.oid=t.relnamespace
		WHERE n.nspname=$1 AND t.relname='incident_correlation_overrides'
		  AND i.indisunique AND i.indisvalid AND i.indnullsnotdistinct
		  AND i.indnkeyatts=9 AND i.indpred IS NOT NULL
		  AND pg_get_expr(i.indpred,i.indrelid) IN ('active','(active)')
		  AND pg_get_indexdef(i.indexrelid,1,true)='tenant_id'
		  AND pg_get_indexdef(i.indexrelid,2,true)='source_incident_id'
		  AND pg_get_indexdef(i.indexrelid,3,true)='plane'
		  AND pg_get_indexdef(i.indexrelid,4,true)='kind'
		  AND pg_get_indexdef(i.indexrelid,5,true)='target'
		  AND pg_get_indexdef(i.indexrelid,6,true)='prefix'
		  AND pg_get_indexdef(i.indexrelid,7,true)='identity_lookup_attempted'
		  AND pg_get_indexdef(i.indexrelid,8,true)='entity_context_id'
		  AND pg_get_indexdef(i.indexrelid,9,true)='entity_id'
	)`
	err = p.ddlPool().QueryRow(ctx, scopedIndexSQL, schema).Scan(&equivalent)
	if err != nil {
		return fmt.Errorf("silo: inspect scoped incident override index: %w", err)
	}
	if !equivalent {
		var namedValid bool
		err = p.ddlPool().QueryRow(ctx, `SELECT i.indisvalid FROM pg_index i
			JOIN pg_class x ON x.oid=i.indexrelid
			JOIN pg_namespace n ON n.oid=x.relnamespace
			WHERE n.nspname=$1 AND x.relname=$2`, schema, newIndex).Scan(&namedValid)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return fmt.Errorf("silo: inspect named incident override index: %w", err)
		case namedValid:
			return errors.New("silo: named incident override index has unexpected columns")
		default:
			if _, err := p.ddlPool().Exec(ctx,
				"DROP INDEX CONCURRENTLY IF EXISTS "+quoteIdent(schema)+"."+quoteIdent(newIndex)); err != nil {
				return fmt.Errorf("silo: discard invalid incident override index: %w", err)
			}
		}
		_, err = p.ddlPool().Exec(ctx, "CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "+
			quoteIdent(schema)+"."+quoteIdent(newIndex)+" ON "+
			quoteIdent(schema)+`."incident_correlation_overrides" `+
			`(tenant_id,source_incident_id,plane,kind,target,prefix,`+
			`identity_lookup_attempted,entity_context_id,entity_id) `+
			`NULLS NOT DISTINCT WHERE active`)
		if err != nil {
			return fmt.Errorf("silo: build scoped incident override index: %w", err)
		}
		if err := p.ddlPool().QueryRow(ctx, scopedIndexSQL, schema).Scan(&equivalent); err != nil {
			return fmt.Errorf("silo: recheck scoped incident override index: %w", err)
		}
		if !equivalent {
			return errors.New("silo: scoped incident override index did not become valid")
		}
	}
	// A crash after the new build but before the old drop is safe. Retry sees
	// the verified new index and finishes the drop. Find cloned old indexes by
	// their six columns rather than assuming LIKE retained the public name.
	rows, err := p.ddlPool().Query(ctx, `SELECT x.relname FROM pg_index i
		JOIN pg_class t ON t.oid=i.indrelid
		JOIN pg_class x ON x.oid=i.indexrelid
		JOIN pg_namespace n ON n.oid=t.relnamespace
		WHERE n.nspname=$1 AND t.relname='incident_correlation_overrides'
		  AND i.indisunique AND i.indnkeyatts=6 AND i.indpred IS NOT NULL
		  AND pg_get_expr(i.indpred,i.indrelid) IN ('active','(active)')
		  AND pg_get_indexdef(i.indexrelid,1,true)='tenant_id'
		  AND pg_get_indexdef(i.indexrelid,2,true)='source_incident_id'
		  AND pg_get_indexdef(i.indexrelid,3,true)='plane'
		  AND pg_get_indexdef(i.indexrelid,4,true)='kind'
		  AND pg_get_indexdef(i.indexrelid,5,true)='target'
		  AND pg_get_indexdef(i.indexrelid,6,true)='prefix'`, schema)
	if err != nil {
		return fmt.Errorf("silo: inspect legacy incident override indexes: %w", err)
	}
	var oldNames []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		oldNames = append(oldNames, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, name := range oldNames {
		if _, err := p.ddlPool().Exec(ctx,
			"DROP INDEX CONCURRENTLY IF EXISTS "+quoteIdent(schema)+"."+quoteIdent(name)); err != nil {
			return fmt.Errorf("silo: drop legacy incident override index %q: %w", name, err)
		}
	}
	return nil
}
