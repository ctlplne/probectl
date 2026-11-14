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
	"strings"

	"github.com/jackc/pgx/v5"
)

type configArchiveIndex struct {
	name, columns, predicate string
	unique                   bool
}

// Build outside execPlan: retained archives remain writable during catch-up.
// Verify every replacement before releasing name-only uniqueness. A crashed
// build is retried; a same-name but different valid index fails closed.
func (p *Provisioner) ensureDeviceConfigIndexes(ctx context.Context, schema string) error {
	var present bool
	if err := p.ddlPool().QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, quoteIdent(schema)+`."device_configs"`).Scan(&present); err != nil || !present {
		return err
	}
	for _, index := range []configArchiveIndex{
		{"device_configs_bound_stream_version_idx", "tenant_id,entity_context_id,device_entity_id,binding_agent_id,binding_source_ref,binding_source_assigned_at,binding_agent_assigned_at,version", "entity_context_id IS NOT NULL", true},
		{"device_configs_legacy_stream_version_idx", "tenant_id,device,version", "entity_context_id IS NULL", true},
		{"device_configs_bound_observed_idx", "tenant_id,entity_context_id,device_entity_id,binding_agent_id,binding_source_ref,observed_at DESC,id", "entity_context_id IS NOT NULL", false},
	} {
		if err := p.ensureDeviceConfigIndex(ctx, schema, index); err != nil {
			return err
		}
	}
	// LIKE may choose a different constraint name. Match the original complete
	// key, never an index name prefix or another table's uniqueness.
	rows, err := p.ddlPool().Query(ctx, `SELECT c.conname FROM pg_constraint c JOIN pg_index i ON i.indexrelid=c.conindid
 WHERE c.conrelid=$1::regclass AND c.contype='u' AND i.indnkeyatts=3 AND i.indpred IS NULL
 AND pg_get_indexdef(i.indexrelid,1,true)='tenant_id' AND pg_get_indexdef(i.indexrelid,2,true)='device'
 AND pg_get_indexdef(i.indexrelid,3,true)='version'`, quoteIdent(schema)+`."device_configs"`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		names = append(names, name)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	table := quoteIdent(schema) + `."device_configs"`
	if len(names) > 0 {
		tx, err := p.ddlPool().Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout='5s'"); err != nil {
			return err
		}
		for _, name := range names {
			if _, err := tx.Exec(ctx, "ALTER TABLE "+table+" DROP CONSTRAINT "+quoteIdent(name)); err != nil {
				return err
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	for _, name := range []string{"device_configs_binding_complete", "device_configs_binding_device_fk"} {
		if _, err := p.ddlPool().Exec(ctx, "ALTER TABLE "+table+" VALIDATE CONSTRAINT "+quoteIdent(name)); err != nil {
			return err
		}
	}
	return nil
}

func (p *Provisioner) configArchiveIndexReady(ctx context.Context, schema string, index configArchiveIndex) (bool, error) {
	var ready bool
	columns := strings.Split(index.columns, ",")
	descending := make([]bool, len(columns))
	for i, column := range columns {
		descending[i] = strings.HasSuffix(column, " DESC")
		columns[i] = strings.TrimSuffix(column, " DESC")
	}
	err := p.ddlPool().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_index i
 WHERE i.indrelid=$1::regclass AND i.indisvalid AND i.indisunique=$2
 AND ARRAY(SELECT pg_get_indexdef(i.indexrelid,k,true) FROM generate_series(1,i.indnkeyatts) k ORDER BY k)=$3::text[]
 AND pg_get_expr(i.indpred,i.indrelid)=$4
 AND ARRAY(SELECT pg_index_column_has_property(i.indexrelid,k,'desc') FROM generate_series(1,i.indnkeyatts) k ORDER BY k)=$5::boolean[])`, quoteIdent(schema)+`."device_configs"`, index.unique,
		columns, "("+index.predicate+")", descending).Scan(&ready)
	return ready, err
}

func (p *Provisioner) ensureDeviceConfigIndex(ctx context.Context, schema string, index configArchiveIndex) error {
	if ready, err := p.configArchiveIndexReady(ctx, schema, index); ready || err != nil {
		return err
	}
	var valid bool
	err := p.ddlPool().QueryRow(ctx, `SELECT i.indisvalid FROM pg_index i WHERE i.indexrelid=to_regclass($1)`, quoteIdent(schema)+"."+quoteIdent(index.name)).Scan(&valid)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return err
	case valid:
		return fmt.Errorf("silo: archive index %s has unexpected shape", index.name)
	default:
		if _, err := p.ddlPool().Exec(ctx, "DROP INDEX CONCURRENTLY IF EXISTS "+quoteIdent(schema)+"."+quoteIdent(index.name)); err != nil {
			return err
		}
	}
	unique := ""
	if index.unique {
		unique = "UNIQUE "
	}
	if _, err := p.ddlPool().Exec(ctx, "CREATE "+unique+"INDEX CONCURRENTLY IF NOT EXISTS "+quoteIdent(index.name)+" ON "+quoteIdent(schema)+`."device_configs" (`+index.columns+") WHERE "+index.predicate); err != nil {
		return err
	}
	ready, err := p.configArchiveIndexReady(ctx, schema, index)
	if err == nil && !ready {
		return errors.New("silo: archive index did not become valid")
	}
	return err
}
