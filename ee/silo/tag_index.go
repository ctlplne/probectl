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
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

type tagIndexTarget struct {
	table, name string
	columns     []string
}

var tagIndexTargets = []tagIndexTarget{
	{table: "entities", name: "entities_tenant_context_id_kind_uidx",
		columns: []string{"tenant_id", "context_id", "id", "kind"}},
	{table: "entity_source_contexts", name: "entity_sources_tenant_context_identity_uidx",
		columns: []string{"tenant_id", "context_id", "agent_id", "source_kind", "source_ref"}},
}

// ensureTagStorageIndexes builds only missing FK targets on an existing silo.
// It runs before CatchUpPlan's transaction creates/grants tag tables, so an
// active tenant cannot write a newly visible assignment without its typed FKs.
// CREATE INDEX CONCURRENTLY keeps existing entity writers available.
func (p *Provisioner) ensureTagStorageIndexes(ctx context.Context, schema string, cat Catalog) error {
	if len(tagStoragePlan(schema, cat.TenantTables, false)) == 0 {
		return nil // the public tag migration has not installed its tables
	}
	present := make(map[string]bool, len(cat.SchemaTables))
	for _, table := range cat.SchemaTables {
		present[table] = true
	}
	for _, target := range tagIndexTargets {
		if !present[target.table] {
			// CatchUpPlan will CREATE TABLE LIKE the current public table,
			// including an equivalent index, while the silo is still closed.
			continue
		}
		if err := p.ensureTagIndex(ctx, schema, target); err != nil {
			return err
		}
	}
	return nil
}

func (p *Provisioner) ensureTagIndex(ctx context.Context, schema string, target tagIndexTarget) error {
	inspect := func() (exists, valid, correct bool, err error) {
		var table string
		var unique, usable, unpredicated bool
		var columns []string
		err = p.ddlPool().QueryRow(ctx, `SELECT t.relname,i.indisunique,i.indisvalid,
			i.indpred IS NULL,ARRAY(
				SELECT pg_get_indexdef(i.indexrelid,n,true)
				FROM generate_series(1,i.indnkeyatts) n ORDER BY n)
			FROM pg_class x
			JOIN pg_namespace ns ON ns.oid=x.relnamespace
			JOIN pg_index i ON i.indexrelid=x.oid
			JOIN pg_class t ON t.oid=i.indrelid
			WHERE ns.nspname=$1 AND x.relname=$2`, schema, target.name).
			Scan(&table, &unique, &usable, &unpredicated, &columns)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, false, false, nil
		}
		if err != nil {
			return false, false, false, fmt.Errorf("silo: inspect tag index %s: %w", target.name, err)
		}
		return true, usable, table == target.table && unique && unpredicated &&
			slices.Equal(columns, target.columns), nil
	}
	exists, valid, correct, err := inspect()
	if err != nil {
		return err
	}
	if exists && !correct {
		return fmt.Errorf("silo: tag index %s has unexpected table or columns", target.name)
	}
	if exists && valid {
		return nil
	}
	if exists {
		if _, err := p.ddlPool().Exec(ctx,
			"DROP INDEX CONCURRENTLY IF EXISTS "+quoteIdent(schema)+"."+quoteIdent(target.name)); err != nil {
			return fmt.Errorf("silo: discard invalid tag index %s: %w", target.name, err)
		}
	}
	columns := make([]string, len(target.columns))
	for i, column := range target.columns {
		columns[i] = quoteIdent(column)
	}
	if _, err := p.ddlPool().Exec(ctx,
		"CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS "+quoteIdent(target.name)+
			" ON "+quoteIdent(schema)+"."+quoteIdent(target.table)+
			" ("+strings.Join(columns, ",")+")"); err != nil {
		return fmt.Errorf("silo: build tag index %s: %w", target.name, err)
	}
	exists, valid, correct, err = inspect()
	if err != nil {
		return err
	}
	if !exists || !valid || !correct {
		return fmt.Errorf("silo: tag index %s did not become valid", target.name)
	}
	return nil
}
