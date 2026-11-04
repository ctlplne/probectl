// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

// Inspect only an already-failed synthetic fixture. This never supplies a
// production result, alters the original assertion, changes reader authority,
// or increases a query limit. Do not log SQL, transport or credentials.
func diagnoseMatrixMembers(t *testing.T, store *ClickHouse, query PlanQuery) {
	t.Helper()
	if query.Tags == nil || query.SelectedColumns != nil || query.SelectedMatrixRows != nil {
		return
	}
	budget := ExplorerQueryBudget(store)
	ctx, cancel := context.WithTimeout(withExplorerBudget(t.Context(), budget), budget.ExecutionLimit)
	defer cancel()
	run := func() ([]map[string]any, error) {
		vocabulary, err := query.Tags.Vocabulary(query.TenantID)
		if err != nil {
			return nil, err
		}
		plan, err := flow.NormalizeQueryPlanWithVocabulary(query.Plan, time.Now(), vocabulary)
		if err != nil {
			return nil, err
		}
		target, err := store.route(ctx, query.TenantID)
		if err != nil {
			return nil, err
		}
		lane, err := store.readLane(target, query.TenantID)
		if err != nil {
			return nil, err
		}
		if !lane.Reader {
			return nil, ErrExplorerBudget
		}
		external, err := query.Tags.externalData(ctx, query.TenantID, plan, budget.MemoryBytes/4)
		if err != nil {
			return nil, err
		}
		names, err := explorerInterfaceNames(ctx, store.explorerInterfaces, query.TenantID, plan, budget)
		if err != nil {
			return nil, err
		}
		source, err := store.planSourceFor(ctx, target, lane, query.TenantID, plan)
		if err != nil {
			return nil, err
		}
		sql, params, err := planSQLWithTags(budget, plan, source.table, names, query.TenantID, query.Tags,
			query.SelectedGroups, query.SelectedColumns, query.SelectedChartGroups, query.SelectedMatrixRows)
		if err != nil {
			return nil, err
		}
		end := strings.Index(sql, "\nSELECT 'detail' AS kind,")
		const input = "matrix_input AS (SELECT "
		if end < 0 || strings.Count(sql[:end], input) != 1 {
			return nil, ErrExplorerBudget
		}
		prefix := strings.Replace(sql[:end], input, input+
			"filtered.__probectl_source_row AS original_row,filtered.__probectl_source_column AS original_column,", 1)
		settings, err := budget.settings()
		if err != nil {
			return nil, err
		}
		params["tenant"] = query.TenantID
		projection := "SELECT tupleElement(__probectl_matrix_rows,2) AS row_members," +
			"tupleElement(__probectl_matrix_columns,2) AS column_members,original_row,original_column,g,c,o,p FROM matrix_input LIMIT 8 "
		return store.explorerQueryRows(ctx, target, lane, query.TenantID, prefix+"\n"+projection+settings, params, external...)
	}
	rows, err := run()
	if err != nil {
		t.Logf("matrix member diagnostic refused=true deadline=%t", ctx.Err() != nil)
		return
	}
	encoded, err := json.Marshal(rows)
	if err != nil || len(encoded) > 8192 {
		t.Logf("matrix member diagnostic rows=%d bytes=%d values_omitted=true", len(rows), len(encoded))
		return
	}
	t.Logf("matrix member diagnostic synthetic=%s", encoded)
}
