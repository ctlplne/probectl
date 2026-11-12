// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tenantlife

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func flowQuerySubjectTable(table string) bool {
	return table == "flow_query_filters" || table == "flow_query_views" || table == "bgp_flow_capture_objects" || table == "alert_rules"
}

type flowQuerySubjectScan struct {
	table, exactSQL, documentSQL string
	exact                        []string
	document                     *govern.SubjectDocumentMatcher
	rows                         int
	emit                         func([]byte) error
}

func newFlowQuerySubjectScan(table string, aliases subjectAliasSet) (*flowQuerySubjectScan, error) {
	if !flowQuerySubjectTable(table) || len(aliases.values()) == 0 {
		return nil, errors.New("tenantlife: decoded flow configuration scope refused")
	}
	policy := subjectPostgresTablePolicies[table]
	var exact, documents, safe []string
	for _, column := range policy.exact {
		exact = append(exact, `lower(COALESCE(subject_row.`+pgIdent(column)+`::text,''))=ANY($2::text[])`)
	}
	for _, column := range policy.contains {
		document := "subject_row." + pgIdent(column)
		if table == "alert_rules" {
			document = alertSubjectDocumentSQL(column)
		}
		documents = append(documents, document)
	}
	if table == "bgp_flow_capture_objects" {
		// Only source identifiers are subject-bearing. Numeric routes, evidence
		// UUIDs and structural tenant/context IDs are not person ownership.
		documents = nil
		for _, path := range []string{"{data,Owner,AgentID}", "{data,Source,Route,Source,CollectorAgentID}", "{data,Source,Route,Source,SourceRef}", "{data,Destination,Route,Source,CollectorAgentID}", "{data,Destination,Route,Source,SourceRef}"} {
			documents = append(documents, "(subject_row.searchable_body #> '"+path+"')")
		}
	}
	for _, alias := range aliases.values() {
		if isSafeContainsIdentifier(alias) {
			safe = append(safe, alias)
		}
	}
	if len(exact) == 0 {
		exact = append(exact, "($2::text[] IS NULL AND FALSE)")
	}
	if len(documents) == 0 {
		return nil, errors.New("tenantlife: decoded flow configuration policy unavailable")
	}
	var matcher *govern.SubjectDocumentMatcher
	if len(safe) != 0 {
		var err error
		matcher, err = govern.NewSubjectDocumentMatcher(safe, govern.DefaultSubjectDocumentBudget())
		if err != nil {
			return nil, err
		}
	}
	return &flowQuerySubjectScan{table: table, exactSQL: "(" + strings.Join(exact, " OR ") + ")", documentSQL: "jsonb_build_array(" + strings.Join(documents, ",") + ")", exact: aliases.normalizedValues(), document: matcher, rows: 128}, nil
}

type flowQuerySubjectRecord struct{ id string }

// walk selects only classified fields for deletion. Export additionally selects
// the ordinary portable row. There is no raw-JSON substring prefilter or total
// row cap. Close each page before its callback may issue another SQL command.
func (scan *flowQuerySubjectScan) walk(ctx context.Context, scope tenancy.Scope, locked bool, page func([]flowQuerySubjectRecord) error) (int64, error) {
	ambient, ok := tenancy.FromContext(ctx)
	if scan == nil || !flowQuerySubjectTable(scan.table) || scan.rows <= 0 || page == nil || !ok || ambient != scope.Tenant || scope.Q == nil {
		return 0, errors.New("tenantlife: decoded flow configuration scan refused")
	}
	portable, suffix := "NULL::json", ""
	if scan.emit != nil {
		portable = "row_to_json(subject_row)"
	}
	// Capture objects deliberately grant no UPDATE privilege, which PostgreSQL
	// also requires for SELECT FOR UPDATE. Their writer and this eraser already
	// serialize on the tenant audit lock; exact deletion counts still fail closed
	// on a concurrent destructive change. Mutable query rows keep their row lock.
	if locked && scan.table != "bgp_flow_capture_objects" {
		suffix = " FOR UPDATE OF subject_row"
	}
	id, projection, cursor := "subject_row.id", "subject_row.id::text", "$3::uuid"
	if scan.table == "bgp_flow_capture_objects" {
		id = `encode(subject_row.digest,'hex') COLLATE "C"`
		projection, cursor = id, `$3::text COLLATE "C"`
	}
	query := `SELECT ` + projection + `,` + scan.exactSQL + `,` + scan.documentSQL + `,` + portable + ` FROM ` + pgIdent(scan.table) + ` AS subject_row
 WHERE subject_row.tenant_id=$1::uuid AND (` + cursor + ` IS NULL OR ` + id + `>` + cursor + `)
 ORDER BY ` + id + ` LIMIT $4` + suffix
	var after *string
	var total int64
	for {
		last, count, matched, err := scan.readPage(ctx, scope, query, after, page)
		if err != nil {
			return 0, err
		}
		if matched > math.MaxInt64-total {
			return 0, errors.New("tenantlife: decoded subject count overflow")
		}
		total += matched
		if count == 0 {
			return total, nil
		}
		after = &last
	}
}

func (scan *flowQuerySubjectScan) readPage(ctx context.Context, scope tenancy.Scope, query string, after *string, page func([]flowQuerySubjectRecord) error) (string, int, int64, error) {
	rows, err := scope.Q.Query(ctx, query, scope.Tenant.String(), scan.exact, after, scan.rows)
	if err != nil {
		return "", 0, 0, err
	}
	defer rows.Close()
	var records []flowQuerySubjectRecord
	last, count := "", 0
	for rows.Next() {
		var id string
		var exact bool
		var document, raw []byte
		if err := rows.Scan(&id, &exact, &document, &raw); err != nil {
			clear(document)
			clear(raw)
			return "", 0, 0, err
		}
		matched, err := scan.matches(ctx, exact, document)
		clear(document)
		if err != nil || id == "" || after != nil && id <= *after || count != 0 && id <= last || count >= scan.rows {
			clear(raw)
			if err == nil {
				err = errors.New("tenantlife: decoded configuration page integrity refused")
			}
			return "", 0, 0, err
		}
		last, count = id, count+1
		if matched {
			if scan.emit != nil {
				err := scan.emit(raw)
				clear(raw)
				if err != nil {
					return "", 0, 0, err
				}
			}
			clear(raw)
			records = append(records, flowQuerySubjectRecord{id: id})
		} else {
			clear(raw)
		}
	}
	if err := rows.Err(); err != nil {
		return "", 0, 0, err
	}
	rows.Close()
	if err := ctx.Err(); err != nil {
		return "", 0, 0, err
	}
	if err := page(records); err != nil {
		return "", 0, 0, err
	}
	return last, count, int64(len(records)), nil
}

// Export emits and clears one matching portable row at a time. Its callback
// writes only to the existing bounded-memory export staging writer; it cannot
// issue nested queries on this active read connection.
func (e *Engine) exportFlowQuerySubject(ctx context.Context, tenant, table string, aliases subjectAliasSet, w io.Writer) (int64, error) {
	scan, err := newFlowQuerySubjectScan(table, aliases)
	if err != nil {
		return 0, err
	}
	scan.emit = func(raw []byte) error {
		if n, err := w.Write(raw); err != nil {
			return err
		} else if n != len(raw) {
			return io.ErrShortWrite
		}
		if n, err := io.WriteString(w, "\n"); err != nil {
			return err
		} else if n != 1 {
			return io.ErrShortWrite
		}
		return nil
	}
	var count int64
	err = tenancy.InTenant(ctx, e.pool, func(ctx context.Context, scope tenancy.Scope) error {
		if scope.Tenant.String() != tenant {
			return errors.New("tenantlife: decoded configuration export scope refused")
		}
		var err error
		count, err = scan.walk(ctx, scope, false, func([]flowQuerySubjectRecord) error { return nil })
		return err
	})
	return count, err
}

func (scan *flowQuerySubjectScan) matches(ctx context.Context, exact bool, document []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if scan.document == nil {
		return exact, nil
	}
	// Validate the whole decoded document even if its owner already matches.
	matched, err := scan.document.MatchJSON(ctx, document)
	if err != nil {
		return false, err
	}
	projected, changed, err := projectSavedQuerySubject(ctx, scan.table, document)
	defer clear(projected)
	if err != nil {
		return false, err
	}
	if changed {
		matched, err = scan.document.MatchJSON(ctx, projected)
		if err != nil {
			return false, err
		}
	}
	return exact || matched, nil
}

func eraseFlowQuerySubjectRows(ctx context.Context, scope tenancy.Scope, table string, aliases subjectAliasSet) (int64, int64, error) {
	scan, err := newFlowQuerySubjectScan(table, aliases)
	if err != nil {
		return 0, 0, err
	}
	deleted, err := scan.walk(ctx, scope, true, func(records []flowQuerySubjectRecord) error {
		if len(records) == 0 {
			return nil
		}
		ids := make([]string, len(records))
		for i, record := range records {
			ids[i] = record.id
		}
		selector := "id=ANY($2::uuid[])"
		if table == "bgp_flow_capture_objects" {
			selector = "digest=ANY(ARRAY(SELECT decode(item,'hex') FROM unnest($2::text[]) AS candidate(item)))"
		}
		tag, err := scope.Q.Exec(ctx, `DELETE FROM `+pgIdent(table)+` WHERE tenant_id=$1::uuid AND `+selector, scope.Tenant.String(), ids)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != int64(len(ids)) {
			return errors.New("tenantlife: decoded flow configuration deletion count mismatch")
		}
		return nil
	})
	if err != nil {
		return 0, 0, err
	}
	remaining, err := scan.walk(ctx, scope, false, func([]flowQuerySubjectRecord) error { return nil })
	if err != nil {
		return 0, 0, err
	}
	if remaining != 0 {
		return deleted, remaining, fmt.Errorf("tenantlife: decoded flow configuration has %d subject matches remaining", remaining)
	}
	return deleted, remaining, nil
}
