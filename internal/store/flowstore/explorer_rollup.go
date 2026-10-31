// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/chclient"
	"github.com/ctlplne/probectl/internal/store/chmigrate"
)

// v6 retains original inputs behind the hourly index. It does not invent ports,
// event timestamps or identity labels for older hourly-only rows (version0).
var fullRollupColumns = []struct{ name, typ string }{
	{"agent_id", "String"}, {"obs_domain", "UInt32"},
	{"ts", "DateTime64(3) DEFAULT toDateTime64(bucket,3)"}, {"start_ts", "DateTime64(3)"},
	{"src_port", "UInt16"}, {"dst_port", "UInt16"}, {"net_type", "LowCardinality(String)"},
	{"in_if", "UInt32"}, {"out_if", "UInt32"}, {"vlan", "UInt16"}, {"tos", "UInt8"}, {"tcp_flags", "UInt8"}, {"next_hop", "String"},
	{"bytes", "UInt64"}, {"packets", "UInt64"}, {"sampling", "UInt64"},
	{"src_asn", "UInt32"}, {"src_as_name", "String"}, {"src_country", "LowCardinality(String)"},
	{"dst_asn", "UInt32"}, {"dst_as_name", "String"}, {"dst_country", "LowCardinality(String)"},
}

func fullRollupSelect(source string) (columns, selection string) {
	names := []string{"tenant_id", "bucket", "protocol", "exporter", "src_addr", "dst_addr", "transport", "row_id", "bytes_scaled", "packets_scaled", "flow_count", "subject_keys"}
	values := []string{"tenant_id", "toStartOfHour(ts) AS bucket", "protocol", "exporter", "src_addr", "dst_addr", "transport", flowRollupRowIDExpr() + " AS row_id", "bytes_scaled", "packets_scaled", "toUInt64(1) AS flow_count", flowSubjectValuesExpr() + " AS subject_keys"}
	for _, column := range fullRollupColumns {
		names = append(names, column.name)
		values = append(values, column.name)
	}
	names = append(names, "coverage_version")
	values = append(values, "toUInt8(1) AS coverage_version")
	return strings.Join(names, ","), "SELECT " + strings.Join(values, ",") + " FROM " + source
}

func fullRollupMigration(raw, rollup, oldView string) chmigrate.Migration {
	additions := []string{}
	for _, column := range fullRollupColumns {
		additions = append(additions, "ADD COLUMN IF NOT EXISTS "+column.name+" "+column.typ)
	}
	additions = append(additions, "ADD COLUMN IF NOT EXISTS coverage_version UInt8 DEFAULT 0")
	columns, selection := fullRollupSelect(raw)
	return chmigrate.Migration{Version: 6, Name: "flow_rollup_complete_inputs", Statements: []string{
		"ALTER TABLE " + rollup + " " + strings.Join(additions, ", "),
		"CREATE MATERIALIZED VIEW IF NOT EXISTS " + oldView + "_v6 TO " + rollup + " AS " + selection,
		"DROP TABLE IF EXISTS " + oldView,
		// Raw legacy rows can share an empty row_id. Derive their stable identity
		// before destination FINAL dedup, rather than collapsing them in the source.
		"INSERT INTO " + rollup + " (" + columns + ") " + selection + " SETTINGS max_threads=2,max_memory_usage=536870912",
	}, Destructive: true, Justification: "retire only the old derived materialized view after installing its replacement; destination and aged-out history are preserved; append retained complete inputs with the unchanged stable dedup key"}
}

func fullRollupBackfillSQL(raw, rollup string) string {
	columns, selection := fullRollupSelect(raw)
	return "INSERT INTO " + rollup + " (" + columns + ") " + selection + " WHERE tenant_id={tenant:String} AND ts >= {from:DateTime64(3)} AND ts < {to:DateTime64(3)} SETTINGS max_threads=2,max_memory_usage=536870912"
}

// PlanSourceCoverage describes actual retained inputs, never a promised range
// inferred from a configured TTL. Mixed older/newer input reports their common
// fields and the coarsest input resolution.
type PlanSourceCoverage struct {
	Fields            []string `json:"fields"`
	ResolutionSeconds int      `json:"resolution_seconds"`
	CompleteInputs    bool     `json:"complete_inputs"`
}

// PlanCoverageError is an actionable refusal, not a partial result. Its fields
// contain only registry names and server-derived temporal coverage.
type PlanCoverageError struct {
	ResolutionSeconds int
	UnavailableFields []string
	Reason            string
}

func (e *PlanCoverageError) Error() string {
	message := fmt.Sprintf("flow source coverage requires %d-second input resolution: %s", e.ResolutionSeconds, e.Reason)
	if len(e.UnavailableFields) > 0 {
		message += "; unavailable fields: " + strings.Join(e.UnavailableFields, ", ")
	}
	return message
}

type planSource struct {
	table, kind string
	coverage    *PlanSourceCoverage
}

func allPlanFields() []string {
	fields := []string{}
	for _, field := range flow.QueryFields() {
		fields = append(fields, field.Name)
	}
	return fields
}

// planSourceFor uses the same reader policy and explicit scope as execution.
// The first raw timestamp is an indexed coverage observation, not a day cap.
func (c *ClickHouse) planSourceFor(ctx context.Context, target Target, lane chclient.ReadLane, tenant string, plan flow.QueryPlan) (planSource, error) {
	settings, err := explorerBudgetFor(ctx).settings()
	if err != nil {
		return planSource{}, err
	}
	raw, err := tableFor(target)
	if err != nil {
		return planSource{}, err
	}
	rollup, err := rollupTableFor(target)
	if err != nil {
		return planSource{}, err
	}
	params := chParams{"tenant": tenant, "from": chTimeParam(plan.From), "to": chTimeParam(plan.To)}
	rows, err := c.explorerQueryRows(ctx, target, lane, tenant, "SELECT ts FROM "+raw+" FINAL WHERE tenant_id={tenant:String} ORDER BY ts LIMIT 1 "+settings, params)
	if err != nil {
		return planSource{}, err
	}
	oldest := time.Unix(0, 0).UTC()
	if len(rows) > 1 {
		return planSource{}, errors.New("invalid raw source coverage")
	}
	if len(rows) == 1 {
		oldest = chParseTime(chToString(rows[0]["ts"]))
		if oldest.IsZero() {
			return planSource{}, errors.New("invalid raw source coverage timestamp")
		}
	}
	params["raw_from"] = chTimeParam(oldest)
	// The hour predicate includes legacy rows at both boundary hours. Complete
	// inputs additionally retain their exact event time for execution.
	probe := "SELECT toString(countIf(coverage_version=0)) AS legacy,toString(countIf(ts<{raw_from:DateTime64(3)} OR {raw_from:DateTime64(3)}=toDateTime64(0,3))) AS before_raw FROM " + rollup + " FINAL WHERE tenant_id={tenant:String} AND bucket>=toStartOfHour({from:DateTime64(3)}) AND bucket<{to:DateTime64(3)} " + settings
	rows, err = c.explorerQueryRows(ctx, target, lane, tenant, probe, params)
	if err != nil {
		return planSource{}, err
	}
	if len(rows) != 1 {
		return planSource{}, errors.New("invalid retained source coverage")
	}
	legacy := chToUint64(rows[0]["legacy"])
	beforeRaw := chToUint64(rows[0]["before_raw"])
	choice := plan.DataSeries
	if choice == "auto" {
		choice = "raw"
		if beforeRaw > 0 || plan.BucketSeconds >= 3600 {
			choice = "rollup"
		}
	}
	if choice == "raw" {
		if beforeRaw > 0 {
			return planSource{}, &PlanCoverageError{Reason: "this range includes retained history beyond raw coverage; choose auto or rollup", ResolutionSeconds: 60}
		}
		return planSource{table: raw, kind: "raw"}, nil
	}
	coverage := &PlanSourceCoverage{Fields: allPlanFields(), ResolutionSeconds: 60, CompleteInputs: true}
	if legacy > 0 {
		coverage.CompleteInputs = false
		coverage.ResolutionSeconds = 3600
		coverage.Fields = nil
		for _, field := range flow.QueryFields() {
			if field.LegacyHourly {
				coverage.Fields = append(coverage.Fields, field.Name)
			}
		}
		fields := append(append(append(append([]string{}, plan.GroupBy...), plan.MatrixWith...), flow.QueryFilterFields(plan.Filter)...), planDistinctFields(plan)...)
		missing := []string{}
		for _, name := range fields {
			if !slices.Contains(coverage.Fields, name) && !slices.Contains(missing, name) {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			return planSource{}, &PlanCoverageError{Reason: "older hourly history did not retain these fields; narrow to complete-input coverage", ResolutionSeconds: 3600, UnavailableFields: missing}
		}
		if plan.BucketSeconds%3600 != 0 || !plan.From.Equal(plan.From.Truncate(time.Hour)) || !plan.To.Equal(plan.To.Truncate(time.Hour)) {
			return planSource{}, &PlanCoverageError{Reason: "older hourly-only inputs need whole-hour bounds and hour-multiple buckets; newer complete inputs support arbitrary bounds", ResolutionSeconds: 3600}
		}
	}
	return planSource{table: rollup, kind: "rollup", coverage: coverage}, nil
}

// Exact retained columns inherit the existing raw-input clock. The unchanged
// hourly subset remains after expiry; keeping complete inputs forever requires
// the same explicit retentionDays=0 choice as raw storage.
func (c *ClickHouse) configureFullRollupRetention(ctx context.Context, base, table string, days int) error {
	if days < 0 || !explorerTablePattern.MatchString(table) {
		return errors.New("invalid complete flow retention configuration")
	}
	columns := append([]struct{ name, typ string }{}, fullRollupColumns...)
	columns = append(columns, struct{ name, typ string }{"coverage_version", "UInt8 DEFAULT 0"})
	if days == 0 {
		// ClickHouse24.8 rejects REMOVE TTL when a column has none. Remove
		// individually, ignoring only that exact already-absent diagnostic;
		// missing tables, privileges, transport and all other errors fail closed.
		for _, column := range columns {
			err := c.exec(ctx, base, "ALTER TABLE "+table+" MODIFY COLUMN "+column.name+" REMOVE TTL", nil, nil)
			if err != nil {
				if strings.Contains(err.Error(), "Code: 36.") && strings.Contains(err.Error(), "Column `"+column.name+"` doesn't have TTL, cannot remove it.") {
					continue
				}
				return err
			}
		}
		return nil
	}
	clauses := []string{}
	for _, column := range columns {
		action := "MODIFY COLUMN " + column.name + " REMOVE TTL"
		if days > 0 {
			action = "MODIFY COLUMN " + column.name + " " + column.typ + fmt.Sprintf(" TTL bucket + INTERVAL %d DAY", days)
		}
		clauses = append(clauses, action)
	}
	return c.exec(ctx, base, "ALTER TABLE "+table+" "+strings.Join(clauses, ", "), nil, nil)
}

func (c *ClickHouse) expireCompleteRollupInputs(ctx context.Context, target Target, tenant string, cutoff time.Time) error {
	table, err := rollupTableFor(target)
	if err != nil {
		return err
	}
	updates := []string{}
	for _, column := range fullRollupColumns {
		value := "0"
		switch {
		case column.name == "ts":
			value = "toDateTime64(bucket,3)"
		case strings.Contains(column.typ, "String"):
			value = "''"
		}
		updates = append(updates, column.name+"="+value)
	}
	updates = append(updates, "coverage_version=0")
	return c.exec(ctx, target.BaseURL, "ALTER TABLE "+table+" UPDATE "+strings.Join(updates, ",")+" WHERE tenant_id={tenant:String} AND coverage_version=1 AND ts<{cutoff:DateTime64(3)} SETTINGS mutations_sync=2", chParams{"tenant": tenant, "cutoff": chTimeParam(cutoff)}, nil)
}
