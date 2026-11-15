// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"strings"

	"github.com/ctlplne/probectl/internal/store/chmigrate"
)

var serviceColumns = []struct{ name, typ string }{
	{"src_service", "LowCardinality(String)"}, {"src_service_region", "LowCardinality(String)"}, {"src_service_provider", "LowCardinality(String)"}, {"src_service_status", "LowCardinality(String)"},
	{"dst_service", "LowCardinality(String)"}, {"dst_service_region", "LowCardinality(String)"}, {"dst_service_provider", "LowCardinality(String)"}, {"dst_service_status", "LowCardinality(String)"},
	{"service_classified_at", "String"}, {"service_evidence", "String"},
}

func serviceRollupSelect(source string) (columns, selection string) {
	columns, selection = routingCaptureRollupSelect(source)
	var names []string
	for _, column := range serviceColumns {
		names = append(names, column.name)
	}
	extra := strings.Join(names, ",")
	return columns + "," + extra, strings.TrimSuffix(selection, " FROM "+source) + "," + extra + " FROM " + source
}

// v1–v9 remain immutable. Empty metadata on older inputs means unavailable
// classification; never substitute today's range catalog for past history.
func serviceAttributionMigration(raw, rollup, oldView string) chmigrate.Migration {
	var additions []string
	for _, column := range serviceColumns {
		additions = append(additions, "ADD COLUMN IF NOT EXISTS "+column.name+" "+column.typ)
	}
	_, selection := serviceRollupSelect(raw)
	return chmigrate.Migration{Version: 10, Name: "flow_published_service_attribution", Statements: []string{
		"ALTER TABLE " + raw + " " + strings.Join(additions, ", "),
		"ALTER TABLE " + rollup + " " + strings.Join(additions, ", "),
		"CREATE MATERIALIZED VIEW IF NOT EXISTS " + oldView + "_v10 TO " + rollup + " AS " + selection,
		"DROP TABLE IF EXISTS " + oldView + "_v7",
	}, Destructive: true, Justification: "replace only the derived materialized view after installing its complete replacement; preserve raw and hourly history, original dedup keys and tenant partitions; older classifications remain unknown"}
}
