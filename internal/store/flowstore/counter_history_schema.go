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

const sharedCounterHistoryTable = "probectl_device_counters"
const sharedCounterPollTable = "probectl_device_counter_polls"

func counterPollTableFor(target Target) (string, error) {
	table, err := counterHistoryTableFor(target)
	return strings.TrimSuffix(table, sharedCounterHistoryTable) + sharedCounterPollTable, err
}

func counterHistoryTableFor(target Target) (string, error) {
	if target.Database == "" {
		return sharedCounterHistoryTable, nil
	}
	if !chIdentRe.MatchString(target.Database) {
		return "", ErrCounterHistoryInput
	}
	return target.Database + "." + sharedCounterHistoryTable, nil
}

func counterHistoryDDL(table string) string {
	return `CREATE TABLE IF NOT EXISTS ` + table + ` (
 tenant_id String, context_id String, device_id String,
 agent_id String, source_ref String, sender_serial String,
 source_assigned_unix_nanos Int64, agent_assigned_unix_nanos Int64,
 capture_key String, raw_digest String, captured_unix_nanos Int64,
 poll_started_unix_nanos Int64, poll_completed_unix_nanos Int64,
 population UInt32, if_index UInt32, name LowCardinality(String),
 counter_value UInt64, counter_width UInt8,
 uptime_ticks UInt32, discontinuity_ticks UInt32,
 uptime_known UInt8, discontinuity_known UInt8,
 row_id String,
 ts DateTime64(9,'UTC') MATERIALIZED fromUnixTimestamp64Nano(poll_started_unix_nanos),
 CONSTRAINT counter_identity CHECK tenant_id!='' AND context_id!='' AND device_id!=''
  AND agent_id!='' AND source_ref!='' AND sender_serial!=''
  AND length(capture_key)=64 AND length(raw_digest)=64 AND length(row_id)=64,
 CONSTRAINT counter_poll_clock CHECK poll_started_unix_nanos>0
  AND poll_completed_unix_nanos>=poll_started_unix_nanos AND captured_unix_nanos>0
  AND source_assigned_unix_nanos>0 AND source_assigned_unix_nanos<=poll_started_unix_nanos
  AND agent_assigned_unix_nanos>0 AND agent_assigned_unix_nanos<=poll_started_unix_nanos,
 CONSTRAINT counter_word CHECK (counter_width=32 OR counter_width=64)
  AND (counter_width=64 OR counter_value<=4294967295) AND if_index>0 AND population>0,
 CONSTRAINT counter_clock_presence CHECK uptime_known IN (0,1) AND discontinuity_known IN (0,1)
  AND (uptime_known=1 OR uptime_ticks=0)
  AND (discontinuity_known=1 OR discontinuity_ticks=0)
) ENGINE = ReplacingMergeTree
PARTITION BY (tenant_id,toYYYYMMDD(ts))
ORDER BY (tenant_id,context_id,device_id,agent_id,source_ref,
 source_assigned_unix_nanos,agent_assigned_unix_nanos,ts,if_index,name,row_id)`
}

func counterHistoryMigration(flowTable string) chmigrate.Migration {
	prefix := strings.TrimSuffix(flowTable, sharedFlowsTable)
	return chmigrate.Migration{Version: 8, Name: "exact_device_counter_history", Statements: []string{
		counterHistoryDDL(prefix + sharedCounterHistoryTable), counterPollDDL(prefix + sharedCounterPollTable),
	}}
}

// A single-row commit marker is published only after control authority counts
// every distinct original point. Failed multi-block inserts stay invisible.
func counterPollDDL(table string) string {
	return `CREATE TABLE IF NOT EXISTS ` + table + ` (
 tenant_id String, context_id String, device_id String, agent_id String, source_ref String,
 source_assigned_unix_nanos Int64, agent_assigned_unix_nanos Int64,
 capture_key String, poll_started_unix_nanos Int64, population UInt32,
 ts DateTime64(9,'UTC') MATERIALIZED fromUnixTimestamp64Nano(poll_started_unix_nanos),
 CONSTRAINT counter_poll_identity CHECK tenant_id!='' AND context_id!='' AND device_id!=''
  AND agent_id!='' AND source_ref!='' AND length(capture_key)=64
  AND poll_started_unix_nanos>0 AND population>0
  AND source_assigned_unix_nanos>0 AND source_assigned_unix_nanos<=poll_started_unix_nanos
  AND agent_assigned_unix_nanos>0 AND agent_assigned_unix_nanos<=poll_started_unix_nanos
) ENGINE = ReplacingMergeTree
PARTITION BY (tenant_id,toYYYYMMDD(ts))
ORDER BY (tenant_id,context_id,device_id,agent_id,source_ref,
 source_assigned_unix_nanos,agent_assigned_unix_nanos,ts,capture_key)`
}

func counterCommittedPredicate(target Target, window bool) (string, error) {
	table, err := counterPollTableFor(target)
	predicate := "tenant_id={tenant:String}"
	if window {
		predicate += " AND ts>=fromUnixTimestamp64Nano({from:Int64}) AND ts<=fromUnixTimestamp64Nano({to:Int64})"
	}
	return "(capture_key,population) IN (SELECT capture_key,population FROM " + table + " FINAL WHERE " + predicate + ")", err
}

// Expand the existing history in every pooled or silo target. Old observations
// retain unknown speed; migration 8's applied schema/checksum stays unchanged.
func counterSpeedMigration(flowTable string) chmigrate.Migration {
	table := strings.TrimSuffix(flowTable, sharedFlowsTable) + sharedCounterHistoryTable
	return chmigrate.Migration{Version: 9, Name: "counter_original_interface_speed", Statements: []string{
		"ALTER TABLE " + table + " ADD COLUMN IF NOT EXISTS interface_speed_bps UInt64 DEFAULT 0",
		"ALTER TABLE " + table + " ADD COLUMN IF NOT EXISTS interface_speed_known UInt8 DEFAULT 0",
		"ALTER TABLE " + table + " ADD CONSTRAINT IF NOT EXISTS counter_speed_presence CHECK interface_speed_known IN (0,1) AND (interface_speed_known=1 OR interface_speed_bps=0)",
	}}
}
