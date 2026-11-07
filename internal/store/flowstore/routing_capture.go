// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"strings"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/chmigrate"
)

var errRoutingCaptureRow = errors.New("flowstore: incomplete or mismatched routing capture reference")

func validateRoutingCaptureRow(row Row) error {
	if row.RawFlowDigest == "" && row.RoutingCaptureKey == "" && row.RoutingCapturedUnixNanos == 0 {
		return nil
	}
	if row.RoutingCapturedUnixNanos <= 0 {
		return errRoutingCaptureRow
	}
	raw, err := hex.DecodeString(row.RawFlowDigest)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != row.RawFlowDigest {
		return errRoutingCaptureRow
	}
	var digest [32]byte
	copy(digest[:], raw)
	exporter, e1 := netip.ParseAddr(row.Exporter)
	source, e2 := netip.ParseAddr(row.SrcAddr)
	destination, e3 := netip.ParseAddr(row.DstAddr)
	if e1 != nil || e2 != nil || e3 != nil {
		return errRoutingCaptureRow
	}
	key, err := entity.FlowCaptureKey(row.TenantID, row.AgentID, digest, entity.FlowCaptureInput{Exporter: exporter, Source: source, Destination: destination, Protocol: row.Protocol, Domain: row.ObsDomain})
	if err != nil || row.RoutingCaptureKey != hex.EncodeToString(key[:]) {
		return errRoutingCaptureRow
	}
	return nil
}

var routingCaptureColumns = []struct{ name, typ string }{
	{"raw_flow_digest", "String DEFAULT ''"},
	{"routing_capture_key", "String DEFAULT ''"},
	{"routing_captured_unix_nanos", "Int64 DEFAULT 0"},
}

func retainedFlowColumns() []struct{ name, typ string } {
	columns := append([]struct{ name, typ string }{}, fullRollupColumns...)
	return append(columns, routingCaptureColumns...)
}

func routingCaptureRollupSelect(source string) (columns, selection string) {
	columns, selection = fullRollupSelect(source)
	names := []string{}
	for _, column := range routingCaptureColumns {
		names = append(names, column.name)
	}
	extra := strings.Join(names, ",")
	return columns + "," + extra, strings.TrimSuffix(selection, " FROM "+source) + "," + extra + " FROM " + source
}

// v1–v6 remain immutable. Existing raw and hourly-only history receives empty
// references, never a guessed path. Install the complete replacement index
// before retiring its predecessor and backfill only retained original inputs.
func routingCaptureMigration(raw, rollup, oldView string) chmigrate.Migration {
	additions := []string{}
	for _, column := range routingCaptureColumns {
		additions = append(additions, "ADD COLUMN IF NOT EXISTS "+column.name+" "+column.typ)
	}
	columns, selection := routingCaptureRollupSelect(raw)
	return chmigrate.Migration{Version: 7, Name: "flow_original_routing_capture", Statements: []string{
		"ALTER TABLE " + raw + " " + strings.Join(additions, ", "),
		"ALTER TABLE " + rollup + " " + strings.Join(additions, ", "),
		"CREATE MATERIALIZED VIEW IF NOT EXISTS " + oldView + "_v7 TO " + rollup + " AS " + selection,
		"DROP TABLE IF EXISTS " + oldView + "_v6",
		"INSERT INTO " + rollup + " (" + columns + ") " + selection + " SETTINGS max_threads=2,max_memory_usage=2147483648",
	}, Destructive: true, Justification: "replace only the derived materialized view after installing its complete replacement; preserve raw and hourly data, backfilling immutable references only from retained inputs"}
}
