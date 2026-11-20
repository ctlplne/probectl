// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type BGPASPathHistoryPosition struct {
	ObservedAt time.Time `json:"observed_at"`
	Vantage    string    `json:"vantage"`
	Sequence   int64     `json:"sequence,string"`
	Operation  int32     `json:"operation"`
	ID         string    `json:"id"`
}

type BGPASPathHistorySelection struct {
	Monitor    string
	SourceKind string
	Vantage    string
	From, To   time.Time
	After      *BGPASPathHistoryPosition
	Limit      int
}

type BGPASPathHistoryRecord struct {
	BGPASPathHistoryPosition
	SourceKind    string          `json:"source_kind"`
	SourceEpoch   string          `json:"source_epoch"`
	Kind          string          `json:"kind"`
	HasPathID     bool            `json:"has_path_id"`
	PathID        uint32          `json:"path_id"`
	ContextID     string          `json:"context_id,omitempty"`
	RouterID      string          `json:"router_id,omitempty"`
	ChangeEventID string          `json:"change_event_id,omitempty"`
	Original      json.RawMessage `json:"-"`
	Previous      json.RawMessage `json:"previous,omitempty"`
	Current       json.RawMessage `json:"current,omitempty"`
}

func validBGPASPathHistorySelection(query BGPASPathHistorySelection) bool {
	if !bgpVisibilityID(query.Monitor) || len(query.Vantage) > 256 || query.From.IsZero() ||
		!query.From.Before(query.To) || query.Limit < 1 {
		return false
	}
	if query.SourceKind != "" && query.SourceKind != "router_bmp" && query.SourceKind != "public_mrt" {
		return false
	}
	after := query.After
	return after == nil || bgpVisibilityID(after.ID) && len(after.Vantage) > 0 && len(after.Vantage) <= 256 &&
		after.Sequence >= 0 && after.Operation >= 0 && !after.ObservedAt.Before(query.From) && after.ObservedAt.Before(query.To)
}

// BGPASPathHistoryInScope reads one ordered, resource-admitted page in an
// already admitted tenant snapshot. Private source details still require
// verification and current entity/resource authority before publication.
func BGPASPathHistoryInScope(ctx context.Context, sc tenancy.Scope, query BGPASPathHistorySelection,
	profile BGPRoutingBudget) ([]BGPASPathHistoryRecord, bool, error) {
	if err := verifyBGPVisibilityScope(ctx, sc); err != nil {
		return nil, false, err
	}
	if !validBGPASPathHistorySelection(query) {
		return nil, false, ErrBGPVisibilityInput
	}
	if err := routingBatchPopulationCharge(&profile, query.Limit, 512, 512); err != nil {
		return nil, false, err
	}
	if _, err := BGPVisibilityMonitorInScope(ctx, sc, query.Monitor); err != nil {
		return nil, false, err
	}
	var (
		at    *time.Time
		after BGPASPathHistoryPosition
	)
	if query.After != nil {
		after = *query.After
		at = &after.ObservedAt
	}
	rows, err := sc.Q.Query(ctx, `SELECT id::text,observed_at,vantage_key,source_sequence,source_operation,source_kind,source_epoch,
 event_kind,has_path_id,path_id,COALESCE(context_id::text,''),COALESCE(router_id::text,''),COALESCE(change_event_id::text,''),
 CASE WHEN size.bytes<=$12 THEN original::text END,
 CASE WHEN size.bytes<=$12 THEN previous_path::text END,CASE WHEN size.bytes<=$12 THEN current_path::text END
 FROM bgp_as_path_history
 CROSS JOIN LATERAL (SELECT octet_length(original::text)::bigint+COALESCE(octet_length(previous_path::text),0)
 +COALESCE(octet_length(current_path::text),0) AS bytes) size
 WHERE tenant_id=$1 AND monitor_id=$2 AND observed_at>=$3 AND observed_at<$4
 AND ($5::text='' OR source_kind=$5) AND ($6::text='' OR vantage_key=$6)
 AND observed_at<=COALESCE($7::timestamptz,$4::timestamptz)
 AND ($7::timestamptz IS NULL OR (observed_at,vantage_key,source_sequence,source_operation,id) <
     ($7::timestamptz,$8::text,$9::bigint,$10::integer,NULLIF($11::text,'')::uuid))
 ORDER BY observed_at DESC,vantage_key DESC,source_sequence DESC,source_operation DESC,id DESC LIMIT $13`,
		sc.Tenant.String(), query.Monitor, query.From, query.To, query.SourceKind, query.Vantage, at, after.Vantage,
		after.Sequence, after.Operation, after.ID, profile.MemoryBytes/8, query.Limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	return readBGPASPathHistoryRows(rows, query.Limit, profile)
}

func readBGPASPathHistoryRows(rows pgx.Rows, limit int, profile BGPRoutingBudget) ([]BGPASPathHistoryRecord, bool, error) {
	history := []BGPASPathHistoryRecord{}
	for rows.Next() {
		if len(history) == limit {
			return history, true, nil
		}
		var point BGPASPathHistoryRecord
		var pathID int64
		var original, previous, current []byte
		err := rows.Scan(&point.ID, &point.ObservedAt, &point.Vantage, &point.Sequence, &point.Operation, &point.SourceKind,
			&point.SourceEpoch, &point.Kind, &point.HasPathID, &pathID, &point.ContextID, &point.RouterID, &point.ChangeEventID,
			&original, &previous, &current)
		if err != nil {
			return nil, false, err
		}
		if len(original) == 0 {
			return nil, false, ErrBGPRoutingBudget
		}
		if err := routingBatchPopulationCharge(&profile, len(original)+len(previous)+len(current), 8, 8); err != nil {
			return nil, false, err
		}
		point.PathID = uint32(pathID)
		point.Original, point.Previous, point.Current = original, previous, current
		history = append(history, point)
	}
	return history, false, rows.Err()
}
