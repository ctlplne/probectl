// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Record the complete prefix population only when the authenticated source
// reaches End-of-RIB. A staging or repaired view has its own generation.
func appendOwnedASPathBaseline(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, ref BGPRoutingViewRef,
	view routingWriteView, batch BGPRoutingBatch, digest [32]byte) error {
	selection, err := routingSelectionJSON(source)
	if err != nil {
		return err
	}
	original := routingChangeSource{Version: 1, Source: source, ViewBornAt: view.born, ViewID: ref.ID, Generation: ref.Generation,
		Sequence: strconv.FormatInt(batch.Sequence, 10), BatchDigest: hex.EncodeToString(digest[:]), View: view.kind, AFI: batch.AFI, SAFI: batch.SAFI}
	if encoded, ok := selection.(string); ok {
		original.Selection = json.RawMessage(encoded)
	}
	body, err := json.Marshal(original)
	if err != nil {
		return err
	}
	vantage := ownedASPathVantage(source, ref)
	family := 6
	if batch.AFI == 1 {
		family = 4
	}
	_, err = sc.Q.Exec(ctx, `WITH watched AS (
 SELECT tenant_id,id,prefix FROM bgp_visibility_monitors
 WHERE tenant_id=$1 AND family(prefix)=$12 AND created_at<=$8::timestamptz FOR KEY SHARE
)
 INSERT INTO bgp_as_path_history (tenant_id,monitor_id,source_kind,vantage_key,source_epoch,event_digest,
 observed_at,source_sequence,source_operation,has_path_id,path_id,context_id,router_id,collector_agent_id,source_ref,
 event_kind,original,current_path)
 SELECT monitor.tenant_id,monitor.id,'router_bmp',$6,$4::uuid::text,$7,$8,$9,
 (row_number() OVER (PARTITION BY monitor.id ORDER BY entry.has_path_id,entry.path_id)-1)::integer,
 COALESCE(entry.has_path_id,false),COALESCE(entry.path_id,0),$2,$5,$10,$11,'baseline',$13::jsonb,
 CASE WHEN entry.prefix IS NOT NULL THEN jsonb_build_object('segments',entry.segments,
 'observed_at',entry.observed_at,'sequence',entry.sequence::text,'next_hops',entry.next_hops) END
 FROM watched monitor LEFT JOIN bgp_routing_entries entry ON entry.tenant_id=$1 AND entry.context_id=$2
 AND entry.view_id=$3 AND entry.generation=$4 AND entry.prefix=monitor.prefix`,
		source.TenantID, source.ContextID, ref.ID, ref.Generation, source.RouterID, vantage, digest[:], batch.ObservedAt,
		batch.Sequence, source.CollectorAgentID, source.SourceRef, family, body)
	return err
}

func ownedASPathVantage(source BGPRoutingSource, ref BGPRoutingViewRef) string {
	return hex.EncodeToString(crypto.Hash([]byte(source.ContextID + "/" + source.RouterID + "/" + ref.ID)))
}

// VerifyBGPASPathHistorySourceInScope binds a private history row to its
// original source, current credentials and current resource authorization.
func VerifyBGPASPathHistorySourceInScope(ctx context.Context, sc tenancy.Scope, prefix netip.Prefix,
	row BGPASPathHistoryRecord, profile BGPRoutingBudget, authorize RoutingChangeAuthorizer) (change.RouteReference, error) {
	none := change.RouteReference{}
	if err := verifyBGPVisibilityScope(ctx, sc); err != nil {
		return none, err
	}
	if authorize == nil || row.SourceKind != "router_bmp" || !prefix.IsValid() {
		return none, errRoutingChangeSource
	}
	if err := requireRoutingReadSnapshot(ctx, sc); err != nil {
		return none, err
	}
	original, err := decodeRetainedRoutingChangeSource(ctx, sc, row.Original, profile)
	if err != nil {
		return none, err
	}
	source := original.Source
	if original.Generation != row.SourceEpoch || original.Sequence != strconv.FormatInt(row.Sequence, 10) ||
		!source.ObservedAt.Truncate(time.Microsecond).Equal(row.ObservedAt) || (original.AFI == 1) != prefix.Addr().Is4() ||
		source.ContextID != row.ContextID || source.RouterID != row.RouterID ||
		row.Vantage != ownedASPathVantage(source, BGPRoutingViewRef{ID: original.ViewID, Generation: original.Generation}) {
		return none, change.ErrRouteReference
	}
	event, err := ownedASPathAuthorizationEvent(ctx, sc, prefix, row, original)
	if err != nil {
		return none, err
	}
	until, err := verifyRoutingChangeSourceInScope(ctx, sc, original)
	if err != nil {
		return none, err
	}
	if err := authorize(ctx, sc, source, event); err != nil {
		return none, err
	}
	if !time.Now().UTC().Before(until) {
		return none, ErrBGPRoutingSourceUnavailable
	}
	return *event.Routing, ctx.Err()
}

func ownedASPathAuthorizationEvent(ctx context.Context, sc tenancy.Scope, prefix netip.Prefix,
	row BGPASPathHistoryRecord, original routingChangeSource) (change.Event, error) {
	if row.ChangeEventID != "" {
		event := change.Event{}
		if err := scanChange(sc.Q.QueryRow(ctx, `SELECT `+changeCols+` FROM change_events
 WHERE tenant_id=$1 AND id=$2 AND prefix=$3 AND routing_source=$4::jsonb`,
			sc.Tenant.String(), row.ChangeEventID, prefix.String(), string(row.Original)), &event); err != nil {
			return change.Event{}, err
		}
		if event.Routing == nil || event.Routing.UpdateIndex != int(row.Operation) || event.Routing.HasPathID != row.HasPathID ||
			event.Routing.PathID != row.PathID || !sameRoutingChangeOriginal(original, *event.Routing) {
			return change.Event{}, change.ErrRouteReference
		}
		return event, nil
	}
	if row.Kind != "baseline" {
		return change.Event{}, change.ErrRouteReference
	}
	source := original.Source
	reference := change.RouteReference{Version: 1, ContextID: source.ContextID, RouterID: source.RouterID,
		BaseContextID: source.ContextID, BaseRouterID: source.RouterID, ViewID: original.ViewID, Generation: original.Generation,
		Sequence: original.Sequence, BatchDigest: original.BatchDigest, ObservedAt: source.ObservedAt,
		View: original.View, AFI: original.AFI, SAFI: original.SAFI, Action: "announcement",
		UpdateIndex: int(row.Operation), HasPathID: row.HasPathID, PathID: row.PathID}
	if bound := source.routingSelection; bound != nil {
		reference.BaseContextID, reference.BaseRouterID = bound.BaseContextID, bound.BaseRouterID
	}
	if err := reference.Validate(); err != nil {
		return change.Event{}, err
	}
	return change.Event{TenantID: sc.Tenant.String(), Kind: change.KindRoute, Source: ownedRoutingChangeSource,
		Target: source.RouterID, Prefix: prefix.String(), OccurredAt: source.ObservedAt, Routing: &reference}, nil
}
