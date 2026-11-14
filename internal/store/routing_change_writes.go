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
	"strconv"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The existing fenced routing writer owns this call. References and original
// source metadata commit atomically with the complete accepted route batch.
// It runs before entry mutation so selected-route updates compare the actual
// previous path, not an inferred public feed or a later current RIB.
func appendOwnedRoutingChanges(ctx context.Context, sc tenancy.Scope, source BGPRoutingSource, ref BGPRoutingViewRef, view routingWriteView, batch BGPRoutingBatch, digest [32]byte, updates []routingPreparedChange, profile BGPRoutingBudget) error {
	if err := validateBGPRoutingSource(ctx, sc, source); err != nil {
		return err
	}
	if len(updates) == 0 {
		return ctx.Err()
	}
	common := change.RouteReference{Version: 1, ContextID: source.ContextID, RouterID: source.RouterID, BaseContextID: source.ContextID, BaseRouterID: source.RouterID,
		ViewID: ref.ID, Generation: ref.Generation, Sequence: strconv.FormatInt(batch.Sequence, 10), BatchDigest: hex.EncodeToString(digest[:]), ObservedAt: batch.ObservedAt,
		View: view.kind, Action: "announcement", AFI: batch.AFI, SAFI: batch.SAFI}
	var selection json.RawMessage
	if selected := source.routingSelection; selected != nil {
		common.BaseContextID, common.BaseRouterID = selected.BaseContextID, selected.BaseRouterID
		var err error
		selection, err = json.Marshal(selected)
		if err != nil {
			return err
		}
	}
	if err := common.Validate(); err != nil {
		return err
	}
	original := routingChangeSource{Version: 1, Source: source, Selection: selection, ViewBornAt: view.born, ViewID: ref.ID, Generation: ref.Generation,
		Sequence: common.Sequence, BatchDigest: common.BatchDigest, View: common.View, AFI: batch.AFI, SAFI: batch.SAFI}
	private, err := json.Marshal(original)
	if err != nil {
		return err
	}
	public, err := json.Marshal(common)
	if err != nil {
		return err
	}
	// Preserve every admitted update, including intermediate updates to the same
	// prefix in one batch; the current RIB writer may coalesce its final state.
	// These are the already admitted batch's same typed changes;
	// original attributes/segments are shared rather than copied per event.
	body, err := json.Marshal(updates)
	if err != nil {
		return err
	}
	if int64(len(body)) > profile.MemoryBytes/8 || int64(len(body)) > profile.WorkUnits/8 || int64(len(public)+len(private)) > profile.MemoryBytes/8 || int64(len(public)+len(private)) > profile.WorkUnits/8 {
		return ErrBGPRoutingBudget
	}
	_, err = sc.Q.Exec(ctx, `WITH incoming AS (
 SELECT input.*,element.ordinality FROM jsonb_array_elements($5::jsonb) WITH ORDINALITY AS element(body,ordinality)
 CROSS JOIN LATERAL jsonb_to_record(element.body) AS input("Prefix" cidr,"HasPathID" boolean,"PathID" bigint,"Withdraw" boolean,"Segments" jsonb,"Attributes" jsonb,"NextHops" inet[])
), previous AS (
 SELECT input.*,lag(ordinality) OVER updates AS prior_ordinal,
 lag("Withdraw") OVER updates AS prior_withdraw,lag("Segments") OVER updates AS prior_segments,
 lag("Attributes") OVER updates AS prior_attributes,lag("NextHops") OVER updates AS prior_hops
 FROM incoming input WINDOW updates AS (PARTITION BY "Prefix","HasPathID","PathID" ORDER BY ordinality)
), originals AS (
 SELECT input.*,CASE WHEN prior_ordinal IS NOT NULL THEN NOT prior_withdraw ELSE old.prefix IS NOT NULL END AS prior_present,
 CASE WHEN prior_ordinal IS NOT NULL THEN prior_segments ELSE old.segments END AS original_segments,
 CASE WHEN prior_ordinal IS NOT NULL THEN prior_attributes ELSE old.attributes END AS original_attributes,
 CASE WHEN prior_ordinal IS NOT NULL THEN prior_hops ELSE old.next_hops END AS original_hops
 FROM previous input LEFT JOIN bgp_routing_entries old ON
 old.tenant_id=$1 AND old.context_id=$2 AND old.view_id=$3 AND old.generation=$4 AND old.prefix=input."Prefix"
 AND old.has_path_id=input."HasPathID" AND old.path_id=input."PathID"
), facts AS (
 SELECT originals.*,
 CASE WHEN prior_present AND NOT "Withdraw" THEN original_segments IS DISTINCT FROM "Segments" OR original_hops IS DISTINCT FROM "NextHops" ELSE false END AS path_changed,
 CASE WHEN prior_present AND NOT "Withdraw" THEN original_attributes-'MRT' IS DISTINCT FROM "Attributes"-'MRT' ELSE false END AS attributes_changed
 FROM originals
), classified AS (
 SELECT facts.*,CASE WHEN "Withdraw" THEN 'withdrawal'
 WHEN $9 IN ('loc_rib','operator_loc_rib') AND prior_present AND (path_changed OR attributes_changed) THEN 'selected_route_update'
 ELSE 'announcement' END AS action FROM facts
)
 INSERT INTO change_events(tenant_id,source,kind,title,summary,target,prefix,ref,occurred_at,routing,routing_source)
 SELECT $1,$10,'route','BGP '||action||' '||"Prefix"::text,
 'Observed owned-router '||action||' in '||$9||'; no forwarding-state claim.',$11,"Prefix"::text,$12,$8,
 $6::jsonb||jsonb_build_object('update_index',ordinality-1,'action',action,'has_path_id',"HasPathID",'path_id',"PathID",'prior_present',prior_present,'path_changed',path_changed,'attributes_changed',attributes_changed),$7::jsonb
 FROM classified`, source.TenantID, source.ContextID, ref.ID, ref.Generation, body, public, private, batch.ObservedAt, view.kind, ownedRoutingChangeSource, source.RouterID, common.BatchDigest)
	return err
}
