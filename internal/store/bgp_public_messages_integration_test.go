// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real application-role PG/TLS/RLS and whole-source store transactions. Source
// frames/issued identities are modeled; no actual public collector claim.
func TestPublicSnapshotMessagesPublishWholeTenantSourcesAndRefuseAtomicOmissions(t *testing.T) {
	f := newRoleInputsFixture(t)
	base, profile := publicSnapshotFixture()
	run := func(tenant string, fn func(context.Context, tenancy.Scope) error) error {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		return tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), tenant, entity.ErrScopeMismatch, func(ctx context.Context) error { return tenancy.InTenant(ctx, f.pool, fn) })
	}
	now := func(tenant string) time.Time {
		var at time.Time
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at)
		})
		return at
	}
	stage := func(tenant string, empty, unknown bool) (BGPPublicSnapshotInput, BGPPublicSnapshotStageResult) {
		input := base
		input.ObservationID = uuid.NewString()
		input.ObservedAt = now(tenant)
		input.SenderSerial = f.serials[tenant+"role-listener"]
		clock := input.ObservedAt.Add(-30 * time.Second).UnixNano()
		input.SourceObservedUnixNanos = &clock
		if unknown {
			input.SourceObservedUnixNanos = nil
		}
		if empty {
			input.Definitions = []BGPRoutingViewDefinition{}
		}
		var out BGPPublicSnapshotStageResult
		if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			out, err = (BGPRouting{}).StagePublicSnapshotInScope(ctx, sc, input, profile)
			return err
		}); err != nil || out.Status != "staged" {
			t.Fatal("public message fixture could not stage source", out, err)
		}
		return input, out
	}
	message := func(tenant string, input BGPPublicSnapshotInput, staged BGPPublicSnapshotStageResult, sequence int64, complete bool) BGPPublicSnapshotMessage {
		at := now(tenant)
		out := BGPPublicSnapshotMessage{CollectorAgentID: input.CollectorAgentID, SenderSerial: input.SenderSerial, SourceRef: input.SourceRef, SnapshotID: staged.ID, Sequence: sequence, ObservedAt: at, WireDigest: crypto.Hash([]byte("source-record:" + tenant + staged.ID)), Complete: complete}
		if !complete {
			for index, view := range staged.Views {
				change := routingChangeFixture()
				if view.AFI == 2 {
					change.Prefix = netip.MustParsePrefix("2001:db8::/32")
				}
				change.Segments[1].Values[0] -= uint32(index)
				out.Batches = append(out.Batches, BGPPublicSnapshotBatch{BGPRoutingViewRef: view.BGPRoutingViewRef, BGPRoutingBatch: BGPRoutingBatch{Sequence: sequence, AFI: view.AFI, SAFI: view.SAFI, ObservedAt: at, Changes: []BGPRoutingChange{change}}})
			}
		}
		return out
	}
	apply := func(tenant string, input BGPPublicSnapshotMessage) BGPRoutingApplyResult {
		var out BGPRoutingApplyResult
		if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			out, err = (BGPRouting{}).ApplyPublicSnapshotMessageInScope(ctx, sc, input, profile, time.Hour)
			return err
		}); err != nil {
			t.Fatal("public message transaction failed", err)
		}
		return out
	}
	state := func(tenant, id string) (string, int, int) {
		var state string
		var current, entries int
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT state,(SELECT count(*) FROM bgp_routing_views v WHERE v.tenant_id=h.tenant_id AND v.context_id=h.context_id AND v.public_snapshot_id=h.id AND v.state='current'),(SELECT count(*) FROM bgp_routing_entries e JOIN bgp_routing_views v ON(v.tenant_id,v.context_id,v.id,v.generation)=(e.tenant_id,e.context_id,e.view_id,e.generation) WHERE v.tenant_id=h.tenant_id AND v.context_id=h.context_id AND v.public_snapshot_id=h.id) FROM bgp_public_snapshots h WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&state, &current, &entries)
		})
		return state, current, entries
	}
	sources := make([]BGPPublicSnapshotStageResult, 2)
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id) VALUES($1,'role-listener','public_bgp',$2,$3)`, tenant, base.SourceRef, f.contextID)
			return err
		})
		input, source := stage(tenant, false, false)
		sources[lane] = source
		data := message(tenant, input, source, 1, false)
		if out := apply(tenant, data); out.Status != "applied" {
			t.Fatal("whole public data message refused", out)
		}
		if state, current, entries := state(tenant, source.ID); state != "staging" || current != 0 || entries != 3 {
			t.Fatal("partial public source became current or lost complete message", state, current, entries)
		}
		if out := apply(tenant, data); out.Status != "replayed" {
			t.Fatal("exact public data retry changed source", out)
		}
		complete := message(tenant, input, source, 2, true)
		if out := apply(tenant, complete); out.Status != "applied" {
			t.Fatal("complete public source was not atomically published", out)
		}
		if state, current, entries := state(tenant, source.ID); state != "current" || current != 3 || entries != 3 {
			t.Fatal("public publication exposed a partial cohort or another tenant", state, current, entries)
		}
		if out := apply(tenant, complete); out.Status != "replayed" {
			t.Fatal("complete source retry revived or replaced its snapshot", out)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var until time.Time
			var total int
			if err := sc.Q.QueryRow(ctx, `SELECT valid_until,(SELECT count(*) FROM bgp_public_snapshots) FROM bgp_public_snapshots WHERE tenant_id=$1 AND id=$2`, tenant, source.ID).Scan(&until, &total); err != nil {
				return err
			}
			if total != 1 || until.After(time.Unix(0, *input.SourceObservedUnixNanos).Add(time.Hour)) {
				t.Fatal("published public source crossed tenant storage or renewed original data age", total, until)
			}
			var raw []byte
			if err := sc.Q.QueryRow(ctx, `SELECT segments FROM bgp_routing_entries WHERE tenant_id=$1 AND view_id=$2`, tenant, source.Views[0].ID).Scan(&raw); err != nil {
				return err
			}
			var path []BGPRoutingSegment
			if err := json.Unmarshal(raw, &path); err != nil {
				return err
			}
			if len(path) != 3 || path[0].Kind != 3 || path[1].Values[0] != ^uint32(0) || path[2].Kind != 1 {
				t.Fatal("public publication lost complete segment kinds or full ASN", path)
			}
			return nil
		})
	}
	input, source := stage(f.tenants[0], false, false)
	attack := message(f.tenants[0], input, source, 1, false)
	attack.Batches[1].BGPRoutingViewRef = sources[1].Views[1].BGPRoutingViewRef
	if out := apply(f.tenants[0], attack); out.Status != "invalidated" {
		t.Fatal("public source borrowed a foreign staged view", out)
	}
	if got, current, entries := state(f.tenants[0], source.ID); got != "invalid" || current != 0 || entries != 0 {
		t.Fatal("rejected public message committed partial route writes", got, current, entries)
	}
	if got, current, entries := state(f.tenants[1], sources[1].ID); got != "current" || current != 3 || entries != 3 {
		t.Fatal("foreign public message changed sibling source", got, current, entries)
	}
	for _, tc := range []struct {
		name                         string
		empty, unknown, gap, corrupt bool
		want                         string
	}{{"empty", true, false, false, false, "applied"}, {"unknown-clock", false, true, false, false, "invalidated"}, {"gap", false, false, true, false, "invalidated"}, {"corrupt-manifest", false, false, false, true, "invalidated"}} {
		t.Run(tc.name, func(t *testing.T) {
			input, source := stage(f.tenants[0], tc.empty, tc.unknown)
			if tc.corrupt {
				f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
					_, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET peer_identity=jsonb_set(peer_identity,'{PeerASN}','64496'::jsonb) WHERE tenant_id=$1 AND public_snapshot_id=$2`, f.tenants[0], source.ID)
					return err
				})
			}
			sequence := int64(1)
			if tc.gap {
				sequence = 2
			}
			out := apply(f.tenants[0], message(f.tenants[0], input, source, sequence, true))
			if out.Status != tc.want {
				t.Fatal("public completion manufactured data or lost a genuine empty source", out, tc.want)
			}
		})
	}
}
