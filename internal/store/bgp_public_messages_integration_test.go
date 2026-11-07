// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
		provePublishedPublicSnapshotRead(t, f, tenant, input, source, profile)
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
	if got, err := publicSnapshotReadForFixture(t, f, f.tenants[0], base, sources[0].ID, "2001:db8::1", profile, time.Hour); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || got.Paths != nil {
		t.Fatal("public reader revived a replaced source", got, err)
	}
	if got, err := publicSnapshotReadForFixture(t, f, f.tenants[0], base, sources[1].ID, "2001:db8::1", profile, time.Hour); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || got.Paths != nil {
		t.Fatal("public reader borrowed a sibling snapshot", got, err)
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
			got, err := publicSnapshotReadForFixture(t, f, f.tenants[0], input, source.ID, "2001:db8::1", profile, time.Hour)
			want := ErrBGPRoutingSourceUnavailable
			if tc.empty {
				want = ErrBGPRoutingRouteMissing
			}
			if !errors.Is(err, want) || got.Paths != nil {
				t.Fatal("public reader confused empty, unavailable or incomplete source", got, err)
			}
		})
	}
	t.Run("mrt-empty-source-record", func(t *testing.T) {
		tenant := f.tenants[0]
		input := base
		input.Definitions = nil
		input.ObservationID, input.ObservedAt = uuid.NewString(), now(tenant)
		input.SenderSerial = f.serials[tenant+"role-listener"]
		clock := input.ObservedAt.Unix() * 1_000_000_000
		input.SourceObservedUnixNanos = &clock
		input.SourceRecord = publicMRTRecordForTest([]byte{0, 255, 1}, true, false, uint32(input.ObservedAt.Unix()))
		var staged BGPPublicSnapshotStageResult
		if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			staged, err = (BGPRouting{}).StagePublicSnapshotInScope(ctx, sc, input, profile)
			return err
		}); err != nil || staged.Status != "staged" || len(staged.Views) != 0 {
			t.Fatal("original empty MRT source could not stage", staged, err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var original []byte
			var charge int64
			if err := sc.Q.QueryRow(ctx, `SELECT source_record,charged_bytes FROM bgp_public_snapshots WHERE tenant_id=$1 AND id=$2`, tenant, staged.ID).Scan(&original, &charge); err != nil {
				return err
			}
			if !bytes.Equal(original, input.SourceRecord) || charge < 512+int64(len(original)) {
				t.Fatal("empty MRT source lost original bytes or state accounting", charge)
			}
			return nil
		})
		f.in(f.tenants[1], func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_public_snapshots WHERE source_record IS NOT NULL`).Scan(&count); err != nil {
				return err
			}
			if count != 0 {
				t.Fatal("original MRT bytes crossed tenant storage", count)
			}
			return nil
		})
		if out := apply(tenant, message(tenant, input, staged, 1, true)); out.Status != "applied" {
			t.Fatal("genuine empty MRT source could not complete", out)
		}
		if got, err := publicSnapshotReadForFixture(t, f, tenant, input, staged.ID, "192.0.2.1", profile, time.Hour); !errors.Is(err, ErrBGPRoutingRouteMissing) || got.Paths != nil {
			t.Fatal("empty raw MRT source manufactured a route", got, err)
		}
		changed := publicMRTRecordForTest([]byte{0, 255, 2}, true, false, uint32(input.ObservedAt.Unix()))
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE bgp_public_snapshots SET source_record=$3 WHERE tenant_id=$1 AND id=$2`, tenant, staged.ID, changed)
			return err
		})
		got, readErr := publicSnapshotReadForFixture(t, f, tenant, input, staged.ID, "192.0.2.1", profile, time.Hour)
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE bgp_public_snapshots SET source_record=$3 WHERE tenant_id=$1 AND id=$2`, tenant, staged.ID, input.SourceRecord)
			return err
		})
		if !errors.Is(readErr, ErrBGPRoutingView) || got.Paths != nil {
			t.Fatal("current empty MRT source discarded changed original metadata", got, readErr)
		}
		input.SourceRecord = changed
		if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			staged, err = (BGPRouting{}).StagePublicSnapshotInScope(ctx, sc, input, profile)
			return err
		}); err != nil || staged.Status != "invalidated" {
			t.Fatal("MRT source retry replaced original record", staged, err)
		}
	})
	t.Run("read-manifest", func(t *testing.T) {
		tenant := f.tenants[1]
		var original []byte
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT peer_identity FROM bgp_routing_views WHERE tenant_id=$1 AND id=$2`, tenant, sources[1].Views[0].ID).Scan(&original)
		})
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET peer_identity=jsonb_set(peer_identity,'{Cursor}','"changed-current-source"'::jsonb) WHERE tenant_id=$1 AND id=$2`, tenant, sources[1].Views[0].ID)
			return err
		})
		got, err := publicSnapshotReadForFixture(t, f, tenant, base, sources[1].ID, "2001:db8::1", profile, time.Hour)
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, restoreErr := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET peer_identity=$3::jsonb WHERE tenant_id=$1 AND id=$2`, tenant, sources[1].Views[0].ID, original)
			return restoreErr
		})
		if !errors.Is(err, ErrBGPRoutingView) || got.Paths != nil {
			t.Fatal("public reader accepted changed complete source metadata", got, err)
		}
	})
	t.Run("read-revoked", func(t *testing.T) {
		tenant := f.tenants[1]
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='test' WHERE tenant_id=$1 AND agent_id='role-listener'`, tenant)
			return err
		})
		if got, err := publicSnapshotReadForFixture(t, f, tenant, base, sources[1].ID, "2001:db8::1", profile, time.Hour); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || got.Paths != nil {
			t.Fatal("public reader accepted a revoked collector", got, err)
		}
	})
}
