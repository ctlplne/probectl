// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual application-role TLS Postgres/FORCE-RLS, original MRT bytes and the
// production source decoder/writer/reader. Issued identities remain modeled;
// this does not attest a live upstream or the restricted mTLS listener.
func TestPublicMRTRecordsKeepOriginalPathsTenantScopeAndWholeSourceRefusal(t *testing.T) {
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
	stage := func(tenant string) (BGPPublicSnapshotInput, BGPPublicSnapshotStageResult) {
		input := base
		input.ObservationID, input.ObservedAt = uuid.NewString(), now(tenant)
		input.SenderSerial = f.serials[tenant+"role-listener"]
		input.Definitions = nil
		clock := input.ObservedAt.Unix() * 1_000_000_000
		input.SourceObservedUnixNanos = &clock
		input.SourceRecord = publicMRTRecordForTest([]byte{0, 255}, false, false, uint32(input.ObservedAt.Unix()))
		var out BGPPublicSnapshotStageResult
		if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			out, err = (BGPRouting{}).StagePublicSnapshotInScope(ctx, sc, input, profile)
			return err
		}); err != nil || out.Status != "staged" || len(out.Views) != 2 {
			t.Fatal("raw MRT source could not stage original peer manifest", out, err)
		}
		return input, out
	}
	makeMessage := func(tenant string, input BGPPublicSnapshotInput, source BGPPublicSnapshotStageResult, sequence int64, complete bool) BGPPublicSnapshotMessage {
		return BGPPublicSnapshotMessage{CollectorAgentID: input.CollectorAgentID, SenderSerial: input.SenderSerial, SourceRef: input.SourceRef, SnapshotID: source.ID, Sequence: sequence, ObservedAt: now(tenant), Complete: complete}
	}
	apply := func(tenant string, input BGPPublicSnapshotMessage, raw []byte) BGPRoutingApplyResult {
		var out BGPRoutingApplyResult
		if err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			out, err = (BGPRouting{}).ApplyPublicMRTFrameInScope(ctx, sc, input, raw, profile, time.Hour)
			return err
		}); err != nil {
			t.Fatal("raw MRT source frame did not commit its acceptance or refusal", out, err)
		}
		return out
	}
	var sources [2]BGPPublicSnapshotStageResult
	var inputs [2]BGPPublicSnapshotInput
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id)VALUES($1,'role-listener','public_bgp',$2,$3)`, tenant, base.SourceRef, f.contextID)
			return err
		})
		input, source := stage(tenant)
		sources[lane], inputs[lane] = source, input
		for i, afi := range []uint16{1, 2} {
			message := makeMessage(tenant, input, source, int64(i+1), false)
			raw := publicMRTRIBRecordForTest(afi, uint32(64497+lane), 0, uint32(input.ObservedAt.Unix()), false)
			if out := apply(tenant, message, raw); out.Status != "applied" {
				t.Fatal("complete original MRT record was refused", out)
			}
			if i == 1 {
				if out := apply(tenant, message, raw); out.Status != "replayed" {
					t.Fatal("exact raw MRT retry changed its source", out)
				}
			}
		}
		complete := makeMessage(tenant, input, source, 3, true)
		if out := apply(tenant, complete, nil); out.Status != "applied" {
			t.Fatal("validated MRT source EOF did not publish whole families", out)
		}
		if out := apply(tenant, complete, nil); out.Status != "replayed" {
			t.Fatal("MRT EOF retry renewed or replaced source", out)
		}
		for _, tc := range []struct {
			address string
			count   int
		}{{"192.0.2.9", 2}, {"2001:db8::1", 1}} {
			got, err := publicSnapshotReadForFixture(t, f, tenant, input, source.ID, tc.address, profile, time.Hour)
			if err != nil || len(got.Paths) != tc.count || got.Source.TenantID != tenant {
				t.Fatal("raw MRT current lookup lost whole paths or tenant scope", got, err)
			}
			for _, path := range got.Paths {
				mrt := path.Path.Attributes.MRT
				if len(path.Path.Segments) != 3 || path.Path.Segments[1].Values[1] != uint32(64497+lane) || mrt == nil || mrt.RecordUnixNanos != *input.SourceObservedUnixNanos || mrt.OriginatedUnixNanos != 0 || mrt.Sequence != ^uint32(0) || mrt.PeerIndex != 0 {
					t.Fatal("raw MRT source lost original facts or borrowed sibling paths", path)
				}
			}
		}
	}
	foreign := makeMessage(f.tenants[0], inputs[0], sources[1], 4, false)
	var refused BGPRoutingApplyResult
	if err := run(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		refused, err = (BGPRouting{}).ApplyPublicMRTFrameInScope(ctx, sc, foreign, publicMRTRIBRecordForTest(1, 64497, 0, uint32(inputs[0].ObservedAt.Unix()), false), profile, time.Hour)
		return err
	}); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || refused.Status != "" {
		t.Fatal("raw MRT sender borrowed a sibling snapshot", refused, err)
	}
	t.Run("malformed-known-source", func(t *testing.T) {
		tenant := f.tenants[0]
		input, source := inputs[0], sources[0]
		message := makeMessage(tenant, input, source, 4, false)
		var out BGPRoutingApplyResult
		err := run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			out, err = (BGPRouting{}).ApplyPublicMRTFrameInScope(ctx, sc, message, publicMRTRIBRecordForTest(1, 64497, 0, uint32(input.ObservedAt.Unix()), true), profile, time.Hour)
			return err
		})
		if err != nil || out.Status != "invalidated" {
			t.Fatal("malformed MRT source was not atomically invalidated", out, err)
		}
		if got, err := publicSnapshotReadForFixture(t, f, tenant, input, source.ID, "192.0.2.9", profile, time.Hour); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || got.Paths != nil {
			t.Fatal("malformed MRT source kept former current paths", got, err)
		}
	})
	input, source := stage(f.tenants[0])
	if out := apply(f.tenants[0], makeMessage(f.tenants[0], input, source, 1, false), publicMRTRIBRecordForTest(1, 64497, 1, uint32(input.ObservedAt.Unix()), false)); out.Status != "invalidated" {
		t.Fatal("raw MRT record borrowed an undefined peer", out)
	}
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_entries e JOIN bgp_routing_views v ON(v.tenant_id,v.context_id,v.id,v.generation)=(e.tenant_id,e.context_id,e.view_id,e.generation)WHERE v.tenant_id=$1 AND v.public_snapshot_id=$2`, f.tenants[0], source.ID).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			t.Fatal("refused raw MRT source committed a partial route", count)
		}
		return nil
	})
	if got, err := publicSnapshotReadForFixture(t, f, f.tenants[1], inputs[1], sources[1].ID, "192.0.2.9", profile, time.Hour); err != nil || len(got.Paths) != 2 {
		t.Fatal("raw MRT refusal changed sibling source", got, err)
	}
}
