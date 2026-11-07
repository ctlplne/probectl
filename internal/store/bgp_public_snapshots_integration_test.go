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
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual app-role TLS/Postgres/RLS; modeled source metadata/credentials.
// This proves private whole-source staging, not complete/current publication.
func TestPublicSnapshotStagingKeepsWholeTenantManifestReplayRollbackAndEmptyWithdrawal(t *testing.T) {
	f := newRoleInputsFixture(t)
	base, profile := publicSnapshotFixture()
	inputs := make([]BGPPublicSnapshotInput, len(f.tenants))
	initial := make([]BGPPublicSnapshotStageResult, len(f.tenants))
	advance := func(tenant string, input BGPPublicSnapshotInput) BGPPublicSnapshotInput {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&input.ObservedAt)
		})
		return input
	}
	rollback := errors.New("rollback whole public stage")
	stage := func(tenant string, input BGPPublicSnapshotInput, abort bool) (BGPPublicSnapshotStageResult, error) {
		var out BGPPublicSnapshotStageResult
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		err := tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), tenant, entity.ErrScopeMismatch, func(ctx context.Context) error {
			return tenancy.InTenant(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
				var err error
				out, err = (BGPRouting{}).StagePublicSnapshotInScope(ctx, sc, input, profile)
				if err == nil && abort {
					return rollback
				}
				return err
			})
		})
		return out, err
	}
	state := func(tenant, id string) (string, int) {
		var state string
		var views int
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT state,(SELECT count(*) FROM bgp_routing_views v WHERE v.tenant_id=h.tenant_id AND v.context_id=h.context_id AND v.public_snapshot_id=h.id AND v.state=h.state) FROM bgp_public_snapshots h WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&state, &views)
		})
		return state, views
	}
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_source_contexts(tenant_id,agent_id,source_kind,source_ref,context_id) VALUES($1,'role-listener','public_bgp',$2,$3)`, tenant, base.SourceRef, f.contextID)
			return err
		})
		input := advance(tenant, base)
		input.SenderSerial = f.serials[tenant+"role-listener"]
		out, err := stage(tenant, input, false)
		if err != nil || out.Status != "staged" || out.ID != input.ObservationID || len(out.Views) != 3 {
			t.Fatal("whole owned public manifest failed private staging", out, err)
		}
		if got, count := state(tenant, out.ID); got != "staging" || count != 3 {
			t.Fatal("public manifest published early or lost a declared view", got, count)
		}
		inputs[lane], initial[lane] = input, out
		replay, err := stage(tenant, input, false)
		if err != nil || replay.Status != "replayed" || !reflect.DeepEqual(replay.Views, out.Views) {
			t.Fatal("exact public retry changed its private generation", replay, err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var count, current, expected int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE state='current'),min(expected_views) FROM bgp_public_snapshots`).Scan(&count, &current, &expected); err != nil {
				return err
			}
			if count != 1 || current != 0 || expected != 3 {
				t.Fatal("public snapshot leaked tenant headers or fabricated completeness", count, current, expected)
			}
			return nil
		})
	}
	next := advance(f.tenants[0], inputs[0])
	next.ObservationID = uuid.NewString()
	if _, err := stage(f.tenants[0], next, true); !errors.Is(err, rollback) {
		t.Fatal("whole public replacement did not reach rollback", err)
	}
	if got, count := state(f.tenants[0], initial[0].ID); got != "staging" || count != 3 {
		t.Fatal("rolled-back replacement retired former public cohort", got, count)
	}
	changed := inputs[0]
	changed.Definitions = append([]BGPRoutingViewDefinition(nil), changed.Definitions...)
	peer := *changed.Definitions[2].Public
	peer.PeerASN = 64496
	changed.Definitions[2].Public = &peer
	conflict, err := stage(f.tenants[0], changed, false)
	if err != nil || conflict.Status != "invalidated" || len(conflict.Views) != 0 {
		t.Fatal("conflicting public retry was not a committed refusal", conflict, err)
	}
	if got, count := state(f.tenants[0], initial[0].ID); got != "invalid" || count != 3 {
		t.Fatal("conflicting public retry retained partial source cohort", got, count)
	}
	if got, count := state(f.tenants[1], initial[1].ID); got != "staging" || count != 3 {
		t.Fatal("public refusal changed sibling tenant", got, count)
	}
	empty := advance(f.tenants[0], inputs[0])
	empty.ObservationID = uuid.NewString()
	empty.Definitions = []BGPRoutingViewDefinition{}
	out, err := stage(f.tenants[0], empty, false)
	if err != nil || out.Status != "staged" || out.Views == nil || len(out.Views) != 0 {
		t.Fatal("complete empty public manifest required a fabricated peer", out, err)
	}
	if got, count := state(f.tenants[0], out.ID); got != "staging" || count != 0 {
		t.Fatal("empty public stage fabricated a route or publication", got, count)
	}
	if replay, err := stage(f.tenants[0], empty, false); err != nil || replay.Status != "replayed" || replay.Views == nil || len(replay.Views) != 0 {
		t.Fatal("complete empty public retry lost its identity", replay, err)
	}
	stale := inputs[0]
	stale.ObservationID = uuid.NewString()
	if _, err := stage(f.tenants[0], stale, false); !errors.Is(err, ErrBGPRoutingSourceUnavailable) {
		t.Fatal("old public observation replaced a newer source generation", err)
	}
	foreign := advance(f.tenants[0], inputs[0])
	foreign.ObservationID = uuid.NewString()
	foreign.SenderSerial = inputs[1].SenderSerial
	if _, err := stage(f.tenants[0], foreign, false); !errors.Is(err, ErrBGPRoutingSourceUnavailable) {
		t.Fatal("foreign collector credential staged a public cohort", err)
	}
	if got, count := state(f.tenants[0], out.ID); got != "staging" || count != 0 {
		t.Fatal("refused source changed current owned empty staging", got, count)
	}
}
