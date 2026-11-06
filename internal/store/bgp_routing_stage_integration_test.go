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
	"strings"

	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Actual application-role Postgres; current sender/origin rows are modeled.
// This proves the data boundary, not the separate end-to-end mTLS intake.
func TestBGPRoutingStagingKeepsTenantRetryLeaseAndAtomicCompletePeer(t *testing.T) {
	f := newRoleInputsFixture(t)
	nonce := uuid.NewString()
	profile := routingViewBudget()
	profile.LeaseDuration = 5 * time.Minute
	sources := []BGPRoutingSource{routingFixtureSource(f, 0), routingFixtureSource(f, 1)}
	inputs := make([]BGPRoutingPeerUpInput, 2)
	receipts := make([]BGPRoutingStageResult, 2)
	stage := func(lane int, input BGPRoutingPeerUpInput, budget BGPRoutingBudget) (BGPRoutingStageResult, error) {
		var result BGPRoutingStageResult
		err := routingFixtureWrite(t, f, sources[lane], func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			result, err = (BGPRouting{}).StagePeerInScope(ctx, sc, input, budget)
			return err
		})
		return result, err
	}
	count := func(lane int, state string) int {
		var total int
		f.in(sources[lane].TenantID, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE tenant_id=$1 AND state=$2`, sources[lane].TenantID, state).Scan(&total)
		})
		return total
	}
	lease := func(lane int, ref BGPRoutingStagedView) time.Time {
		var until time.Time
		f.in(sources[lane].TenantID, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT valid_until FROM bgp_routing_views WHERE tenant_id=$1 AND id=$2 AND generation=$3`, sources[lane].TenantID, ref.ID, ref.Generation).Scan(&until)
		})
		return until
	}
	for lane, source := range sources {
		inputs[lane] = BGPRoutingPeerUpInput{CollectorAgentID: source.CollectorAgentID, SenderSerial: source.SenderSerial, SourceRef: source.SourceRef, OriginSerial: source.OriginSerial, ObservationID: nonce, ObservedAt: source.ObservedAt, FrameDigest: crypto.Hash([]byte(source.TenantID)), Definitions: []BGPRoutingViewDefinition{routingLookupDefinition(1), routingLookupDefinition(2)}}
		var err error
		receipts[lane], err = stage(lane, inputs[lane], profile)
		if err != nil || receipts[lane].Status != "staged" || len(receipts[lane].Views) != 2 || count(lane, "staging") != 2 || count(lane, "current") != 0 {
			t.Fatal("complete source staging lost tenant/family or published before completion", err, receipts[lane])
		}
		beforeLease := lease(lane, receipts[lane].Views[0])
		retry, err := stage(lane, inputs[lane], profile)
		if err != nil || retry.Status != "replayed" || !reflect.DeepEqual(retry.Views, receipts[lane].Views) || count(lane, "staging") != 2 || !lease(lane, receipts[lane].Views[0]).Equal(beforeLease) {
			t.Fatal("exact routing retry changed generation or duplicated retained state", err, retry)
		}
	}
	if receipts[0].Views[0].ID == receipts[1].Views[0].ID {
		t.Fatal("routing nonce was treated as cross-tenant source authority")
	}
	// Even a directly supplied foreign reference remains invisible under RLS.
	f.in(sources[1].TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		var total int
		err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE id=$1 AND generation=$2`, receipts[0].Views[0].ID, nonce).Scan(&total)
		if err == nil && total != 0 {
			t.Fatal("foreign routing generation escaped tenant RLS")
		}
		return err
	})
	unbound := inputs[0]
	unbound.ObservationID = uuid.NewString()
	unbound.ObservedAt = routingFixtureTime(f)
	unbound.Definitions = append([]BGPRoutingViewDefinition(nil), unbound.Definitions...)
	unbound.Definitions[0].Peer.Distinguisher[0] = 1
	if _, err := stage(0, unbound, profile); !errors.Is(err, errBGPRoutingContextBinding) || count(0, "staging") != 2 || count(1, "staging") != 2 {
		t.Fatal("unbound routing VRF changed storage context", err)
	}
	changed := inputs[0]
	changed.FrameDigest = crypto.Hash([]byte("altered original Peer Up"))
	refused, err := stage(0, changed, profile)
	if err != nil || refused.Status != "invalidated" || len(refused.Views) != 0 || count(0, "staging") != 0 || count(1, "staging") != 2 {
		t.Fatal("altered routing retry retained current state or damaged another tenant", err, refused)
	}
	// A fresh source incarnation is admitted, but an old nonce cannot reset it.
	fresh := inputs[0]
	fresh.ObservationID = uuid.NewString()
	fresh.ObservedAt = routingFixtureTime(f)
	newer, err := stage(0, fresh, profile)
	if err != nil || newer.Status != "staged" {
		t.Fatal("fresh routing source refused after invalidation", err, newer)
	}
	stale, err := stage(0, inputs[0], profile)
	if err != nil || stale.Status != "invalidated" || count(0, "staging") != 2 {
		t.Fatal("old routing Peer Up retired a newer incarnation", err, stale)
	}
	clockChanged := fresh
	clockChanged.ObservedAt = clockChanged.ObservedAt.Add(time.Nanosecond)
	clockRefused, err := stage(0, clockChanged, profile)
	if err != nil || clockRefused.Status != "invalidated" || count(0, "staging") != 0 || count(1, "staging") != 2 {
		t.Fatal("sub-microsecond retry clock change retained routing state", err, clockRefused)
	}
	fresh.ObservationID = uuid.NewString()
	fresh.ObservedAt = routingFixtureTime(f)
	if restored, err := stage(0, fresh, profile); err != nil || restored.Status != "staged" {
		t.Fatal("fresh routing source not restored before admission control", err, restored)
	}
	allRows := func() int {
		var total int
		f.in(sources[0].TenantID, func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_views WHERE tenant_id=$1`, sources[0].TenantID).Scan(&total)
		})
		return total
	}
	beforeRows := allRows()
	late := fresh
	late.ObservationID = uuid.NewString()
	late.ObservedAt = routingFixtureTime(f)
	var fault *routingStageFaultWriter
	var lateResult BGPRoutingStageResult
	err = routingFixtureWrite(t, f, sources[0], func(ctx context.Context, sc tenancy.Scope) error {
		fault = &routingStageFaultWriter{Querier: sc.Q}
		sc.Q = fault
		var err error
		lateResult, err = (BGPRouting{}).StagePeerInScope(ctx, sc, late, profile)
		return err
	})
	if err != nil || fault == nil || fault.updates != 2 || lateResult.Status != "invalidated" || allRows() != beforeRows || count(0, "staging") != 0 || count(1, "staging") != 2 {
		t.Fatal("late routing family fault escaped whole-source rollback", err, lateResult)
	}
	fresh.ObservationID = uuid.NewString()
	fresh.ObservedAt = routingFixtureTime(f)
	if restored, err := stage(0, fresh, profile); err != nil || restored.Status != "staged" {
		t.Fatal("fresh routing source not restored after storage fault", err, restored)
	}
	// Whole replacement admission failure commits invalidation without leaving
	// one admitted family behind or reviving the formerly complete source.
	fresh.ObservationID = uuid.NewString()
	fresh.ObservedAt = routingFixtureTime(f)
	small := profile
	small.StateBytes = 1
	failed, err := stage(0, fresh, small)
	if err != nil || failed.Status != "invalidated" || count(0, "staging") != 0 || count(1, "staging") != 2 {
		t.Fatal("refused routing replacement left partial family state or foreign mutation", err, failed)
	}
}

// Model a late client-visible storage error after actual writes to Postgres.
// The receipt above verifies real rollback, not a fake transactional database.
type routingStageFaultWriter struct {
	tenancy.Querier
	updates int
}

func (q *routingStageFaultWriter) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.HasPrefix(sql, "UPDATE bgp_routing_views SET id=$5,generation=$6") {
		q.updates++
		if q.updates == 2 {
			return pgconn.CommandTag{}, errors.New("modeled second-family identity write failure")
		}
	}
	return q.Querier.Exec(ctx, sql, args...)
}
