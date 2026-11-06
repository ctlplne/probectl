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

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/migrations"
)

type routingClockReceipt struct {
	state         string
	born, lease   time.Time
	observed      *time.Time
	sequence      int64
	clockSequence *int64
}

func routingFixtureClock(f *roleInputsFixture, source BGPRoutingSource, ref BGPRoutingViewRef) routingClockReceipt {
	var receipt routingClockReceipt
	f.in(source.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT state,observed_at,valid_until,last_message_observed_at,last_sequence,message_clock_sequence
 FROM bgp_routing_views WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND generation=$4`, source.TenantID, source.ContextID, ref.ID, ref.Generation).
			Scan(&receipt.state, &receipt.born, &receipt.lease, &receipt.observed, &receipt.sequence, &receipt.clockSequence)
	})
	return receipt
}

func TestBGPRoutingHeartbeatKeepsIncarnationSequenceClockAndTenantLease(t *testing.T) {
	f := newRoleInputsFixture(t)
	sources := []BGPRoutingSource{routingFixtureSource(f, 0), routingFixtureSource(f, 1)}
	refs := []BGPRoutingViewRef{routingFixtureBegin(t, f, sources[0]), routingFixtureBegin(t, f, sources[1])}
	profile := routingViewBudget()
	profile.LeaseDuration = 20 * time.Minute
	apply := func(lane int, batch BGPRoutingBatch, want string) {
		t.Helper()
		result, err := routingFixtureApply(t, f, sources[lane], refs[lane], batch, profile)
		if err != nil || result.Status != want {
			t.Fatal("routing heartbeat result differs", result, want, err)
		}
	}
	// A heartbeat is ordered source liveness, never initial-view completion.
	heartbeat := BGPRoutingBatch{Sequence: 1, AFI: 1, SAFI: 1, ObservedAt: routingFixtureTime(f), Heartbeat: true}
	apply(1, heartbeat, "applied")
	if got := routingFixtureClock(f, sources[1], refs[1]); got.state != "staging" || got.sequence != 1 {
		t.Fatal("heartbeat manufactured a complete initial routing view")
	}
	for lane := range sources {
		sequence := int64(1 + lane)
		apply(lane, BGPRoutingBatch{Sequence: sequence, AFI: 1, SAFI: 1, ObservedAt: routingFixtureTime(f), EndOfRIB: true}, "applied")
	}
	before := routingFixtureClock(f, sources[0], refs[0])
	sibling := routingFixtureClock(f, sources[1], refs[1])
	heartbeat = BGPRoutingBatch{Sequence: 2, AFI: 1, SAFI: 1, ObservedAt: routingFixtureTime(f), Heartbeat: true}
	apply(0, heartbeat, "applied")
	current := routingFixtureClock(f, sources[0], refs[0])
	if current.state != "current" || !current.born.Equal(before.born) || !current.lease.After(before.lease) ||
		!current.lease.Equal(heartbeat.ObservedAt.Add(profile.LeaseDuration)) || current.observed == nil ||
		!current.observed.Equal(heartbeat.ObservedAt) || current.clockSequence == nil || *current.clockSequence != 2 {
		t.Fatal("ordered heartbeat lost immutable birth or exact admitted lease")
	}
	profile.LeaseDuration = 2 * time.Hour
	apply(0, heartbeat, "replayed")
	if got := routingFixtureClock(f, sources[0], refs[0]); !got.lease.Equal(current.lease) || !got.observed.Equal(*current.observed) {
		t.Fatal("replayed routing heartbeat extended its former lease")
	}
	heartbeat.Sequence, heartbeat.ObservedAt = 3, routingFixtureTime(f)
	apply(0, heartbeat, "applied")
	f.in(sources[0].TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		source := sources[0]
		source.ObservedAt = heartbeat.ObservedAt
		authority, err := (BGPRouting{}).SourceAuthorityInScope(ctx, sc, source)
		if err != nil {
			return err
		}
		if got := routingFixtureClock(f, source, refs[0]); !got.lease.Equal(authority.ValidUntil) {
			t.Fatal("heartbeat lease exceeded its current source credentials")
		}
		return nil
	})
	current = routingFixtureClock(f, sources[0], refs[0])
	heartbeat.Sequence, heartbeat.ObservedAt = 5, routingFixtureTime(f)
	apply(0, heartbeat, "invalidated")
	if got := routingFixtureClock(f, sources[0], refs[0]); got.state != "invalid" || !got.lease.Equal(current.lease) || got.sequence != 3 {
		t.Fatal("heartbeat skipped unapplied routing data or renewed an invalid generation")
	}
	if got := routingFixtureClock(f, sources[1], refs[1]); got.state != sibling.state || got.sequence != sibling.sequence || !got.lease.Equal(sibling.lease) {
		t.Fatal("heartbeat changed sibling tenant routing authority")
	}
}

func TestBGPRoutingMessageClockRejectsLegacyWritersAndUnusableHeartbeats(t *testing.T) {
	f := newRoleInputsFixture(t)
	ddl, err := migrations.FS.ReadFile("0177_bgp_routing_message_clock.sql")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := f.pool.Exec(t.Context(), string(ddl)); err != nil {
			t.Fatal("routing message clock migration is not idempotent", err)
		}
	}
	source := routingFixtureSource(f, 0)
	ref := routingFixtureBegin(t, f, source)
	complete := BGPRoutingBatch{Sequence: 1, AFI: 1, SAFI: 1, ObservedAt: routingFixtureTime(f), EndOfRIB: true}
	if result, err := routingFixtureApply(t, f, source, ref, complete, routingViewBudget()); err != nil || result.Status != "applied" {
		t.Fatal(result, err)
	}
	for _, sql := range []string{
		`UPDATE bgp_routing_views SET next_sequence=3,last_sequence=2 WHERE tenant_id=$1 AND id=$2`,
		`UPDATE bgp_routing_views SET message_clock_sequence=NULL WHERE tenant_id=$1 AND id=$2`,
		`UPDATE bgp_routing_views SET last_message_observed_at=observed_at-interval '1 second' WHERE tenant_id=$1 AND id=$2`,
	} {
		err := routingFixtureWrite(t, f, source, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, sql, source.TenantID, ref.ID)
			return err
		})
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "23514" {
			t.Fatal("legacy routing writer bypassed the paired message clock", err)
		}
	}
	profile := routingViewBudget()
	profile.LeaseDuration = time.Minute
	for _, kind := range []string{"legacy-clock", "clock-regression", "stale-heartbeat"} {
		t.Run(kind, func(t *testing.T) {
			source = routingFixtureSource(f, 0)
			ref = routingFixtureBegin(t, f, source)
			complete := BGPRoutingBatch{Sequence: 1, AFI: 1, SAFI: 1, ObservedAt: routingFixtureTime(f), EndOfRIB: true}
			if result, err := routingFixtureApply(t, f, source, ref, complete, profile); err != nil || result.Status != "applied" {
				t.Fatal(result, err)
			}
			before := routingFixtureClock(f, source, ref)
			heartbeat := BGPRoutingBatch{Sequence: 2, AFI: 1, SAFI: 1, ObservedAt: routingFixtureTime(f), Heartbeat: true}
			budget := profile
			switch kind {
			case "legacy-clock":
				f.in(source.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
					_, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET last_message_observed_at=NULL,message_clock_sequence=NULL WHERE tenant_id=$1 AND id=$2`, source.TenantID, ref.ID)
					return err
				})
			case "clock-regression":
				heartbeat.ObservedAt = before.born
			case "stale-heartbeat":
				budget.LeaseDuration = time.Nanosecond
			}
			result, err := routingFixtureApply(t, f, source, ref, heartbeat, budget)
			after := routingFixtureClock(f, source, ref)
			if err != nil || result.Status != "invalidated" || after.state != "invalid" || after.sequence != 1 || !after.lease.Equal(before.lease) {
				t.Fatal("unusable routing heartbeat retained former attribution", kind, result, err)
			}
		})
	}
}
