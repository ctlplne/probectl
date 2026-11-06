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
	"errors"
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func routingFixtureSource(f *roleInputsFixture, lane int) BGPRoutingSource {
	tenant := f.tenants[lane]
	return BGPRoutingSource{Scope: entity.Scope{TenantID: tenant, ContextID: f.contextID}, RouterID: f.routerID,
		CollectorAgentID: "role-listener", SourceRef: "role-router", SenderSerial: f.serials[tenant+"role-listener"], OriginSerial: f.serials[tenant+"role-router"], ObservedAt: routingFixtureTime(f)}
}

func routingFixtureTime(f *roleInputsFixture) time.Time {
	var observed time.Time
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&observed)
	})
	return observed
}

func routingFixtureBegin(t *testing.T, f *roleInputsFixture, source BGPRoutingSource) BGPRoutingViewRef {
	t.Helper()
	var view BGPRoutingView
	err := routingFixtureWrite(t, f, source, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		view, err = (BGPRouting{}).BeginViewInScope(ctx, sc, source, routingViewFixture(), source.ObservedAt.Add(5*time.Minute), routingViewBudget())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return BGPRoutingViewRef{ID: view.ID, Generation: view.Generation}
}

func routingFixtureWrite(t *testing.T, f *roleInputsFixture, source BGPRoutingSource, fn func(context.Context, tenancy.Scope) error) error {
	t.Helper()
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(source.TenantID))
	return tenancy.FencedTenantWrite(ctx, tenancy.NewPostgresWriterFence(f.pool), source.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
		return tenancy.InTenant(ctx, f.pool, fn)
	})
}

func routingFixtureApply(t *testing.T, f *roleInputsFixture, source BGPRoutingSource, ref BGPRoutingViewRef, batch BGPRoutingBatch, budget BGPRoutingBudget) (BGPRoutingApplyResult, error) {
	t.Helper()
	source.ObservedAt = batch.ObservedAt
	var result BGPRoutingApplyResult
	err := routingFixtureWrite(t, f, source, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		result, err = (BGPRouting{}).ApplyBatchInScope(ctx, sc, source, ref, batch, budget)
		return err
	})
	return result, err
}

func TestBGPRoutingBatchesKeepCompleteTenantPathsReplayWithdrawalAndPublication(t *testing.T) {
	f := newRoleInputsFixture(t)
	sources := []BGPRoutingSource{routingFixtureSource(f, 0), routingFixtureSource(f, 1)}
	refs := []BGPRoutingViewRef{routingFixtureBegin(t, f, sources[0]), routingFixtureBegin(t, f, sources[1])}
	// Reuse exact generation IDs in both tenants, not merely the same prefix.
	f.in(sources[1].TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE bgp_routing_views SET id=$2,generation=$3 WHERE tenant_id=$1`, sources[1].TenantID, refs[0].ID, refs[0].Generation)
		return err
	})
	refs[1] = refs[0]
	first := BGPRoutingBatch{Sequence: 1, AFI: 1, SAFI: 1, ObservedAt: routingFixtureTime(f)}
	for _, path := range []struct {
		present bool
		value   uint32
	}{{false, 0}, {true, 0}, {true, math.MaxUint32}} {
		change := routingChangeFixture()
		change.HasPathID, change.PathID = path.present, path.value
		first.Changes = append(first.Changes, change)
	}
	apply := func(lane int, batch BGPRoutingBatch, want string) {
		t.Helper()
		result, err := routingFixtureApply(t, f, sources[lane], refs[lane], batch, routingViewBudget())
		if err != nil || result.Status != want {
			t.Fatal("whole routing batch result differs", result, want, err)
		}
	}
	assertView := func(lane int, state string, rows, sequence int64) {
		t.Helper()
		f.in(sources[lane].TenantID, func(ctx context.Context, sc tenancy.Scope) error {
			var gotState string
			var gotRows, gotSequence, actualRows, foreign int64
			if err := sc.Q.QueryRow(ctx, `SELECT state,row_count,last_sequence FROM bgp_routing_views WHERE tenant_id=$1 AND id=$2 AND generation=$3`, sources[lane].TenantID, refs[lane].ID, refs[lane].Generation).Scan(&gotState, &gotRows, &gotSequence); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE tenant_id<>$1) FROM bgp_routing_entries`, sources[lane].TenantID).Scan(&actualRows, &foreign); err != nil {
				return err
			}
			if gotState != state || gotRows != rows || actualRows != rows || gotSequence != sequence || foreign != 0 {
				t.Fatal("routing batch mixed tenant, initial view or complete path population", gotState, gotRows, actualRows, gotSequence, foreign)
			}
			return nil
		})
	}
	for lane := range sources {
		apply(lane, first, "applied")
		assertView(lane, "staging", 3, 1)
	}
	apply(0, first, "replayed")
	assertView(0, "staging", 3, 1)
	complete := BGPRoutingBatch{Sequence: 2, AFI: 1, SAFI: 1, ObservedAt: routingFixtureTime(f), EndOfRIB: true}
	for lane := range sources {
		apply(lane, complete, "applied")
		assertView(lane, "current", 3, 2)
	}
	withdraw := BGPRoutingChange{Prefix: first.Changes[0].Prefix, HasPathID: true, PathID: 0, Withdraw: true}
	replacement := routingChangeFixture()
	replacement.HasPathID, replacement.PathID = false, 0
	replacement.Segments[1].Values[1] = 64498
	ordered := BGPRoutingBatch{Sequence: 3, AFI: 1, SAFI: 1, ObservedAt: routingFixtureTime(f), Changes: []BGPRoutingChange{withdraw, replacement, {Prefix: replacement.Prefix, Withdraw: true}, replacement}}
	apply(0, ordered, "applied")
	assertView(0, "current", 2, 3)
	assertView(1, "current", 3, 2)
	f.in(sources[0].TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		var segmentsRaw, attributesRaw []byte
		var hops []string
		if err := sc.Q.QueryRow(ctx, `SELECT segments,attributes,ARRAY(SELECT unnest(next_hops)::text) FROM bgp_routing_entries
 WHERE tenant_id=$1 AND view_id=$2 AND has_path_id AND path_id=4294967295`, sources[0].TenantID, refs[0].ID).Scan(&segmentsRaw, &attributesRaw, &hops); err != nil {
			return err
		}
		var segments []BGPRoutingSegment
		var attributes BGPRoutingAttributes
		if err := json.Unmarshal(segmentsRaw, &segments); err != nil {
			return err
		}
		if err := json.Unmarshal(attributesRaw, &attributes); err != nil {
			return err
		}
		if segments[0].Kind != 3 || segments[1].Values[0] != math.MaxUint32 || segments[1].Values[1] != segments[1].Values[2] ||
			segments[2].Kind != 1 || len(attributes.Wire) != 4 || attributes.Wire[1].Value == nil || attributes.Wire[3].Value != nil || len(hops) != 2 {
			t.Fatal("persisted routing batch lost full structured path or attributes")
		}
		return nil
	})
	foreign := sources[0]
	foreign.SenderSerial = sources[1].SenderSerial
	if result, err := routingFixtureApply(t, f, foreign, refs[0], ordered, routingViewBudget()); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || result.Status != "" {
		t.Fatal("foreign sender changed or acknowledged an owned route generation", result, err)
	}
	assertView(0, "current", 2, 3)
	gap := BGPRoutingBatch{Sequence: 5, AFI: 1, SAFI: 1, ObservedAt: routingFixtureTime(f)}
	apply(0, gap, "invalidated")
	assertView(0, "invalid", 2, 3)
	assertView(1, "current", 3, 2)
	apply(0, ordered, "invalidated")
	// Exact replay does not bypass current credential checks.
	f.in(sources[1].TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET revoked_at=clock_timestamp(),revoked_by='fixture' WHERE tenant_id=$1 AND serial=$2`, sources[1].TenantID, sources[1].OriginSerial)
		return err
	})
	if result, err := routingFixtureApply(t, f, sources[1], refs[1], complete, routingViewBudget()); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || result.Status != "" {
		t.Fatal("routing replay bypassed current origin revocation", result, err)
	}
}

func TestBGPRoutingBatchRefusalInvalidatesWithoutPartialWritesOrEpochRevival(t *testing.T) {
	f := newRoleInputsFixture(t)
	source := routingFixtureSource(f, 0)
	for _, kind := range []string{"memory", "state", "family", "completion", "conflict"} {
		t.Run(kind, func(t *testing.T) {
			source.ObservedAt = routingFixtureTime(f)
			ref := routingFixtureBegin(t, f, source)
			initial := BGPRoutingBatch{Sequence: 1, AFI: 1, SAFI: 1, ObservedAt: routingFixtureTime(f), Changes: []BGPRoutingChange{routingChangeFixture()}}
			if result, err := routingFixtureApply(t, f, source, ref, initial, routingViewBudget()); err != nil || result.Status != "applied" {
				t.Fatal(result, err)
			}
			batch, budget := initial, routingViewBudget()
			batch.Sequence, batch.ObservedAt = 2, routingFixtureTime(f)
			switch kind {
			case "memory":
				budget.MemoryBytes = 1
			case "state":
				budget.StateBytes = 1
			case "family":
				batch.AFI = 2
			case "completion":
				batch.EndOfRIB = true
			case "conflict":
				batch.Sequence = 1
			}
			result, err := routingFixtureApply(t, f, source, ref, batch, budget)
			if err != nil || result.Status != "invalidated" {
				t.Fatal("refused routing update did not commit invalidation", result, err)
			}
			f.in(source.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
				var state string
				var sequence, rows, entries int64
				if err := sc.Q.QueryRow(ctx, `SELECT state,last_sequence,row_count FROM bgp_routing_views WHERE tenant_id=$1 AND id=$2 AND generation=$3`, source.TenantID, ref.ID, ref.Generation).Scan(&state, &sequence, &rows); err != nil {
					return err
				}
				if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_entries WHERE tenant_id=$1 AND view_id=$2 AND generation=$3`, source.TenantID, ref.ID, ref.Generation).Scan(&entries); err != nil {
					return err
				}
				if state != "invalid" || sequence != 1 || rows != 1 || entries != 1 {
					t.Fatal("routing refusal retained authority or a partial batch", state, sequence, rows, entries)
				}
				return nil
			})
		})
	}
	source.ObservedAt = routingFixtureTime(f)
	ref := routingFixtureBegin(t, f, source)
	f.in(source.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_source_contexts SET assigned_at=clock_timestamp() WHERE tenant_id=$1 AND source_kind='bmp_peer'`, source.TenantID)
		return err
	})
	source.ObservedAt = routingFixtureTime(f)
	f.in(source.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (BGPRouting{}).SourceAuthorityInScope(ctx, sc, source)
		return err
	})
	batch := BGPRoutingBatch{Sequence: 1, AFI: 1, SAFI: 1, ObservedAt: source.ObservedAt, EndOfRIB: true}
	if result, err := routingFixtureApply(t, f, source, ref, batch, routingViewBudget()); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || result.Status != "" {
		t.Fatal("new source assignment revived a former routing generation", result, err)
	}
}

type routingFaultWriter struct {
	tenancy.Querier
	inserts int
	fault   func(context.Context) error
}

func (q *routingFaultWriter) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.HasPrefix(sql, "INSERT INTO bgp_routing_entries") {
		q.inserts++
		if q.inserts == 2 {
			if err := q.fault(ctx); err != nil {
				return pgconn.CommandTag{}, err
			}
		}
	}
	return q.Querier.Exec(ctx, sql, args...)
}

// Inject a modeled store failure or origin expiry after a real first INSERT.
// Prove actual Postgres rolls back all route, counter and identity changes.
func TestBGPRoutingBatchRollsBackLateStorageFaultAndOriginExpiry(t *testing.T) {
	f := newRoleInputsFixture(t)
	for _, kind := range []string{"store", "origin-expiry"} {
		t.Run(kind, func(t *testing.T) {
			source := routingFixtureSource(f, 0)
			ref := routingFixtureBegin(t, f, source)
			batch := BGPRoutingBatch{Sequence: 1, AFI: 1, SAFI: 1, ObservedAt: routingFixtureTime(f), EndOfRIB: true}
			if result, err := routingFixtureApply(t, f, source, ref, batch, routingViewBudget()); err != nil || result.Status != "applied" {
				t.Fatal(result, err)
			}
			batch.Sequence, batch.ObservedAt, batch.EndOfRIB = 2, routingFixtureTime(f), false
			batch.Changes = []BGPRoutingChange{routingChangeFixture(), routingChangeFixture()}
			batch.Changes[1].Prefix = netip.MustParsePrefix("198.51.100.0/24")
			source.ObservedAt = batch.ObservedAt
			injected := errors.New("modeled second route storage failure")
			want := injected
			var writer *routingFaultWriter
			err := routingFixtureWrite(t, f, source, func(ctx context.Context, sc tenancy.Scope) error {
				writer = &routingFaultWriter{Querier: sc.Q}
				writer.fault = func(ctx context.Context) error {
					if kind == "store" {
						return injected
					}
					want = ErrBGPRoutingSourceUnavailable
					_, err := sc.Q.Exec(ctx, `UPDATE agent_identities SET not_after=clock_timestamp() WHERE tenant_id=$1 AND serial=$2`, source.TenantID, source.OriginSerial)
					return err
				}
				sc.Q = writer
				_, err := (BGPRouting{}).ApplyBatchInScope(ctx, sc, source, ref, batch, routingViewBudget())
				return err
			})
			if writer == nil || writer.inserts != 2 || !errors.Is(err, want) {
				t.Fatal("routing batch acknowledged a late store fault or expired origin", kind, err)
			}
			f.in(source.TenantID, func(ctx context.Context, sc tenancy.Scope) error {
				var state string
				var sequence, rows, entries int64
				if err := sc.Q.QueryRow(ctx, `SELECT state,last_sequence,row_count FROM bgp_routing_views WHERE tenant_id=$1 AND id=$2 AND generation=$3`, source.TenantID, ref.ID, ref.Generation).Scan(&state, &sequence, &rows); err != nil {
					return err
				}
				if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_routing_entries WHERE tenant_id=$1 AND view_id=$2 AND generation=$3`, source.TenantID, ref.ID, ref.Generation).Scan(&entries); err != nil {
					return err
				}
				if state != "current" || sequence != 1 || rows != 0 || entries != 0 {
					t.Fatal("late routing failure escaped complete rollback", state, sequence, rows, entries)
				}
				_, err := (BGPRouting{}).SourceAuthorityInScope(ctx, sc, source)
				return err
			})
		})
	}
}
