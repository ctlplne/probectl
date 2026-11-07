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
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real application-role Postgres/FORCE-RLS and immutable storage lifecycle.
// Source/path metadata is modeled; this is not a physical sender or public
// current-reader authorization receipt.
func TestRoutingCaptureRepositoryKeepsFirstTenantSnapshotAndErasureTombstone(t *testing.T) {
	f := newRoleInputsFixture(t)
	budget := routingViewBudget()
	key := routingCaptureHash([]byte("same verified raw flow identity"))
	otherKey := routingCaptureHash([]byte("another verified raw flow identity"))
	var generations [2]int64
	var objects [2]routingCaptureObjects
	var inputs [2]BGPRoutingFlowLookup
	for lane, tenant := range f.tenants {
		input := routingCaptureFixture(t)
		input.Owner.Scope = entity.Scope{TenantID: tenant, ContextID: f.contextID}
		input.Owner.RouterID = f.routerID
		input.Source.Route.Source.Scope = input.Owner.Scope
		input.Source.Route.Source.RouterID = f.routerID
		input.Destination = input.Source
		inputs[lane] = input
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		var err error
		objects[lane], err = freezeRoutingCapture(ctx, input, budget)
		if err != nil {
			t.Fatal(err)
		}
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			generations[lane], err = flowsnapshot.SourceGenerationInScope(ctx, sc)
			return err
		})
	}
	write := func(lane int, flowKey [32]byte, object *routingCaptureObjects, limits BGPRoutingBudget) (routingCaptureReceipt, error) {
		t.Helper()
		var result routingCaptureReceipt
		err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[lane])), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			result, err = retainRoutingCaptureInScope(ctx, sc, flowKey, object, generations[lane], limits)
			return err
		})
		return result, err
	}
	read := func(lane int, flowKey [32]byte) (routingCaptureReceipt, bool, error) {
		t.Helper()
		var result routingCaptureReceipt
		var exists bool
		err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[lane])), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			result, exists, err = readRoutingCaptureInScope(ctx, sc, flowKey, budget)
			return err
		})
		return result, exists, err
	}
	for lane := range f.tenants {
		if _, err := write(lane, key, &objects[lane], budget); err != nil {
			t.Fatal(err)
		}
		receipt, exists, err := read(lane, key)
		if err != nil || !exists || receipt.outcome != "captured" || receipt.objects == nil {
			t.Fatal("complete first capture was not readable", lane, receipt.outcome, err)
		}
		got, err := decodeRoutingCapture(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[lane])), *receipt.objects, budget)
		if err != nil || !reflect.DeepEqual(got, inputs[lane]) {
			t.Fatal("stored first capture lost complete paths, clocks or tenant identity", lane, err)
		}
	}
	intentKey := routingCaptureHash([]byte("unattested provisional raw flow"))
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			ref, err := retainRoutingCaptureIntentInScope(ctx, sc, intentKey, objects[lane], generations[lane], budget)
			if err != nil {
				return err
			}
			if ref.Key != intentKey || !ref.CapturedAt.Equal(inputs[lane].CapturedAt) {
				t.Fatal("provisional ingestion changed complete first identity or clock")
			}
			intent, exists, err := loadRoutingCaptureIntentInScope(ctx, sc, intentKey)
			if err != nil || !exists {
				t.Fatal("provisional ingestion lost its first epoch and clock", err)
			}
			private, err := readRoutingCaptureIntentPayloadInScope(ctx, sc, intent, budget)
			if err != nil || private == nil {
				t.Fatal("private candidate lost complete source data", err)
			}
			decoded, err := decodeRoutingCapture(ctx, *private, budget)
			if err != nil || !reflect.DeepEqual(decoded, inputs[lane]) {
				t.Fatal("private candidate changed complete original paths or source clocks", err)
			}
			var own, foreign int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_flow_capture_intents`).Scan(&own); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_flow_capture_intents WHERE tenant_id=$1`, f.tenants[1-lane]).Scan(&foreign); err != nil {
				return err
			}
			if own != 1 || foreign != 0 {
				t.Fatal("provisional routing capture crossed storage tenant isolation", own, foreign)
			}
			return nil
		})
		if receipt, exists, err := read(lane, intentKey); err != nil || exists || receipt.objects != nil {
			t.Fatal("unattested private candidate became canonical routing evidence", err)
		}
	}
	// A later current view cannot replace the successfully committed capture.
	later := inputs[0]
	later.CapturedAt = later.CapturedAt.Add(time.Second)
	later.Source.Route.LastSequence++
	newer, err := freezeRoutingCapture(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[0])), later, budget)
	if err != nil {
		t.Fatal(err)
	}
	if receipt, err := write(0, key, &newer, budget); err != nil || !receipt.capturedAt.Equal(inputs[0].CapturedAt) {
		t.Fatal("retry changed the first successful routing capture", err)
	}
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		ref, err := retainRoutingCaptureIntentInScope(ctx, sc, intentKey, newer, generations[0], budget)
		if err == nil && !ref.CapturedAt.Equal(inputs[0].CapturedAt) {
			t.Fatal("provisional retry replaced its first processing clock")
		}
		return err
	})
	if _, err := write(0, otherKey, &objects[0], budget); err != nil {
		t.Fatal(err)
	}
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		var total, foreign int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_flow_capture_objects`).Scan(&total); err != nil {
			return err
		}
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_flow_capture_objects WHERE tenant_id=$1`, f.tenants[1]).Scan(&foreign); err != nil {
			return err
		}
		if total != 2 || foreign != 0 {
			t.Fatal("shared capture content duplicated or crossed storage RLS", total, foreign)
		}
		_, err := sc.Q.Exec(ctx, `DELETE FROM bgp_flow_capture_objects WHERE tenant_id=$1 AND digest=$2`, f.tenants[0], objects[0].facts.digest[:])
		return err
	})
	if receipt, exists, err := read(0, key); err != nil || !exists || receipt.outcome != "retired" || receipt.objects != nil {
		t.Fatal("erased capture retained payload or lost its first-capture tombstone", err)
	}
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			var intents, payloads int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_flow_capture_intents WHERE tenant_id=$1 AND flow_key=$2`, tenant, intentKey[:]).Scan(&intents); err != nil {
				return err
			}
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_flow_capture_intent_payloads WHERE tenant_id=$1 AND flow_key=$2`, tenant, intentKey[:]).Scan(&payloads); err != nil {
				return err
			}
			if intents != 1 || payloads != lane {
				t.Fatal("provisional payload erasure lost its tombstone or changed sibling", intents, payloads, lane)
			}
			return nil
		})
	}
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		ref, err := retainRoutingCaptureIntentInScope(ctx, sc, intentKey, objects[0], generations[0], budget)
		if err != nil {
			return err
		}
		var payloads int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM bgp_flow_capture_intent_payloads WHERE tenant_id=$1 AND flow_key=$2`, f.tenants[0], intentKey[:]).Scan(&payloads); err != nil {
			return err
		}
		if !ref.CapturedAt.Equal(inputs[0].CapturedAt) || payloads != 0 {
			t.Fatal("erased provisional retry refilled its payload or changed first clock", payloads)
		}
		return nil
	})
	if _, err := write(0, key, &objects[0], budget); err != nil {
		t.Fatal(err)
	}
	// Reusing the same legitimate content for a new flow must not revive an
	// earlier payload link removed by erasure.
	thirdKey := routingCaptureHash([]byte("fresh distinct verified flow"))
	if _, err := write(0, thirdKey, &objects[0], budget); err != nil {
		t.Fatal(err)
	}
	if receipt, exists, err := read(0, key); err != nil || !exists || receipt.outcome != "retired" || receipt.objects != nil {
		t.Fatal("reinserted content revived an erased first capture", err)
	}
	if receipt, exists, err := read(1, key); err != nil || !exists || receipt.outcome != "captured" || receipt.objects == nil {
		t.Fatal("one tenant's erasure changed its sibling capture", err)
	}
	unavailableKey := routingCaptureHash([]byte("unavailable first routing lookup"))
	if _, err := write(0, unavailableKey, nil, budget); err != nil {
		t.Fatal(err)
	}
	if receipt, err := write(0, unavailableKey, &objects[0], budget); err != nil || receipt.outcome != "unavailable" {
		t.Fatal("retry invented evidence after an unavailable first capture", err)
	}
	limitedKey := routingCaptureHash([]byte("unadmitted capture"))
	limited := budget
	limited.StateBytes = 1
	if _, err := write(0, limitedKey, &objects[0], limited); !errors.Is(err, ErrBGPRoutingBudget) {
		t.Fatal("retained capture ignored complete tenant state admission", err)
	}
	if _, exists, err := read(0, limitedKey); err != nil || exists {
		t.Fatal("refused capture left a partial first receipt", err)
	}
	rollback := errors.New("injected caller rollback")
	rollbackKey := routingCaptureHash([]byte("rolled back capture"))
	err = tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[0])), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := retainRoutingCaptureInScope(ctx, sc, rollbackKey, &objects[0], generations[0], budget); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if _, exists, err := read(0, rollbackKey); err != nil || exists {
		t.Fatal("rolled back capture left partial metadata", err)
	}
	for _, statement := range []string{
		`UPDATE bgp_flow_capture_receipts SET outcome='unavailable' WHERE tenant_id=$1`,
		`UPDATE bgp_flow_capture_objects SET payload=payload WHERE tenant_id=$1`,
		`UPDATE bgp_flow_capture_payloads SET facts_digest=facts_digest WHERE tenant_id=$1`,
		`UPDATE bgp_flow_capture_intents SET source_generation=source_generation WHERE tenant_id=$1`,
		`UPDATE bgp_flow_capture_intent_payloads SET facts_digest=facts_digest WHERE tenant_id=$1`,
	} {
		err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[0])), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, statement, f.tenants[0])
			return err
		})
		var postgres *pgconn.PgError
		if !errors.As(err, &postgres) || postgres.Code != "42501" {
			t.Fatal("application role immutable capture boundary did not deny UPDATE", err)
		}
	}
	foreignKey := routingCaptureHash([]byte("foreign content link"))
	err = tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[0])), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_receipts(tenant_id,flow_key,captured_at_unix_nanos,outcome) VALUES($1,$2,$3,'captured')`, f.tenants[0], foreignKey[:], inputs[0].CapturedAt.UnixNano()); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_payloads(tenant_id,flow_key,facts_digest,clocks_digest) VALUES($1,$2,$3,$4)`, f.tenants[0], foreignKey[:], objects[1].facts.digest[:], objects[1].clocks.digest[:])
		return err
	})
	var postgres *pgconn.PgError
	if !errors.As(err, &postgres) || postgres.Code != "23503" {
		t.Fatal("capture storage borrowed another tenant's content", err)
	}
	if _, exists, err := read(0, foreignKey); err != nil || exists {
		t.Fatal("foreign payload refusal retained a partial receipt", err)
	}
	err = tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[0])), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_intents(tenant_id,flow_key,source_generation,captured_at_unix_nanos) VALUES($1,$2,$3,$4)`, f.tenants[0], foreignKey[:], generations[0], inputs[0].CapturedAt.UnixNano()); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_intent_payloads(tenant_id,flow_key,facts_digest,clocks_digest) VALUES($1,$2,$3,$4)`, f.tenants[0], foreignKey[:], objects[1].facts.digest[:], objects[1].clocks.digest[:])
		return err
	})
	if !errors.As(err, &postgres) || postgres.Code != "23503" {
		t.Fatal("provisional capture borrowed another tenant's content", err)
	}
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		if err := audit.LockTenantStream(ctx, sc.Q, f.tenants[0]); err != nil {
			return err
		}
		return flowsnapshot.InvalidateSourceGenerationInScope(ctx, sc)
	})
	if _, err := write(0, limitedKey, &objects[0], budget); !errors.Is(err, flowsnapshot.ErrInvalidating) {
		t.Fatal("pre-erasure routing capture republished source data", err)
	}
	err = tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[0])), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := retainRoutingCaptureIntentInScope(ctx, sc, limitedKey, objects[0], generations[0], budget)
		return err
	})
	if !errors.Is(err, flowsnapshot.ErrInvalidating) {
		t.Fatal("pre-erasure provisional capture republished source data", err)
	}
}
