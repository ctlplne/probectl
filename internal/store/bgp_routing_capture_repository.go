// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type routingCaptureReceipt struct {
	key        [32]byte
	capturedAt time.Time
	outcome    string
	objects    *routingCaptureObjects
}

func routingCaptureScope(ctx context.Context, sc tenancy.Scope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant {
		return entity.ErrScopeMismatch
	}
	if canonical, err := validRegistryUUID(tenant.String()); err != nil || canonical != tenant.String() {
		return entity.ErrScopeMismatch
	}
	if sc.Q == nil {
		return ErrBGPRoutingSourceUnavailable
	}
	return nil
}

// The caller owns a fenced, routed tenant transaction and must return every
// error. This repository creates no reader grant. First capture, including an
// unavailable result, wins; missing erased payloads can never be refilled by a
// retry through this seam. Current user/source authorization remains separate.
func retainRoutingCaptureInScope(ctx context.Context, sc tenancy.Scope, key [32]byte, objects *routingCaptureObjects, sourceGeneration int64, budget BGPRoutingBudget) (routingCaptureReceipt, error) {
	if err := routingCaptureScope(ctx, sc); err != nil {
		return routingCaptureReceipt{}, err
	}
	if key == ([32]byte{}) || budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || budget.StateBytes <= 0 {
		return routingCaptureReceipt{}, ErrBGPRoutingBudget
	}
	// Share lifecycle lock order with subject erasure and report publication.
	// A capture started before validated erasure cannot republish old content.
	if err := audit.LockTenantStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
		return routingCaptureReceipt{}, err
	}
	if err := flowsnapshot.MatchSourceGenerationInScope(ctx, sc, sourceGeneration); err != nil {
		return routingCaptureReceipt{}, err
	}
	if err := lockBGPRoutingState(ctx, sc); err != nil {
		return routingCaptureReceipt{}, err
	}
	previous, exists, err := loadRoutingCaptureReceiptInScope(ctx, sc, key)
	if err != nil || exists {
		return previous, err
	}
	if objects != nil {
		if _, err := decodeRoutingCapture(ctx, *objects, budget); err != nil {
			return routingCaptureReceipt{}, err
		}
	}
	if err := admitRetainedRoutingCapture(ctx, sc, objects, budget); err != nil {
		return routingCaptureReceipt{}, err
	}
	receipt := routingCaptureReceipt{key: key, outcome: "unavailable"}
	if objects != nil {
		receipt.outcome, receipt.capturedAt = "captured", objects.capturedAt
	} else if err := sc.Q.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&receipt.capturedAt); err != nil {
		return routingCaptureReceipt{}, err
	}
	if _, err := sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_receipts(tenant_id,flow_key,captured_at_unix_nanos,outcome) VALUES($1,$2,$3,$4)`, sc.Tenant.String(), key[:], receipt.capturedAt.UnixNano(), receipt.outcome); err != nil {
		return routingCaptureReceipt{}, err
	}
	if objects != nil {
		if err := insertRoutingCapturePayload(ctx, sc, key, *objects); err != nil {
			return routingCaptureReceipt{}, err
		}
	}
	return receipt, nil
}

func loadRoutingCaptureReceiptInScope(ctx context.Context, sc tenancy.Scope, key [32]byte) (routingCaptureReceipt, bool, error) {
	if err := routingCaptureScope(ctx, sc); err != nil {
		return routingCaptureReceipt{}, false, err
	}
	out := routingCaptureReceipt{key: key}
	var nanos int64
	err := sc.Q.QueryRow(ctx, `SELECT captured_at_unix_nanos,outcome FROM bgp_flow_capture_receipts WHERE tenant_id=$1 AND flow_key=$2`, sc.Tenant.String(), key[:]).Scan(&nanos, &out.outcome)
	if errors.Is(err, pgx.ErrNoRows) {
		return routingCaptureReceipt{}, false, nil
	}
	if err != nil {
		return routingCaptureReceipt{}, false, err
	}
	out.capturedAt = time.Unix(0, nanos).UTC()
	return out, true, nil
}

// This is a private storage read, not a capability: an outward adapter must
// independently check the current actor and every retained context/source.
// A repeatable snapshot prevents a concurrent erase/reinsert from mixing the
// first receipt and two different content objects. The caller must not expose
// captured evidence if its current publication authorization has changed.
func readRoutingCaptureInScope(ctx context.Context, sc tenancy.Scope, key [32]byte, budget BGPRoutingBudget) (routingCaptureReceipt, bool, error) {
	if err := routingCaptureScope(ctx, sc); err != nil {
		return routingCaptureReceipt{}, false, err
	}
	if err := requireRoutingReadSnapshot(ctx, sc); err != nil {
		return routingCaptureReceipt{}, false, err
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || budget.StateBytes <= 0 {
		return routingCaptureReceipt{}, false, ErrBGPRoutingBudget
	}
	receipt, exists, err := loadRoutingCaptureReceiptInScope(ctx, sc, key)
	if err != nil || !exists || receipt.outcome != "captured" {
		return receipt, exists, err
	}
	var facts, clocks []byte
	err = sc.Q.QueryRow(ctx, `SELECT facts_digest,clocks_digest FROM bgp_flow_capture_payloads WHERE tenant_id=$1 AND flow_key=$2`, sc.Tenant.String(), key[:]).Scan(&facts, &clocks)
	if errors.Is(err, pgx.ErrNoRows) {
		receipt.outcome = "retired"
		return receipt, true, nil
	}
	if err != nil || len(facts) != 32 || len(clocks) != 32 {
		return routingCaptureReceipt{}, false, errRoutingCaptureFormat
	}
	objects := routingCaptureObjects{capturedAt: receipt.capturedAt}
	for i, item := range []struct {
		digest []byte
		kind   string
	}{{facts, "routing_facts"}, {clocks, "routing_clocks"}} {
		object, err := readRoutingCaptureObjectInScope(ctx, sc, item.digest, item.kind, budget)
		if err != nil {
			return routingCaptureReceipt{}, false, err
		}
		if i == 0 {
			objects.facts = object
		} else {
			objects.clocks = object
		}
	}
	if _, err := decodeRoutingCapture(ctx, objects, budget); err != nil {
		return routingCaptureReceipt{}, false, err
	}
	receipt.objects = &objects
	return receipt, true, nil
}

func readRoutingCaptureObjectInScope(ctx context.Context, sc tenancy.Scope, digest []byte, kind string, budget BGPRoutingBudget) (routingCaptureObject, error) {
	var size int64
	if err := sc.Q.QueryRow(ctx, `SELECT octet_length(payload)::bigint FROM bgp_flow_capture_objects WHERE tenant_id=$1 AND digest=$2 AND kind=$3`, sc.Tenant.String(), digest, kind).Scan(&size); err != nil {
		return routingCaptureObject{}, err
	}
	if size <= 0 || size > budget.MemoryBytes/16 || size > budget.WorkUnits/8 {
		return routingCaptureObject{}, ErrBGPRoutingBudget
	}
	var object routingCaptureObject
	if err := sc.Q.QueryRow(ctx, `SELECT payload FROM bgp_flow_capture_objects WHERE tenant_id=$1 AND digest=$2 AND kind=$3 AND octet_length(payload)::bigint=$4`, sc.Tenant.String(), digest, kind, size).Scan(&object.payload); err != nil {
		return routingCaptureObject{}, err
	}
	copy(object.digest[:], digest)
	return object, nil
}

func admitRetainedRoutingCapture(ctx context.Context, sc tenancy.Scope, objects *routingCaptureObjects, budget BGPRoutingBudget) error {
	used, err := routingStateBytesInScope(ctx, sc)
	if err != nil {
		return err
	}
	next := int64(2048)
	if objects != nil {
		next += 2048
		for _, object := range []routingCaptureObject{objects.facts, objects.clocks} {
			var exists bool
			if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bgp_flow_capture_objects WHERE tenant_id=$1 AND digest=$2)`, sc.Tenant.String(), object.digest[:]).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				cost := int64(len(object.payload))*3 + 4096
				if cost > budget.StateBytes || next > budget.StateBytes-cost {
					return ErrBGPRoutingBudget
				}
				next += cost
			}
		}
	}
	if used < 0 || next > budget.StateBytes || used > budget.StateBytes-next {
		return ErrBGPRoutingBudget
	}
	return nil
}

func insertRoutingCapturePayload(ctx context.Context, sc tenancy.Scope, key [32]byte, objects routingCaptureObjects) error {
	for i, object := range []routingCaptureObject{objects.facts, objects.clocks} {
		kind := "routing_facts"
		if i == 1 {
			kind = "routing_clocks"
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_objects(tenant_id,digest,kind,payload) VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,digest) DO NOTHING`, sc.Tenant.String(), object.digest[:], kind, object.payload); err != nil {
			return err
		}
		var same bool
		if err := sc.Q.QueryRow(ctx, `SELECT kind=$3 AND payload=$4 FROM bgp_flow_capture_objects WHERE tenant_id=$1 AND digest=$2`, sc.Tenant.String(), object.digest[:], kind, object.payload).Scan(&same); err != nil {
			return err
		}
		if !same {
			return errRoutingCaptureFormat
		}
	}
	_, err := sc.Q.Exec(ctx, `INSERT INTO bgp_flow_capture_payloads(tenant_id,flow_key,facts_digest,clocks_digest) VALUES($1,$2,$3,$4)`, sc.Tenant.String(), key[:], objects.facts.digest[:], objects.clocks.digest[:])
	return err
}
