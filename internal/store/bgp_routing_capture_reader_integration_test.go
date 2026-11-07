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

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func readFlowCaptureForTest(t *testing.T, f *roleInputsFixture, lane int, raw [32]byte, input BGPRoutingFlowInput, ref BGPRoutingCaptureReference, authorize func(context.Context, entity.ContextRecord) error) (BGPRoutingFlowLookup, error) {
	t.Helper()
	var out BGPRoutingFlowLookup
	err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(f.tenants[lane])), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		out, err = (BGPRouting{}).readFlowCaptureInScope(ctx, sc, "routing-flow", entity.FlowCaptureWitness{RawDigest: raw, Input: input}, ref, routingViewBudget(), authorize)
		return err
	})
	return out, err
}

func proveCapturedRoutingReaderRequiresCurrentContextAndOriginalReference(t *testing.T, f *roleInputsFixture, first [2]BGPRoutingCaptureReference, raw [32]byte, input BGPRoutingFlowInput, changes []BGPRoutingChange) {
	t.Helper()
	for lane, tenant := range f.tenants {
		calls := 0
		authorize := func(_ context.Context, record entity.ContextRecord) error {
			calls++
			if record.TenantID != tenant || record.ContextID != f.contextID {
				t.Fatal("retained routing reader authorized another tenant or claimed context")
			}
			return nil
		}
		lookup, err := readFlowCaptureForTest(t, f, lane, raw, input, first[lane], authorize)
		if err != nil || calls != 1 || !lookup.CapturedAt.Equal(first[lane].CapturedAt) || !reflect.DeepEqual(lookup.Source.Route.Paths, []BGPRoutingChange{changes[lane]}) {
			t.Fatal("current retained routing reader lost its complete original snapshot", lane, calls, err)
		}
		denied := errors.New("current context permission removed")
		lookup, err = readFlowCaptureForTest(t, f, lane, raw, input, first[lane], func(context.Context, entity.ContextRecord) error { return denied })
		if !errors.Is(err, denied) || !reflect.DeepEqual(lookup, BGPRoutingFlowLookup{}) {
			t.Fatal("retained routing key bypassed current context authorization", err)
		}
		err = tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			budget := routingViewBudget()
			budget.MemoryBytes, budget.WorkUnits = 1, 1
			_, err := (BGPRouting{}).readFlowCaptureInScope(ctx, sc, "routing-flow", entity.FlowCaptureWitness{RawDigest: raw, Input: input}, first[lane], budget, func(context.Context, entity.ContextRecord) error { return denied })
			return err
		})
		if !errors.Is(err, denied) {
			t.Fatal("denied retained routing read disclosed payload admission", err)
		}
		if lookup, err = readFlowCaptureForTest(t, f, lane, raw, input, first[lane], nil); !errors.Is(err, entity.ErrScopeMismatch) || !reflect.DeepEqual(lookup, BGPRoutingFlowLookup{}) {
			t.Fatal("retained routing reader accepted absent context authorization", err)
		}
		for _, ref := range []BGPRoutingCaptureReference{first[1-lane], {Key: first[lane].Key, CapturedAt: first[lane].CapturedAt.Add(time.Nanosecond)}} {
			if lookup, err = readFlowCaptureForTest(t, f, lane, raw, input, ref, authorize); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || !reflect.DeepEqual(lookup, BGPRoutingFlowLookup{}) {
				t.Fatal("retained routing reader accepted a foreign or changed first reference", err)
			}
		}
		other := raw
		other[0] ^= 1
		if lookup, err = readFlowCaptureForTest(t, f, lane, other, input, first[lane], authorize); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || !reflect.DeepEqual(lookup, BGPRoutingFlowLookup{}) {
			t.Fatal("retained routing reader detached original raw identity", err)
		}
	}
}

func requireRetiredRoutingReaderUnavailable(t *testing.T, f *roleInputsFixture, lane int, raw [32]byte, input BGPRoutingFlowInput, ref BGPRoutingCaptureReference) {
	t.Helper()
	lookup, err := readFlowCaptureForTest(t, f, lane, raw, input, ref, func(context.Context, entity.ContextRecord) error { return nil })
	if !errors.Is(err, ErrBGPRoutingSourceUnavailable) || !reflect.DeepEqual(lookup, BGPRoutingFlowLookup{}) {
		t.Fatal("retained routing reader reused removed current source authority", err)
	}
}
