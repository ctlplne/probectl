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
	"strings"
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
	proveCapturedNextHopReadRequiresCurrentSupportingEvidence(t, f, first, raw, input, changes)
}

func proveCapturedNextHopReadRequiresCurrentSupportingEvidence(t *testing.T, f *roleInputsFixture, first [2]BGPRoutingCaptureReference, raw [32]byte, input BGPRoutingFlowInput, changes []BGPRoutingChange) {
	t.Helper()
	allow := func(context.Context, entity.ContextRecord) error { return nil }
	before, err := readFlowCaptureForTest(t, f, 0, raw, input, first[0], allow)
	if err != nil || len(before.Source.NextHops) != 1 || before.Source.NextHops[0].ASN == nil || len(before.Source.NextHops[0].Sources) != 1 {
		t.Fatal("supporting next-hop source control lacks its original positive", err)
	}
	id := strings.TrimPrefix(before.Source.NextHops[0].Sources[0], "evidence/")
	f.in(f.tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entity_evidence SET expires_at=clock_timestamp()-interval '1 microsecond' WHERE tenant_id=$1 AND id=$2`, f.tenants[0], id)
		return err
	})
	after, err := readFlowCaptureForTest(t, f, 0, raw, input, first[0], allow)
	if err != nil || len(after.Source.NextHops) != 1 || after.Source.NextHops[0].ASN != nil || len(after.Source.NextHops[0].Sources) != 0 || after.Source.NextHops[0].Reason != "current_source_unavailable" || !reflect.DeepEqual(after.Source.Route.Paths, []BGPRoutingChange{changes[0]}) || !after.CapturedAt.Equal(first[0].CapturedAt) {
		t.Fatal("retained next-hop read reused unavailable support or erased independent paths", err)
	}
	sibling, err := readFlowCaptureForTest(t, f, 1, raw, input, first[1], allow)
	if err != nil || sibling.Source.NextHops[0].ASN == nil {
		t.Fatal("supporting source expiry crossed tenant", err)
	}
	// Restore the source through a new real evidence write. The old retained
	// reference keeps its expired supporting identity; it is never refilled.
	f.peerAtAddress(f.tenants[0], "2001:db8::1", 65010)
}

func requireRetiredRoutingReaderUnavailable(t *testing.T, f *roleInputsFixture, lane int, raw [32]byte, input BGPRoutingFlowInput, ref BGPRoutingCaptureReference) {
	t.Helper()
	lookup, err := readFlowCaptureForTest(t, f, lane, raw, input, ref, func(context.Context, entity.ContextRecord) error { return nil })
	if !errors.Is(err, ErrBGPRoutingSourceUnavailable) || !reflect.DeepEqual(lookup, BGPRoutingFlowLookup{}) {
		t.Fatal("retained routing reader reused removed current source authority", err)
	}
}
