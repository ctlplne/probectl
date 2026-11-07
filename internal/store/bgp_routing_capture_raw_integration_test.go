// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"strconv"
	"testing"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func proveCompleteRawCaptureBatchKeepsTenantAndAtomicRefusal(t *testing.T, f *roleInputsFixture, service *BGPRoutingFlowCaptures, input BGPRoutingFlowInput) {
	t.Helper()
	const count = 1001
	witnesses := make([]entity.FlowCaptureWitness, count)
	for i := range witnesses {
		witnesses[i] = entity.FlowCaptureWitness{RawDigest: routingCaptureHash([]byte("complete-raw-stage-" + strconv.Itoa(i))), Input: input}
	}
	var paired [][]BGPRoutingCaptureReference
	for lane, tenant := range f.tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		refs, err := service.StageRaw(ctx, "routing-flow", witnesses, routingViewBudget())
		if err != nil || len(refs) != count {
			t.Fatal("complete raw staging omitted later original witnesses", len(refs), err)
		}
		retry, err := service.StageRaw(ctx, "routing-flow", witnesses, routingViewBudget())
		if err != nil || len(retry) != count {
			t.Fatal("complete raw staging retry lost its first references", len(retry), err)
		}
		for i, witness := range witnesses {
			key, err := service.captureKey(ctx, "routing-flow", witness.RawDigest, input, routingViewBudget())
			if err != nil || refs[i].Key != key || refs[i].CapturedAt.IsZero() || retry[i] != refs[i] || (lane == 1 && paired[0][i].Key == refs[i].Key) {
				t.Fatal("raw staging changed complete order, first clock or tenant identity", i, err)
			}
		}
		paired = append(paired, refs)
		err = tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			for _, ref := range refs {
				intent, exists, err := loadRoutingCaptureIntentInScope(ctx, sc, ref.Key)
				if err != nil || !exists || intent.reference() != ref {
					t.Fatal("complete raw staging lost a durable private first reference", err)
				}
				if receipt, exists, err := readRoutingCaptureInScope(ctx, sc, ref.Key, routingViewBudget()); err != nil || exists || receipt.objects != nil {
					t.Fatal("raw batch created canonical route authority without sender evidence", err)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		bad := make([]entity.FlowCaptureWitness, count)
		for i := range bad {
			bad[i] = entity.FlowCaptureWitness{RawDigest: routingCaptureHash([]byte("refused-raw-stage-" + strconv.Itoa(i))), Input: input}
		}
		firstKey, err := service.captureKey(ctx, "routing-flow", bad[0].RawDigest, input, routingViewBudget())
		if err != nil {
			t.Fatal(err)
		}
		bad[len(bad)-1].RawDigest = [32]byte{}
		if refs, err := service.StageRaw(ctx, "routing-flow", bad, routingViewBudget()); err == nil || refs != nil {
			t.Fatal("malformed complete raw batch returned partial first references")
		}
		err = tenancy.InTenantReadSnapshot(ctx, f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, exists, err := loadRoutingCaptureIntentInScope(ctx, sc, firstKey)
			if err == nil && exists {
				t.Fatal("malformed final raw witness retained a partial private batch")
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
