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

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDeviceCounterBatchWitnessesKeepCompleteOriginalSetAndTenantBoundary(t *testing.T) {
	fixtures := deviceCounterFixtures(t)
	keys := [2][][32]byte{}
	for lane, f := range fixtures {
		for i := range 2 {
			input := f.input
			input.PollStartedAt = input.PollStartedAt.Add(time.Duration(i) * time.Nanosecond)
			input.PollCompletedAt = input.PollStartedAt.Add(time.Nanosecond)
			digest := f.digest
			digest[0] += byte(i)
			ref, err := f.service.CaptureAuthenticated(f.ctx(t.Context()), f.sender, f.serial, digest, input, 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			keys[lane] = append(keys[lane], ref.Key)
		}
		inTenant(t.Context(), t, f.pool, f.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			got, err := f.service.LookupWitnessesInScope(ctx, sc, append(keys[lane], keys[lane][0]), 1<<20)
			if err != nil || len(got) != 2 {
				t.Fatal("complete receipt set or exact redelivery was lost", len(got), err)
			}
			for _, key := range keys[lane] {
				if got[key].Key != key || got[key].Scope.TenantID != f.tenant || got[key].DeviceID != f.device || got[key].SenderSerial != f.serial {
					t.Fatal("batched original receipt lost tenant/source provenance", got[key])
				}
			}
			if got, err := f.service.LookupWitnessesInScope(ctx, sc, keys[lane], 1); !errors.Is(err, ErrCounterCaptureBudget) || got != nil {
				t.Fatal("unadmitted receipt set returned a prefix", got, err)
			}
			return nil
		})
	}
	a, b := fixtures[0], fixtures[1]
	inTenant(t.Context(), t, a.pool, a.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		mixed := append(append([][32]byte{}, keys[0]...), keys[1]...)
		if got, err := a.service.LookupWitnessesInScope(ctx, sc, mixed, 1<<20); !errors.Is(err, ErrCounterCaptureUnavailable) || got != nil {
			t.Fatal("foreign original receipt shortened a tenant result instead of refusing it", got, err)
		}
		foreign := tenancy.WithTenant(ctx, tenancy.ID(b.tenant))
		if got, err := a.service.LookupWitnessesInScope(foreign, sc, keys[0], 1<<20); err == nil || got != nil {
			t.Fatal("batched receipt lookup replaced a contradictory tenant scope", got, err)
		}
		_, err := sc.Q.Exec(ctx, `DELETE FROM device_counter_capture_sources WHERE tenant_id=$1 AND capture_key=$2`, a.tenant, keys[0][0][:])
		return err
	})
	inTenant(t.Context(), t, a.pool, a.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		if got, err := a.service.LookupWitnessesInScope(ctx, sc, keys[0], 1<<20); !errors.Is(err, ErrCounterCaptureUnavailable) || got != nil {
			t.Fatal("erased original receipt left a successful surviving prefix", got, err)
		}
		return nil
	})
	inTenant(t.Context(), t, b.pool, b.tenant, func(ctx context.Context, sc tenancy.Scope) error {
		got, err := b.service.LookupWitnessesInScope(ctx, sc, keys[1], 1<<20)
		if err != nil || len(got) != 2 {
			t.Fatal("sibling original receipt set was affected by erasure", got, err)
		}
		return nil
	})
}
