// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowconversation

import (
	"testing"
	"time"
)

func TestJournalPreparePolicyWithoutDeadline(t *testing.T) {
	f := newMessageCodecFixture(t)
	meta := inputMetadata()
	meta.ExpiresAt = time.Time{}
	prepared, err := f.codec.PrepareInput(f.requestContext(t), f.scope, meta, []string{"ai.query", "flow.read", "metrics.read"}, []byte(`{"q":"policy permits retention without a deadline"}`), f.authorize)
	if err != nil || prepared.input == nil || !prepared.input.meta.ExpiresAt.IsZero() {
		t.Fatal("policy-authorized unlimited retention cannot be represented", err)
	}
}

func TestStorageDeadlineNeverExtendsFinitePolicy(t *testing.T) {
	if !StorageDeadline(time.Time{}).IsZero() {
		t.Fatal("keep-forever policy became a fabricated timestamp")
	}
	for _, nanos := range []int64{0, 1, 499, 500, 999, 1000, 123456789, 999999999} {
		value := time.Unix(1793296800, nanos).In(time.FixedZone("owned-offset", 19800))
		got := StorageDeadline(value)
		if got.After(value) || value.Sub(got) >= time.Microsecond || got.Nanosecond()%1000 != 0 || got.Location() != time.UTC || StorageDeadline(got) != got {
			t.Fatal("storage timestamp rounded past authoritative retention", nanos)
		}
	}
}
