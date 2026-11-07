// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"errors"
	"testing"
	"time"
)

func TestPublicSnapshotFreshnessUsesOriginalClockAndIndependentAuthorityLimits(t *testing.T) {
	asOf := time.Unix(1700000100, 987654321)
	origin := asOf.Add(-30*time.Minute - 17*time.Nanosecond)
	clock := origin.UnixNano()
	until, err := publicSnapshotDataLease(&clock, asOf, asOf.Add(2*time.Hour), asOf.Add(3*time.Hour), time.Hour)
	if err != nil || !until.Equal(origin.Add(time.Hour)) {
		t.Fatal("public source lease came from receipt time or lost original nanoseconds", until, err)
	}
	for _, limits := range [][2]time.Time{{asOf.Add(time.Minute), asOf.Add(time.Hour)}, {asOf.Add(time.Hour), asOf.Add(2 * time.Minute)}} {
		got, err := publicSnapshotDataLease(&clock, asOf, limits[0], limits[1], time.Hour)
		want := limits[0]
		if limits[1].Before(want) {
			want = limits[1]
		}
		if err != nil || !got.Equal(want) {
			t.Fatal("public data freshness exceeded capture or credential authority", got, err)
		}
	}
	negative, future, expired := int64(-1), asOf.Add(time.Nanosecond).UnixNano(), asOf.Add(-2*time.Hour).UnixNano()
	for _, bad := range []*int64{nil, &negative, &future, &expired} {
		if until, err := publicSnapshotDataLease(bad, asOf, asOf.Add(time.Hour), asOf.Add(time.Hour), time.Hour); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || !until.IsZero() {
			t.Fatal("unknown, future or stale source acquired current data lease", until, err)
		}
	}
	for _, limits := range [][2]time.Time{{asOf, asOf.Add(time.Hour)}, {asOf.Add(time.Hour), asOf}} {
		if until, err := publicSnapshotDataLease(&clock, asOf, limits[0], limits[1], time.Hour); !errors.Is(err, ErrBGPRoutingSourceUnavailable) || !until.IsZero() {
			t.Fatal("expired capture or source authority acquired current data lease", until, err)
		}
	}
	if until, err := publicSnapshotDataLease(&clock, asOf, asOf.Add(time.Hour), asOf.Add(time.Hour), 0); !errors.Is(err, ErrBGPRoutingBudget) || !until.IsZero() {
		t.Fatal("public freshness accepted missing server policy", until, err)
	}
	zero := int64(0)
	epoch := time.Unix(0, 0)
	if until, err := publicSnapshotDataLease(&zero, epoch, epoch.Add(time.Hour), epoch.Add(time.Hour), time.Hour); err != nil || !until.Equal(epoch.Add(time.Hour)) {
		t.Fatal("explicit epoch source clock became absent", until, err)
	}
	maximum := int64(^uint64(0) >> 1)
	edge := time.Unix(0, maximum)
	if until, err := publicSnapshotDataLease(&maximum, edge, edge.Add(time.Minute), edge.Add(time.Hour), time.Hour); err != nil || !until.Equal(edge.Add(time.Minute)) {
		t.Fatal("full source wire clock overflowed during lease admission", until, err)
	}
}
