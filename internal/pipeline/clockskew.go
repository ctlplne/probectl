// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"sync/atomic"
	"time"
)

// CORRECT-012: agents stamp samples with their OWN clock. A misconfigured or
// drifting agent can stamp samples far in the FUTURE; written verbatim they
// poison range queries, staleness/no-data evaluation, and "latest" views (a
// future sample is always "newest"). We clamp implausibly-future samples back
// to ingest time and surface the skew so the operator can fix the agent clock —
// never silently trust an out-of-bounds timestamp.

// MaxFutureSkew is how far ahead of ingest time a sample may be stamped before
// it is treated as clock skew and clamped. Small benign skews (sub-window NTP
// drift) pass through untouched; only gross future-dating is clamped.
const MaxFutureSkew = 5 * time.Minute

var maxFutureSkewMillis = MaxFutureSkew.Milliseconds()

var (
	futureClamped     atomic.Uint64 // samples clamped because they were too far in the future
	maxObservedSkewMs atomic.Int64  // largest future skew observed (ms), for the skew gauge
)

// clampFutureSample returns tms unchanged unless it is more than MaxFutureSkew
// ahead of nowMillis, in which case it clamps to nowMillis and records the skew
// (CORRECT-012). It does NOT touch past timestamps — legitimately-late
// store-and-forward drains must keep their real event time.
func clampFutureSample(tms, nowMillis int64) int64 {
	skew := tms - nowMillis
	if skew > maxFutureSkewMillis {
		futureClamped.Add(1)
		for {
			cur := maxObservedSkewMs.Load()
			if skew <= cur || maxObservedSkewMs.CompareAndSwap(cur, skew) {
				break
			}
		}
		return nowMillis
	}
	return tms
}

// clampFutureTime is the time.Time form of clampFutureSample for the row-store
// planes (OTLP traces/logs, flow), whose event time lands as a ClickHouse
// DateTime, not a Prometheus millis sample (CORRECT-006). A zero time is left
// untouched (callers apply their own "no event time" fallback); a far-future
// time is clamped to now and counted on the same skew counters, so every ingest
// path shares one clamp and one /metrics surface.
func clampFutureTime(t, now time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	clamped := clampFutureSample(t.UnixMilli(), now.UnixMilli())
	if clamped == now.UnixMilli() && t.UnixMilli() != now.UnixMilli() {
		return now
	}
	return t
}

// FutureClamped reports how many samples have been clamped for being stamped
// too far in the future (CORRECT-012 observability — exported to /metrics).
func FutureClamped() uint64 { return futureClamped.Load() }

// MaxObservedFutureSkewMillis reports the largest future clock skew seen so far
// (milliseconds); the skew-delta gauge reads this.
func MaxObservedFutureSkewMillis() int64 { return maxObservedSkewMs.Load() }
