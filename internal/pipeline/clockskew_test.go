// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"testing"
	"time"
)

// CORRECT-012: a sample stamped far in the future is clamped to ingest time and
// counted; an in-window (including slightly-future and legitimately-past)
// timestamp passes through untouched.
func TestClampFutureSample(t *testing.T) {
	now := time.Now().UnixMilli()

	// Far future (1h ahead): clamped to now, counted.
	before := FutureClamped()
	if got := clampFutureSample(now+time.Hour.Milliseconds(), now); got != now {
		t.Fatalf("far-future sample not clamped: got %d, want %d", got, now)
	}
	if FutureClamped() != before+1 {
		t.Fatal("clamp was not counted")
	}

	// Small benign skew (1m, under the 5m bound): untouched.
	near := now + time.Minute.Milliseconds()
	if got := clampFutureSample(near, now); got != near {
		t.Fatalf("in-window future skew was clamped: got %d, want %d", got, near)
	}

	// Legitimately-late drain (1h in the past): never clamped — real event time.
	past := now - time.Hour.Milliseconds()
	if got := clampFutureSample(past, now); got != past {
		t.Fatalf("past sample was altered: got %d, want %d", got, past)
	}
}

func TestNormalizeEventTimeUnixNano(t *testing.T) {
	receivedAt := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

	if got := NormalizeEventTimeUnixNano(0, receivedAt); !got.Equal(receivedAt) {
		t.Fatalf("zero event time = %s, want receive time %s", got, receivedAt)
	}

	past := receivedAt.Add(-time.Hour)
	if got := NormalizeEventTimeUnixNano(past.UnixNano(), receivedAt); !got.Equal(past) {
		t.Fatalf("past event time was altered: got %s, want %s", got, past)
	}

	before := FutureClamped()
	if got := NormalizeEventTimeUnixNano(receivedAt.Add(time.Hour).UnixNano(), receivedAt); !got.Equal(receivedAt) {
		t.Fatalf("future event time = %s, want clamp to %s", got, receivedAt)
	}
	if FutureClamped() <= before {
		t.Fatal("future event-time clamp was not counted")
	}
}
