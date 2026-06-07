package breaker

import (
	"errors"
	"testing"
	"time"
)

func TestBreakerOpensAfterThresholdAndShortCircuits(t *testing.T) {
	now := time.Unix(0, 0)
	b := New(3, time.Minute)
	b.now = func() time.Time { return now }
	boom := errors.New("upstream down")
	calls := 0
	fn := func() error { calls++; return boom }

	for i := 0; i < 3; i++ {
		if err := b.Do(fn); err != boom {
			t.Fatalf("call %d err = %v, want the upstream error", i, err)
		}
	}
	if st := b.Stats(); st.State != StateOpen || st.Trips != 1 {
		t.Fatalf("after threshold: %+v", st)
	}
	// Now open: calls short-circuit WITHOUT hitting the upstream.
	before := calls
	if err := b.Do(fn); err != ErrOpen {
		t.Fatalf("open breaker err = %v, want ErrOpen", err)
	}
	if calls != before {
		t.Fatal("open breaker still called the upstream")
	}
	if b.Stats().ShortCircuits != 1 {
		t.Fatalf("short-circuit not counted: %+v", b.Stats())
	}
}

func TestBreakerHalfOpenRecovers(t *testing.T) {
	now := time.Unix(0, 0)
	b := New(2, time.Minute)
	b.now = func() time.Time { return now }
	boom := errors.New("down")
	_ = b.Do(func() error { return boom })
	_ = b.Do(func() error { return boom }) // open
	if b.Stats().State != StateOpen {
		t.Fatal("breaker should be open")
	}

	// Cooldown elapses → half-open: the next call probes.
	now = now.Add(2 * time.Minute)
	if b.Stats().State != StateHalfOpen {
		t.Fatalf("after cooldown state = %s, want half-open", b.Stats().State)
	}
	probed := false
	if err := b.Do(func() error { probed = true; return nil }); err != nil {
		t.Fatalf("half-open probe err = %v", err)
	}
	if !probed {
		t.Fatal("half-open must let one call through")
	}
	if st := b.Stats(); st.State != StateClosed || st.ConsecFailures != 0 {
		t.Fatalf("after successful probe: %+v", st)
	}
}

func TestBreakerHalfOpenProbeFailureReArms(t *testing.T) {
	now := time.Unix(0, 0)
	b := New(1, time.Minute)
	b.now = func() time.Time { return now }
	_ = b.Do(func() error { return errors.New("x") }) // open immediately (threshold 1)
	now = now.Add(2 * time.Minute)                    // half-open
	if err := b.Do(func() error { return errors.New("still down") }); err == nil {
		t.Fatal("probe should surface the failure")
	}
	// Re-armed, still open; only ONE trip was counted (no double-count on probe).
	if st := b.Stats(); st.State != StateOpen || st.Trips != 1 {
		t.Fatalf("after failed probe: %+v", st)
	}
}

func TestBreakerSuccessResetsFailureRun(t *testing.T) {
	b := New(3, time.Minute)
	_ = b.Do(func() error { return errors.New("x") })
	_ = b.Do(func() error { return errors.New("x") })
	_ = b.Do(func() error { return nil }) // success resets the run
	if st := b.Stats(); st.ConsecFailures != 0 || st.State != StateClosed {
		t.Fatalf("success must reset: %+v", st)
	}
	// Two more failures should not trip (run was reset).
	_ = b.Do(func() error { return errors.New("x") })
	_ = b.Do(func() error { return errors.New("x") })
	if b.Stats().State == StateOpen {
		t.Fatal("breaker tripped despite the reset")
	}
}
