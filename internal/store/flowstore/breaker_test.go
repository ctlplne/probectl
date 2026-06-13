// SPDX-License-Identifier: LicenseRef-probectl-TBD

package flowstore

import (
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/breaker"
)

// SCALE-021: each routed silo endpoint gets its OWN circuit breaker, so one
// down tenant silo can't trip writes for the rest. The pooled default ("")
// reuses the long-lived breaker; distinct BaseURLs get distinct, stable
// breakers (same URL -> same instance, so trip state accumulates correctly).
func TestBreakerPerTarget(t *testing.T) {
	c := &ClickHouse{breaker: breaker.New(0, 0)}

	if c.breakerFor("") != c.breaker {
		t.Fatal(`breakerFor("") must reuse the pooled default breaker`)
	}

	a1 := c.breakerFor("http://silo-a:8123")
	a2 := c.breakerFor("http://silo-a:8123/") // trailing slash normalized
	b1 := c.breakerFor("http://silo-b:8123")

	if a1 != a2 {
		t.Fatal("same silo endpoint must map to the same breaker (state must accumulate)")
	}
	if a1 == b1 {
		t.Fatal("different silos must have independent breakers (blast-radius isolation)")
	}
	if a1 == c.breaker || b1 == c.breaker {
		t.Fatal("siloed breakers must be distinct from the pooled default")
	}
}
