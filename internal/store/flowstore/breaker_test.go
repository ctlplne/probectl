// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store/chclient"
)

// SCALE-021 (now via the shared chclient, CODE-006): each routed silo endpoint
// gets its OWN circuit breaker, so one down tenant silo can't trip writes for
// the rest. The pooled default ("") reuses the long-lived breaker; distinct
// BaseURLs get distinct, stable breakers (same URL -> same instance).
func TestBreakerPerTarget(t *testing.T) {
	conn := chclient.NewWithClient(crypto.HardenedHTTPClient(30 * time.Second))

	def := conn.BreakerFor("")
	if conn.BreakerFor("") != def {
		t.Fatal(`BreakerFor("") must reuse the pooled default breaker`)
	}

	a1 := conn.BreakerFor("http://silo-a:8123")
	a2 := conn.BreakerFor("http://silo-a:8123/") // trailing slash normalized
	b1 := conn.BreakerFor("http://silo-b:8123")

	if a1 != a2 {
		t.Fatal("same silo endpoint must map to the same breaker (state must accumulate)")
	}
	if a1 == b1 {
		t.Fatal("different silos must have independent breakers (blast-radius isolation)")
	}
	if a1 == def || b1 == def {
		t.Fatal("siloed breakers must be distinct from the pooled default")
	}
}
