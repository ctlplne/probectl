// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package a2a

import (
	"fmt"
	"testing"
)

// INJ-06: POST /v1/a2a/mesh scheduled a full directed mesh — sites*(sites-1)
// sessions — allocated and enqueued up front in the request goroutine with no
// cap. A ~1 MiB body (tens of thousands of sites) demanded a ~1e9-element,
// ~157 GB slice, so one editor request could OOM the stateless control plane.
// A request above the site cap must be rejected before any allocation.
//
// The literal 64 mirrors maxMeshSites in mesh.go; it is the contract guarded.
func TestMeshRejectsRequestAboveSiteCap(t *testing.T) {
	const siteCap = 64
	sites := func(n int) []SiteAgent {
		a := make([]SiteAgent, n)
		for i := range a {
			s := fmt.Sprintf("site-%05d", i)
			a[i] = SiteAgent{AgentID: "agent-" + s, Site: s}
		}
		return a
	}

	s := NewMeshScheduler(NewBroker())

	// Above the site cap → rejected (the handler maps this to HTTP 4xx) before
	// the O(n^2) allocation.
	if _, err := s.StartMesh("tenant-a", sites(siteCap+1), "udp", 1); err == nil {
		t.Fatalf("a mesh with %d sites must be rejected (site cap %d)", siteCap+1, siteCap)
	}

	// At the cap → accepted, exactly sites*(sites-1) sessions, bounded.
	full, err := s.StartMesh("tenant-a", sites(siteCap), "udp", 1)
	if err != nil {
		t.Fatalf("a mesh at the site cap must succeed: %v", err)
	}
	if want := siteCap * (siteCap - 1); len(full) != want {
		t.Fatalf("full mesh = %d sessions, want %d", len(full), want)
	}
}
