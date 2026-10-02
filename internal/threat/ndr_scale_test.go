// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package threat

// Regression coverage for ING-18: the lateral-movement detector used to add
// every destination to an UNBOUNDED per-source map and rescan the WHOLE map on
// every flow (both to prune and to count fan-out), so one scanner's per-flow
// cost grew with the number of hosts it touched — an O(destinations) stall and
// an unbounded-memory DoS. Worse, a single engine-wide lock covered ALL
// tenants, so that scan also stalled every other tenant's ObserveFlow (a
// cross-tenant latency coupling). These tests pin the fix via the real
// ObserveFlow entry point: a bounded working set, an O(1) post-fire path, and
// per-tenant locks.

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/topology"
)

// onlyLateralRules returns just the built-in lateral rule, so an engine built
// from it exercises the lateral detector in isolation — the other detectors'
// (bounded, pre-existing) per-destination bookkeeping would otherwise dominate
// the cost of feeding tens of thousands of distinct destinations and obscure
// what this test pins. ObserveFlow is still the real entry point.
func onlyLateralRules(t *testing.T) []DetectionRule {
	t.Helper()
	var lat []DetectionRule
	for _, r := range mustRules(t) {
		if r.Kind == KindLateral {
			lat = append(lat, r)
		}
	}
	if len(lat) == 0 {
		t.Fatal("no lateral rule loaded")
	}
	return lat
}

// TestLateralFiredCounterIsConstantWork reproduces the finding's scan: one
// source sweeping 50k distinct internal hosts on an east-west port. Once the
// rule fires (at the fan-out threshold) the source is suppressed and every
// later flow must take the O(1) counter path instead of re-scanning the map —
// so the working set stays tiny no matter how many hosts are swept. On the
// unbounded baseline the map grows to 50k (RED here), and per-flow cost grew
// with it (the measured ~54s@40k quadratic stall).
func TestLateralFiredCounterIsConstantWork(t *testing.T) {
	rules := onlyLateralRules(t)
	e := NewEngine(rules, nil, nil) // nil topology: nothing excluded, so it fires fast
	rule := rules[0]
	const n = 50000
	const src = "10.9.9.9"

	var hits int
	for i := 0; i < n; i++ {
		dst := fmt.Sprintf("10.0.%d.%d", (i/256)%256, i%256)
		for _, s := range e.ObserveFlow("t1", FlowObservation{
			Src: src, Dst: dst, DstPort: 445, Bytes: 100,
			At: t0.Add(time.Duration(i) * time.Millisecond)}) {
			if s.Kind == "ndr.lateral" {
				hits++
			}
		}
	}

	// Detection still fires — bounding is not silent dropping (G7-9). It fires
	// exactly once because the source is then in its suppression window.
	if hits != 1 {
		t.Fatalf("want exactly 1 lateral detection, got %d", hits)
	}

	st := e.tenants["t1"].lateral[src]
	if st == nil {
		t.Fatal("no lateral state for the scanning source")
	}
	// Bounded working set: <= the cap regardless of the 50k destinations fed.
	// RED on baseline (grows to ~50k).
	if cap := lateralCap(rule); len(st.dsts) > cap {
		t.Fatalf("per-source destination map unbounded: len=%d > cap=%d", len(st.dsts), cap)
	}
	// And the O(1) post-fire path actually absorbed the bulk of the scan
	// (the "keep a counter, don't rescan" path), rather than re-scanning.
	if st.postFire < n-1000 {
		t.Fatalf("post-fire short-circuit not taken: postFire=%d, want ~%d", st.postFire, n)
	}
}

// TestLateralMapCapBoundsGrowth exercises the cap itself, in the case where the
// rule NEVER fires: topology marks every destination as an expected neighbor,
// so fan-out stays 0 and the source is never suppressed — yet the working set
// must still stay bounded by the cap (stalest evicted). RED on baseline (the
// map grows to every distinct destination).
func TestLateralMapCapBoundsGrowth(t *testing.T) {
	const n = 2000
	const src = "10.0.0.66"
	known := make([]string, 0, n)
	dsts := make([]string, 0, n)
	for i := 0; i < n; i++ {
		d := fmt.Sprintf("10.1.%d.%d", (i/256)%256, i%256)
		dsts = append(dsts, d)
		known = append(known, d) // every destination is an EXPECTED neighbor
	}
	rules := onlyLateralRules(t)
	e := NewEngine(rules, nil, fakeTopo{known: known})
	rule := rules[0]

	for i, d := range dsts {
		for _, s := range e.ObserveFlow("t1", FlowObservation{
			Src: src, Dst: d, DstPort: 445, Bytes: 100,
			At: t0.Add(time.Duration(i) * time.Millisecond)}) {
			if s.Kind == "ndr.lateral" {
				t.Fatalf("lateral fired although every destination is a known neighbor: %+v", s)
			}
		}
	}
	st := e.tenants["t1"].lateral[src]
	if st == nil {
		t.Fatal("no lateral state for the source")
	}
	if cap := lateralCap(rule); len(st.dsts) > cap {
		t.Fatalf("per-source destination map unbounded: len=%d > cap=%d", len(st.dsts), cap)
	}
}

// gateTopo is a NeighborSource whose Neighbors lookup blocks for one chosen
// tenant (holding that tenant's detector lock) until released — a deterministic
// way to prove one tenant's in-flight ObserveFlow does not hold a lock another
// tenant needs.
type gateTopo struct {
	blockTenant string
	entered     chan struct{}
	release     chan struct{}
	once        *sync.Once
}

func (g *gateTopo) ForTenant(tenant string) (topology.TenantStore, error) {
	return gateTenantTopo{block: tenant == g.blockTenant, g: g}, nil
}

// gateTenantTopo embeds fakeTenantTopo for its no-op TenantStore methods and
// overrides only Neighbors.
type gateTenantTopo struct {
	fakeTenantTopo
	block bool
	g     *gateTopo
}

func (t gateTenantTopo) Neighbors(string, time.Time) []string {
	if t.block {
		t.g.once.Do(func() { close(t.g.entered) })
		<-t.g.release
	}
	return nil
}

// TestNDRCrossTenantNonInterference proves the engine lock is sharded per
// tenant: while tenant A is blocked deep inside ObserveFlow (holding A's own
// lock), tenant B's ObserveFlow still completes. On the baseline's single
// engine-wide lock, B blocks on A and this test times out (RED). Black-box via
// the real ObserveFlow entry point — the only wall-clock element is a generous
// timeout that distinguishes "completed" from a HARD block, not a latency
// threshold.
func TestNDRCrossTenantNonInterference(t *testing.T) {
	gate := &gateTopo{
		blockTenant: "tenant-A",
		entered:     make(chan struct{}),
		release:     make(chan struct{}),
		once:        &sync.Once{},
	}
	e := testEngine(t, nil, gate)
	defer close(gate.release) // always let A finish

	// Tenant A: one internal east-west flow that reaches the topology lookup,
	// where gateTopo blocks while holding A's detector lock.
	go func() {
		_ = e.ObserveFlow("tenant-A", FlowObservation{
			Src: "10.0.0.1", Dst: "10.0.0.2", DstPort: 445, At: t0})
	}()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("tenant A never reached the topology lookup")
	}

	// While A is blocked, tenant B's ObserveFlow must not wait on A.
	bDone := make(chan struct{})
	go func() {
		_ = e.ObserveFlow("tenant-B", FlowObservation{
			Src: "10.0.9.1", Dst: "10.0.9.2", DstPort: 445, At: t0})
		close(bDone)
	}()
	select {
	case <-bDone:
		// Good: B was not blocked by A's in-flight scan.
	case <-time.After(5 * time.Second):
		t.Fatal("tenant B's ObserveFlow blocked on tenant A — engine lock is not per-tenant (ING-18)")
	}
}
