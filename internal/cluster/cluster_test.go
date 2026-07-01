// SPDX-License-Identifier: LicenseRef-probectl-TBD

package cluster

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeProbe is a settable Prober: tests drive the observed recovery/epoch.
type fakeProbe struct{ p Probe }

func (f *fakeProbe) Probe(context.Context) Probe { return f.p }
func (f *fakeProbe) set(p Probe)                 { f.p = p }

func topo() Topology {
	return Topology{Region: "us-east", Regions: []string{"us-east", "eu-west"},
		ReplicationMode: ReplicationSync, RPOSeconds: 0, RTOSeconds: 60}
}

// TestRegionFailover is the named failover test (RTO/RPO mechanic): a healthy
// primary, then primary loss (writes fenced), then a standby promoted in the
// other region on a NEW epoch — writes resume. The control plane fails forward
// (a higher epoch), never back, so committed data on the promoted node is not
// lost (RPO bound holds under sync replication).
func TestRegionFailover(t *testing.T) {
	ctx := context.Background()
	writer := &fakeProbe{p: Probe{InRecovery: false, Epoch: 1, WriterRegion: "us-east"}}
	reader := &fakeProbe{p: Probe{InRecovery: true, Epoch: 1, WriterRegion: "us-east", LagSeconds: 0.2}}
	m := NewManager(topo(), writer, reader)

	// Steady state: the writer is usable.
	m.Refresh(ctx)
	if ok, reason := m.WriterUsable(); !ok {
		t.Fatalf("healthy primary must be usable: %s", reason)
	}
	if m.Status().Writer.Role != RoleWriter {
		t.Fatalf("writer role: %+v", m.Status().Writer)
	}

	// Primary lost: the writer endpoint errors (node down). Writes fence.
	writer.set(Probe{Err: errors.New("connection refused")})
	m.Refresh(ctx)
	if ok, _ := m.WriterUsable(); ok {
		t.Fatal("a down primary must fence writes")
	}

	// Failover: the standby in eu-west is promoted (epoch bumped to 2 by
	// cluster_promote) and the writer endpoint re-points to it. The OLD reader
	// also now follows the new primary (epoch 2).
	writer.set(Probe{InRecovery: false, Epoch: 2, WriterRegion: "eu-west"})
	reader.set(Probe{InRecovery: true, Epoch: 2, WriterRegion: "eu-west", LagSeconds: 0.1})
	m.Refresh(ctx)
	if ok, reason := m.WriterUsable(); !ok {
		t.Fatalf("writes must resume after promotion: %s", reason)
	}
	st := m.Status()
	if st.HighestEpoch != 2 || st.Writer.WriterRegion != "eu-west" {
		t.Fatalf("failover must advance the epoch + writer region: %+v", st)
	}
}

// TestSplitBrainFencing is the named split-brain test: once a promotion to a
// higher epoch is observed (via the replica that follows the true primary), a
// STALE ex-primary still in primary-role on the OLD epoch — e.g. the writer
// endpoint briefly flips back to it during a partition — is FENCED. A lower
// epoch can never reclaim; only the current (highest) epoch writes.
func TestSplitBrainFencing(t *testing.T) {
	ctx := context.Background()
	// The writer endpoint currently points at the old primary (epoch 1), but
	// the replica already follows a NEW primary promoted to epoch 2.
	writer := &fakeProbe{p: Probe{InRecovery: false, Epoch: 1, WriterRegion: "us-east"}}
	reader := &fakeProbe{p: Probe{InRecovery: true, Epoch: 2, WriterRegion: "eu-west"}}
	m := NewManager(topo(), writer, reader)
	m.Refresh(ctx)

	// The old primary is real (not in recovery) but on a superseded epoch:
	// fence it — writing here would be a split-brain write.
	ok, reason := m.WriterUsable()
	if ok {
		t.Fatal("a stale primary on a lower epoch must be fenced")
	}
	if m.Status().Writer.Role != RoleStale {
		t.Fatalf("the stale node must classify as stale: %+v (%s)", m.Status().Writer, reason)
	}

	// The endpoint catches up to the real primary (epoch 2): writes resume.
	writer.set(Probe{InRecovery: false, Epoch: 2, WriterRegion: "eu-west"})
	m.Refresh(ctx)
	if ok, reason := m.WriterUsable(); !ok {
		t.Fatalf("the current primary must be usable: %s", reason)
	}

	// A lower epoch can NEVER reclaim, even if the endpoint flaps back.
	writer.set(Probe{InRecovery: false, Epoch: 1, WriterRegion: "us-east"})
	m.Refresh(ctx)
	if ok, _ := m.WriterUsable(); ok {
		t.Fatal("a lower epoch must never reclaim the writer role (monotonic fence)")
	}
	if m.Status().HighestEpoch != 2 {
		t.Fatalf("the epoch high-water mark must not regress: %d", m.Status().HighestEpoch)
	}
}

// TestStandbyEndpointFenced: the writer endpoint pointing at a read-only
// standby (a half-finished failover) fences writes with a clear reason, while
// the status still reports the node as a reader.
func TestStandbyEndpointFenced(t *testing.T) {
	ctx := context.Background()
	writer := &fakeProbe{p: Probe{InRecovery: true, Epoch: 1}}
	m := NewManager(topo(), writer, nil)
	m.Refresh(ctx)
	ok, reason := m.WriterUsable()
	if ok || reason == "" {
		t.Fatalf("a read-only standby endpoint must fence writes with a reason: ok=%v reason=%q", ok, reason)
	}
	if m.Status().Writer.Role != RoleReader {
		t.Fatalf("role: %+v", m.Status().Writer)
	}
}

// TestFencedBeforeFirstProbe: configured multi-region replicas start read-only
// until the first cluster probe proves the writer endpoint is the current
// primary. Startup is the riskiest moment for split-brain, so fail closed.
func TestFencedBeforeFirstProbe(t *testing.T) {
	m := NewManager(topo(), &fakeProbe{}, nil)
	if ok, reason := m.WriterUsable(); ok || reason == "" {
		t.Fatalf("writes must be fenced until the first probe resolves: ok=%v reason=%q", ok, reason)
	}
	st := m.Status()
	if st.WritesUsable || st.Writer.Role != RoleUnknown {
		t.Fatalf("unprobed status must surface an unknown/fenced writer: %+v", st)
	}
}

// TestStatusShape: the surfaced status carries the topology, both nodes, the
// usable verdict, and the epoch — the health/metrics contract.
func TestStatusShape(t *testing.T) {
	ctx := context.Background()
	writer := &fakeProbe{p: Probe{Epoch: 3, WriterRegion: "us-east"}}
	reader := &fakeProbe{p: Probe{InRecovery: true, Epoch: 3, LagSeconds: 1.5}}
	m := NewManager(topo(), writer, reader).WithNow(func() time.Time { return time.Unix(1700000000, 0) })
	m.Refresh(ctx)
	st := m.Status()
	if st.Topology.Region != "us-east" || len(st.Topology.Regions) != 2 {
		t.Fatalf("topology: %+v", st.Topology)
	}
	if st.Reader == nil || st.Reader.LagSeconds != 1.5 || st.Reader.Role != RoleReader {
		t.Fatalf("reader status: %+v", st.Reader)
	}
	if !st.WritesUsable || st.HighestEpoch != 3 {
		t.Fatalf("status: %+v", st)
	}
}
