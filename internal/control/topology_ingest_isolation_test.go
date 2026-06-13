// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/imfeelingtheagi/probectl/internal/store/ebpfstore"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

func t6Log() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// okBinding is a fake TenantBinding that VERIFIES anything — so the test proves
// the edges-only rejection comes from the missing agent identity (TENANT-006),
// not from a binding that happens to fail.
type okBinding struct{}

func (okBinding) Verify(_ context.Context, _, _ string) error { return nil }

// TENANT-006 red-team: an edges-only eBPF batch carries no agent id, so its
// tenant claim is unverifiable. With registry verification active (binding set,
// as in production), such a batch must be REJECTED fail-closed — a credential
// holder cannot forge a foreign tenant onto the pooled topology/eBPF planes via
// the edges-only path. A normal flows+edges batch still stores.
func TestEdgesOnlyEBPFBatchRejectedFailClosed(t *testing.T) {
	ctx := context.Background()
	topoStore := topology.NewMemoryStore()
	edges := ebpfstore.NewMemory()
	tc := NewTopologyConsumer(nil, topoStore, t6Log()).
		WithEBPFStore(edges).
		WithTenantBinding(okBinding{}) // production verification active

	// Forged edges-only batch: a foreign tenant on edges, no flows/agent.
	forged := &ebpfv1.FlowBatch{Edges: []*ebpfv1.ServiceEdge{{
		TenantId: "victim-tenant", Source: "evil", Destination: "svc-secret",
		DestinationPort: 443, L7Protocol: "http",
	}}}
	raw, err := proto.Marshal(forged)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := tc.handleEBPF(ctx, bus.Message{Value: raw}); err != nil {
		t.Fatalf("handleEBPF: %v", err)
	}

	// Nothing for the forged tenant landed — in the durable store nor the graph.
	if got, _ := edges.TopEdges(ctx, "victim-tenant", ebpfstore.EdgeQuery{}); len(got) != 0 {
		t.Fatalf("forged edges-only batch stored %d edges (CROSS-TENANT WRITE INJECTION)", len(got))
	}
	if snap := topoStore.Latest("victim-tenant"); len(snap.Edges) != 0 {
		t.Fatalf("forged edges-only batch wrote %d topology edges (injection)", len(snap.Edges))
	}

	// A legitimate flows+edges batch (the agent identity is present and
	// verifies) still stores normally — the rule rejects only the spoof shape.
	legit := &ebpfv1.FlowBatch{
		Flows: []*ebpfv1.Flow{{TenantId: "real-tenant", AgentId: "agent-1"}},
		Edges: []*ebpfv1.ServiceEdge{{TenantId: "real-tenant", Source: "a", Destination: "b",
			DestinationPort: 80, L7Protocol: "http"}},
	}
	rawLegit, _ := proto.Marshal(legit)
	if err := tc.handleEBPF(ctx, bus.Message{Value: rawLegit}); err != nil {
		t.Fatalf("handleEBPF legit: %v", err)
	}
	if got, _ := edges.TopEdges(ctx, "real-tenant", ebpfstore.EdgeQuery{}); len(got) != 1 {
		t.Fatalf("legit flows+edges batch stored %d edges, want 1", len(got))
	}
}
