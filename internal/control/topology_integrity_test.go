// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/imfeelingtheagi/probectl/internal/metrics"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/store/ebpfstore"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

type denyTopologyBinding struct{}

func (denyTopologyBinding) Verify(context.Context, string, string) error {
	return pipeline.ErrTenantNotBound
}

type allowTopologyBinding struct{}

func (allowTopologyBinding) Verify(context.Context, string, string) error { return nil }

type failingTopologyEBPFStore struct{}

func (failingTopologyEBPFStore) Insert(context.Context, []ebpfstore.Edge) error {
	return errors.New("fixture persist failure")
}

func (failingTopologyEBPFStore) TopEdges(context.Context, string, ebpfstore.EdgeQuery) ([]ebpfstore.Edge, error) {
	return nil, nil
}

func (failingTopologyEBPFStore) DeleteTenant(context.Context, string) (int64, error) { return 0, nil }

func (failingTopologyEBPFStore) Close() error { return nil }

func TestTopologyIntegrityCountsMalformedInputs(t *testing.T) {
	ctx := context.Background()
	reg := metrics.New("test", "abc")
	tc := NewTopologyConsumer(nil, topology.NewMemoryStore(), t6Log()).WithMetrics(reg)
	garbage := bus.Message{Value: []byte{0xff, 0xff, 0xff}}

	if err := tc.handleEBPF(ctx, garbage); err != nil {
		t.Fatalf("malformed ebpf must not error stream: %v", err)
	}
	if err := tc.handleBGP(ctx, garbage); err != nil {
		t.Fatalf("malformed bgp must not error stream: %v", err)
	}
	if err := tc.handleDevice(ctx, garbage); err != nil {
		t.Fatalf("malformed device must not error stream: %v", err)
	}

	stats := tc.IntegrityStats()
	if stats.EBPF.Received != 1 || stats.EBPF.Malformed != 1 || stats.EBPF.Stored != 0 {
		t.Fatalf("ebpf stats = %+v, want received=1 malformed=1 stored=0", stats.EBPF)
	}
	if stats.BGP.Received != 1 || stats.BGP.Malformed != 1 || stats.BGP.Stored != 0 {
		t.Fatalf("bgp stats = %+v, want received=1 malformed=1 stored=0", stats.BGP)
	}
	if stats.Device.Received != 1 || stats.Device.Malformed != 1 || stats.Device.Stored != 0 {
		t.Fatalf("device stats = %+v, want received=1 malformed=1 stored=0", stats.Device)
	}
	for _, name := range []string{
		"probectl_topology_ebpf_malformed_total",
		"probectl_topology_bgp_malformed_total",
		"probectl_topology_device_malformed_total",
	} {
		if got := reg.Counter(name, "").Value(); got != 1 {
			t.Fatalf("%s = %d, want 1", name, got)
		}
	}
}

func TestTopologyIntegrityCountsRejectedInputs(t *testing.T) {
	ctx := context.Background()
	reg := metrics.New("test", "abc")
	tc := NewTopologyConsumer(nil, topology.NewMemoryStore(), t6Log()).
		WithMetrics(reg).
		WithTenantBinding(denyTopologyBinding{})

	ebpfGood := &ebpfv1.FlowBatch{
		Flows: []*ebpfv1.Flow{{TenantId: "tenant-a", AgentId: "agent-1"}},
		Edges: []*ebpfv1.ServiceEdge{{
			TenantId: "tenant-a", Source: "api", Destination: "db", DestinationPort: 5432,
		}},
	}
	if err := tc.handleEBPF(ctx, bus.Message{Value: mustTopologyProto(t, ebpfGood)}); err != nil {
		t.Fatalf("tenant-rejected ebpf must not error stream: %v", err)
	}

	deviceGood := &devicev1.DeviceMetricBatch{Metrics: []*devicev1.DeviceMetric{{
		TenantId: "tenant-a", AgentId: "agent-1", DeviceAddress: "10.0.0.9",
	}}}
	if err := tc.handleDevice(ctx, bus.Message{Value: mustTopologyProto(t, deviceGood)}); err != nil {
		t.Fatalf("tenant-rejected device must not error stream: %v", err)
	}

	tc.WithTenantBinding(allowTopologyBinding{})
	edgesOnly := &ebpfv1.FlowBatch{Edges: []*ebpfv1.ServiceEdge{{
		TenantId: "tenant-a", Source: "api", Destination: "db", DestinationPort: 5432,
	}}}
	if err := tc.handleEBPF(ctx, bus.Message{Value: mustTopologyProto(t, edgesOnly)}); err != nil {
		t.Fatalf("edges-only rejected ebpf must not error stream: %v", err)
	}

	mixedTenant := &ebpfv1.FlowBatch{
		Flows: []*ebpfv1.Flow{{TenantId: "tenant-a", AgentId: "agent-1"}},
		Edges: []*ebpfv1.ServiceEdge{{
			TenantId: "tenant-b", Source: "api", Destination: "db", DestinationPort: 5432,
		}},
	}
	if err := tc.handleEBPF(ctx, bus.Message{Value: mustTopologyProto(t, mixedTenant)}); err != nil {
		t.Fatalf("mixed-tenant rejected ebpf must not error stream: %v", err)
	}

	stats := tc.IntegrityStats()
	if stats.EBPF.Rejected != 3 || stats.EBPF.Stored != 0 {
		t.Fatalf("ebpf rejected stats = %+v, want rejected=3 stored=0", stats.EBPF)
	}
	if stats.Device.Rejected != 1 || stats.Device.Stored != 0 {
		t.Fatalf("device rejected stats = %+v, want rejected=1 stored=0", stats.Device)
	}
	if got := reg.Counter("probectl_topology_ebpf_rejected_total", "").Value(); got != 3 {
		t.Fatalf("ebpf rejected metric = %d, want 3", got)
	}
	if got := reg.Counter("probectl_topology_device_rejected_total", "").Value(); got != 1 {
		t.Fatalf("device rejected metric = %d, want 1", got)
	}
}

func TestTopologyIntegrityCountsUnscopedPersistFailedAndStored(t *testing.T) {
	ctx := context.Background()
	reg := metrics.New("test", "abc")
	tc := NewTopologyConsumer(nil, topology.NewMemoryStore(), t6Log()).
		WithEBPFStore(failingTopologyEBPFStore{}).
		WithMetrics(reg)
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

	ebpfBatch := &ebpfv1.FlowBatch{Edges: []*ebpfv1.ServiceEdge{
		{Source: "no-tenant", Destination: "db", DestinationPort: 5432},
		{
			TenantId: "tenant-a", Source: "api", Destination: "db", DestinationPort: 5432,
			FirstSeenUnixNano: at.UnixNano(),
		},
	}}
	if err := tc.handleEBPF(ctx, bus.Message{Value: mustTopologyProto(t, ebpfBatch)}); err == nil {
		t.Fatal("durable eBPF persist failure must return an error so the bus does not acknowledge the original batch")
	}

	if err := tc.handleBGP(ctx, bus.Message{Value: mustTopologyProto(t, &bgpv1.BGPEvent{
		Prefix: "198.51.100.0/24",
	})}); err != nil {
		t.Fatalf("unscoped bgp: %v", err)
	}
	if err := tc.handleBGP(ctx, bus.Message{Value: mustTopologyProto(t, &bgpv1.BGPEvent{
		TenantId: "tenant-a", Prefix: "198.51.100.0/24", NewOriginAsn: 64500,
	})}); err != nil {
		t.Fatalf("stored bgp: %v", err)
	}

	deviceBatch := &devicev1.DeviceMetricBatch{Metrics: []*devicev1.DeviceMetric{
		{DeviceAddress: "10.0.0.1"},
		{TenantId: "tenant-a"},
		{TenantId: "tenant-a", DeviceAddress: "10.0.0.9", DeviceName: "edge-r1"},
	}}
	if err := tc.handleDevice(ctx, bus.Message{Value: mustTopologyProto(t, deviceBatch)}); err != nil {
		t.Fatalf("device mixed integrity batch: %v", err)
	}

	stats := tc.IntegrityStats()
	if stats.EBPF.Stored != 1 || stats.EBPF.Unscoped != 1 || stats.EBPF.PersistFailed != 1 {
		t.Fatalf("ebpf stats = %+v, want stored=1 unscoped=1 persist_failed=1", stats.EBPF)
	}
	if stats.BGP.Stored != 1 || stats.BGP.Unscoped != 1 {
		t.Fatalf("bgp stats = %+v, want stored=1 unscoped=1", stats.BGP)
	}
	if stats.Device.Stored != 1 || stats.Device.Unscoped != 1 || stats.Device.Malformed != 1 {
		t.Fatalf("device stats = %+v, want stored=1 unscoped=1 malformed=1", stats.Device)
	}
	if got := reg.Counter("probectl_topology_ebpf_persist_failed_total", "").Value(); got != 1 {
		t.Fatalf("ebpf persist_failed metric = %d, want 1", got)
	}
	if got := reg.Counter("probectl_topology_bgp_unscoped_total", "").Value(); got != 1 {
		t.Fatalf("bgp unscoped metric = %d, want 1", got)
	}
	if got := reg.Counter("probectl_topology_device_stored_total", "").Value(); got != 1 {
		t.Fatalf("device stored metric = %d, want 1", got)
	}
}

func mustTopologyProto(t *testing.T, msg proto.Message) []byte {
	t.Helper()
	raw, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}
