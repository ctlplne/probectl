// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

// Topology + what-if API (S43, F40-full). GET /v1/topology serves the
// tenant's dependency graph (live, or AS IT WAS at ?at= — the versioned-graph
// contract); POST /v1/topology/whatif simulates a node/link failure and
// returns the predicted impact with its coverage/honesty block. The graph is
// fed by a consumer over the streams the control plane already receives
// (eBPF service edges, BGP events, device telemetry) plus path discoveries at
// save time. Tenant first, always: every read resolves the caller's tenant
// before touching the store (guardrail 1).

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
	devicev1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/device/v1"
	ebpfv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/store/ebpfstore"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

// WithTopology attaches the topology store backing /v1/topology and the
// what-if API. nil is a no-op (the endpoints report topology_running=false).
func (s *Server) WithTopology(st topology.Store) *Server {
	if st != nil {
		s.topo = st
		s.rebuildAnalyzer()
	}
	return s
}

// handleTopology serves GET /v1/topology[?at=RFC3339] — the caller's tenant's
// graph in the layout-agnostic viz shape, with the coverage block.
func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.topo == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"topology_running": false,
			"nodes":            []topology.VizNode{}, "edges": []topology.VizEdge{},
		})
		return nil
	}
	// No ?at → the LIVE graph (everything currently known); ?at → the graph
	// as it was at that instant (the versioned-graph contract).
	at, err := atParam(r, time.Time{})
	if err != nil {
		return err
	}
	graph, err := s.topo.ForTenant(tid)
	if err != nil {
		return apierror.Forbidden("tenant topology scope is invalid").Wrap(err)
	}
	var snap topology.Snapshot
	if at.IsZero() {
		snap = graph.Latest()
	} else {
		snap = graph.SnapshotAt(at)
	}
	viz := topology.ToViz(snap)
	writeJSON(w, http.StatusOK, map[string]any{
		"topology_running": true,
		"at":               snap.At.UTC(),
		"nodes":            viz.Nodes,
		"edges":            viz.Edges,
		"coverage":         topology.SnapshotCoverage(snap),
	})
	return nil
}

// whatIfRequest is the simulation request: the node or edge id to fail.
type whatIfRequest struct {
	Target string `json:"target"`
	At     string `json:"at,omitempty"` // RFC3339; empty = now
}

// handleWhatIf serves POST /v1/topology/whatif — predicted impact of failing
// one element. Read-only: it simulates on a copy and never mutates the graph
// (observe-only; acting on predictions is S-EE5, human-gated).
func (s *Server) handleWhatIf(w http.ResponseWriter, r *http.Request) error {
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	if s.topo == nil {
		return apierror.Unavailable("topology is not wired on this deployment")
	}
	var req whatIfRequest
	if err := decodeJSONLimit(r, 1<<16, &req); err != nil {
		return err
	}
	if req.Target == "" {
		return apierror.BadRequest("target (node or edge id) is required")
	}
	var at time.Time // zero = simulate over the live graph
	if req.At != "" {
		parsed, err := time.Parse(time.RFC3339, req.At)
		if err != nil {
			return apierror.BadRequest("at must be RFC3339")
		}
		at = parsed
	}
	// The SLO engine (S45) feeds SLO impact into the simulation when wired;
	// a typed-nil must become a nil INTERFACE so Simulate's checks behave.
	var sloSrc topology.SLOSource
	if s.sloEngine != nil {
		sloSrc = s.sloEngine
	}
	imp, err := topology.Simulate(s.topo, tid, req.Target, at, sloSrc)
	if err != nil {
		return apierror.NotFound(err.Error())
	}
	writeJSON(w, http.StatusOK, imp)
	return nil
}

// atParam parses ?at=RFC3339 with a default.
func atParam(r *http.Request, def time.Time) (time.Time, error) {
	raw := r.URL.Query().Get("at")
	if raw == "" {
		return def, nil
	}
	at, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, apierror.BadRequest("at must be RFC3339")
	}
	return at, nil
}

// TopologyConsumer folds the streams the control plane already receives into
// the dependency graph: eBPF service edges (S20/S21), BGP routing events
// (S14), and device telemetry (S39). Path discoveries fold in at save time
// (see handleDiscoverPath). Unscoped records are dropped (guardrail 1).
type TopologyConsumer struct {
	store   topology.Store
	bus     bus.Bus
	log     *slog.Logger
	binding pipeline.TenantBinding // TENANT-101; nil = unit tests
	clock   func() time.Time
	ledger  *topologyIntegrityLedger
	// ebpf is the durable eBPF aggregate store (ARCH-008). When set, every
	// verified service edge is also persisted, so the differentiator plane has
	// history and survives a restart instead of living only in the RAM graph.
	// nil = not wired (in-RAM graph only, the previous behavior).
	ebpf ebpfstore.Store
}

// WithEBPFStore wires durable persistence of eBPF service-edge aggregates
// (ARCH-008). nil keeps the in-RAM-only behavior.
func (tc *TopologyConsumer) WithEBPFStore(s ebpfstore.Store) *TopologyConsumer {
	tc.ebpf = s
	return tc
}

// NewTopologyConsumer builds the consumer over a non-nil store.
func NewTopologyConsumer(b bus.Bus, st topology.Store, log *slog.Logger) *TopologyConsumer {
	if log == nil {
		log = slog.Default()
	}
	return &TopologyConsumer{store: st, bus: b, log: log, clock: time.Now, ledger: newTopologyIntegrityLedger()}
}

// WithTenantBinding installs registry-backed tenant verification (TENANT-101)
// for the agent-published planes this view derives from. nil = unit tests.
func (tc *TopologyConsumer) WithTenantBinding(b pipeline.TenantBinding) *TopologyConsumer {
	tc.binding = b
	return tc
}

func (tc *TopologyConsumer) receivedAt() time.Time {
	if tc != nil && tc.clock != nil {
		return tc.clock()
	}
	return time.Now()
}

// rejectBatch verifies a batch's claimed identities and reports whether the
// batch must be dropped (fail closed) — counted, never silent.
func (tc *TopologyConsumer) rejectBatch(ctx context.Context, plane string, ids []pipeline.Identity) bool {
	if tc.binding == nil || len(ids) == 0 {
		return false
	}
	if _, _, err := pipeline.VerifyBatchTenant(ctx, tc.binding, "", ids); err != nil {
		tc.log.Error("REJECTED batch: tenant verification failed (TENANT-101, fail closed)",
			"view", "topology", "plane", plane, "claimed_tenant", ids[0].Tenant,
			"agent_id", ids[0].Agent, "error", err.Error())
		tc.ledger.addRejected(plane, 1)
		return true
	}
	return false
}

// Run subscribes until ctx is canceled. The topology graph is a pure in-RAM
// view, so it uses PER-REPLICA consumer groups (viewGroup) — each replica fans
// in the whole stream and builds the complete graph, making /v1/topology
// coherent at any replica count (ARCH-003).
func (tc *TopologyConsumer) Run(ctx context.Context) error {
	errc := make(chan error, 3)
	go func() { errc <- tc.bus.Subscribe(ctx, bus.EBPFFlowsTopic, viewGroup("topology-ebpf"), tc.handleEBPF) }()
	go func() { errc <- tc.bus.Subscribe(ctx, bus.BGPEventsTopic, viewGroup("topology-bgp"), tc.handleBGP) }()
	go func() {
		errc <- tc.bus.Subscribe(ctx, bus.DeviceMetricsTopic, viewGroup("topology-device"), tc.handleDevice)
	}()
	return <-errc
}

func (tc *TopologyConsumer) handleEBPF(ctx context.Context, msg bus.Message) error {
	tc.ledger.addReceived("ebpf", 1)
	var batch ebpfv1.FlowBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		tc.ledger.addMalformed("ebpf", 1)
		tc.log.Warn("topology: skipping malformed ebpf batch", "error", err)
		return nil
	}
	// Identity comes from the FLOWS (edges carry tenant only); every edge must
	// share the flows' tenant — a mixed batch is rejected as an injection
	// vector. An edges-only batch (no agent to verify) passes homogeneity
	// only; emitters always batch flows alongside edges in practice.
	ids := make([]pipeline.Identity, 0, len(batch.GetFlows()))
	for _, f := range batch.GetFlows() {
		ids = append(ids, pipeline.Identity{Tenant: f.GetTenantId(), Agent: f.GetAgentId()})
	}
	if tc.rejectBatch(ctx, "ebpf", ids) {
		return nil
	}
	// TENANT-006: an edges-only batch carries no agent id, so its tenant claim
	// is UNVERIFIABLE against the registry — a credential holder could forge a
	// foreign tenant on edges alone (the residual pooled-lane injection vector).
	// When registry verification is active (production), an edges-only batch
	// FAILS CLOSED. Emitters always batch flows alongside edges in practice, so
	// this rejects only the spoof shape, not legitimate traffic. (Unit tests
	// run with no binding and keep the prior in-RAM behavior.)
	if tc.binding != nil && len(ids) == 0 && len(batch.GetEdges()) > 0 {
		tc.ledger.addRejected("ebpf", 1)
		tc.log.Error("REJECTED batch: edges-only eBPF batch has no agent identity to verify (TENANT-006, fail closed)",
			"view", "topology", "plane", "ebpf", "edges", len(batch.GetEdges()),
			"claimed_tenant", batch.GetEdges()[0].GetTenantId())
		return nil
	}
	if len(ids) > 0 {
		for _, e := range batch.GetEdges() {
			if e.GetTenantId() != "" && e.GetTenantId() != ids[0].Tenant {
				tc.ledger.addRejected("ebpf", 1)
				tc.log.Error("REJECTED batch: edge tenant differs from flow tenant (TENANT-101, fail closed)",
					"view", "topology", "flow_tenant", ids[0].Tenant, "edge_tenant", e.GetTenantId())
				return nil
			}
		}
	}
	receivedAt := tc.receivedAt()
	var durable []ebpfstore.Edge
	for _, e := range batch.GetEdges() {
		if e.GetTenantId() == "" {
			tc.ledger.addUnscoped("ebpf", 1)
			continue
		}
		firstSeen, lastSeen := serviceEdgeTimes(e, receivedAt)
		graph, err := tc.store.ForTenant(e.GetTenantId())
		if err != nil {
			tc.ledger.addUnscoped("ebpf", 1)
			tc.log.Error("topology: rejecting ebpf edge with invalid tenant scope", "tenant_id", e.GetTenantId(), "error", err.Error())
			continue
		}
		graph.ObserveServiceEdge(topology.FromServiceEdge(e), firstSeen)
		if !lastSeen.Equal(firstSeen) {
			graph.ObserveServiceEdge(topology.FromServiceEdge(e), lastSeen)
		}
		if tc.ebpf != nil {
			durable = append(durable, ebpfstore.Edge{
				TenantID: e.GetTenantId(), AgentID: e.GetSource(),
				WindowStart: firstSeen.Truncate(time.Minute),
				SrcWorkload: e.GetSource(), DstWorkload: e.GetDestination(),
				DstPort: uint16(e.GetDestinationPort()), L7Protocol: e.GetL7Protocol(),
				Bytes: e.GetBytes(), Packets: e.GetPackets(), Connections: e.GetConnections(),
			})
		}
		tc.ledger.addStored("ebpf", 1)
	}
	// ARCH-008: persist the aggregates (best-effort — a store blip must not drop
	// the in-RAM graph update above; the durable copy backfills on the next batch).
	if tc.ebpf != nil && len(durable) > 0 {
		if err := tc.ebpf.Insert(ctx, durable); err != nil {
			tc.ledger.addPersistFailed("ebpf", uint64(len(durable)))
			tc.log.Warn("ebpf aggregate persist failed (in-RAM graph unaffected)", "error", err.Error())
		}
	}
	return nil
}

func (tc *TopologyConsumer) handleBGP(_ context.Context, msg bus.Message) error {
	tc.ledger.addReceived("bgp", 1)
	var ev bgpv1.BGPEvent
	if err := proto.Unmarshal(msg.Value, &ev); err != nil {
		tc.ledger.addMalformed("bgp", 1)
		tc.log.Warn("topology: skipping malformed bgp event", "error", err)
		return nil
	}
	if ev.GetTenantId() == "" {
		tc.ledger.addUnscoped("bgp", 1)
		return nil
	}
	graph, err := tc.store.ForTenant(ev.GetTenantId())
	if err != nil {
		tc.ledger.addUnscoped("bgp", 1)
		tc.log.Error("topology: rejecting bgp event with invalid tenant scope", "tenant_id", ev.GetTenantId(), "error", err.Error())
		return nil
	}
	at := pipeline.NormalizeEventTimeUnixNano(ev.GetDetectedAtUnixNano(), tc.receivedAt())
	graph.ObserveRouting(topology.FromBGPEvent(&ev), at)
	tc.ledger.addStored("bgp", 1)
	return nil
}

func (tc *TopologyConsumer) handleDevice(ctx context.Context, msg bus.Message) error {
	tc.ledger.addReceived("device", 1)
	var batch devicev1.DeviceMetricBatch
	if err := proto.Unmarshal(msg.Value, &batch); err != nil {
		tc.ledger.addMalformed("device", 1)
		tc.log.Warn("topology: skipping malformed device batch", "error", err)
		return nil
	}
	ids := make([]pipeline.Identity, 0, len(batch.GetMetrics()))
	for _, m := range batch.GetMetrics() {
		ids = append(ids, pipeline.Identity{Tenant: m.GetTenantId(), Agent: m.GetAgentId()})
	}
	if tc.rejectBatch(ctx, "device", ids) {
		return nil
	}
	receivedAt := tc.receivedAt()
	for _, m := range batch.GetMetrics() {
		if m.GetTenantId() == "" {
			tc.ledger.addUnscoped("device", 1)
			continue
		}
		if m.GetDeviceAddress() == "" {
			tc.ledger.addMalformed("device", 1)
			continue
		}
		graph, err := tc.store.ForTenant(m.GetTenantId())
		if err != nil {
			tc.ledger.addUnscoped("device", 1)
			tc.log.Error("topology: rejecting device metric with invalid tenant scope", "tenant_id", m.GetTenantId(), "error", err.Error())
			continue
		}
		// S39 telemetry exposes no interface IPs yet, so this yields device
		// nodes without device→hop links — surfaced as a coverage note by the
		// what-if API, never silently complete.
		graph.ObserveDevice(topology.DeviceInput{
			Address: m.GetDeviceAddress(),
			Name:    m.GetDeviceName(),
		}, pipeline.NormalizeEventTimeUnixNano(m.GetTimeUnixNano(), receivedAt))
		tc.ledger.addStored("device", 1)
	}
	return nil
}

func serviceEdgeTimes(e *ebpfv1.ServiceEdge, receivedAt time.Time) (time.Time, time.Time) {
	firstUnixNano := e.GetFirstSeenUnixNano()
	lastUnixNano := e.GetLastSeenUnixNano()
	switch {
	case firstUnixNano == 0 && lastUnixNano != 0:
		firstUnixNano = lastUnixNano
	case lastUnixNano == 0 && firstUnixNano != 0:
		lastUnixNano = firstUnixNano
	}
	firstSeen := pipeline.NormalizeEventTimeUnixNano(firstUnixNano, receivedAt)
	lastSeen := pipeline.NormalizeEventTimeUnixNano(lastUnixNano, receivedAt)
	if lastSeen.Before(firstSeen) {
		firstSeen, lastSeen = lastSeen, firstSeen
	}
	return firstSeen, lastSeen
}
