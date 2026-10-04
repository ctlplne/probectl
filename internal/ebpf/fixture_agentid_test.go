// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
)

// TestFixtureFlowStampedWithRunningCollectorIdentity is RTP-17's proof. The
// bundled recorded fixture (testdata/flows.json) carries a BAKED agent_id; a
// real collector's registered identity is a different id. The agent is bound to
// its own enrolled identity, so — exactly as it forces tenant_id — it must
// stamp its OWN registered agent_id onto every observed flow, overwriting the
// foreign baked one. Keeping the baked id made the control plane reject the
// whole batch ("agent not found": the (tenant_id, agent_id) pair is verified
// against the tenant's registry and the baked id is not in it) unless an
// operator hand-inserted that fixed id. No live kernel — the recorded-fixture
// path, driven through New()+Run() to the bus the control plane consumes.
func TestFixtureFlowStampedWithRunningCollectorIdentity(t *testing.T) {
	const (
		// boundTenant matches the tenant baked into testdata/flows.json so the
		// tenant guard passes and the flows are observed, not rejected.
		boundTenant = "00000000-0000-0000-0000-000000000001"
		// bakedAgentID is the agent_id baked into testdata/flows.json — foreign
		// to the collector running this agent.
		bakedAgentID = "00000000-0000-0000-0000-000000000101"
		// runningAgentID is the collector's OWN registered identity (what
		// register-collector minted and the registry knows).
		runningAgentID = "e1b3987a-3dbf-4458-8726-9db9224c7af6"
	)

	mem := bus.NewMemory()
	defer mem.Close()

	var (
		mu    sync.Mutex
		flows []*ebpfv1.Flow
	)
	subCtx, subCancel := context.WithCancel(context.Background())
	defer subCancel()
	go func() {
		_ = mem.Subscribe(subCtx, bus.EBPFFlowsTopic, "test", func(_ context.Context, m bus.Message) error {
			var batch ebpfv1.FlowBatch
			if err := proto.Unmarshal(m.Value, &batch); err != nil {
				t.Errorf("decode batch: %v", err)
				return nil
			}
			mu.Lock()
			flows = append(flows, batch.GetFlows()...)
			mu.Unlock()
			return nil
		})
	}()
	if !mem.WaitForSubscribers(context.Background(), bus.EBPFFlowsTopic, 1) {
		t.Fatal("subscriber never attached")
	}

	cfg := &Config{
		APIVersion:    ConfigAPIVersion,
		TenantID:      boundTenant,
		AgentID:       runningAgentID, // the running collector's registered id
		Host:          "node-9",       // distinct from identity to prove agent_id, not host, is stamped
		FixturePath:   "testdata/flows.json",
		FlushInterval: 10 * time.Millisecond,
		Bus:           BusConfig{Mode: "memory"},
	}
	agent, err := New(cfg, mem, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := agent.Run(runCtx); err != nil {
		t.Fatalf("agent run: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(flows)
		mu.Unlock()
		if n >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(flows) == 0 {
		t.Fatal("no flows reached the bus")
	}
	for _, f := range flows {
		if got := f.GetAgentId(); got != runningAgentID {
			t.Fatalf("flow reached the bus with agent_id %q, want the running collector id %q (the baked fixture id %q must be overwritten, not survive)",
				got, runningAgentID, bakedAgentID)
		}
		if f.GetTenantId() != boundTenant {
			t.Fatalf("flow tenant = %q, want %q", f.GetTenantId(), boundTenant)
		}
	}
}
