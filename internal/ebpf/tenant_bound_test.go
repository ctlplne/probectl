// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
)

// TestFixtureCannotAssertForeignTenant is T-d8cff8f6's proof: the agent is
// bound to ONE tenant by its enrollment-rendered configuration, and a fixture
// (or any source) record asserting a different tenant is dropped before the
// bus — it can never ride this agent's identity into another tenant's data.
func TestFixtureCannotAssertForeignTenant(t *testing.T) {
	const bound, foreign = "tenant-a", "tenant-mallory"

	fixture := []map[string]any{
		{ // foreign assertion: must be REFUSED
			"tenant_id": foreign, "host": "h1",
			"source_address": "10.0.0.1", "source_port": 1111,
			"destination_address": "10.9.9.9", "destination_port": 9999,
			"network_transport": "tcp", "network_type": "ipv4",
			"bytes": 10, "packets": 1, "direction": "egress", "state": "established",
		},
		{ // explicit matching tenant: passes
			"tenant_id": bound, "host": "h1",
			"source_address": "10.0.0.1", "source_port": 2222,
			"destination_address": "10.2.2.2", "destination_port": 443,
			"network_transport": "tcp", "network_type": "ipv4",
			"bytes": 20, "packets": 2, "direction": "egress", "state": "established",
		},
		{ // recorded without a tenant: stamped with the bound identity
			"host":           "h1",
			"source_address": "10.0.0.1", "source_port": 3333,
			"destination_address": "10.3.3.3", "destination_port": 443,
			"network_transport": "tcp", "network_type": "ipv4",
			"bytes": 30, "packets": 3, "direction": "egress", "state": "established",
		},
	}
	raw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "flows.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

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
		TenantID:      bound,
		Host:          "h1",
		FixturePath:   path,
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
		if n >= 2 || time.Now().After(deadline) {
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
		if f.GetTenantId() != bound {
			t.Fatalf("flow with tenant %q reached the bus; only %q may", f.GetTenantId(), bound)
		}
		if f.GetDestinationPort() == 9999 {
			t.Fatalf("the foreign-tenant flow reached the bus: %+v", f)
		}
	}
	ports := map[uint32]bool{}
	for _, f := range flows {
		ports[f.GetSourcePort()] = true
	}
	if !ports[2222] || !ports[3333] {
		t.Fatalf("bound-tenant flows missing from the bus: got ports %v", ports)
	}
}
