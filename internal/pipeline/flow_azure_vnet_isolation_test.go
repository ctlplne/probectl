// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build isolation

package pipeline

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/flow/cloudflow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/testsupport"
)

type azureVNetFixtureLane struct {
	bus.Bus
	consumer *FlowConsumer
	lanes    map[string]string
}

func (b azureVNetFixtureLane) Publish(ctx context.Context, topic string, key, value []byte) error {
	tenant := b.lanes[topic]
	if tenant == "" || bus.TenantFromKey(key) != tenant {
		return fmt.Errorf("unexpected flow lane %q", topic)
	}
	return b.consumer.handleLane(ctx, bus.Message{Key: key, Value: value}, topic, tenant)
}

func TestAzureVNetFlowCollectorKeepsOverlappingTenantFlowsSeparate(t *testing.T) {
	endpoint := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if endpoint == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL is required for Azure VNet flow isolation")
	}
	store, err := flowstore.NewClickHouse(endpoint, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	red, blue := uuid.NewString(), uuid.NewString()
	consumer := NewFlowConsumer(bus.NewMemory(), store, nil, testLogger()).WithStrictTenantLanes(true)
	fixtureBus := azureVNetFixtureLane{consumer: consumer, lanes: make(map[string]string)}
	const agent = "same-vnet-collector"
	for i, tenant := range []string{red, blue} {
		namespace := "azure-vnet-proof-" + tenant
		topic, err := bus.TopicFor(namespace, bus.FlowEventsTopic)
		if err != nil {
			t.Fatal(err)
		}
		fixtureBus.lanes[topic] = tenant
		emitter, err := flow.NewNamespacedBusEmitter(fixtureBus, tenant, namespace)
		if err != nil {
			t.Fatal(err)
		}
		other := []string{blue, red}[i]
		tuple := fmt.Sprintf("%d,10.0.0.4,192.0.2.20,5000,443,6,O,E,NX,1,%d,2,%d", now.Unix(), 100*(i+1), 800*(i+1))
		payload := fmt.Sprintf(`{"records":[{"category":"FlowLogFlowEvent","flowLogVersion":4,"tenant_id":%q,
                  "targetResourceID":"/subscriptions/demo/providers/Microsoft.Network/virtualNetworks/shared",
                  "flowRecords":{"flows":[{"flowGroups":[{"flowTuples":[%q]}]}]}}]}`, other, tuple)
		if n, bad, err := cloudflow.Emit(t.Context(), cloudflow.ProviderAzureVNet, tenant, agent, strings.NewReader(payload), emitter); err != nil || bad != 0 || n != 2 {
			t.Fatalf("collector for tenant %d emitted %d, malformed %d, error %v", i, n, bad, err)
		}
		t.Cleanup(func() {
			ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			if _, err := store.DeleteTenant(ctx, tenant); err != nil {
				t.Error(err)
			}
		})
	}
	for i, tenant := range []string{red, blue} {
		rows, err := store.TopTalkers(t.Context(), flowstore.TopQuery{
			TenantID: tenant, Now: now.Add(time.Minute), Window: time.Hour, By: flowstore.BySrc, Limit: 5,
		})
		if err != nil || len(rows) != 2 || rows[0].Key != "192.0.2.20" || rows[0].Bytes != uint64(800*(i+1)) ||
			rows[1].Key != "10.0.0.4" || rows[1].Bytes != uint64(100*(i+1)) {
			t.Fatalf("tenant %d read foreign or misattributed traffic: %+v, %v", i, rows, err)
		}
	}
}
