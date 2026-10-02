// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"io"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

// ING-03: the pooled network-results and RUM lanes once stored the tenant
// written in the message payload without comparing it to the bus key (the
// publisher was assumed trusted). On a shared Kafka/NATS bus any credential
// holder can write these topics, so a forged record keyed for one tenant but
// claiming another was filed under the victim. The consumer must bind these
// lanes to the KEY tenant (the authenticated producer identity) and reject a
// record whose payload tenant disagrees — counted on the tenant-rejected meter
// — so a credential for tenant A can never store a record under tenant B.
func TestPooledLaneRejectsPayloadTenantDisagreeingWithBusKey(t *testing.T) {
	pooled := []struct {
		name  string
		topic string
		key   []byte // what the authenticated producer's bus key resolves to
	}{
		// network results are keyed tenant|bucket by the control plane.
		{"network", bus.NetworkResultsTopic, bus.TenantKey("tenant-a", "agent-a1")},
		// RUM is keyed with the plain app-key tenant.
		{"rum", bus.RUMEventsTopic, []byte("tenant-a")},
	}
	for _, tc := range pooled {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			w := tsdb.NewMemory()
			c := NewConsumer(bus.NewMemory(), w, "test", logging.New(io.Discard, "error", "json"))
			lane := topicGroup{topic: tc.topic} // pooled: verify=false, laneTenant=""

			handle := func(payloadTenant string, key []byte) {
				t.Helper()
				raw, err := proto.Marshal(&resultv1.Result{
					TenantId: payloadTenant, AgentId: "agent-a1", CanaryType: "icmp", Success: true,
				})
				if err != nil {
					t.Fatal(err)
				}
				if err := c.handleLane(ctx, bus.Message{Topic: tc.topic, Key: key, Value: raw}, lane); err != nil {
					t.Fatalf("handleLane: %v", err)
				}
			}

			// Forged: key is tenant-a (the credential), payload claims tenant-b.
			before := c.rejectedTenant.Load()
			handle("tenant-b", tc.key)
			if got := c.rejectedTenant.Load() - before; got != 1 {
				t.Fatalf("forged key≠payload record: rejected delta=%d, want 1", got)
			}
			if n := len(w.Query("probectl_probe_success", map[string]string{"tenant_id": "tenant-b"})); n != 0 {
				t.Fatalf("forged record stored under victim tenant-b (%d series)", n)
			}
			if n := len(w.Snapshot()); n != 0 {
				t.Fatalf("forged record wrote %d series, want 0", n)
			}

			// An empty key (no authenticated tenant) also fails closed.
			before = c.rejectedTenant.Load()
			handle("tenant-a", nil)
			if got := c.rejectedTenant.Load() - before; got != 1 {
				t.Fatalf("empty-key record: rejected delta=%d, want 1", got)
			}

			// Legitimate: key and payload agree — stored under the key tenant.
			before = c.rejectedTenant.Load()
			handle("tenant-a", tc.key)
			if got := c.rejectedTenant.Load() - before; got != 0 {
				t.Fatalf("legitimate record rejected (delta=%d)", got)
			}
			got := w.Query("probectl_probe_success", map[string]string{"tenant_id": "tenant-a"})
			if len(got) != 1 {
				t.Fatalf("legitimate record: want 1 tenant-a series, got %d", len(got))
			}
		})
	}
}
