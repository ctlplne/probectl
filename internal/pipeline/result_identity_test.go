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
	"github.com/ctlplne/probectl/internal/otel"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

// A result's free-form attributes must never override its identity: tenant_id
// is the TSDB isolation label (docs/guardrails.md G7-1), and a result's
// TenantId/AgentId come from the agent's mTLS identity or the lane, never from
// the attributes map the agent fills in. An agent of tenant-a that sets
// probectl.tenant.id=tenant-b must still write only tenant-a series, on every
// result lane the consumer reads.
func TestResultAttributesCannotOverrideIdentityOnAnyLane(t *testing.T) {
	ns, err := bus.TopicFor("t-a", bus.NetworkResultsTopic)
	if err != nil {
		t.Fatal(err)
	}
	lanes := []struct {
		name string
		lane topicGroup
	}{
		{"network", topicGroup{topic: bus.NetworkResultsTopic}},
		{"endpoint", topicGroup{topic: bus.EndpointResultsTopic, verify: true}},
		{"rum", topicGroup{topic: bus.RUMEventsTopic}},
		{"namespaced", topicGroup{topic: ns, laneTenant: "tenant-a"}},
	}
	for _, tc := range lanes {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			w := tsdb.NewMemory()
			c := NewConsumer(bus.NewMemory(), w, "test", logging.New(io.Discard, "error", "json")).
				WithTenantBinding(&fakeBinding{pairs: map[[2]string]bool{{"tenant-a", "agent-a1"}: true}})

			raw, err := proto.Marshal(&resultv1.Result{
				TenantId:   "tenant-a",
				AgentId:    "agent-a1",
				CanaryType: "icmp",
				Success:    true,
				Attributes: map[string]string{
					otel.AttrTenantID:   "tenant-b",
					otel.AttrAgentID:    "agent-b1",
					otel.AttrCanaryType: "http",
					otel.AttrTestID:     "test-1",
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			msg := bus.Message{Topic: tc.lane.topic, Key: []byte("tenant-a"), Value: raw}
			if err := c.handleLane(ctx, msg, tc.lane); err != nil {
				t.Fatalf("handleLane: %v", err)
			}

			if got := w.Query("probectl_probe_success", map[string]string{"tenant_id": "tenant-b"}); len(got) != 0 {
				t.Fatalf("tenant-a result stored under tenant-b: %v", got[0].Labels)
			}
			for _, s := range w.Snapshot() {
				if s.Labels["tenant_id"] != "tenant-a" || s.Labels["agent_id"] != "agent-a1" || s.Labels["canary_type"] != "icmp" {
					t.Fatalf("identity label taken from attributes: %s %v", s.Metric, s.Labels)
				}
			}
			got := w.Query("probectl_probe_success", map[string]string{"tenant_id": "tenant-a"})
			if len(got) != 1 {
				t.Fatalf("want 1 tenant-a success series, got %d", len(got))
			}
			if got[0].Labels["test_id"] != "test-1" {
				t.Fatalf("non-identity attribute lost: %v", got[0].Labels)
			}
		})
	}
}
