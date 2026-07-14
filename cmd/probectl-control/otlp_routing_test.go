// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

type captureBus struct {
	mu   sync.Mutex
	msgs []bus.Message
}

func (c *captureBus) Publish(_ context.Context, topic string, key, value []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.msgs = append(c.msgs, bus.Message{
		Topic: topic,
		Key:   append([]byte(nil), key...),
		Value: append([]byte(nil), value...),
	})
	return nil
}

func (*captureBus) Subscribe(context.Context, string, string, bus.Handler) error { return nil }
func (*captureBus) Close() error                                                 { return nil }

type otlpTestRouter struct {
	targets map[string]tenancy.Targets
}

func (r otlpTestRouter) TargetsFor(_ context.Context, tenantID string) (tenancy.Targets, error) {
	return r.targets[tenantID], nil
}

func (r otlpTestRouter) BusNamespaces(context.Context) ([]string, error) { return nil, nil }

func (r otlpTestRouter) BusNamespaceTenants(context.Context) (map[string]string, error) {
	return nil, nil
}

func withOTLPTestRouter(t *testing.T, r tenancy.Router) {
	t.Helper()
	prev := tenancy.CurrentRouter()
	tenancy.SetRouter(r)
	t.Cleanup(func() { tenancy.SetRouter(prev) })
}

func TestPublishOTLPBusRoutesThroughTenantBusNamespace(t *testing.T) {
	withOTLPTestRouter(t, otlpTestRouter{targets: map[string]tenancy.Targets{
		"t-a": {Model: tenancy.IsolationHybrid, BusNamespace: "tenant-a"},
	}})
	b := &captureBus{}

	if err := publishOTLPBus(context.Background(), b, bus.OTLPTracesTopic, "t-a", "span-1", []byte("payload")); err != nil {
		t.Fatal(err)
	}
	if len(b.msgs) != 1 {
		t.Fatalf("published %d messages, want 1", len(b.msgs))
	}
	if want := "probectl.tenant-a.otlp.traces"; b.msgs[0].Topic != want {
		t.Fatalf("topic = %q, want %q", b.msgs[0].Topic, want)
	}
	if got := string(b.msgs[0].Key); !strings.Contains(got, "t-a") {
		t.Fatalf("key = %q, want tenant-bucketed key containing t-a", got)
	}
}

func TestPublishOTLPBusFailsClosedOnInvalidTenantBusNamespace(t *testing.T) {
	withOTLPTestRouter(t, otlpTestRouter{targets: map[string]tenancy.Targets{
		"t-a": {Model: tenancy.IsolationHybrid, BusNamespace: "bad.namespace"},
	}})
	b := &captureBus{}

	err := publishOTLPBus(context.Background(), b, bus.OTLPMetricsTopic, "t-a", "metric-1", []byte("payload"))
	if err == nil || !strings.Contains(err.Error(), "route topic") {
		t.Fatalf("invalid namespace error = %v, want route-topic failure", err)
	}
	if len(b.msgs) != 0 {
		t.Fatalf("published %d messages with an invalid tenant namespace; want fail-closed zero", len(b.msgs))
	}
}
