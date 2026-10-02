// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

// AUTHZ-11 accompanying tenant-isolation test (guardrail 1, docs/guardrails.md
// G7-1): the secondary bus consumers that derive a tenant from a producer-set
// value on the shared pooled lane must not let one tenant's bus credentials
// forge a record under another tenant. In a strict profile the shared lane is
// refused outright, so an attacker publishing on it — whatever (tenant, agent)
// pair or message key it asserts — produces NO cross-tenant eBPF TLS posture row
// and NO cross-tenant BGP incident/SIEM export. Helpers are shared with
// authz11_secondary_consumer_strict_lane_test.go (same package).

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/siem"
	"github.com/ctlplne/probectl/internal/threat"
)

func TestAuthz11SecondaryConsumersIsolateForgedSharedLane(t *testing.T) {
	ctx := context.Background()

	// eBPF TLS posture: attacker holds agent-a (bound to tenant-a) and forges a
	// batch for the VICTIM on the shared lane. Strict mode refuses it — no
	// posture lands under either tenant.
	t.Run("ebpf_tls_posture", func(t *testing.T) {
		postures := threat.NewPostureStore(0)
		cs := NewEBPFTLSPostureConsumer(nil, postures, buildTLSAnalyzer(&config.Config{}), intelTestLog()).
			WithTenantBinding(ndrFakeBinding{"agent-a": "tenant-a"}).
			WithStrictTenantLanes(true)
		forged := mustAuthz11TLSBatch(t, "tenant-victim", "agent-a")
		if err := cs.handleLane(ctx, bus.Message{Value: forged}, ""); err != nil {
			t.Fatalf("handleLane: %v", err)
		}
		for _, tenant := range []string{"tenant-victim", "tenant-a"} {
			if got := postures.Len(tenant); got != 0 {
				t.Fatalf("forged shared-lane batch projected %d posture row(s) under %q; want 0", got, tenant)
			}
		}
	})

	// BGP incident: attacker forges the victim tenant in the message key on the
	// shared lane. Strict mode refuses it — no incident, no SIEM export.
	t.Run("bgp_incident", func(t *testing.T) {
		snk := &capSender{}
		fmtr, _ := siem.NewFormatter("cef")
		fw := siem.NewForwarder(fmtr, snk, siem.Config{BufferSize: 8, RetryBackoff: time.Millisecond}, testLog())
		fctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { _ = fw.Run(fctx); close(done) }()
		defer func() { cancel(); <-done }()

		store := incident.NewMemoryStore()
		cs := NewBGPIncidentConsumer(nil, incident.NewCorrelator(store, time.Hour, testLog()), testLog()).
			WithSIEM(fw).
			WithStrictTenantLanes(true)
		forged := mustAuthz11BGPEvent(t, "tenant-victim")
		if err := cs.handleLane(fctx, bus.Message{Key: bus.TenantKey("tenant-victim", "rrc00"), Value: forged}, ""); err != nil {
			t.Fatalf("handleLane: %v", err)
		}
		if open, err := store.OpenIncidents(fctx, "tenant-victim"); err != nil || len(open) != 0 {
			t.Fatalf("forged shared-lane BGP event correlated %d incident(s) (err=%v); want 0", len(open), err)
		}
		if got := len(snk.records()); got != 0 {
			t.Fatalf("forged shared-lane BGP event emitted %d SIEM record(s); want 0", got)
		}
	})
}
