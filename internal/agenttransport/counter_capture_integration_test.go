// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package agenttransport_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

type counterPublicationProbe struct {
	check     func(context.Context, bus.Message) error
	published int
}

func (p *counterPublicationProbe) Publish(ctx context.Context, topic string, key, value []byte) error {
	if err := p.check(ctx, bus.Message{Topic: topic, Key: key, Value: value}); err != nil {
		return err
	}
	p.published++
	return nil
}
func (*counterPublicationProbe) Subscribe(context.Context, string, string, bus.Handler) error {
	return nil
}
func (*counterPublicationProbe) Close() error { return nil }

// Real issued mTLS and application-role Postgres, with original typed wire
// bytes and an in-process publication observer. Physical SNMP/broker/history
// persistence and served billing acceptance remain separate.
func TestCounterWitnessRealMTLSBindsTwoTenantsBeforeRawPublication(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	server := startTestServer(ctx, t, pool, func(s *agenttransport.Server) { s.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil)) })
	area, router, sender := newUUID(t), newUUID(t), newUUID(t)
	type lane struct {
		tenant, serial string
		client         *agent.EvidenceClient
		input          entity.CounterCaptureInput
		metrics        []device.Metric
	}
	var lanes [2]lane
	for i := range lanes {
		tenant, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("counter-wire-%d-%d", i, time.Now().UnixNano()), "counter wire")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
				t.Error(err)
			}
		})
		var cert, key []byte
		var serial string
		for _, uri := range []string{crypto.AgentSPIFFEID(tenant.ID, sender), crypto.EntitySPIFFEID(tenant.ID, sender)} {
			cert, key, err = server.ca.IssueClientCert(sender, uri, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(cert)
			if block == nil {
				t.Fatal("missing fixture certificate")
			}
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			serial = leaf.SerialNumber.Text(16)
			if err := store.NewAgentIdentities(pool).Record(ctx, tenant.ID, sender, uri, serial, leaf.NotAfter, ""); err != nil {
				t.Fatal(err)
			}
		}
		bound := tenancy.WithTenant(ctx, tenancy.ID(tenant.ID))
		if err := tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (store.Agents{}).Register(ctx, sc, sender, "counter-agent", "192.0.2.1", "fixture", crypto.AgentSPIFFEID(tenant.ID, sender), nil); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'same site','same VRF')`, tenant.ID, area, newUUID(t), newUUID(t)); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','same router')`, tenant.ID, area, router); err != nil {
				return err
			}
			return store.NewEntityRegistry(pool).AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: sender, Kind: entity.DeviceTarget, SourceRef: "192.0.2.1"}, area, router)
		}); err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		client, err := agent.DialEntityEvidence(server.addr, writeTemp(t, dir, "evidence.crt", cert), writeTemp(t, dir, "evidence.key", key), server.caFile, "localhost")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		lanes[i] = lane{tenant: tenant.ID, serial: serial, client: client}
	}
	var at time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		t.Fatal(err)
	}
	at = at.Add(123 * time.Nanosecond)
	witnesses := store.NewDeviceCounterCaptures(pool)
	var first [2]entity.CounterCaptureReference
	for i := range lanes {
		l := &lanes[i]
		zero := uint32(0)
		l.input = entity.CounterCaptureInput{ConfiguredTarget: "192.0.2.1", PollStartedAt: at, PollCompletedAt: at.Add(time.Nanosecond), PointCount: 2}
		for _, name := range []string{device.MetricIfInOctets, device.MetricIfOutOctets} {
			l.metrics = append(l.metrics, device.Metric{TenantID: l.tenant, AgentID: sender, Device: "192.0.2.1", Source: device.SourceSNMP, IfIndex: 7, Name: name, At: at, ExactCounter: &device.CounterValue{Value: ^uint64(0) - uint64(i), Width: 64, UptimeTicks: zero, DiscontinuityTicks: zero, UptimeKnown: true, DiscontinuityKnown: true, PollStartedAt: at, PollCompletedAt: at.Add(time.Nanosecond)}})
		}
		probe := &counterPublicationProbe{check: func(ctx context.Context, msg bus.Message) error {
			if msg.Topic != bus.DeviceCountersTopic {
				t.Fatal("counter publication reached the legacy lane")
			}
			raw, err := device.ParseCounterBatch(ctx, l.tenant, msg.Value, 8<<20, 8<<20)
			if err != nil {
				return err
			}
			capture, err := witnesses.LookupWitness(tenancy.WithTenant(ctx, tenancy.ID(l.tenant)), sender, raw.Digest, raw.Input)
			if err != nil {
				return err
			}
			if capture.Scope != (entity.Scope{TenantID: l.tenant, ContextID: area}) || capture.DeviceID != router || capture.SenderSerial != l.serial || raw.Metrics[0].ExactCounter.Value != ^uint64(0)-uint64(i) {
				t.Fatal("raw bytes lost the certified tenant, canonical source or exact counter")
			}
			if first[i].Key == ([32]byte{}) {
				first[i] = capture.CounterCaptureReference
			} else if first[i] != capture.CounterCaptureReference {
				t.Fatal("retry changed original witness clock")
			}
			return nil
		}}
		emitter := device.NewBusEmitter(probe, l.tenant)
		if err := emitter.EmitCounters(ctx, l.metrics); err == nil || probe.published != 0 {
			t.Fatal("missing evidence channel published an unauthenticated raw batch")
		}
		emitter.WithCounterWitness(l.client)
		for range 2 {
			if err := emitter.EmitCounters(ctx, l.metrics); err != nil {
				t.Fatal("real counter witness failed before publication", err)
			}
		}
		if probe.published != 2 {
			t.Fatal("complete raw retry was lost")
		}
		emitter.WithCounterWitness(lanes[1-i].client)
		if err := emitter.EmitCounters(ctx, l.metrics); err == nil || probe.published != 2 {
			t.Fatal("foreign evidence channel published another tenant's counter bytes")
		}
	}
	if first[0].Key == first[1].Key {
		t.Fatal("same source identifiers crossed certified tenants")
	}
}
