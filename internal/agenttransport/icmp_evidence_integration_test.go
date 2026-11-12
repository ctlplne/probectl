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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsupport"
)

type icmpWireLane struct {
	tenant, sender, serial string
	definition             testspec.ExecutableDefinition
	client                 *agent.EvidenceClient
}

func seedICMPWireLane(ctx context.Context, t *testing.T, pool *pgxpool.Pool, server testServer, area, router string) icmpWireLane {
	t.Helper()
	tenant, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("icmp-wire-%d", time.Now().UnixNano()), "ICMP wire")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=$1`, tenant.ID); err != nil {
			t.Error(err)
		}
	})
	lane := icmpWireLane{tenant: tenant.ID, sender: newUUID(t), definition: testspec.ExecutableDefinition{ID: newUUID(t), Type: "icmp", Target: "127.0.0.1", IntervalSeconds: 30, TimeoutSeconds: 2, Params: map[string]string{"allow_private_targets": "true", "count": "3", "payload_bytes": "4096"}}}
	var cert, key []byte
	for _, uri := range []string{crypto.AgentSPIFFEID(lane.tenant, lane.sender), crypto.EntitySPIFFEID(lane.tenant, lane.sender)} {
		cert, key, err = server.ca.IssueClientCert(lane.sender, uri, time.Hour)
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
		lane.serial = leaf.SerialNumber.Text(16)
		if err := store.NewAgentIdentities(pool).Record(ctx, lane.tenant, lane.sender, uri, lane.serial, leaf.NotAfter, ""); err != nil {
			t.Fatal(err)
		}
	}
	bound := tenancy.WithTenant(ctx, tenancy.ID(lane.tenant))
	if err := tenancy.InTenant(bound, pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := (store.Agents{}).Register(ctx, sc, lane.sender, "icmp-agent", "127.0.0.1", "fixture", crypto.AgentSPIFFEID(lane.tenant, lane.sender), nil); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES($1,$2,$3,$4,'same site','same VRF')`, lane.tenant, area, newUUID(t), newUUID(t)); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES($1,$2,$3,'device','same router')`, lane.tenant, area, router); err != nil {
			return err
		}
		params, err := json.Marshal(lane.definition.Params)
		if err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,type,target,interval_seconds,timeout_seconds,params,enabled) VALUES($1,$2,'ICMP router','icmp',$3,30,2,$4::jsonb,true)`, lane.tenant, lane.definition.ID, lane.definition.Target, params); err != nil {
			return err
		}
		registry := store.NewEntityRegistry(pool)
		if err := registry.AssignPathTestContext(ctx, sc, lane.definition.ID, area); err != nil {
			return err
		}
		return registry.AssignEntitySource(ctx, sc, entity.SourceKey{AgentID: lane.sender, Kind: entity.PathAgent, SourceRef: lane.definition.ID}, area, router)
	}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	lane.client, err = agent.DialEntityEvidence(server.addr, writeTemp(t, dir, "evidence.crt", cert), writeTemp(t, dir, "evidence.key", key), server.caFile, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lane.client.Close() })
	return lane
}

func (lane icmpWireLane) observe(ctx context.Context, t *testing.T, id string) entity.Observation {
	t.Helper()
	definition := lane.definition
	probe, err := canary.NewICMP(canary.Config{Type: definition.Type, Target: definition.Target, Interval: time.Duration(definition.IntervalSeconds) * time.Second, Timeout: time.Duration(definition.TimeoutSeconds) * time.Second, Params: definition.Params})
	if err != nil {
		t.Fatal(err)
	}
	result, err := probe.Run(ctx)
	if err != nil {
		testsupport.SkipOrFatal(t, "real ICMP socket unavailable: %v", err)
	}
	m := result.ICMP
	if !result.Success || m == nil || !m.Complete() || m.Replies != m.Expected {
		t.Fatal("real source did not retain the configured echo batch", result.Error, m)
	}
	digest, err := testspec.DefinitionHash(definition)
	if err != nil {
		t.Fatal(err)
	}
	observation := entity.Observation{ID: id, Source: entity.SourceKey{AgentID: lane.sender, Kind: entity.PathAgent, SourceRef: definition.ID}, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: m.TargetIP}, SourceRef: "icmp:configured-test", ObservedAt: m.CompletedAt,
		ICMP: &entity.ICMPMeasurement{Version: 1, DefinitionHash: digest, StartedAt: m.StartedAt, CompletedAt: m.CompletedAt, Requested: uint32(m.Expected), Attempted: uint32(m.Attempted), Transmitted: uint32(m.Transmitted), Replies: uint32(m.Replies), SendErrors: uint32(m.SendErrors), ReadComplete: m.ReadComplete, Canceled: m.Canceled, IOFailed: m.IOFailed, Responders: m.Responders}}
	observation, err = observation.Normalize(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return observation
}

// Real socket -> existing evidence client -> issued mTLS listener -> app-role
// FORCE-RLS storage. The lab router-failure/notification/recovery proof is separate.
func TestICMPMeasurementRealMTLSKeepsCurrentDefinitionTenantAndReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	server := startTestServer(ctx, t, pool, func(s *agenttransport.Server) { s.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil)) })
	area, router, observationID := newUUID(t), newUUID(t), newUUID(t)
	lanes := []icmpWireLane{seedICMPWireLane(ctx, t, pool, server, area, router), seedICMPWireLane(ctx, t, pool, server, area, router)}
	claims := make([]entity.Observation, len(lanes))
	for i, lane := range lanes {
		claims[i] = lane.observe(ctx, t, observationID)
		for range 2 {
			accepted, unresolved, err := lane.client.Submit(ctx, []entity.Observation{claims[i]})
			if err != nil || accepted != 1 || unresolved != 0 {
				t.Fatal("real typed evidence or replay refused", accepted, unresolved, err)
			}
		}
	}
	for i, lane := range lanes {
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(lane.tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			var gotTenant, gotArea, gotRouter, gotSender, gotSerial string
			var body []byte
			if err := sc.Q.QueryRow(ctx, `SELECT tenant_id::text,context_id::text,entity_id::text,agent_id,sender_serial,icmp_measurement FROM entity_evidence WHERE observation_id=$1`, observationID).Scan(&gotTenant, &gotArea, &gotRouter, &gotSender, &gotSerial, &body); err != nil {
				return err
			}
			var got entity.ICMPMeasurement
			if err := json.Unmarshal(body, &got); err != nil {
				return err
			}
			if gotTenant != lane.tenant || gotArea != area || gotRouter != router || gotSender != lane.sender || gotSerial != lane.serial || !reflect.DeepEqual(&got, claims[i].ICMP) {
				return fmt.Errorf("typed measurement changed source, tenant, complete payload or clock")
			}
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence`).Scan(&count); err != nil {
				return err
			}
			if count != 1 {
				return fmt.Errorf("same-id source leaked or replay duplicated: %d", count)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	forged := lanes[0].observe(ctx, t, newUUID(t))
	forged.Source.SourceRef = lanes[1].definition.ID
	if accepted, unresolved, err := lanes[0].client.Submit(ctx, []entity.Observation{forged}); err != nil || accepted != 0 || unresolved != 1 {
		t.Fatal("foreign current test was borrowed", accepted, unresolved, err)
	}
	changed := claims[0]
	changed.ICMP = new(entity.ICMPMeasurement)
	*changed.ICMP = *claims[0].ICMP
	changed.ICMP.Replies--
	if _, _, err := lanes[0].client.Submit(ctx, []entity.Observation{changed}); status.Code(err) != codes.AlreadyExists {
		t.Fatal("same UUID changed stored ICMP metadata", err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(lanes[0].tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE tests SET params=jsonb_set(params,'{count}','"4"'::jsonb),updated_at=clock_timestamp() WHERE id=$1`, lanes[0].definition.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	stale := lanes[0].observe(ctx, t, newUUID(t)) // real old profile, captured AFTER the server changed
	if accepted, unresolved, err := lanes[0].client.Submit(ctx, []entity.Observation{stale}); err != nil || accepted != 0 || unresolved != 1 {
		t.Fatal("old definition authorized a new measurement", accepted, unresolved, err)
	}
	lanes[0].definition.Params["count"] = "4"
	fresh := lanes[0].observe(ctx, t, newUUID(t))
	if accepted, unresolved, err := lanes[0].client.Submit(ctx, []entity.Observation{fresh}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatal("current complete profile refused", accepted, unresolved, err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(lanes[0].tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_path_test_contexts WHERE test_id=$1`, lanes[0].definition.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	withdrawn := lanes[0].observe(ctx, t, newUUID(t))
	if accepted, unresolved, err := lanes[0].client.Submit(ctx, []entity.Observation{withdrawn}); err != nil || accepted != 0 || unresolved != 1 {
		t.Fatal("withdrawn context still authorized health evidence", accepted, unresolved, err)
	}
	healthySibling := lanes[1].observe(ctx, t, newUUID(t))
	if accepted, unresolved, err := lanes[1].client.Submit(ctx, []entity.Observation{healthySibling}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatal("healthy sibling inherited source withdrawal", accepted, unresolved, err)
	}
}
