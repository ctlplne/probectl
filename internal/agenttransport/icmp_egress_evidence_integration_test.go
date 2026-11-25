// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package agenttransport_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestICMPEgressEvidenceRealMTLSKeepsTenantWitnessesIndependent(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	server := startTestServer(ctx, t, pool, func(s *agenttransport.Server) {
		s.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	})
	area, router, observationID := newUUID(t), newUUID(t), newUUID(t)
	var lanes [2]icmpWireLane
	var claims [2]entity.Observation
	for i := range lanes {
		lanes[i] = seedICMPWireLane(ctx, t, pool, server, area, router, func(d *testspec.ExecutableDefinition) {
			d.Target, d.Params["payload_bytes"] = "203.0.113.90", "56"
			d.Params[testspec.RoutingProbeHandoffParam] = newUUID(t)
			d.Params[testspec.RoutingProbePeerParam] = "192.0.2.1"
			d.Params[testspec.RoutingProbeInterfaceParam] = "enp2s0.20"
			d.Params[testspec.RoutingProbeSourceParam] = fmt.Sprintf("192.0.2.%d", i+10)
			d.Params[testspec.RoutingProbePeerMACParam] = fmt.Sprintf("02:01:02:03:04:%02x", i+10)
		})
	}
	var databaseTime time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&databaseTime); err != nil {
		t.Fatal(err)
	}
	// Use the same execution time after both bindings and certificate issues.
	// A sibling request must fail its ownership check even though its clock
	// fits both senders' issuance windows.
	start := time.Now().UTC()
	if databaseTime.After(start) {
		start = databaseTime.UTC()
	}
	end := start.Truncate(time.Microsecond).Add(1712 * time.Nanosecond)
	for i, lane := range lanes {
		claims[i] = icmpEgressClaim(t, lane, observationID, i, end)
		accepted, unresolved, err := lane.client.Submit(ctx, []entity.Observation{claims[i]})
		if err != nil || accepted != 1 || unresolved != 0 {
			t.Fatalf("tenant %d v4 witness not persisted: accepted %d unresolved %d err %v", i, accepted, unresolved, err)
		}
	}
	for i, lane := range lanes {
		verifyICMPEgressTenantRow(ctx, t, pool, lane, claims[i], lanes[1-i])
		borrowed := claims[1-i]
		borrowed.ID, borrowed.Source.AgentID = newUUID(t), lane.sender
		accepted, unresolved, err := lane.client.Submit(ctx, []entity.Observation{borrowed})
		if err != nil || accepted != 0 || unresolved != 1 {
			t.Fatalf("tenant %d borrowed sibling definition: accepted %d unresolved %d err %v", i, accepted, unresolved, err)
		}
	}
	mislabeled := claims[0]
	mislabeled.ID = newUUID(t)
	measurement, witness := *mislabeled.ICMP, *mislabeled.ICMP.Egress
	witness.PeerMAC = claims[1].ICMP.Egress.PeerMAC
	measurement.Egress, mislabeled.ICMP = &witness, &measurement
	if accepted, unresolved, err := lanes[0].client.Submit(ctx, []entity.Observation{mislabeled}); err != nil || accepted != 0 || unresolved != 1 {
		t.Fatalf("definition accepted a different first hop: accepted %d unresolved %d err %v", accepted, unresolved, err)
	}
	replay := claims[0]
	modified, samples := *replay.ICMP, *replay.ICMP.RoundTrips
	samples.ExecutionNanos++
	modified.RoundTrips, replay.ICMP = &samples, &modified
	if _, _, err := lanes[0].client.Submit(ctx, []entity.Observation{replay}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("same observation replaced the original execution: %v", err)
	}
}

func icmpEgressClaim(t *testing.T, lane icmpWireLane, observationID string, index int, end time.Time) entity.Observation {
	t.Helper()
	digest, err := testspec.DefinitionHash(lane.definition)
	if err != nil {
		t.Fatal(err)
	}
	measurement := &entity.ICMPMeasurement{
		Version: entity.ICMPVersionEgress, DefinitionHash: digest, StartedAt: end.Add(-time.Microsecond), CompletedAt: end,
		Requested: 3, Attempted: 3, Transmitted: 3, ReadComplete: true, Responders: []string{},
		RoundTrips: &entity.ICMPRoundTrips{Nanos: []uint64{}, ExecutionNanos: 1000},
		Egress: &entity.ICMPEgressWitness{Interface: "enp2s0.20", Source: fmt.Sprintf("192.0.2.%d", index+10),
			PeerMAC: fmt.Sprintf("02:01:02:03:04:%02x", index+10), Transmitted: 3},
	}
	if index == 1 {
		measurement.Replies, measurement.Responders = 2, []string{lane.definition.Target}
		measurement.RoundTrips.Nanos = []uint64{100, 120}
	}
	claim, err := (entity.Observation{ID: observationID, ObservedAt: end,
		Source:    entity.SourceKey{AgentID: lane.sender, Kind: entity.PathAgent, SourceRef: lane.definition.ID},
		Alias:     entity.AliasKey{Kind: entity.AddressAlias, Value: lane.definition.Target},
		SourceRef: "icmp:configured-test", ICMP: measurement}).Normalize(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

func verifyICMPEgressTenantRow(ctx context.Context, t *testing.T, pool *pgxpool.Pool, lane icmpWireLane,
	claim entity.Observation, sibling icmpWireLane) {
	t.Helper()
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(lane.tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		var body []byte
		var sender, serial string
		var indexClock time.Time
		if err := sc.Q.QueryRow(ctx, `SELECT icmp_measurement,agent_id,sender_serial,observed_at FROM entity_evidence
			WHERE tenant_id=$1 AND observation_id=$2`, lane.tenant, claim.ID).Scan(&body, &sender, &serial, &indexClock); err != nil {
			return err
		}
		var got entity.ICMPMeasurement
		if err := json.Unmarshal(body, &got); err != nil {
			return err
		}
		if !reflect.DeepEqual(&got, claim.ICMP) || sender != lane.sender || serial != lane.serial || !indexClock.Equal(claim.ObservedAt) {
			return fmt.Errorf("stored witness, original time or identity changed")
		}
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence WHERE tenant_id=$1 AND observation_id=$2`, sibling.tenant, claim.ID).Scan(&count); err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("sibling witness was visible under tenant scope")
		}
		var partialAccepted bool
		if err := sc.Q.QueryRow(ctx, `SELECT public.probectl_icmp_measurement_valid(
			jsonb_set($1::jsonb,'{egress,transmitted}','2'::jsonb),$2::inet)`, body, claim.Alias.Value).Scan(&partialAccepted); err != nil {
			return err
		}
		if partialAccepted {
			return fmt.Errorf("storage validator allowed an incomplete witness")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
