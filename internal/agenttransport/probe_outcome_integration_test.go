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
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestConfiguredProbeOutcomeRealHTTPSMTLSKeepsTenantDefinitionHistoryAndReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	var responseCode atomic.Int32
	responseCode.Store(http.StatusOK)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(int(responseCode.Load())) }))
	t.Cleanup(target.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw})
	caDir := t.TempDir()
	caFile := writeTemp(t, caDir, "target-ca.crt", ca)
	canary.SetCAFileDir(caDir)
	t.Cleanup(func() { canary.SetCAFileDir("") })
	server := startTestServer(ctx, t, pool, func(s *agenttransport.Server) { s.WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil)) })
	area, router, observationID := newUUID(t), newUUID(t), newUUID(t)
	lanes := []icmpWireLane{seedICMPWireLane(ctx, t, pool, server, area, router), seedICMPWireLane(ctx, t, pool, server, area, router)}
	from := time.Now().UTC()
	in := func(lane int, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(lanes[lane].tenant)), pool, fn); err != nil {
			t.Fatal(err)
		}
	}
	for i := range lanes {
		lane := &lanes[i]
		lane.definition.Type = "http"
		lane.definition.Target = target.URL + "/health"
		lane.definition.Params = map[string]string{"allow_private_targets": "true", "ca_file": caFile, "expect_status": "200"}
		in(i, func(ctx context.Context, sc tenancy.Scope) error {
			params, err := json.Marshal(lane.definition.Params)
			if err != nil {
				return err
			}
			_, err = sc.Q.Exec(ctx, `UPDATE tests SET name='HTTPS application',type='http',target=$3,params=$4::jsonb,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, lane.tenant, lane.definition.ID, lane.definition.Target, params)
			if err != nil {
				return err
			}
			// Retargeting correctly withdraws the old context binding. Rebind
			// explicitly, then keep only the general test context: an HTTP
			// outcome does not acquire authority from a path trace.
			if err := store.NewEntityRegistry(pool).AssignPathTestContext(ctx, sc, lane.definition.ID, area); err != nil {
				return err
			}
			_, err = sc.Q.Exec(ctx, `DELETE FROM entity_path_test_contexts WHERE tenant_id=$1 AND test_id=$2`, lane.tenant, lane.definition.ID)
			return err
		})
	}
	observe := func(lane int, id string, wantSuccess bool) entity.Observation {
		t.Helper()
		definition := lanes[lane].definition
		probe, err := canary.NewHTTP(canary.Config{Type: definition.Type, Target: definition.Target, Timeout: time.Duration(definition.TimeoutSeconds) * time.Second, Params: definition.Params})
		if err != nil {
			t.Fatal(err)
		}
		result, err := probe.Run(ctx)
		if err != nil || result.Success != wantSuccess {
			t.Fatal("actual verified HTTPS outcome disagreed", result.Success, result.Error, err)
		}
		digest, err := testspec.DefinitionHash(definition)
		if err != nil {
			t.Fatal(err)
		}
		completed := result.StartedAt.Add(result.Duration)
		claim := entity.Observation{ID: id, Source: entity.SourceKey{AgentID: lanes[lane].sender, Kind: entity.PathAgent, SourceRef: definition.ID}, Alias: entity.AliasKey{Kind: entity.ConfiguredTestAlias, Value: definition.ID}, SourceRef: "probe:configured-test", ObservedAt: completed,
			Outcome: &entity.ProbeOutcome{Version: 1, DefinitionHash: digest, CanaryType: definition.Type, StartedAt: result.StartedAt, CompletedAt: completed, Success: result.Success}}
		claim, err = claim.Normalize(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return claim
	}
	claims := make([]entity.Observation, len(lanes))
	for i, lane := range lanes {
		claims[i] = observe(i, observationID, true)
		for range 2 {
			accepted, unresolved, err := lane.client.Submit(ctx, []entity.Observation{claims[i]})
			if err != nil || accepted != 1 || unresolved != 0 {
				t.Fatal("typed HTTPS outcome or exact replay refused", accepted, unresolved, err)
			}
		}
	}
	responseCode.Store(http.StatusServiceUnavailable)
	for i, lane := range lanes {
		resolved, err := store.NewEntityRegistry(pool).ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(lane.tenant)), entity.Scope{TenantID: lane.tenant, ContextID: area}, entity.AliasKey{Kind: entity.ConfiguredTestAlias, Value: lane.definition.ID})
		if err != nil || resolved.Status != entity.Resolved || resolved.EntityID != router {
			t.Fatal("current configured alias lost its owned source", resolved, err)
		}
		failed := observe(i, newUUID(t), false)
		accepted, unresolved, err := lane.client.Submit(ctx, []entity.Observation{failed})
		if err != nil || accepted != 1 || unresolved != 0 {
			t.Fatal("real failed application outcome was lost", accepted, unresolved, err)
		}
		in(i, func(ctx context.Context, sc tenancy.Scope) error {
			var gotTenant, gotArea, gotRouter, gotSender, gotSerial string
			var body []byte
			if err := sc.Q.QueryRow(ctx, `SELECT tenant_id::text,context_id::text,entity_id::text,agent_id,sender_serial,probe_outcome FROM entity_evidence WHERE observation_id=$1`, observationID).Scan(&gotTenant, &gotArea, &gotRouter, &gotSender, &gotSerial, &body); err != nil {
				return err
			}
			var outcome entity.ProbeOutcome
			if err := json.Unmarshal(body, &outcome); err != nil {
				return err
			}
			if gotTenant != lane.tenant || gotArea != area || gotRouter != router || gotSender != lane.sender || gotSerial != lane.serial || !reflect.DeepEqual(&outcome, claims[i].Outcome) {
				return fmt.Errorf("retained outcome changed tenant, source, original clock or body")
			}
			var count int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entity_evidence`).Scan(&count); err != nil {
				return err
			}
			if count != 2 {
				return fmt.Errorf("replay duplicated or sibling outcomes leaked: %d", count)
			}
			return nil
		})
		err = tenancy.InTenantReadSnapshot(tenancy.WithTenant(ctx, tenancy.ID(lane.tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			inputs := &store.IncidentImpactInputs{TenantID: lane.tenant, SourceGeneration: 1, Entities: []store.IncidentImpactEntity{{ContextID: area, EntityID: router, IncidentRoot: true}}}
			sources, err := (store.Incidents{}).ConfiguredImpactTestsInScope(ctx, sc, inputs, 1<<20, func(_ context.Context, c entity.ContextRecord, m store.IncidentImpactEntity, testID string) error {
				if c.TenantID != lane.tenant || c.ContextID != area || m.EntityID != router || testID != "" && testID != lane.definition.ID {
					return entity.ErrScopeMismatch
				}
				return nil
			})
			if err != nil {
				return err
			}
			if len(sources) != 1 || sources[0].Type != "http" {
				return fmt.Errorf("non-ICMP metadata required a path trace or borrowed another definition")
			}
			records, err := (store.Incidents{}).IncidentTestMeasurementsInScope(ctx, sc, sources, from, time.Now().UTC(), 1<<20)
			if err != nil {
				return err
			}
			good, bad := 0, 0
			for _, record := range records {
				if !record.Available || record.Outcome == nil || record.ICMP != nil {
					return fmt.Errorf("original configured outcome unavailable or relabelled")
				}
				if record.Outcome.Success {
					good++
				} else {
					bad++
				}
			}
			if len(records) != 2 || good != 1 || bad != 1 {
				return fmt.Errorf("historical outcome inventory changed: %d/%d/%d", len(records), good, bad)
			}
			return (store.Incidents{}).RecheckIncidentTestMeasurementsInScope(ctx, sc, records, 1<<20)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	forged := observe(0, newUUID(t), false)
	forged.Source.SourceRef = lanes[1].definition.ID
	forged.Alias.Value = lanes[1].definition.ID
	forged.Outcome.DefinitionHash, _ = testspec.DefinitionHash(lanes[1].definition)
	if accepted, unresolved, err := lanes[0].client.Submit(ctx, []entity.Observation{forged}); err != nil || accepted != 0 || unresolved != 1 {
		t.Fatal("foreign configured test was borrowed", accepted, unresolved, err)
	}
	changed := claims[0]
	outcome := *changed.Outcome
	outcome.Success = false
	changed.Outcome = &outcome
	if _, _, err := lanes[0].client.Submit(ctx, []entity.Observation{changed}); status.Code(err) != codes.AlreadyExists {
		t.Fatal("same UUID changed retained outcome", err)
	}
	in(0, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE tests SET params=jsonb_set(params,'{expect_status}','"503"'::jsonb),updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2`, lanes[0].tenant, lanes[0].definition.ID)
		return err
	})
	stale := observe(0, newUUID(t), false)
	if accepted, unresolved, err := lanes[0].client.Submit(ctx, []entity.Observation{stale}); err != nil || accepted != 0 || unresolved != 1 {
		t.Fatal("old definition authorized a newly captured outcome", accepted, unresolved, err)
	}
	lanes[0].definition.Params["expect_status"] = "503"
	fresh := observe(0, newUUID(t), true)
	if accepted, unresolved, err := lanes[0].client.Submit(ctx, []entity.Observation{fresh}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatal("current definition refused its actual outcome", accepted, unresolved, err)
	}
	in(0, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_test_contexts WHERE tenant_id=$1 AND test_id=$2`, lanes[0].tenant, lanes[0].definition.ID)
		return err
	})
	resolved, err := store.NewEntityRegistry(pool).ResolveAlias(tenancy.WithTenant(ctx, tenancy.ID(lanes[0].tenant)), entity.Scope{TenantID: lanes[0].tenant, ContextID: area}, entity.AliasKey{Kind: entity.ConfiguredTestAlias, Value: lanes[0].definition.ID})
	if err != nil || resolved.Status != entity.Unresolved {
		t.Fatal("withdrawn configured alias remained current", resolved, err)
	}
	withdrawn := observe(0, newUUID(t), true)
	if accepted, unresolved, err := lanes[0].client.Submit(ctx, []entity.Observation{withdrawn}); err != nil || accepted != 0 || unresolved != 1 {
		t.Fatal("withdrawn metadata context retained measurement authority", accepted, unresolved, err)
	}
	sibling := observe(1, newUUID(t), false)
	if accepted, unresolved, err := lanes[1].client.Submit(ctx, []entity.Observation{sibling}); err != nil || accepted != 1 || unresolved != 0 {
		t.Fatal("sibling inherited definition or source withdrawal", accepted, unresolved, err)
	}
	t.Log("real-integration: real verified HTTPS success/503, issued evidence mTLS, paired app-role PG/RLS typed retention/replay/history/current-definition/context withdrawal; public incident/SLO/customer and full sender lifecycle remain separate")
}
