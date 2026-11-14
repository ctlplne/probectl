// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

// Actual TLS/application-role Postgres/RLS and served current-source reads;
// route originals are modeled authenticated fixtures, not physical-router proof.
func TestChangeEffectsServesExactOriginalsAndKeepsCurrentTenantSourceBoundary(t *testing.T) {
	f := newRoleExplanationAPIFixture(t)
	f.server.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	originals := map[string]change.Event{}
	for lane, tenant := range f.tenants {
		seedInternetRoutingView(t, f, tenant, uint32(64497+lane))
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permChangeRead, permFlowRead, permTestRead, "entities.read", "metrics.read", "events.read", permAIQuery} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			events, err := (store.ChangeEvents{}).List(ctx, sc, 200)
			if err != nil {
				return err
			}
			if len(events) != 1 || events[0].Routing == nil {
				t.Fatal("missing original router change")
			}
			originals[tenant] = events[0]
			return nil
		})
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	input := changeEffectsInput{From: time.Now().UTC().Add(-time.Hour), To: time.Now().UTC().Add(time.Minute)}
	read := func(tenant, id string) (int, []byte) {
		t.Helper()
		query := url.Values{"from": {input.From.Format(time.RFC3339Nano)}, "to": {input.To.Format(time.RFC3339Nano)}}
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, socket.URL+"/v1/changes/"+url.PathEscape(id)+"/effects?"+query.Encode(), nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, body
	}
	for _, tenant := range f.tenants {
		code, body := read(tenant, originals[tenant].ID)
		var result changeEffectsResponse
		if code != http.StatusOK || json.Unmarshal(body, &result) != nil || result.Original.Routing == nil || *result.Original.Routing != *originals[tenant].Routing || result.UnresolvedRoot || !result.Before.To.Equal(originals[tenant].OccurredAt) || !result.After.From.Equal(originals[tenant].OccurredAt) {
			t.Fatal("exact original comparison was unavailable or changed its source", code, string(body))
		}
		if result.Before.ObservedTotals != nil || result.After.ObservedTotals != nil || len(result.Tests) != 0 {
			t.Fatal("missing original measurements became invented counters or latency")
		}
	}
	seedInterfaceRoleMCPConsent(f)
	args := func(tenant string) map[string]any {
		return map[string]any{"change_id": originals[tenant].ID, "from": input.From, "to": input.To}
	}
	checkNative := func(tenant string, result changeEffectsResponse) {
		t.Helper()
		if result.ContractVersion != "probectl.change-effects.v1" || result.Original.TenantID != tenant || result.Original.ID != originals[tenant].ID || result.Original.Routing == nil || *result.Original.Routing != *originals[tenant].Routing || result.Before.ObservedTotals != nil || result.After.ObservedTotals != nil {
			t.Fatal("native comparison changed an exact original or invented counters")
		}
	}
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		for lane, tenant := range f.tenants {
			var result changeEffectsResponse
			call(tenant, "change_effects", args(tenant), &result, true)
			checkNative(tenant, result)
			spoofed := args(tenant)
			spoofed["tenant_id"] = f.tenants[1-lane]
			call(tenant, "change_effects", spoofed, nil, false)
			call(tenant, "change_effects", args(f.tenants[1-lane]), nil, false)
		}
	}
	cfg := &config.Config{AIRedactIPs: true, AIRedactHostnames: true, AIRedactPII: true}
	native := NewMCPServerWithPolicyLoader(cfg, f.server.log, f.pool, f.server.pathStore, 0, NewAIEgressGate(cfg, f.server.log, f.pool), nil, nil, f.server.MCPPolicyLoader(), f.server.aiSources())
	authenticator := NewMCPAuthenticator(f.pool, NewTenantStatusCache(f.pool, 0), false)
	streams := map[string]*interfaceRoleStdioClient{}
	const wire = "2026-07-28"
	for _, tenant := range f.tenants {
		stream := openInterfaceRoleStdio(t, native, authenticator, f.tokens[tenant], wire)
		streams[tenant] = stream
		var result changeEffectsResponse
		stream.call(t, wire, "change_effects", args(tenant), &result, true)
		checkNative(tenant, result)
	}
	a, b := f.tenants[0], f.tenants[1]
	if code, body := read(a, originals[b].ID); code == http.StatusOK || strings.Contains(string(body), originals[b].ID) {
		t.Fatal("another tenant's original was disclosed", code)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/changes", nil)
	request.Header.Set("Authorization", "Bearer "+f.tokens[a])
	actor := f.server.resolvePrincipal(request)
	if actor == nil {
		t.Fatal("missing current test user")
	}
	request = request.WithContext(auth.WithPrincipal(t.Context(), actor))
	scope := f.server.configEvidenceForRequest(request, permChangeRead, permFlowRead, permTestRead, "events.read")
	_, publication, err := f.server.computeChangeEffects(request.Context(), scope, originals[a].ID, input)
	if err != nil {
		t.Fatal(err)
	}
	defer publication.close()
	if err := publication.check(t.Context()); err != nil {
		t.Fatal("returning the read canceled publication admission", err)
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entity_source_contexts WHERE tenant_id=$1 AND agent_id='role-listener' AND source_kind='bmp_peer' AND source_ref='role-router'`, a)
		return err
	})
	if err := publication.check(t.Context()); err == nil {
		t.Fatal("late source removal published an original comparison")
	}
	if code, body := read(a, originals[a].ID); code == http.StatusOK || strings.Contains(string(body), originals[a].ID) {
		t.Fatal("removed original source remained available", code)
	}
	if code, body := read(b, originals[b].ID); code != http.StatusOK {
		t.Fatal("source removal crossed the tenant boundary", code, string(body))
	}
	streams[a].call(t, wire, "change_effects", args(a), nil, false)
	var sibling changeEffectsResponse
	streams[b].call(t, wire, "change_effects", args(b), &sibling, true)
	checkNative(b, sibling)
}

func TestChangeEffectsReadsCompleteOriginalRoundTripsThroughCurrentTenantStorage(t *testing.T) {
	f, _, graphs := seedDependencyGraphFixture(t)
	f.server.WithFlowStore(flowstore.NewMemory()).WithFairness(fairness.NewGate(fairness.DefaultPolicy(), nil))
	for lane, tenant := range f.tenants {
		node := graphs[tenant].Nodes[0]
		serial := strings.ReplaceAll(gouuid.NewString(), "-", "")
		if err := store.NewAgentIdentities(f.pool).Record(t.Context(), tenant, node.AgentID, crypto.EntitySPIFFEID(tenant, node.AgentID), serial, time.Now().Add(time.Hour), ""); err != nil {
			t.Fatal(err)
		}
		var definition testspec.ExecutableDefinition
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permChangeRead, permFlowRead, permTestRead, "events.read"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			var params []byte
			if err := sc.Q.QueryRow(ctx, `SELECT id::text,type,target,interval_seconds,timeout_seconds,params FROM tests WHERE tenant_id=$1 AND id=$2`, tenant, node.TestID).Scan(&definition.ID, &definition.Type, &definition.Target, &definition.IntervalSeconds, &definition.TimeoutSeconds, &params); err != nil {
				return err
			}
			return json.Unmarshal(params, &definition.Params)
		})
		digest, err := testspec.DefinitionHash(definition)
		if err != nil {
			t.Fatal(err)
		}
		probe, err := canary.NewICMP(canary.Config{Type: definition.Type, Target: definition.Target, Interval: time.Duration(definition.IntervalSeconds) * time.Second, Timeout: time.Duration(definition.TimeoutSeconds) * time.Second, Params: definition.Params})
		if err != nil {
			t.Fatal(err)
		}
		n := uint32(canary.ICMPRequestedPackets(probe))
		observe := func(sample uint64) {
			t.Helper()
			at := f.observedAt(tenant)
			rtts := make([]uint64, n)
			for i := range rtts {
				rtts[i] = sample
			}
			m := &entity.ICMPMeasurement{Version: 3, DefinitionHash: digest, StartedAt: at, CompletedAt: at, Requested: n, Attempted: n, Transmitted: n, Replies: n, ReadComplete: true, Responders: []string{definition.Target}, RoundTrips: &entity.ICMPRoundTrips{Nanos: rtts, ExecutionNanos: sample}}
			claim := entity.Observation{ID: gouuid.NewString(), Source: entity.SourceKey{AgentID: node.AgentID, Kind: entity.PathAgent, SourceRef: node.TestID}, Alias: entity.AliasKey{Kind: entity.AddressAlias, Value: definition.Target}, SourceRef: "icmp:configured-test", ObservedAt: at, ICMP: m}
			receipt, err := store.NewEntityRegistry(f.pool).WriteEvidenceBatchReceipt(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), node.AgentID, serial, []entity.Observation{claim})
			if err != nil || receipt.Accepted != 1 || receipt.ICMPMeasurements != 1 {
				t.Fatal("original RTT receipt was not retained", receipt, err)
			}
		}
		observe(uint64(1000 + lane))
		seedInternetRoutingView(t, f, tenant, uint32(64497+lane))
		observe(uint64(2000 + lane))
		var original change.Event
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			events, err := (store.ChangeEvents{}).List(ctx, sc, 200)
			if err == nil && len(events) == 1 {
				original = events[0]
			}
			return err
		})
		request := httptest.NewRequest(http.MethodGet, "/v1/changes", nil)
		request.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		actor := f.server.resolvePrincipal(request)
		request = request.WithContext(auth.WithPrincipal(t.Context(), actor))
		scope := f.server.configEvidenceForRequest(request, permChangeRead, permFlowRead, permTestRead, "events.read")
		result, publication, err := f.server.computeChangeEffects(request.Context(), scope, original.ID, changeEffectsInput{From: original.OccurredAt.Add(-time.Minute), To: f.observedAt(tenant).Add(time.Second)})
		if err != nil {
			t.Fatal("retained original comparison was unavailable", err)
		}
		if len(result.Tests) != 1 || result.Tests[0].TestID != node.TestID {
			t.Fatal("comparison lost its exact configured source", result.Tests)
		}
		for side, period := range []change.EffectTestPeriod{result.Tests[0].Before, result.Tests[0].After} {
			want := strconv.Itoa(1000*(side+1) + lane)
			if period.Latency == nil || period.Latency.MeanNanos != want || period.Latency.Samples != strconv.FormatUint(uint64(n), 10) || len(period.Observations) != 1 || period.Observations[0].RoundTrips == nil || len(period.Observations[0].RoundTrips.Nanos) != int(n) || period.LossRatio == nil || *period.LossRatio != "0" {
				t.Fatal("complete original RTTs/counters changed or crossed tenants", side, period)
			}
		}
		if err := publication.check(t.Context()); err != nil {
			t.Fatal(err)
		}
		publication.close()
	}
}
