// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package agenttransport_test

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/a2a"
	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsync"
)

// TestFetchTestBundleTenantIsolationOverMTLS is the G9 end-to-end isolation
// proof on the real wire (docs/guardrails.md G7-1, G7-4): two tenants, one agent
// each, real Postgres under RLS, real mTLS. Each agent pulls ONLY its own
// tenant's tests, in a bundle that verifies against the deployment key and names
// its own tenant; every create/update/delete moves the version and the
// heartbeat nudges an agent that is behind.
func TestFetchTestBundleTenantIsolationOverMTLS(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	src, err := testsync.NewSource(pool, priv)
	if err != nil {
		t.Fatal(err)
	}
	broker := a2a.NewBroker()
	ts := startTestServerWithBroker(ctx, t, pool, broker, func(s *agenttransport.Server) { s.WithTestBundles(src) })

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	ta, err := store.NewTenants(pool).Create(ctx, "tb-a-"+sfx, "TB A")
	if err != nil {
		t.Fatal(err)
	}
	tb, err := store.NewTenants(pool).Create(ctx, "tb-b-"+sfx, "TB B")
	if err != nil {
		t.Fatal(err)
	}
	mk := func(tenant, name, target string) string {
		var id string
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, s tenancy.Scope) error {
			tt, err := (store.Tests{}).Create(ctx, s, store.TestInput{Name: name, Type: "http", Target: target,
				IntervalSeconds: 30, TimeoutSeconds: 5, Enabled: true})
			if err != nil {
				return err
			}
			id = tt.ID
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	idA := mk(ta.ID, "a", "https://a.example.com")
	idB := mk(tb.ID, "b", "https://b.example.com")

	clientA, agentA := agentClient(ctx, t, ts, ta.ID)
	clientB, agentB := agentClient(ctx, t, ts, tb.ID)
	rpcCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	reg, err := clientA.Register(rpcCtx, &agentv1.RegisterRequest{Hostname: "a", AgentVersion: "0.0.0-dev"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(reg.GetServerCapabilities(), "agent.fetch_test_bundle.v1") || reg.GetConfigEpoch() != 2 {
		t.Fatalf("register = caps %v epoch %d; want the pull capability and the tenant's version 2",
			reg.GetServerCapabilities(), reg.GetConfigEpoch())
	}
	if _, err := clientB.Register(rpcCtx, &agentv1.RegisterRequest{Hostname: "b", AgentVersion: "0.0.0-dev"}); err != nil {
		t.Fatal(err)
	}

	pull := func(c agentv1.AgentServiceClient, known uint64) (*agentv1.FetchTestBundleResponse, *testsync.Bundle) {
		t.Helper()
		resp, err := c.FetchTestBundle(rpcCtx, &agentv1.FetchTestBundleRequest{KnownVersion: known})
		if err != nil {
			t.Fatalf("FetchTestBundle: %v", err)
		}
		if resp.GetNotModified() {
			return resp, nil
		}
		b, err := testsync.Verify(resp.GetSignedBundle(), pub, int64(known))
		if err != nil {
			t.Fatalf("pulled bundle does not verify: %v", err)
		}
		return resp, b
	}
	ids := func(b *testsync.Bundle) []string {
		var out []string
		for _, tt := range b.Tests {
			out = append(out, tt.ID)
		}
		return out
	}

	_, bundleA := pull(clientA, 0)
	if bundleA.TenantID != ta.ID || !slices.Equal(ids(bundleA), []string{idA}) {
		t.Fatalf("agent A pulled tenant %s tests %v; want tenant %s tests [%s]", bundleA.TenantID, ids(bundleA), ta.ID, idA)
	}
	_, bundleB := pull(clientB, 0)
	if bundleB.TenantID != tb.ID || !slices.Equal(ids(bundleB), []string{idB}) {
		t.Fatalf("agent B pulled tenant %s tests %v; want tenant %s tests [%s]", bundleB.TenantID, ids(bundleB), tb.ID, idB)
	}
	if slices.Contains(ids(bundleA), idB) || slices.Contains(ids(bundleB), idA) {
		t.Fatal("ISOLATION BREACH: an agent received another tenant's test")
	}

	// Up to date: not_modified, and the heartbeat does not nudge.
	if resp, _ := pull(clientA, uint64(bundleA.Epoch)); !resp.GetNotModified() {
		t.Fatalf("pull at the current version = %+v, want not_modified", resp)
	}
	hb, err := clientA.Heartbeat(rpcCtx, &agentv1.HeartbeatRequest{AgentId: agentA, ConfigEpoch: uint64(bundleA.Epoch)})
	if err != nil || hb.GetConfigStale() {
		t.Fatalf("current agent heartbeat = %+v, %v; want not stale", hb, err)
	}

	// Tenant B changes its tests: A is NOT nudged (B's version is not A's).
	mk(tb.ID, "b2", "https://b2.example.com")
	waitVersionCache()
	hb, err = clientA.Heartbeat(rpcCtx, &agentv1.HeartbeatRequest{AgentId: agentA, ConfigEpoch: uint64(bundleA.Epoch)})
	if err != nil || hb.GetConfigStale() {
		t.Fatalf("tenant B's change nudged tenant A's agent: %+v, %v", hb, err)
	}

	// Tenant A updates then deletes its test: each change moves the version and
	// the heartbeat nudges until the agent pulls.
	for step, change := range []func(context.Context, tenancy.Scope) error{
		func(ctx context.Context, s tenancy.Scope) error {
			_, err := (store.Tests{}).Update(ctx, s, idA, store.TestInput{Name: "a", Type: "http",
				Target: "https://a-new.example.com", IntervalSeconds: 30, TimeoutSeconds: 5, Enabled: true})
			return err
		},
		func(ctx context.Context, s tenancy.Scope) error { return (store.Tests{}).Delete(ctx, s, idA) },
	} {
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(ta.ID)), pool, change); err != nil {
			t.Fatal(err)
		}
		waitVersionCache()
		hb, err = clientA.Heartbeat(rpcCtx, &agentv1.HeartbeatRequest{AgentId: agentA, ConfigEpoch: uint64(bundleA.Epoch)})
		if err != nil || !hb.GetConfigStale() {
			t.Fatalf("step %d: heartbeat after tenant A's change = %+v, %v; want config_stale", step, hb, err)
		}
		prev := bundleA.Epoch
		_, bundleA = pull(clientA, uint64(prev))
		if bundleA == nil || bundleA.Epoch != prev+1 {
			t.Fatalf("step %d: version did not move by one: prev %d, got %+v", step, prev, bundleA)
		}
		if bundleA.TenantID != ta.ID {
			t.Fatalf("step %d: bundle tenant %s, want %s", step, bundleA.TenantID, ta.ID)
		}
		switch step {
		case 0:
			if len(bundleA.Tests) != 1 || bundleA.Tests[0].Target != "https://a-new.example.com" {
				t.Fatalf("update not reflected: %+v", bundleA.Tests)
			}
		case 1:
			if len(bundleA.Tests) != 0 {
				t.Fatalf("delete not reflected: %+v", bundleA.Tests)
			}
		}
	}

	sessionA, err := broker.StartSession(ta.ID, agentA, "peer-a", "tcp", 1)
	if err != nil {
		t.Fatal(err)
	}
	sessionB, err := broker.StartSession(tb.ID, agentB, "peer-b", "tcp", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InProvider(rpcCtx, pool, func(ctx context.Context, q tenancy.Querier) error {
		_, err := q.Exec(ctx, `UPDATE public.tenants SET prospect_collection_ends_at=clock_timestamp() WHERE id=$1`, ta.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, known := range []uint64{0, uint64(bundleA.Epoch)} {
		response, err := clientA.FetchTestBundle(rpcCtx, &agentv1.FetchTestBundleRequest{KnownVersion: known})
		if status.Code(err) != codes.FailedPrecondition || response != nil {
			t.Fatalf("completed tenant still received a test set at version %d: %v", known, err)
		}
	}
	_, stillCollecting := pull(clientB, 0)
	if stillCollecting.TenantID != tb.ID || !slices.Contains(ids(stillCollecting), idB) {
		t.Fatal("completed tenant changed the sibling's signed test set")
	}
	if response, err := clientA.PollCoordination(rpcCtx, &agentv1.PollCoordinationRequest{}); err != nil || response.GetHasTask() {
		t.Fatal("completed tenant received a new coordination assignment", err)
	}
	if _, err := clientA.ReportEndpoint(rpcCtx, &agentv1.ReportEndpointRequest{SessionId: sessionA, Host: "127.0.0.1", Port: 443}); status.Code(err) != codes.FailedPrecondition {
		t.Fatal("completed tenant could dispatch an initiator assignment", err)
	}
	if response, err := clientB.PollCoordination(rpcCtx, &agentv1.PollCoordinationRequest{}); err != nil || !response.GetHasTask() || response.GetTask().GetSessionId() != sessionB {
		t.Fatal("completed tenant changed the sibling's coordination assignment", err)
	}
	if task, queued, err := broker.PollForWithMeshAdmission(ta.ID, agentA, nil); err != nil || !queued || task.SessionID != sessionA {
		t.Fatal("denied dispatch consumed the completed tenant's queued assignment", err)
	}
}

// waitVersionCache outlasts the source's per-tenant version cache so the next
// heartbeat reads the committed version.
func waitVersionCache() { time.Sleep(2100 * time.Millisecond) }
