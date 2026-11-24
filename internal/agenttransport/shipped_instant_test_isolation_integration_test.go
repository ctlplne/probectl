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
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"

	"github.com/ctlplne/probectl/internal/testspec"
	"github.com/ctlplne/probectl/internal/testsupport/shipped"
)

func TestShippedInstantRunsAndTenantIsolation(t *testing.T) {
	stack := shipped.Start(t, shipped.Options{Name: "instantruns", TenantBand: 3, Env: map[string]string{
		"PROBECTL_TESTSYNC_SIGNING_KEY_FILE":            filepath.Join(t.TempDir(), "testsync-signing-key.pem"),
		"PROBECTL_FAIRNESS_INSTANT_TEST_AGENTS_PER_SEC": "0.25",
		// A small saved-flow library must not cap active test group results.
		"PROBECTL_FLOW_QUERY_LIBRARY_BYTES": "4096",
	}})
	operator := stack.OnboardOperator(t, "root@msp-instant-test.example")
	const site = "test-site"
	lane := func(slug, email string, count int) (string, string, string, []string) {
		var tenant struct{ ID string }
		stack.MustCLI(t, map[string]string{"PROBECTL_API_TOKEN": operator}, &tenant, "provider", "create-tenant",
			"--body", fmt.Sprintf(`{"slug":%q,"name":%q,"isolation_model":"pooled"}`, slug, slug))
		cookie := stack.SignIn(t, tenant.ID, email, slug)
		var test struct{ ID string }
		readShippedInstantJSON(t, stack, cookie, http.MethodPost, "/v1/tests", http.StatusCreated,
			map[string]any{"name": slug, "type": "noop", "interval_seconds": 86400, "timeout_seconds": 3}, &test)
		agents := make([]string, count)
		for i := range agents {
			name := fmt.Sprintf("%s-%d", slug, i)
			agents[i] = uuid.NewString()
			dir := stack.EnrollAgent(t, tenant.ID, agents[i], name)
			stack.StartAgent(t, dir, name, []string{"noop"}, "test_sync:\n  enabled: true\n  interval: 2s\n  allowed_types: [noop]\n", site)
		}
		for _, id := range agents {
			waitShippedInstantAgent(t, stack, cookie, id)
		}
		return tenant.ID, cookie, test.ID, agents
	}
	leftTenant, left, testID, ownerAgents := lane("instant-left", "ada@acme.example", 2)
	rightTenant, right, siblingTestID, siblingAgents := lane("instant-right", "bob@globex.example", 1)
	path := "/v1/tests/" + testID + "/runs"
	type launch struct {
		Key       string                    `json:"idempotency_key"`
		Selection testspec.InstantSelection `json:"selection"`
	}
	type receipt struct {
		ID     string `json:"id"`
		TestID string `json:"test_id"`
	}
	group := launch{uuid.NewString(), testspec.InstantSelection{Site: site}}
	var run, replay receipt
	releaseBundleRead := holdShippedInstantBundleReads(t, stack, len(ownerAgents)+len(siblingAgents))
	start := time.Now()
	readShippedInstantJSON(t, stack, left, http.MethodPost, path, http.StatusAccepted, group, &run)
	readShippedInstantJSON(t, stack, left, http.MethodPost, path, http.StatusTooManyRequests,
		launch{uuid.NewString(), group.Selection}, nil)
	readShippedInstantJSON(t, stack, left, http.MethodPost, path, http.StatusOK, group, &replay)
	if run != replay || run.TestID != testID || run.ID == "" {
		t.Fatalf("idempotent run changed identity: %+v, %+v", run, replay)
	}
	const budget = 8 * time.Second
	runPath := "/v1/test-runs/" + run.ID
	assertShippedInstantResults(t, stack, left, runPath, ownerAgents, budget, start)
	releaseBundleRead()
	assertShippedInstantLeaseRedelivery(t, stack, leftTenant, ownerAgents[0], run.ID)
	assertShippedInstantResultSubstitution(t, stack, leftTenant, rightTenant, siblingAgents[0], run.ID, testID,
		filepath.Join(stack.Dir, "agent-instant-right-0"))
	for _, read := range []string{runPath, runPath + "/events"} {
		readShippedInstantJSON(t, stack, right, http.MethodGet, read, http.StatusNotFound, nil, nil)
	}
	readShippedInstantJSON(t, stack, right, http.MethodPost, path, http.StatusNotFound, group, nil)
	readShippedInstantJSON(t, stack, left, http.MethodPost, path, http.StatusNotFound,
		launch{uuid.NewString(), testspec.InstantSelection{AgentIDs: []string{ownerAgents[0], siblingAgents[0]}}}, nil)

	var sibling receipt
	siblingStart := time.Now()
	readShippedInstantJSON(t, stack, right, http.MethodPost, "/v1/tests/"+siblingTestID+"/runs", http.StatusAccepted,
		launch{uuid.NewString(), testspec.InstantSelection{AgentIDs: siblingAgents}}, &sibling)
	assertShippedInstantResults(t, stack, right, "/v1/test-runs/"+sibling.ID, siblingAgents, budget, siblingStart)

	// An unfinished enrollment in the same site must prevent a partial run.
	offline := uuid.NewString()
	pool := stack.ApplicationReadPool(t)
	if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(leftTenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (store.Agents{}).RegisterWithLabels(ctx, sc, offline, "offline", "offline", "",
			crypto.AgentSPIFFEID(leftTenant, offline), []string{"noop"}, map[string]string{"site": site})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	readShippedInstantJSON(t, stack, left, http.MethodPost, path, http.StatusNotFound,
		launch{uuid.NewString(), group.Selection}, nil)

	var ctx struct {
		ContextID string `json:"context_id"`
	}
	readShippedInstantJSON(t, stack, left, http.MethodPost, "/v1/entity-contexts", http.StatusCreated,
		map[string]string{"site_label": site, "vrf_label": "default"}, &ctx)
	readShippedInstantJSON(t, stack, left, http.MethodPut, "/v1/entity-source-contexts", http.StatusOK,
		map[string]string{"agent_id": ownerAgents[0], "source_kind": "device_target", "source_ref": "192.0.2.15",
			"context_id": ctx.ContextID}, nil)
	var tag struct {
		ID string `json:"id"`
	}
	readShippedInstantJSON(t, stack, left, http.MethodPost, "/v1/tags", http.StatusCreated,
		map[string]string{"key": "test_group"}, &tag)
	readShippedInstantJSON(t, stack, left, http.MethodPost, "/v1/entity-contexts/"+ctx.ContextID+"/tag-assignments", http.StatusCreated,
		map[string]string{"target_kind": "agent", "target_id": ownerAgents[0], "tag_id": tag.ID, "value": "only-left"}, nil)

	tagSelection := testspec.InstantSelection{Tag: &testspec.InstantAgentTag{ContextID: ctx.ContextID, TagID: tag.ID, Value: "only-left"}}
	tagInput := launch{uuid.NewString(), tagSelection}
	readShippedInstantJSON(t, stack, right, http.MethodPost, "/v1/tests/"+siblingTestID+"/runs",
		http.StatusNotFound, tagInput, nil)
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		tagStart := time.Now()
		status, body := stack.Do(t, left, http.MethodPost, path, tagInput)
		if status == http.StatusTooManyRequests {
			continue
		}
		var tagged receipt
		if status != http.StatusAccepted || json.Unmarshal(body, &tagged) != nil {
			t.Fatalf("tag selection could not dispatch: %d %s", status, body)
		}
		assertShippedInstantResults(t, stack, left, "/v1/test-runs/"+tagged.ID, ownerAgents[:1], budget, tagStart)
		if err := tenancy.InProvider(t.Context(), pool, func(ctx context.Context, q tenancy.Querier) error {
			_, err := q.Exec(ctx, `UPDATE public.tenants SET prospect_collection_ends_at=clock_timestamp() WHERE id=$1`, leftTenant)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		readShippedInstantJSON(t, stack, left, http.MethodPost, path, http.StatusConflict,
			launch{uuid.NewString(), testspec.InstantSelection{AgentIDs: ownerAgents[:1]}}, nil)
		readShippedInstantJSON(t, stack, right, http.MethodGet, "/v1/test-runs/"+sibling.ID, http.StatusOK, nil, nil)
		return
	}
	t.Fatal("tag selection never received its tenant's replenished budget")
}

// The lock is confined to this disposable database. Wait until the agents
// are blocked on scheduled bundle reads before asking them to run a test now.
func holdShippedInstantBundleReads(t *testing.T, stack *shipped.Stack, agents int) func() {
	t.Helper()
	pool := stack.ApplicationReadPool(t)
	tx, err := pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	release := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(ctx)
	}
	t.Cleanup(release)
	if _, err := tx.Exec(t.Context(), `LOCK TABLE public.tenant_test_set_versions IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal("could not stall scheduled bundle reads", err)
	}
	shipped.Await(t, "agents are blocked on scheduled bundle reads", 8*time.Second, func() bool {
		var waiting int
		err := tx.QueryRow(t.Context(), `SELECT count(*) FROM pg_locks
 WHERE database=(SELECT oid FROM pg_database WHERE datname=current_database())
   AND relation='public.tenant_test_set_versions'::regclass AND mode='AccessShareLock' AND NOT granted`).Scan(&waiting)
		if err != nil {
			t.Fatal("could not observe blocked bundle reads", err)
		}
		return waiting >= agents
	})
	return release
}

func assertShippedInstantLeaseRedelivery(t *testing.T, stack *shipped.Stack, tenant, agent, completedRun string) {
	t.Helper()
	pool := stack.ApplicationReadPool(t)
	runID, originalLease, nextLease := uuid.NewString(), uuid.NewString(), uuid.NewString()
	rollback := errors.New("roll back the isolated lease-redelivery fixture")
	// Use the shipped application's role and live agent registration. Keep the
	// new queue entry inside this transaction so the real agent cannot race it.
	err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		var serial string
		if err := sc.Q.QueryRow(ctx, `SELECT i.serial FROM agent_identities i JOIN agents a
 ON i.tenant_id=a.tenant_id AND i.agent_id=a.id::text AND i.spiffe_id=a.spiffe_id
 WHERE a.tenant_id=$1 AND a.id=$2 AND i.revoked_at IS NULL AND i.not_after>statement_timestamp()
 ORDER BY i.issued_at DESC LIMIT 1`, tenant, agent).Scan(&serial); err != nil {
			return err
		}
		addRun := func(id string) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO instant_test_runs
 (tenant_id,id,requested_by,requested_with_mfa,idempotency_key,request_hash,test_id,test_updated_at,
  definition_hash,timeout_seconds,created_at,dispatch_until,retain_until)
 SELECT tenant_id,$3,requested_by,requested_with_mfa,$3,request_hash,test_id,test_updated_at,
        definition_hash,timeout_seconds,statement_timestamp(),statement_timestamp()+interval '20 seconds',statement_timestamp()+interval '1 day'
 FROM instant_test_runs WHERE tenant_id=$1 AND id=$2`, tenant, completedRun, id); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO instant_test_assignments (tenant_id,run_id,agent_id,agent_registered_at)
 SELECT tenant_id,$3,id,registered_at FROM agents WHERE tenant_id=$1 AND id=$2`, tenant, agent, id)
			return err
		}
		if err := addRun(runID); err != nil {
			return err
		}
		runs := store.InstantTestRuns{}
		first, err := runs.LeaseNext(ctx, sc, agent, serial, originalLease)
		if err != nil || first == nil || first.LeaseID != originalLease || first.RunID != runID {
			return fmt.Errorf("could not reserve the original test assignment: %v", err)
		}
		retried, err := runs.LeaseNext(ctx, sc, agent, serial, nextLease)
		if err != nil || retried == nil || retried.LeaseID != first.LeaseID || retried.RunID != first.RunID ||
			!retried.IssuedAt.Equal(first.IssuedAt) || !retried.ExpiresAt.Equal(first.ExpiresAt) || retried.DefinitionHash != first.DefinitionHash {
			return fmt.Errorf("retry changed the reserved assignment or deadline: %v", err)
		}
		freshID := uuid.NewString()
		if err := addRun(freshID); err != nil {
			return err
		}
		fresh, err := runs.LeaseNext(ctx, sc, agent, serial, nextLease)
		if err != nil || fresh == nil || fresh.RunID != freshID || fresh.LeaseID != nextLease {
			return fmt.Errorf("a leased test blocked a fresh run for the same agent: %v", err)
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal("instant assignment did not survive an unacknowledged pull", err)
	}
}

func waitShippedInstantAgent(t *testing.T, stack *shipped.Stack, cookie, id string) {
	t.Helper()
	for end := time.Now().Add(25 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		status, body := stack.Do(t, cookie, http.MethodGet, "/v1/agents/"+id, nil)
		var agent struct {
			Status  string `json:"status"`
			TestSet struct {
				AppliedVersion uint64 `json:"applied_version"`
			} `json:"test_set"`
		}
		if status == http.StatusOK && json.Unmarshal(body, &agent) == nil &&
			agent.Status == "online" && agent.TestSet.AppliedVersion > 0 {
			return
		}
	}
	t.Fatalf("agent %s did not apply its signed test bundle", id)
}

func readShippedInstantJSON(t *testing.T, stack *shipped.Stack, cookie, method, path string, want int, input, output any) {
	t.Helper()
	status, body := stack.Do(t, cookie, method, path, input)
	if status != want {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, status, want, body)
	}
	if output != nil {
		if err := json.Unmarshal(body, output); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
}

func assertShippedInstantResults(t *testing.T, stack *shipped.Stack, cookie, path string, agents []string, budget time.Duration, started time.Time) {
	t.Helper()
	status, body := stack.Do(t, cookie, http.MethodGet, path+"/events", nil)
	if status != http.StatusOK || time.Since(started) > budget {
		t.Fatalf("instant results missed %s: time=%s status=%d body=%s", budget, time.Since(started), status, body)
	}
	var final struct {
		Agents []struct {
			AgentID string `json:"agent_id"`
			State   string `json:"state"`
			Result  struct {
				Success bool   `json:"success"`
				Outcome string `json:"outcome"`
			} `json:"result"`
		} `json:"agents"`
	}
	for _, line := range strings.Split(string(body), "\n") {
		if payload, ok := strings.CutPrefix(line, "data: "); ok {
			if err := json.Unmarshal([]byte(payload), &final); err != nil {
				t.Fatalf("event payload: %v", err)
			}
		}
	}
	if len(final.Agents) != len(agents) {
		t.Fatalf("wanted only %v, got %v", agents, final.Agents)
	}
	expected := make(map[string]bool, len(agents))
	for _, id := range agents {
		expected[id] = true
	}
	for _, row := range final.Agents {
		if !expected[row.AgentID] || row.State != "completed" || row.Result.Outcome != "measured" || !row.Result.Success {
			t.Fatalf("unexpected final result: %+v", row)
		}
		delete(expected, row.AgentID)
	}
}

func assertShippedInstantResultSubstitution(t *testing.T, stack *shipped.Stack, owner, sibling, siblingAgent, runID, testID, identity string) {
	t.Helper()
	pool := stack.ApplicationReadPool(t)
	var leaseID string
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(owner)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		return sc.Q.QueryRow(ctx, `SELECT lease_id::text FROM instant_test_assignments
 WHERE tenant_id=$1 AND run_id=$2 AND result_id IS NOT NULL ORDER BY agent_id LIMIT 1`, owner, runID).Scan(&leaseID)
	}); err != nil {
		t.Fatalf("could not identify the owning completed lease: %v", err)
	}
	cfg, _, err := crypto.ClientMTLSConfigRotating(filepath.Join(identity, "cert.pem"), filepath.Join(identity, "key.pem"),
		stack.CAFile, crypto.AgentSPIFFEID(sibling, siblingAgent))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ServerName = "localhost"
	conn, err := grpc.NewClient(stack.AgentAddr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload, err := proto.Marshal(&resultv1.Result{
		ResultId: uuid.NewString(), StartTimeUnixNano: time.Now().UnixNano(), CanaryType: "noop", Success: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = agentv1.NewAgentServiceClient(conn).ReportInstantTestResult(ctx, &agentv1.ReportInstantTestResultRequest{
		RunId: runID, LeaseId: leaseID, TestId: testID, Outcome: "measured", ResultPayload: payload,
	})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("substituted sibling result returned the wrong status: %v", err)
	}
}
