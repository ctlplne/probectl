// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func setupMCPStdioDB(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, testsupport.PostgresDSN(), 5, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		db.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func TestMCPStdioUsesStoredAndDefaultFairness(t *testing.T) {
	db := setupMCPStdioDB(t)
	ctx := context.Background()
	stamp := time.Now().UnixNano()
	tenants := store.NewTenants(db.Pool())
	storedTenant, err := tenants.Create(ctx, fmt.Sprintf("mcp-stdio-stored-%d", stamp), "MCP stdio stored fairness")
	if err != nil {
		t.Fatalf("create stored-policy tenant: %v", err)
	}
	defaultTenant, err := tenants.Create(ctx, fmt.Sprintf("mcp-stdio-default-%d", stamp), "MCP stdio default fairness")
	if err != nil {
		t.Fatalf("create default-policy tenant: %v", err)
	}
	for _, tenantID := range []string{storedTenant.ID, defaultTenant.ID} {
		if err := tenancy.InProvider(ctx, db.Pool(), func(ctx context.Context, q tenancy.Querier) error {
			_, err := q.Exec(ctx,
				`INSERT INTO tenant_governance (tenant_id, ai_remote_egress) VALUES ($1, true)
				 ON CONFLICT (tenant_id) DO UPDATE SET ai_remote_egress = true`,
				tenantID)
			return err
		}); err != nil {
			t.Fatalf("grant MCP egress consent for %s: %v", tenantID, err)
		}
	}
	if err := fairness.NewPGStore(db.Pool()).Upsert(ctx, storedTenant.ID, fairness.Policy{
		QueryConcurrency: 1,
		QueriesPerMin:    2,
	}, "integration-test"); err != nil {
		t.Fatalf("store tenant fairness override: %v", err)
	}

	cfg := &config.Config{
		MCPRatePerMin:            1000,
		FairnessQueryConcurrency: 2,
		FairnessQueriesPerMin:    3,
		FairnessTenantIdleTTL:    time.Hour,
	}
	pathStore := pathstore.NewMemory()
	t.Cleanup(func() {
		if err := pathStore.Close(); err != nil {
			t.Errorf("close path store: %v", err)
		}
	})
	runtime := newMCPStdioRuntime(cfg, quietLogger(), db, pathStore)
	fixedNow := time.Unix(1_800_000_000, 0)
	runtime.fairGate.WithNow(func() time.Time { return fixedNow })

	// Stored policy loading is deliberately asynchronous on the query hot path.
	// Prime it, then wait until this exact production gate has the override.
	runtime.fairGate.EffectivePolicy(ctx, storedTenant.ID)
	deadline := time.Now().Add(3 * time.Second)
	for {
		policy := runtime.fairGate.EffectivePolicy(ctx, storedTenant.ID)
		if policy.QueryConcurrency == 1 && policy.QueriesPerMin == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stored fairness override was not loaded: %+v", policy)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if policy := runtime.fairGate.EffectivePolicy(ctx, defaultTenant.ID); policy.QueryConcurrency != 2 || policy.QueriesPerMin != 3 {
		t.Fatalf("deployment-default fairness = %+v, want concurrency=2 budget=3", policy)
	}

	nextID := 0
	listTests := func(tenantID string) map[string]any {
		t.Helper()
		nextID++
		raw := fmt.Sprintf(
			`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"list_tests","arguments":{}}}`,
			nextID,
		)
		var out bytes.Buffer
		principal := &auth.Principal{TenantID: tenantID, Permissions: map[string]bool{"test.read": true}}
		if err := runtime.server.ServeStdio(ctx, strings.NewReader(raw+"\n"), &out, principal); err != nil {
			t.Fatalf("serve stdio for %s: %v", tenantID, err)
		}
		if !strings.HasSuffix(out.String(), "\n") || strings.Count(out.String(), "\n") != 1 {
			t.Fatalf("stdio response framing for %s = %q, want exactly one newline", tenantID, out.String())
		}
		var response map[string]any
		if err := json.Unmarshal(bytes.TrimSuffix(out.Bytes(), []byte{'\n'}), &response); err != nil {
			t.Fatalf("decode stdio response for %s: %v", tenantID, err)
		}
		result, ok := response["result"].(map[string]any)
		if !ok {
			t.Fatalf("stdio response for %s has no tool result: %v", tenantID, response)
		}
		return result
	}
	assertError := func(result map[string]any, contains string) {
		t.Helper()
		if result["isError"] != true {
			t.Fatalf("tool result = %v, want error containing %q", result, contains)
		}
		content, _ := result["content"].([]any)
		if len(content) != 1 {
			t.Fatalf("tool error content = %v, want one entry", result["content"])
		}
		entry, _ := content[0].(map[string]any)
		text, _ := entry["text"].(string)
		if !strings.Contains(text, contains) {
			t.Fatalf("tool error text = %q, want %q", text, contains)
		}
	}
	assertSuccess := func(result map[string]any) {
		t.Helper()
		if result["isError"] == true {
			t.Fatalf("tool result unexpectedly failed: %v", result)
		}
		if _, ok := result["structuredContent"].(map[string]any); !ok {
			t.Fatalf("successful result lacks structured content: %v", result)
		}
	}

	// The stored tenant gets its tighter 1-in-flight / 2-per-minute policy.
	storedRelease, err := runtime.fairGate.BeginQuery(ctx, storedTenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertError(listTests(storedTenant.ID), fairness.ErrQueryConcurrency.Error())
	storedRelease()
	assertSuccess(listTests(storedTenant.ID))
	assertError(listTests(storedTenant.ID), fairness.ErrQueryBudget.Error())

	// A tenant without an override gets the configured 2-in-flight /
	// 3-per-minute deployment defaults through the same stdio server gate.
	defaultRelease1, err := runtime.fairGate.BeginQuery(ctx, defaultTenant.ID)
	if err != nil {
		t.Fatal(err)
	}
	defaultRelease2, err := runtime.fairGate.BeginQuery(ctx, defaultTenant.ID)
	if err != nil {
		defaultRelease1()
		t.Fatal(err)
	}
	assertError(listTests(defaultTenant.ID), fairness.ErrQueryConcurrency.Error())
	defaultRelease1()
	defaultRelease2()
	assertSuccess(listTests(defaultTenant.ID))
	assertError(listTests(defaultTenant.ID), fairness.ErrQueryBudget.Error())
}
