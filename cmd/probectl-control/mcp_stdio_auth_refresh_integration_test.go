// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

// This invokes the actual command function against real PG tokens, role
// grants, consent and audit. There is no model/network/synthetic auth adapter.
func TestMCPStdioCommandRechecksRealTokenBetweenFrames(t *testing.T) {
	admin := setupMCPStdioDB(t)
	ctx := t.Context()
	tenant, err := store.NewTenants(admin.Pool()).Create(ctx, fmt.Sprintf("stdio-refresh-%d", time.Now().UnixNano()), "Own stdio credential proof")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		attestation, err := tenantlife.New(admin.Pool(), nil, nil, nil, nil, "Local fixture has no backups", quietLogger()).Erase(cleanup, tenant.ID, tenant.Slug, "qa-stdio-fixture")
		if err != nil || !attestation.Complete {
			t.Errorf("own stdio fixture erasure failed: %v", err)
		}
	})
	db := admin
	if dsn := os.Getenv("PROBECTL_FLOW_FILTER_TEST_DATABASE_URL"); dsn != "" {
		db, err = store.Open(ctx, dsn, 5, 0, 5*time.Second)
		if err != nil {
			t.Fatal("runtime database configuration failed")
		}
		defer db.Close()
	}
	var userID string
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		user, err := (store.Users{}).Create(ctx, sc, "stdio-proof@example.test", "Local stdio proof")
		if err != nil {
			return err
		}
		userID = user.ID
		role, err := (store.Roles{}).Create(ctx, sc, "stdio-proof", "Stdio proof", "")
		if err != nil {
			return err
		}
		if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, "test.read"); err != nil {
			return err
		}
		return (store.RoleBindings{}).Bind(ctx, sc, "user", userID, role.ID)
	}); err != nil {
		t.Fatal(err)
	}
	if err := tenancy.InProvider(ctx, admin.Pool(), func(ctx context.Context, q tenancy.Querier) error {
		_, err := q.Exec(ctx, `INSERT INTO tenant_governance(tenant_id,ai_remote_egress) VALUES($1,true)`, tenant.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	token, err := auth.RandomToken()
	if err != nil {
		t.Fatal(err)
	}
	tokenID, err := store.NewMCPTokens(db.Pool()).CreateWithLifetime(ctx, tenant.ID, userID, "stdio-revocation", crypto.Hash([]byte(token)), time.Now().Add(time.Hour), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PROBECTL_MCP_TOKEN", token)
	inputR, inputW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inputR.Close()
	defer inputW.Close()
	outputR, outputW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outputR.Close()
	defer outputW.Close()
	previousIn, previousOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inputR, outputW
	cfg := &config.Config{PathStoreMode: "memory", FlowStoreMode: "memory", ObjectStoreDir: t.TempDir(), MCPRatePerMin: 1000, FairnessQueryConcurrency: 1, FairnessQueriesPerMin: 20, FairnessTenantIdleTTL: time.Hour}
	done := make(chan error, 1)
	go func() { done <- runMCPStdio(cfg, quietLogger(), db) }()
	finished := false
	defer func() {
		_ = inputW.Close()
		if !finished {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("stdio fixture did not exit after input closed")
			}
		}
		os.Stdin, os.Stdout = previousIn, previousOut
	}()
	reader := bufio.NewReader(outputR)
	for step := 0; step < 2; step++ {
		if err := outputR.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := inputW.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_tests","arguments":{}}}` + "\n")); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadBytes('\n')
		if err != nil {
			t.Fatal("stdio command did not produce a bounded frame")
		}
		var reply struct {
			Result struct {
				IsError bool            `json:"isError"`
				Data    json.RawMessage `json:"structuredContent"`
			} `json:"result"`
			Error json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(line, &reply); err != nil {
			t.Fatal("stdio command emitted nonprotocol stdout")
		}
		if step == 0 {
			if len(reply.Error) > 0 || reply.Result.IsError || len(reply.Result.Data) == 0 {
				t.Fatal("initial real command credential failed")
			}
			if _, err := store.NewMCPTokens(db.Pool()).RevokeByID(ctx, tenant.ID, tokenID); err != nil {
				t.Fatal(err)
			}
		} else if len(reply.Error) == 0 || len(reply.Result.Data) > 0 {
			t.Fatal("stdio command reused revoked token on next frame")
		}
	}
	if err := inputW.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stdio command did not stop at EOF")
	}
}
