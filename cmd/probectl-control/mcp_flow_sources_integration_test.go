// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// Actual issued-user bearer/TLS/Postgres authority and the standalone command
// assembly. The ixpfx input is synthetic; this is not real source/router proof.
func TestMCPFlowSourcesRetainConfiguredLocalIXGeneration(t *testing.T) {
	db := setupMCPStdioDB(t)
	testsupport.LockPostgresPublicCatalog(t, db.Pool())
	var tenants []string
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	tokens := map[string]string{}
	for lane := range 2 {
		tenant, err := store.NewTenants(db.Pool()).Create(t.Context(), fmt.Sprintf("stdio-ix-%d-%d", lane, time.Now().UnixNano()), "Own native source fixture")
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tenant.ID)
		var userID string
		if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant.ID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (store.Users{}).Create(ctx, sc, "ix-source@example.test", "Source reader")
			if err != nil {
				return err
			}
			userID = user.ID
			role, err := (store.Roles{}).Create(ctx, sc, "source-reader", "Source reader", "")
			if err != nil {
				return err
			}
			if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, "threat.read"); err != nil {
				return err
			}
			return (store.RoleBindings{}).Bind(ctx, sc, "user", user.ID, role.ID)
		}); err != nil {
			t.Fatal(err)
		}
		token, err := auth.RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.NewMCPTokens(db.Pool()).CreateWithLifetime(t.Context(), tenant.ID, userID, "ix-source-proof", crypto.Hash([]byte(token)), time.Now().Add(time.Hour), nil); err != nil {
			t.Fatal(err)
		}
		tokens[tenant.ID] = token
	}
	path := filepath.Join(t.TempDir(), "ixpfx.json")
	raw, err := json.Marshal(map[string]any{"version": 1, "object": "ixpfx", "observed_at": time.Now().UTC().Add(-time.Minute), "complete": true, "record_count": 1, "data": []map[string]any{{"id": 7, "ixlan_id": 11, "protocol": "IPv4", "prefix": "198.51.100.0/24", "status": "ok"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{AuthMode: "session", FlowStoreMode: "memory", TSDBMode: "memory", ObjectStoreDir: t.TempDir(), FlowEnrichIXPrefixFile: path, FlowEnrichIXPrefixMaxAge: time.Hour, FlowQueryMemoryBytes: 2 << 30, FlowEnrichCacheMax: 16}
	paths := pathstore.NewMemory()
	defer paths.Close()
	sources, closeSources, err := buildMCPFlowSources(cfg, quietLogger(), db, paths)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSources()
	socket := httptest.NewTLSServer(sources.NativeFlow.Handler())
	t.Cleanup(socket.Close)
	for _, tenant := range tenants {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, socket.URL+"/v1/threat/intel/status", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+tokens[tenant])
		req.Header.Set("X-Probectl-Tenant", tenant)
		response, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		var status struct {
			Enabled bool `json:"open_data_enabled"`
			Sources []struct {
				Name    string `json:"name"`
				Status  string `json:"status"`
				Enabled bool   `json:"enabled"`
			} `json:"open_data_sources"`
		}
		if response.StatusCode != http.StatusOK || json.Unmarshal(body, &status) != nil {
			t.Fatal("standalone source catalog authentication fixture failed", response.StatusCode, string(body))
		}
		if !status.Enabled || len(status.Sources) != 1 || status.Sources[0].Name != "peeringdb-ix-prefix-file" || !status.Sources[0].Enabled || status.Sources[0].Status != "ok" {
			t.Fatal("standalone role source omitted configured local IX prefixes", string(body))
		}
	}
}
