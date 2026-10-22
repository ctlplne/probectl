// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func trapIsolationDB(t *testing.T) *store.DB {
	t.Helper()
	ctx := context.Background()
	dsn := os.Getenv("PROBECTL_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://probectl:probectl@localhost:5432/probectl?sslmode=disable"
	}
	db, err := store.Open(ctx, dsn, 5, 0, 5*time.Second)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		db.Close()
		testsupport.SkipOrFatal(t, "no database available: %v", err)
	}
	t.Cleanup(db.Close)
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, db.Pool()); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	return db
}

// TestDeviceTrapReadIsTenantIsolatedThroughAPIAndCLI is the isolation receipt
// for the trap read path above the store: two tenants' traps share a device
// address; GET /v1/device/traps and `probectl device traps` as each tenant
// return only that tenant's trap, including when filtered by the shared
// address or by the other tenant's device.
func TestDeviceTrapReadIsTenantIsolatedThroughAPIAndCLI(t *testing.T) {
	ctx := context.Background()
	db := trapIsolationDB(t)
	suffix := time.Now().UnixNano()
	tenants := map[string]string{}
	for _, name := range []string{"a", "b"} {
		tn, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("trap-api-%s-%d", name, suffix), "Trap API "+name)
		if err != nil {
			t.Fatal(err)
		}
		tenants[name] = tn.ID
	}
	traps := store.NewDeviceTraps(db.Pool())
	now := time.Now().UTC()
	for name, id := range tenants {
		for _, addr := range []string{"10.0.0.1", "10.0.0." + map[string]string{"a": "2", "b": "3"}[name]} {
			if _, err := traps.RecordTrapEvent(ctx, id, device.TrapRecord{
				TenantID: id, AgentID: "agent-" + name, DeviceAddress: addr, SourceAddress: addr,
				AuthPrincipal: "principal-" + name, Version: "snmpv2c", Kind: "snmp.trap.link_down",
				Severity: "warning", TrapOID: ".1.3.6.1.6.3.1.1.5.3", Fingerprint: "fp-" + name + addr,
				ObservedAt: now, ReceivedAt: now,
				VarBinds: []device.TrapVarBind{{OID: ".1.3.6.1.2.1.31.1.1.1.18.2", Type: "OctetString", Value: "marker-" + name}},
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	cfg := &config.Config{HSTSEnabled: true, HSTSMaxAge: time.Hour, AuthMode: "dev"}
	srv := New(cfg, logging.New(io.Discard, "error", "json"), db, db.Pool(), nil, nil).
		WithTenantStatus(NewTenantStatusCache(db.Pool(), 0)).
		WithDeviceTraps(traps)
	ts := httptest.NewTLSServer(srv.Handler())
	t.Cleanup(ts.Close)
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, id := range tenants {
		other := map[string]string{"a": "b", "b": "a"}[name]
		otherDevice := "10.0.0." + map[string]string{"a": "3", "b": "2"}[name]
		for _, query := range []string{"", "?device=10.0.0.1", "?device=" + otherDevice, "?limit=500"} {
			want := map[string]int{"": 2, "?device=10.0.0.1": 1, "?device=" + otherDevice: 0, "?limit=500": 2}[query]
			surfaces := map[string][]byte{
				"GET /v1/device/traps" + query:   trapAPIGet(t, ts.Client(), ts.URL+"/v1/device/traps"+query, id),
				"probectl device traps " + query: trapCLIGet(t, ts.URL, caFile, id, query),
			}
			for surface, raw := range surfaces {
				var resp deviceTrapResponse
				if err := json.Unmarshal(raw, &resp); err != nil {
					t.Fatalf("%s as tenant %s: %v: %s", surface, name, err, raw)
				}
				if len(resp.Items) != want || !resp.CollectionRunning {
					t.Errorf("%s as tenant %s returned %d traps, want %d: %s", surface, name, len(resp.Items), want, raw)
				}
				if bytes.Contains(raw, []byte("marker-"+other)) || bytes.Contains(raw, []byte("principal-"+other)) ||
					bytes.Contains(raw, []byte("agent-"+other)) {
					t.Errorf("CROSS-TENANT TRAP LEAK: %s as tenant %s returned tenant %s's trap: %s", surface, name, other, raw)
				}
			}
		}
	}
}

func trapAPIGet(t *testing.T, c *http.Client, url, tenant string) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Probectl-Tenant", tenant)
	res, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("GET %s as %s = %d: %s", url, tenant, res.StatusCode, raw)
	}
	return raw
}

func trapCLIGet(t *testing.T, baseURL, caFile, tenant, query string) []byte {
	t.Helper()
	args := []string{"--json", "device", "traps"}
	if q := strings.TrimPrefix(query, "?"); q != "" {
		args = append(args, "--query", q)
	}
	env := map[string]string{"PROBECTL_API_URL": baseURL, "PROBECTL_API_TOKEN": "dev", "PROBECTL_TENANT": tenant, "PROBECTL_CA_FILE": caFile}
	var out, errb bytes.Buffer
	if code := cli.RunWithStdin(args, func(k string) string { return env[k] }, bytes.NewReader(nil), &out, &errb); code != 0 {
		t.Fatalf("probectl %s as %s: exit %d: %s", strings.Join(args, " "), tenant, code, errb.String())
	}
	return out.Bytes()
}
