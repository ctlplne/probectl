// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/cmdb"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Loopback source doubles isolate builder wiring. Provider-package proofs
// separately exercise TLS; this is not a real external account receipt.
func TestCMDBBuilderAppliesCompleteLookupCapacityProfiles(t *testing.T) {
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		padding := strings.Repeat("x", 5<<20)
		switch r.URL.Path {
		case "/api/ipam/ip-addresses/":
			_ = json.NewEncoder(w).Encode(map[string]any{"count": 1, "results": []any{map[string]any{"id": 1, "tenant": map[string]int{"id": 7}, "address": "10.0.0.1/32", "dns_name": "owned"}}, "custom_source_data": padding})
		case "/api/now/table/cmdb_ci":
			w.Header().Set("X-Total-Count", "1")
			_ = json.NewEncoder(w).Encode(map[string]any{"result": []any{map[string]string{"sys_id": "one-ci", "name": "owned", "ip_address": "10.0.0.1"}}, "custom_source_data": padding})
		default:
			t.Error("builder used an unexpected source endpoint")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer source.Close()
	for _, provider := range []string{"netbox", "servicenow"} {
		t.Run(provider, func(t *testing.T) {
			cfg := &config.Config{CMDBProvider: provider, CMDBURL: source.URL, CMDBSecret: "test-user:test-secret", CMDBNetBoxTenantMap: map[string]string{tenancy.DefaultTenantID.String(): "7"}, CMDBLookupTimeout: 25 * time.Hour, CMDBResponseBytes: 8 << 20, CMDBMemoryBytes: 1 << 30}
			resolver := BuildCMDB(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
			cis, err := resolver.Lookup(tenancy.WithTenant(t.Context(), tenancy.DefaultTenantID), "10.0.0.1")
			if err != nil || len(cis) != 1 || cis[0].Name != "owned" {
				t.Fatal("deployment builder did not carry complete source profiles", err)
			}
		})
	}
}

type refusedCMDBProvider struct{ err error }

func (*refusedCMDBProvider) Name() string { return "refusal-fixture" }
func (p *refusedCMDBProvider) Lookup(context.Context, string) ([]cmdb.CI, error) {
	return nil, p.err
}

func TestCMDBAdmissionRefusalAPIIsExplicitAndDoesNotEchoSourceData(t *testing.T) {
	for _, failure := range []struct {
		err     error
		message string
	}{
		{cmdb.ErrLookupBudget, "exceeded deployment capacity"},
		{cmdb.ErrLookupIncomplete, "incomplete result"},
	} {
		var logs bytes.Buffer
		provider := &refusedCMDBProvider{err: fmt.Errorf("%w: synthetic-private-source-value", failure.err)}
		srv := testServer(fakePinger{}).WithCMDB(cmdb.NewResolver(provider, time.Hour))
		srv.log = slog.New(slog.NewTextHandler(&logs, nil))
		srv.cmdbKeyOwner = func(_ *http.Request, _ string) (bool, error) { return true, nil }
		rec := do(srv, http.MethodGet, "/v1/cmdb/lookup?key=10.0.0.1")
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), failure.message) || strings.Contains(rec.Body.String()+logs.String(), "synthetic-private-source-value") || !strings.Contains(logs.String(), "error.type=cmdb.lookup.") {
			t.Fatal("CMDB refusal lost its safe classification or echoed source data")
		}
	}
}
