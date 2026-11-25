// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package rmm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/nmsimport"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type credentialResolverFunc func(context.Context, string) ([]byte, func(), error)

func (f credentialResolverFunc) ResolveBytesUncached(ctx context.Context, ref string) ([]byte, func(), error) {
	return f(ctx, ref)
}

func TestInventorySyncRequestsOnlyBoundMonitoringCredential(t *testing.T) {
	var tokenCalls, deviceCalls atomic.Int32
	var wideScope atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ws/oauth/token":
			tokenCalls.Add(1)
			if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.ParseForm() != nil ||
				r.PostForm.Get("grant_type") != "client_credentials" || r.PostForm.Get("scope") != "monitoring" ||
				r.PostForm.Get("client_id") != "lab-client" || r.PostForm.Get("client_secret") != "lab-fixture" {
				t.Error("OAuth request escaped its bound origin, method or scope")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			scope := "monitoring"
			if wideScope.Load() {
				scope += " management"
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"scope": scope, "access_token": "opaque.fixture", "token_type": "Bearer"})
		case "/v2/devices":
			deviceCalls.Add(1)
			if r.Method != http.MethodGet || r.URL.Query().Get("df") != "org=42 AND loc=7" ||
				r.Header.Get("Authorization") != "Bearer opaque.fixture" {
				t.Error("inventory request escaped its bound site or monitoring token")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte("[]"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	site := Site{Vendor: NinjaOne, Account: "test-account", ID: "42:7"}
	raw, err := json.Marshal([]inventoryRoute{{SiteMapping: fixtureSite(tenantAlpha, contextAlpha, site),
		Alias: "source", Origin: server.URL, CredentialRef: "env:RMM_FIXTURE"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := tenancy.WithTenant(t.Context(), tenantAlpha)
	var resolutions, cleanups int
	var writes bool
	resolver := credentialResolverFunc(func(got context.Context, ref string) ([]byte, func(), error) {
		tenant, _ := tenancy.FromContext(got)
		if tenant != tenantAlpha || ref != "env:RMM_FIXTURE" {
			t.Fatal("a request resolved another tenant's credential")
		}
		resolutions++
		return []byte(`{"client_id":"lab-client","client_secret":"lab-fixture"}`), func() { cleanups++ }, nil
	})
	syncer, err := NewInventorySync(raw, resolver, func() bool { return writes }, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if syncer.Available(tenantAlpha.String()) || syncer.Available(tenantBeta.String()) {
		t.Fatal("read-only entitlement advertised an inventory sync")
	}
	var capture nmsimport.CaptureStore
	if _, err := syncer.Start(ctx, contextBeta, "source", capture); !errors.Is(err, nmsimport.ErrPlanUnavailable) {
		t.Fatal("source resolved in a different routing context", err)
	}
	if _, err := syncer.Start(ctx, contextAlpha, "source", capture); !errors.Is(err, license.ErrReadOnly) {
		t.Fatal("read-only entitlement accepted a sync", err)
	}
	if resolutions != 0 || tokenCalls.Load() != 0 || deviceCalls.Load() != 0 {
		t.Fatal("wrong context or read-only entitlement used credentials")
	}
	writes = true
	if !syncer.Available(tenantAlpha.String()) || syncer.Available(tenantBeta.String()) || resolutions != 0 {
		t.Fatal("inventory availability disclosed a sibling site or resolved credentials")
	}
	wideScope.Store(true)
	if _, err := syncer.Start(ctx, contextAlpha, "source", capture); !errors.Is(err, nmsimport.ErrSourceUnavailable) ||
		resolutions != 1 || cleanups != 1 || tokenCalls.Load() != 1 || deviceCalls.Load() != 0 {
		t.Fatal("scope expansion reached device inventory", err)
	}
	wideScope.Store(false)
	if _, err := syncer.Start(ctx, contextAlpha, "source", capture); !errors.Is(err, nmsimport.ErrCaptureAuditUnavailable) ||
		resolutions != 2 || cleanups != 2 || tokenCalls.Load() != 2 || deviceCalls.Load() != 1 {
		t.Fatal("valid scope did not reach the tenant review store", err)
	}
}
