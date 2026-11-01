// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
)

func TestNMSImportSourceRouteRequiresTenantContextAndDeploymentPolicy(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	a, b := freshTenant(t, db, "nms-source-a"), freshTenant(t, db, "nms-source-b")
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id=ANY($1::uuid[])`, []string{a, b}); err != nil {
			t.Errorf("remove NMS source fixtures: %v", err)
		}
	})
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "nms-source-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	type fixture struct{ tenant, contextID, sourceID string }
	makeContext := func(tenant string) fixture {
		t.Helper()
		response := apiReq(t, h, http.MethodPost, "/v1/entity-contexts", tenant,
			map[string]string{"site_label": "West DC", "vrf_label": "Private"})
		var routing entity.ContextRecord
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &routing) != nil {
			t.Fatalf("create import context: %d %s", response.Code, response.Body.String())
		}
		return fixture{tenant: tenant, contextID: routing.ContextID}
	}
	left, right := makeContext(a), makeContext(b)
	prefix := "vault:probectl/nms/{tenant}/"
	configure := func(f fixture, ref string) *httptest.ResponseRecorder {
		t.Helper()
		return apiReq(t, h, http.MethodPost, "/v1/nms-imports/sources", f.tenant,
			map[string]string{"context_id": f.contextID, "instance_ref": "same-lab",
				"https_origin": server.URL, "credential_ref": ref})
	}
	ref := func(tenant string) string { return strings.Replace(prefix, "{tenant}", tenant, 1) + "token" }
	if response := configure(left, ref(a)); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("default-disabled live import: %d %s", response.Code, response.Body.String())
	}
	srv.cfg.NMSImportApprovedCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	srv.cfg.NMSImportRefPrefix = prefix
	srv.cfg.NMSImportCAFile = caFile
	srv.cfg.NMSImportTimeout = time.Second
	for _, f := range []*fixture{&left, &right} {
		response := configure(*f, ref(f.tenant))
		var out struct {
			SourceID string `json:"source_id"`
		}
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &out) != nil ||
			out.SourceID == "" || strings.Contains(response.Body.String(), ref(f.tenant)) ||
			strings.Contains(response.Body.String(), server.URL) {
			t.Fatalf("configure tenant source: %d %s", response.Code, response.Body.String())
		}
		f.sourceID = out.SourceID
	}
	if left.sourceID == right.sourceID || requests.Load() != 0 {
		t.Fatalf("sources collided or configuration called vendor: a=%s b=%s requests=%d",
			left.sourceID, right.sourceID, requests.Load())
	}
	wrongContext := left
	wrongContext.contextID = right.contextID
	if response := configure(wrongContext, ref(a)); response.Code != http.StatusNotFound {
		t.Fatalf("foreign routing context disclosed: %d %s", response.Code, response.Body.String())
	}
	if response := configure(left, "env:UNSAFE_SECRET"); response.Code != http.StatusBadRequest ||
		strings.Contains(response.Body.String(), "UNSAFE_SECRET") {
		t.Fatalf("unapproved reference accepted or echoed: %d %s", response.Code, response.Body.String())
	}
	srv.abac = &abacCache{load: func(_ context.Context, tenant string) ([]auth.Policy, error) {
		if tenant != a {
			return nil, nil
		}
		return []auth.Policy{{Name: "deny west import source", Enabled: true,
			Effect: auth.PolicyDeny, Permission: permNMSImportWrite,
			Resource: map[string]string{"site_label": "West DC"}}}, nil
	}}
	disable := func(f fixture) *httptest.ResponseRecorder {
		t.Helper()
		return apiReq(t, h, http.MethodPost, "/v1/nms-imports/sources/same-lab/disable", f.tenant,
			map[string]string{"context_id": f.contextID})
	}
	if response := disable(left); response.Code != http.StatusForbidden {
		t.Fatalf("context ABAC did not deny source disable: %d %s", response.Code, response.Body.String())
	}
	for i := 0; i < 2; i++ {
		if response := disable(right); response.Code != http.StatusNoContent {
			t.Fatalf("idempotent source disable: %d %s", response.Code, response.Body.String())
		}
	}
	if requests.Load() != 0 {
		t.Fatalf("source configuration or disable made %d vendor requests", requests.Load())
	}
}
