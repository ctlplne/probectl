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
	"github.com/ctlplne/probectl/internal/secrets"
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
	var invalidResponse atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		if invalidResponse.Load() {
			_, _ = w.Write([]byte(`{"status":"ok","devices":[`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "nms-source-ca.pem")
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	type fixture struct{ tenant, contextID, sourceID, planID string }
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
	start := func(f fixture) *httptest.ResponseRecorder {
		t.Helper()
		return apiReq(t, h, http.MethodPost, "/v1/nms-imports/live-plans", f.tenant,
			map[string]string{"context_id": f.contextID, "instance_ref": "same-lab"})
	}
	srv.cfg.NMSImportApprovedCIDRs = nil
	if response := start(left); response.Code != http.StatusServiceUnavailable || requests.Load() != 0 {
		t.Fatalf("removed deployment policy started live plan: %d %s", response.Code, response.Body.String())
	}
	srv.cfg.NMSImportApprovedCIDRs = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	planIDs := make(map[string]bool)
	for _, f := range []*fixture{&left, &right} {
		response := start(*f)
		var out struct {
			PlanID string `json:"plan_id"`
			State  string `json:"state"`
		}
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &out) != nil ||
			out.PlanID == "" || out.State != "capturing" || planIDs[out.PlanID] {
			t.Fatalf("start tenant source plan: %d %s", response.Code, response.Body.String())
		}
		planIDs[out.PlanID] = true
		f.planID = out.PlanID
	}
	if requests.Load() != 0 {
		t.Fatal("starting an inert plan contacted the vendor")
	}
	wrongContext := left
	wrongContext.contextID = right.contextID
	if response := configure(wrongContext, ref(a)); response.Code != http.StatusNotFound {
		t.Fatalf("foreign routing context disclosed: %d %s", response.Code, response.Body.String())
	}
	if response := start(wrongContext); response.Code != http.StatusNotFound {
		t.Fatalf("foreign routing context started a plan: %d %s", response.Code, response.Body.String())
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
	if response := start(left); response.Code != http.StatusForbidden {
		t.Fatalf("context ABAC did not deny plan start: %d %s", response.Code, response.Body.String())
	}
	for i := 0; i < 2; i++ {
		if response := disable(right); response.Code != http.StatusNoContent {
			t.Fatalf("idempotent source disable: %d %s", response.Code, response.Body.String())
		}
	}
	if response := start(right); response.Code != http.StatusNotFound {
		t.Fatalf("disabled source started a plan: %d %s", response.Code, response.Body.String())
	}
	if requests.Load() != 0 {
		t.Fatalf("source configuration or disable made %d vendor requests", requests.Load())
	}
	advance := func(f fixture, contextID string) *httptest.ResponseRecorder {
		t.Helper()
		return apiReq(t, h, http.MethodPost, "/v1/nms-imports/"+f.planID+"/advance",
			f.tenant, map[string]string{"context_id": contextID})
	}
	verifyBeforeApply := func(f fixture, contextID string) *httptest.ResponseRecorder {
		t.Helper()
		return apiReq(t, h, http.MethodPost, "/v1/nms-imports/"+f.planID+"/verify-before-apply",
			f.tenant, map[string]string{"context_id": contextID,
				"snapshot_hash": strings.Repeat("a", 64), "review_hash": strings.Repeat("b", 64)})
	}
	apply := func(f fixture, contextID string) *httptest.ResponseRecorder {
		t.Helper()
		return apiReq(t, h, http.MethodPost, "/v1/nms-imports/"+f.planID+"/apply",
			f.tenant, map[string]string{"context_id": contextID,
				"snapshot_hash": strings.Repeat("a", 64), "review_hash": strings.Repeat("b", 64)})
	}
	if response := advance(left, right.contextID); response.Code != http.StatusNotFound || requests.Load() != 0 {
		t.Fatalf("foreign context advanced source: %d requests=%d", response.Code, requests.Load())
	}
	if response := verifyBeforeApply(left, right.contextID); response.Code != http.StatusNotFound || requests.Load() != 0 {
		t.Fatalf("foreign context reverified source: %d requests=%d", response.Code, requests.Load())
	}
	if response := apply(left, right.contextID); response.Code != http.StatusNotFound || requests.Load() != 0 {
		t.Fatalf("foreign context applied source: %d requests=%d", response.Code, requests.Load())
	}
	if response := advance(left, left.contextID); response.Code != http.StatusForbidden || requests.Load() != 0 {
		t.Fatalf("context policy allowed source advance: %d requests=%d", response.Code, requests.Load())
	}
	if response := verifyBeforeApply(left, left.contextID); response.Code != http.StatusForbidden || requests.Load() != 0 {
		t.Fatalf("context policy allowed source re-verification: %d requests=%d", response.Code, requests.Load())
	}
	if response := apply(left, left.contextID); response.Code != http.StatusForbidden || requests.Load() != 0 {
		t.Fatalf("context policy allowed source apply: %d requests=%d", response.Code, requests.Load())
	}
	srv.abac = nil
	if response := advance(left, left.contextID); response.Code != http.StatusServiceUnavailable || requests.Load() != 0 {
		t.Fatalf("missing credential resolver reached source: %d requests=%d", response.Code, requests.Load())
	}
	if response := verifyBeforeApply(left, left.contextID); response.Code != http.StatusServiceUnavailable || requests.Load() != 0 {
		t.Fatalf("missing credential resolver reached re-verification: %d requests=%d", response.Code, requests.Load())
	}
	srv.WithSecrets(nmsImportTestResolver{})
	if response := verifyBeforeApply(left, left.contextID); response.Code != http.StatusNotFound || requests.Load() != 0 {
		t.Fatalf("unreviewed plan reached source re-verification: %d requests=%d", response.Code, requests.Load())
	}
	if response := apply(left, left.contextID); response.Code != http.StatusNotFound || requests.Load() != 0 {
		t.Fatalf("unreviewed plan applied: %d requests=%d", response.Code, requests.Load())
	}
	invalidResponse.Store(true)
	if response := advance(left, left.contextID); response.Code != http.StatusConflict || requests.Load() != 1 ||
		strings.Contains(response.Body.String(), "fixture") {
		t.Fatalf("incomplete source response became actionable: %d requests=%d body=%s",
			response.Code, requests.Load(), response.Body.String())
	}
}

type nmsImportTestResolver struct{}

func (nmsImportTestResolver) Health() []secrets.BackendHealth { return nil }

func (nmsImportTestResolver) ResolveBytesUncached(context.Context, string) ([]byte, func(), error) {
	value := []byte("fixture")
	return value, func() {
		for i := range value {
			value[i] = 0
		}
	}, nil
}
