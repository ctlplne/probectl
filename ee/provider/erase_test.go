// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

// fakeLifecycle records erase calls (the core engine seam).
type fakeLifecycle struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeLifecycle) Erase(_ context.Context, tenantID, slug, actor string) (tenantlife.Attestation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, tenantID+"|"+slug+"|"+actor)
	return tenantlife.Attestation{
		FormatVersion: 1, TenantID: tenantID, TenantSlug: slug, Actor: actor,
		Complete: true, ReportSHA256: "deadbeef",
		Stores: []tenantlife.StoreResult{{Store: "postgres", VerifiedZero: true}},
	}, nil
}

// TestProviderErase: the operator-facing S-T5 trigger — admin SoD,
// slug-confirmed, audited, attestation returned.
func TestProviderErase(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	life := &fakeLifecycle{}
	f.h.WithLifecycle(life)
	admin := f.bootstrapAndLoginFast(t)

	// Provision a tenant to erase.
	rec := f.doAuthed(t, admin, http.MethodPost, "/provider/v1/tenants",
		map[string]string{"slug": "doomed-co", "name": "Doomed Co"})
	var tn Tenant
	mustDecode(t, rec, &tn)

	// A wrong confirm string is refused — erasure is irreversible.
	rec = f.doAuthed(t, admin, http.MethodPost, "/provider/v1/tenants/"+tn.ID+"/erase",
		map[string]string{"confirm": "wrong-slug"})
	if rec.Code != http.StatusBadRequest || len(life.calls) != 0 {
		t.Fatalf("wrong confirm: %d calls=%v", rec.Code, life.calls)
	}
	// An unknown tenant is not_found before anything runs.
	if rec = f.doAuthed(t, admin, http.MethodPost, "/provider/v1/tenants/tn_ghost/erase",
		map[string]string{"confirm": "x"}); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown tenant: %d", rec.Code)
	}

	// The confirmed erase runs the core engine and returns the attestation.
	rec = f.doAuthed(t, admin, http.MethodPost, "/provider/v1/tenants/"+tn.ID+"/erase",
		map[string]string{"confirm": "doomed-co"})
	if rec.Code != http.StatusOK {
		t.Fatalf("erase: %d %s", rec.Code, rec.Body.String())
	}
	var att tenantlife.Attestation
	mustDecode(t, rec, &att)
	if !att.Complete || att.TenantSlug != "doomed-co" || att.ReportSHA256 == "" {
		t.Fatalf("attestation: %+v", att)
	}
	if len(life.calls) != 1 || !strings.HasPrefix(life.calls[0], tn.ID+"|doomed-co|operator:root@msp.example") {
		t.Fatalf("engine call: %v", life.calls)
	}
	if f.audit.count("provider.tenant_erase") != 1 {
		t.Fatal("provider-side erase must be audited")
	}

	// SoD: a plain operator cannot erase.
	rec2 := f.doAuthed(t, admin, http.MethodPost, "/provider/v1/operators",
		map[string]string{"email": "op@msp.example", "name": "Op", "role": "operator"})
	var created struct {
		Operator    Operator `json:"operator"`
		EnrollToken string   `json:"enroll_token"`
	}
	mustDecode(t, rec2, &created)
	op := f.activateAndIssue(t, created.Operator)
	if rec = f.doAuthed(t, op, http.MethodPost, "/provider/v1/tenants/"+tn.ID+"/erase",
		map[string]string{"confirm": "doomed-co"}); rec.Code != http.StatusForbidden {
		t.Fatalf("SoD: operator erased a tenant: %d", rec.Code)
	}

	// Without the engine attached (pool-less test server) the route is 503.
	bare := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	tok := bare.bootstrapAndLoginFast(t)
	if rec = bare.doAuthed(t, tok, http.MethodPost, "/provider/v1/tenants/x/erase",
		map[string]string{"confirm": "x"}); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("engine-less erase: %d", rec.Code)
	}
}

// slowSilo provisions like the real silo provisioner does under load: slower
// than the control server's global write timeout.
type slowSilo struct {
	fakeSilo
	delay time.Duration
}

func (s *slowSilo) Provision(ctx context.Context, tenantID, residency string, model tenancy.IsolationModel) error {
	time.Sleep(s.delay)
	return s.fakeSilo.Provision(ctx, tenantID, residency, model)
}

// slowEraseLifecycle erases slower than the global write timeout, as a real
// erasure waiting on every store's synchronous delete does.
type slowEraseLifecycle struct {
	fakeLifecycle
	delay time.Duration
}

func (s *slowEraseLifecycle) Erase(ctx context.Context, tenantID, slug, actor string) (tenantlife.Attestation, error) {
	time.Sleep(s.delay)
	return s.fakeLifecycle.Erase(ctx, tenantID, slug, actor)
}

// TestLongProvisionAndEraseResponsesOutliveTheWriteTimeout (WEB-04): a siloed
// provisioning creates a schema and a database for every plane, and a verified
// erasure waits on every store, so both outlive the control server's short
// global write timeout. Without their own budgets the server reset each
// response while the work finished: the operator saw a failure for a tenant
// that now existed, or lost the erasure attestation.
func TestLongProvisionAndEraseResponsesOutliveTheWriteTimeout(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	f.svc.WithSilo(&slowSilo{delay: 600 * time.Millisecond}, nil)
	f.h.WithLifecycle(&slowEraseLifecycle{delay: 600 * time.Millisecond})
	admin := f.bootstrapAndLoginFast(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: f.h, WriteTimeout: 200 * time.Millisecond}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	post := func(path, body string) (int, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+admin)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s: the response was reset: %v", path, err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("POST %s: the response was cut off: %v", path, err)
		}
		return resp.StatusCode, string(raw)
	}

	code, body := post("/provider/v1/tenants", `{"slug":"slow-co","name":"Slow Co","isolation_model":"hybrid"}`)
	var tn Tenant
	if code != http.StatusCreated || json.Unmarshal([]byte(body), &tn) != nil || tn.ID == "" {
		t.Fatalf("the slow hybrid provisioning's answer = %d %q", code, body)
	}
	if code, body = post("/provider/v1/tenants/"+tn.ID+"/erase", `{"confirm":"slow-co"}`); code != http.StatusOK ||
		!strings.Contains(body, `"report_sha256":"deadbeef"`) {
		t.Fatalf("the slow erasure's attestation = %d %q", code, body)
	}
}
