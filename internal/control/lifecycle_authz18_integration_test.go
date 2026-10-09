// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// authz18IRLifecycle is a no-op IRAttributionLifecycle: the engine requires the
// crypto-shred seam before any database-backed erasure, and this test exercises
// the attribution plumbing, not the IR key domain. It keeps no Postgres state,
// so a freshly created tenant has no retained IR evidence rows to clean up.
type authz18IRLifecycle struct{}

func (authz18IRLifecycle) Plan(context.Context, string, string) (string, error) {
	return "authz18-ir-shred-plan", nil
}
func (authz18IRLifecycle) Execute(context.Context, string, string, string) error { return nil }
func (authz18IRLifecycle) RecordFailure(context.Context, string, string, string, string) error {
	return nil
}

// TestLifecycleEraseAttributesHumanPrincipal is the AUTHZ-18 regression for the
// destructive-action attribution leak: the full-tenant erase handler attributed
// its attestation and every provider audit event to a synthetic "tenant:<id>"
// actor instead of the authenticated human operator, so an irreversible erase
// left no record of who performed it.
//
// Driving the real POST /v1/lifecycle/erase handler against a live Postgres,
// the returned attestation and the lifecycle.erase_fence / lifecycle.erase
// provider audit rows must all name the human principal (dev@probectl.local),
// never "tenant:<id>". RED before the fix (handler passed "tenant:"+tid),
// GREEN after.
func TestLifecycleEraseAttributesHumanPrincipal(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	// The erase enumerates the live public tenant-table catalog; serialize with
	// the other integration tests that temporarily mutate that catalog.
	testsupport.LockPostgresPublicCatalog(t, db.Pool())
	ctx := context.Background()

	providerSink := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, db.Pool(), actor, action, target, data)
		return err
	}
	engine := tenantlife.New(
		db.Pool(), flowstore.NewMemory(), nil, tsdb.NewMemory(),
		providerSink, "test backups", testLog(),
	).WithIRAttributionLifecycle(authz18IRLifecycle{})
	srv.WithTenantLife(engine)
	h := srv.Handler()

	slug := fmt.Sprintf("authz18-erase-%d", time.Now().UnixNano())
	tn, err := store.NewTenants(db.Pool()).Create(ctx, slug, slug)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.Pool().Exec(context.Background(),
			`DELETE FROM tenants WHERE id = $1`, tn.ID); err != nil {
			t.Errorf("cleanup erased tenant tombstone: %v", err)
		}
	})

	rec := apiReq(t, h, http.MethodPost, "/v1/lifecycle/erase", tn.ID,
		map[string]any{"confirm": slug})
	if rec.Code != http.StatusOK {
		t.Fatalf("erase = %d: %s", rec.Code, rec.Body)
	}
	var att struct {
		Actor    string `json:"actor"`
		Complete bool   `json:"complete"`
	}
	mustJSON(t, rec, &att)
	if !att.Complete {
		t.Fatalf("erase attestation incomplete: %s", rec.Body)
	}
	// The attestation names the authenticated human operator, not "tenant:<id>".
	if att.Actor != "dev@probectl.local" {
		t.Fatalf("attestation actor = %q, want human principal dev@probectl.local", att.Actor)
	}
	if strings.HasPrefix(att.Actor, "tenant:") {
		t.Fatalf("attestation actor is the synthetic tenant actor %q", att.Actor)
	}

	// Every provider audit event the erase emitted names the human too.
	for _, action := range []string{"lifecycle.erase_fence", "lifecycle.erase"} {
		var actor string
		if err := db.Pool().QueryRow(ctx,
			`SELECT actor FROM provider_audit_events
			  WHERE action = $1 AND target = $2
			  ORDER BY seq DESC LIMIT 1`, action, tn.ID).Scan(&actor); err != nil {
			t.Fatalf("read provider %s event: %v", action, err)
		}
		if actor != "dev@probectl.local" {
			t.Fatalf("provider %s actor = %q, want human principal dev@probectl.local (not tenant:<id>)", action, actor)
		}
	}
}

// TestLifecycleRetentionRejectsBelowProfileMinimum is the AUTHZ-18 regression
// for the retention floor: a production deployment profile carries a compliance
// obligation to keep the audit trail, but the retention handler accepted an
// audit_retention_days below that profile minimum (the operator had not set the
// explicit PROBECTL_AUDIT_RETENTION_MIN floor). A sub-minimum value must be
// rejected as a validation error (422). RED before the fix (accepted / 200),
// GREEN after.
func TestLifecycleRetentionRejectsBelowProfileMinimum(t *testing.T) {
	srv := testServer(fakePinger{})
	srv.cfg.DeploymentProfile = "multi-tenant" // production profile: mandates a floor
	fake := &fakeTenantLifecycle{policy: tenantlife.RetentionPolicy{}}
	srv.tenantLife = fake

	// Below the profile-mandated minimum -> 422, and the engine is never asked
	// to set it.
	rec := lifecycleReq(t, srv, http.MethodPut, "/v1/lifecycle/retention",
		map[string]any{"audit_retention_days": 1})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("PUT audit_retention_days=1 under the multi-tenant profile = %d, want 422: %s",
			rec.Code, rec.Body.String())
	}
	if fake.set.AuditRetentionDays != nil {
		t.Fatalf("engine was asked to persist a sub-minimum retention: %+v", fake.set)
	}

	// At/above the profile minimum -> accepted (not 422).
	if rec := lifecycleReq(t, srv, http.MethodPut, "/v1/lifecycle/retention",
		map[string]any{"audit_retention_days": 30}); rec.Code == http.StatusUnprocessableEntity {
		t.Fatalf("PUT audit_retention_days=30 (== profile minimum) was rejected: %s", rec.Body.String())
	}
}

// TestTenantErasureResponseOutlivesTheWriteTimeout (WEB-04): a full-tenant
// erasure routinely runs past the server's global write timeout. Without its
// own budget the server reset the response while the erasure finished, and
// the tenant admin never received the attestation.
func TestTenantErasureResponseOutlivesTheWriteTimeout(t *testing.T) {
	srv, db := setupAPIServerWithLatest(t, nil)
	ctx := context.Background()
	slug := fmt.Sprintf("web04-erase-%d", time.Now().UnixNano())
	tn, err := store.NewTenants(db.Pool()).Create(ctx, slug, slug)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(context.Background(), `DELETE FROM tenants WHERE id = $1`, tn.ID)
	})
	srv.tenantLife = &slowLifecycle{delay: 600 * time.Millisecond}
	base := serveWithWriteTimeout(t, srv.Handler(), 200*time.Millisecond)

	req, err := http.NewRequest(http.MethodPost, base+"/v1/lifecycle/erase", strings.NewReader(`{"confirm":"`+slug+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Probectl-Tenant", tn.ID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("the erasure's response was reset: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"report_sha256":"slow-receipt"`) {
		t.Fatalf("the erasure's attestation did not arrive: %d %q %v", resp.StatusCode, body, err)
	}
}
