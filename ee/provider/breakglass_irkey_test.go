// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.

package provider

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	coreaudit "github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/license"
)

// irKeylessAudit behaves like the production sink for a tenant whose IR public
// key is absent from PROBECTL_IR_PUBLIC_KEY_DIR: the break-glass append fails
// with the audit layer's wrapped ErrIRKeyUnavailable.
type irKeylessAudit struct{ *memAudit }

func (irKeylessAudit) AppendBreakGlass(
	context.Context, string, string, string, map[string]any, coreaudit.IRAttribution,
) error {
	return fmt.Errorf(
		"append encrypted IR attribution: audit: resolve tenant IR wrapping key: %w: tenant IR public key is absent",
		coreaudit.ErrIRKeyUnavailable,
	)
}

// TestBreakGlassRequestWithoutTenantIRKeyIsAnActionableConflict (DPR-036):
// before this fix the operator got a bare 500 "internal error" and no clue
// that a per-tenant key had to exist. Now the request is a 409 that names the
// tenant, the keyring file, and the two commands that create it — and, as
// before, nothing is persisted.
func TestBreakGlassRequestWithoutTenantIRKeyIsAnActionableConflict(t *testing.T) {
	const tenant = "88929fbe-28e5-4f0a-898e-6c4302c55e57"
	store := NewMemStore()
	mem := &memAudit{}
	now := time.Now()
	svc, err := NewService(
		store,
		irKeylessAudit{mem},
		licenseManager(t, license.TierMSP, 0, 90*24*time.Hour),
		fakeTelemetry{byTenant: map[string][]string{}},
		testEnvelope(t),
		4*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{store: store, svc: svc, audit: mem, now: &now}
	svc.withClock(func() time.Time { return *f.now })
	f.tenantAuth = &fakeTenantAuth{
		sessions:   map[string]*auth.Session{},
		perms:      map[string][]string{},
		attributes: map[string]map[string]string{},
		policies:   map[string][]auth.Policy{},
		policyErr:  map[string]error{},
	}
	f.h = NewHandler(svc, NewSessions(nil), f.tenantAuth, slog.New(slog.NewTextHandler(io.Discard, nil)), bootToken, false)
	token := f.bootstrapAndLoginFast(t)

	rec := f.doAuthed(t, token, http.MethodPost, "/provider/v1/breakglass",
		map[string]any{"tenant_id": tenant, "reason": "design-partner drill", "ttl_minutes": 15})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		`"code":"ir_key_unavailable"`,
		tenant + ".pem",
		"PROBECTL_IR_PUBLIC_KEY_DIR",
		"probectl audit ir-keygen " + tenant,
		"probectl-control ir-key-install " + tenant,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("body %s must contain %q", body, want)
		}
	}
	if strings.Contains(body, "internal error") {
		t.Fatalf("a missing tenant key is an operator precondition, not an internal error: %s", body)
	}
	grants, err := store.ListGrants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 0 {
		t.Fatalf("a refused request must persist no grant, got %d", len(grants))
	}
	if mem.count("provider.breakglass_request") != 0 {
		t.Fatal("no provider audit row may exist for the refused request")
	}
}

// TestTenantIRKeyErrorPassesUnrelatedFailuresThrough keeps a real audit outage
// a 5xx: only the key-absent case becomes the operator-facing conflict.
func TestTenantIRKeyErrorPassesUnrelatedFailuresThrough(t *testing.T) {
	if got := tenantIRKeyError("t", nil); got != nil {
		t.Fatalf("nil must stay nil, got %v", got)
	}
	if got := tenantIRKeyError("t", errAuditUnavailable); got != errAuditUnavailable {
		t.Fatalf("unrelated error must pass through unchanged, got %v", got)
	}
}
