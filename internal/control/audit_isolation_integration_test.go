// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The real-stack receipt for the audit foundation (F23) and the tamper-evidence
// claim (CLM-TAMPER-EVIDENT). What was bound before proved one fresh tenant's
// chain appends and verifies; it could not distinguish "isolated" from "both
// tenants happen to look alike", and it never went through the public API.
//
// Two properties this asserts that the previous receipt could not:
//
//   - The tenants hold DIFFERENT NUMBERS of differently-valued events. A receipt
//     where both sides have identical counts and payloads cannot fail if one
//     tenant's rows were substituted for the other's — the assertion passes
//     either way. Here A has 3 and B has 5, each with its own marker, so a
//     substitution changes the count AND the content.
//   - Tampering is CONTAINED. Corrupting A's chain must make A's verification
//     fail and leave B's intact. A verifier that reported "the audit log is
//     broken" globally would be useless for a multi-tenant deployment, and a
//     single-tenant test cannot tell the two behaviors apart.
//
// Verification runs through GET /v1/audit/verify and listing through GET
// /v1/audit — the surface an operator actually has — rather than by calling the
// store, so the tenant fence is exercised where requests enter. The same two
// properties are then re-proved through the real CLI (`probectl audit verify`,
// `probectl audit list`) against the live server, because "the operator can see
// it" is the claim, and the CLI is how most operators will.
func TestTwoTenantAndProviderAuditStreamsIsolateAndContainTampering(t *testing.T) {
	h, db := setupAPI(t)
	ctx := context.Background()

	tenantA := freshTenant(t, db, "auditiso-a")
	tenantB := freshTenant(t, db, "auditiso-b")
	markerA := fmt.Sprintf("only-in-a-%d", time.Now().UnixNano())
	markerB := fmt.Sprintf("only-in-b-%d", time.Now().UnixNano())

	// Deliberately different cardinality: 3 vs 5.
	seedTenantAudit(t, db, tenantA, markerA, 3)
	seedTenantAudit(t, db, tenantB, markerB, 5)

	// ── 1. each tenant sees its own events, by count AND by value ──────────
	eventsA := listAudit(t, h, tenantA)
	eventsB := listAudit(t, h, tenantB)
	if len(eventsA) != 3 || len(eventsB) != 5 {
		t.Fatalf("seeded cardinality did not survive the API: A=%d (want 3), B=%d (want 5)", len(eventsA), len(eventsB))
	}
	assertMarkers(t, "tenant A", eventsA, markerA, markerB)
	assertMarkers(t, "tenant B", eventsB, markerB, markerA)

	// ── 2. both chains verify clean through the public API ────────────────
	if ok, detail := verifyAudit(t, h, tenantA); !ok {
		t.Fatalf("tenant A chain should verify clean: %s", detail)
	}
	if ok, detail := verifyAudit(t, h, tenantB); !ok {
		t.Fatalf("tenant B chain should verify clean: %s", detail)
	}

	// ── 3. tamper A at the storage layer, as a superuser would ────────────
	// This bypasses the append-only RLS policy on purpose: the question is
	// whether the hash chain notices a row that was changed underneath it.
	tag, err := db.Pool().Exec(ctx,
		`UPDATE audit_events SET actor = 'mallory' WHERE tenant_id = $1 AND seq = 2`, tenantA)
	if err != nil {
		t.Fatalf("tamper: %v", err)
	}
	if tag.RowsAffected() != 1 {
		t.Fatalf("tamper touched %d rows, want exactly 1 — the chain was not modified, so the assertions below would prove nothing", tag.RowsAffected())
	}

	if ok, detail := verifyAudit(t, h, tenantA); ok {
		t.Error("tenant A's chain was tampered with and the verification API still reported it intact")
	} else if !strings.Contains(strings.ToLower(detail), "chain") && detail == "" {
		t.Errorf("tenant A verification failed without saying why: %q", detail)
	}

	// Containment: B is a different chain and must be unaffected.
	if ok, detail := verifyAudit(t, h, tenantB); !ok {
		t.Errorf("tampering with tenant A's chain invalidated tenant B's: %s", detail)
	}
	if got := listAudit(t, h, tenantB); len(got) != 5 {
		t.Errorf("tenant B sees %d events after tampering with A, want 5", len(got))
	}

	// ── 4. the same answers through the real CLI against the live server ──
	// A tampered chain has to be visible to the operator who runs the command,
	// not only to a test that calls the handler.
	live := httptest.NewServer(h)
	defer live.Close()
	outA, codeA := runCLI(t, live.URL, tenantA, "audit", "verify")
	if codeA == 0 {
		t.Errorf("`probectl audit verify` exited 0 for the tampered tenant: %s", outA)
	}
	outB, codeB := runCLI(t, live.URL, tenantB, "audit", "verify")
	if codeB != 0 {
		t.Errorf("`probectl audit verify` exited %d for the intact tenant: %s", codeB, outB)
	}
	// And the CLI listing respects the same fence as the API.
	listB, codeListB := runCLI(t, live.URL, tenantB, "audit", "list")
	if codeListB != 0 {
		t.Fatalf("`probectl audit list` exited %d: %s", codeListB, listB)
	}
	if !strings.Contains(listB, markerB) {
		t.Errorf("`probectl audit list` for tenant B does not show its own events: %s", listB)
	}
	if strings.Contains(listB, markerA) {
		t.Errorf("`probectl audit list` for tenant B shows tenant A's events — cross-tenant leakage through the CLI: %s", listB)
	}

	// ── 5. the provider stream is a separate privilege domain ─────────────
	providerMarker := fmt.Sprintf("provider-only-%d", time.Now().UnixNano())
	if _, err := audit.ProviderAppend(ctx, db.Pool(), "provider-operator", "provider.tenant.list", providerMarker, map[string]any{"marker": providerMarker}); err != nil {
		t.Fatalf("provider append: %v", err)
	}
	if err := audit.ProviderVerify(ctx, db.Pool()); err != nil {
		t.Errorf("provider chain should verify independently of a tampered tenant chain: %v", err)
	}
	for _, tc := range []struct {
		name   string
		tenant string
	}{{"tenant A", tenantA}, {"tenant B", tenantB}} {
		for _, ev := range listAudit(t, h, tc.tenant) {
			if strings.Contains(ev.Target, providerMarker) {
				t.Errorf("%s can see a provider-stream event through /v1/audit: %s", tc.name, ev.Target)
			}
		}
	}
}

// runCLI drives the real CLI in-process against a live server, the way an
// operator's shell would: same argument parsing, same client, same env contract.
func runCLI(t *testing.T, baseURL, tenant string, args ...string) (string, int) {
	t.Helper()
	env := map[string]string{"PROBECTL_API_URL": baseURL, "PROBECTL_TENANT": tenant}
	var out bytes.Buffer
	code := cli.RunWithStdin(args, func(k string) string { return env[k] }, strings.NewReader(""), &out, &out)
	return out.String(), code
}

// seedTenantAudit appends n events carrying marker, through the tenant fence.
func seedTenantAudit(t *testing.T, db *store.DB, tenant, marker string, n int) {
	t.Helper()
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		for i := 0; i < n; i++ {
			if _, err := audit.TenantAppend(ctx, sc, "actor-"+marker, "tenant.update",
				fmt.Sprintf("%s-%d", marker, i), map[string]any{"marker": marker, "i": i}); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed %d audit events for %s: %v", n, tenant, err)
	}
}

func listAudit(t *testing.T, h http.Handler, tenant string) []audit.Event {
	t.Helper()
	rec := apiReq(t, h, http.MethodGet, "/v1/audit?limit=100", tenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/audit as %s: %d %s", tenant, rec.Code, rec.Body)
	}
	var body struct {
		Items []audit.Event `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode audit list: %v", err)
	}
	return body.Items
}

func verifyAudit(t *testing.T, h http.Handler, tenant string) (bool, string) {
	t.Helper()
	rec := apiReq(t, h, http.MethodGet, "/v1/audit/verify", tenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/audit/verify as %s: %d %s", tenant, rec.Code, rec.Body)
	}
	var body struct {
		OK     bool   `json:"ok"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode verify: %v", err)
	}
	return body.OK, body.Detail
}

// assertMarkers proves the listing is the tenant's own and ONLY its own: every
// event carries want, and none carries notWant.
func assertMarkers(t *testing.T, who string, events []audit.Event, want, notWant string) {
	t.Helper()
	if len(events) == 0 {
		t.Fatalf("%s: no events returned, so the marker assertions below would be vacuous", who)
	}
	for _, ev := range events {
		blob := ev.Actor + " " + ev.Action + " " + ev.Target
		if !strings.Contains(blob, want) {
			t.Errorf("%s: event %d does not carry its own marker %q: %s", who, ev.Seq, want, blob)
		}
		if strings.Contains(blob, notWant) {
			t.Errorf("%s: event %d carries the OTHER tenant's marker %q — cross-tenant leakage: %s", who, ev.Seq, notWant, blob)
		}
	}
}
