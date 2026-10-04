// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// memGovStore is an in-memory GovernanceStore for the handler tests (the PG
// round-trip is covered by ee/governance's integration leg).
type memGovStore struct {
	pols map[string]govern.Policy
}

func newMemGov() *memGovStore { return &memGovStore{pols: map[string]govern.Policy{}} }

func (m *memGovStore) PolicyFor(_ context.Context, tenantID string) (govern.Policy, bool, error) {
	p, ok := m.pols[tenantID]
	return p, ok, nil
}
func (m *memGovStore) Upsert(_ context.Context, tenantID string, pol govern.Policy, _ string) error {
	m.pols[tenantID] = pol
	return nil
}

// UpsertAudited mirrors the PG transaction (ee/governance.Store.UpsertAudited):
// the audit append and the policy write commit or roll back together, so a
// failing audit leaves the policy unchanged (AUD-11).
func (m *memGovStore) UpsertAudited(ctx context.Context, tenantID string, pol govern.Policy, _ string, auditTx func(context.Context, tenancy.Querier) error) error {
	if err := auditTx(ctx, nil); err != nil {
		return err
	}
	m.pols[tenantID] = pol
	return nil
}

// govFailAudit wraps memAudit and fails only the governance_set append once
// armed, so the AUD-11 rollback regression can exercise the real handler
// (bootstrap/login still audit normally before the failure is armed).
type govFailAudit struct {
	*memAudit
	failGovernance bool
}

func (a *govFailAudit) Append(ctx context.Context, actor, action, target string, data map[string]any) error {
	if a.failGovernance && action == "provider.governance_set" {
		return errAuditUnavailable
	}
	return a.memAudit.Append(ctx, actor, action, target, data)
}

// TestGovernancePutRollsBackOnAuditFailure is the AUD-11 atomicity regression:
// a consent/redaction change must NOT persist when the provider audit append
// fails. Pre-fix the handler committed the upsert and then appended separately,
// so a failing sink left the new policy stored with no audit record.
func TestGovernancePutRollsBackOnAuditFailure(t *testing.T) {
	sink := &govFailAudit{memAudit: &memAudit{}}
	f := newFixtureWithAudit(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour), sink)
	store := newMemGov()
	store.pols["tn_1"] = govern.Policy{AIRemoteEgress: false, RedactFrom: govern.ClassPII}
	f.h.WithGovernance(&Governance{Store: store})
	token := f.bootstrapAndLoginFast(t)

	sink.failGovernance = true
	// A redaction change (the provider CAN set these) must still roll back with
	// the audit append — ai_remote_egress is tenant-only now, so the atomicity
	// regression uses the redaction floor rather than the consent bit.
	rec := f.doAuthed(t, token, http.MethodPut, "/provider/v1/tenants/tn_1/governance", map[string]any{
		"redact_from": "restricted", "redact_export": true,
	})
	if rec.Code == http.StatusOK {
		t.Fatalf("AUD-11: governance PUT must fail when the audit append fails; got 200")
	}
	if got := store.pols["tn_1"]; got.RedactFrom != govern.ClassPII || got.RedactExport {
		t.Fatalf("AUD-11: redaction change persisted despite a failing audit sink: %+v", got)
	}
}

// TestGovernancePutAuditRecordsConsentOldNew is the AUD-11 audit-completeness
// regression: the provider governance_set event must carry ai_remote_egress
// old/new (the prior event omitted the consent value entirely).
func TestGovernancePutAuditRecordsConsentOldNew(t *testing.T) {
	f, store, token := governedFixture(t)
	// The provider cannot CHANGE the tenant's consent, but a provider governance
	// write (here a redaction change) must still record the consent's old/new in
	// the audit event so the state is transparent — unchanged, so old==new.
	store.pols["tn_1"] = govern.Policy{AIRemoteEgress: true}

	rec := f.doAuthed(t, token, http.MethodPut, "/provider/v1/tenants/tn_1/governance", map[string]any{
		"redact_from": "restricted",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	data := f.audit.lastData("provider.governance_set")
	if data == nil {
		t.Fatalf("AUD-11: no provider.governance_set audit event recorded")
	}
	egress, ok := data["ai_remote_egress"].(map[string]any)
	if !ok {
		t.Fatalf("AUD-11: audit event omits ai_remote_egress old/new: %+v", data)
	}
	if egress["old"] != true || egress["new"] != true {
		t.Fatalf("AUD-11: ai_remote_egress old/new wrong (provider must preserve tenant consent): %+v", egress)
	}
	if !store.pols["tn_1"].AIRemoteEgress {
		t.Fatalf("AUD-11: provider write must preserve the tenant's ai_remote_egress=true")
	}
}

// TestProviderCannotSetTenantAIRemoteEgress is the AUD-11 access-control
// regression: a provider/MSP operator must not enable (or weaken) a tenant's
// remote-AI egress consent from the provider console. Pre-fix the handler
// accepted ai_remote_egress from the provider body and upserted it, so this
// POST-shaped escalation returned 200 and flipped the tenant's consent.
func TestProviderCannotSetTenantAIRemoteEgress(t *testing.T) {
	f, store, token := governedFixture(t)
	store.pols["tn_1"] = govern.Policy{AIRemoteEgress: false, RedactFrom: govern.ClassPII}

	// Attempt to ENABLE a tenant's consent from the provider console → refused.
	rec := f.doAuthed(t, token, http.MethodPut, "/provider/v1/tenants/tn_1/governance", map[string]any{
		"ai_remote_egress": true,
	})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "forbidden_tenant_consent") {
		t.Fatalf("AUD-11: provider enabling ai_remote_egress must be 403 forbidden_tenant_consent; got %d %s", rec.Code, rec.Body.String())
	}
	if store.pols["tn_1"].AIRemoteEgress {
		t.Fatalf("AUD-11: provider PUT flipped the tenant's consent to true")
	}

	// Attempt to WEAKEN an enabled consent from the provider console → refused.
	store.pols["tn_1"] = govern.Policy{AIRemoteEgress: true}
	if rec := f.doAuthed(t, token, http.MethodPut, "/provider/v1/tenants/tn_1/governance",
		map[string]any{"ai_remote_egress": false}); rec.Code != http.StatusForbidden {
		t.Fatalf("AUD-11: provider changing consent (true→false) must be 403; got %d", rec.Code)
	}
	if !store.pols["tn_1"].AIRemoteEgress {
		t.Fatalf("AUD-11: provider PUT weakened the tenant's consent")
	}

	// A provider redaction change that OMITS ai_remote_egress is allowed and
	// preserves the tenant's consent.
	if rec := f.doAuthed(t, token, http.MethodPut, "/provider/v1/tenants/tn_1/governance",
		map[string]any{"redact_from": "restricted"}); rec.Code != http.StatusOK {
		t.Fatalf("AUD-11: provider redaction change (no consent field) must be 200; got %d %s", rec.Code, rec.Body.String())
	}
	if !store.pols["tn_1"].AIRemoteEgress {
		t.Fatalf("AUD-11: omitted ai_remote_egress must preserve the tenant's prior consent")
	}
}

func governedFixture(t *testing.T) (*fixture, *memGovStore, string) {
	t.Helper()
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, 90*24*time.Hour))
	store := newMemGov()
	f.h.WithGovernance(&Governance{Store: store}) // Pool nil → composed PG reads skipped
	token := f.bootstrapAndLoginFast(t)
	return f, store, token
}

// TestGovernanceView: the composed view reports the EFFECTIVE classification
// for every category (IPs-as-PII by default) + the redaction floor.
func TestGovernanceView(t *testing.T) {
	f, store, token := governedFixture(t)
	store.pols["tn_1"] = govern.Policy{
		Overrides:    map[govern.Category]govern.Class{govern.CatHostname: govern.ClassPII},
		RedactFrom:   govern.ClassPII,
		RedactExport: true,
	}
	rec := f.doAuthed(t, token, http.MethodGet, "/provider/v1/tenants/tn_1/governance", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("view: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Classifications map[string]string `json:"classifications"`
		RedactFrom      string            `json:"redact_from"`
		RedactExport    bool              `json:"redact_export"`
		BYOK            string            `json:"byok"`
	}
	mustDecode(t, rec, &out)
	if out.Classifications["ip_address"] != "pii" {
		t.Fatalf("ip_address must classify as pii: %+v", out.Classifications)
	}
	if out.Classifications["hostname"] != "pii" { // the override re-classifies it
		t.Fatalf("hostname override not reflected: %+v", out.Classifications)
	}
	if out.RedactFrom != "pii" || !out.RedactExport {
		t.Fatalf("redaction policy: %+v", out)
	}
	if out.BYOK != "none" { // no pool / no keyring in this unit fixture
		t.Fatalf("byok default: %q", out.BYOK)
	}
}

type errGovRow struct{ err error }

func (r errGovRow) Scan(...any) error { return r.err }

type errGovQuerier struct{ err error }

func (q errGovQuerier) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, q.err
}

func (q errGovQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, q.err
}

func (q errGovQuerier) QueryRow(context.Context, string, ...any) pgx.Row {
	return errGovRow(q)
}

func TestGovernanceViewFailsClosedOnCompositionErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(context.Context, func(context.Context, tenancy.Querier) error) error
	}{
		{
			name: "provider scope",
			run: func(context.Context, func(context.Context, tenancy.Querier) error) error {
				return errors.New("provider role unavailable")
			},
		},
		{
			name: "tenant metadata",
			run: func(ctx context.Context, fn func(context.Context, tenancy.Querier) error) error {
				return fn(ctx, errGovQuerier{err: errors.New("tenant metadata unavailable")})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, store, token := governedFixture(t)
			store.pols["tn_1"] = govern.Policy{}
			f.h.WithGovernance(&Governance{Store: store, providerQuery: tc.run})

			rec := f.doAuthed(t, token, http.MethodGet, "/provider/v1/tenants/tn_1/governance", nil)
			if rec.Code == http.StatusOK {
				t.Fatalf("composition error returned a plausible 200 response: %s", rec.Body.String())
			}
		})
	}
}

// TestGovernancePut: a valid policy is stored + audited; invalid class/floor
// are rejected.
func TestGovernancePut(t *testing.T) {
	f, store, token := governedFixture(t)

	rec := f.doAuthed(t, token, http.MethodPut, "/provider/v1/tenants/tn_1/governance", map[string]any{
		"classifications": map[string]string{"user_agent": "pii"},
		"redact_from":     "confidential",
		"redact_export":   true,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("put: %d %s", rec.Code, rec.Body.String())
	}
	got := store.pols["tn_1"]
	if got.RedactFrom != govern.ClassConfidential || !got.RedactExport ||
		got.Overrides[govern.CatUserAgent] != govern.ClassPII {
		t.Fatalf("policy not stored: %+v", got)
	}

	// Invalid redact_from is rejected.
	if rec := f.doAuthed(t, token, http.MethodPut, "/provider/v1/tenants/tn_1/governance",
		map[string]any{"redact_from": "fortnight"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid floor: %d", rec.Code)
	}
	// Invalid class in an override is rejected.
	if rec := f.doAuthed(t, token, http.MethodPut, "/provider/v1/tenants/tn_1/governance",
		map[string]any{"classifications": map[string]string{"ip_address": "nonsense"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid class: %d", rec.Code)
	}
}

// TestGovernanceReadOnlyDegrade: the license read-only ladder blocks governance
// writes while the view keeps working.
func TestGovernanceReadOnlyDegrade(t *testing.T) {
	f := newFixture(t, licenseManager(t, license.TierMSP, 0, -31*24*time.Hour)) // read_only
	store := newMemGov()
	f.h.WithGovernance(&Governance{Store: store})
	token := f.bootstrapAndLoginReadOnly(t)

	if rec := f.doAuthed(t, token, http.MethodGet, "/provider/v1/tenants/tn_1/governance", nil); rec.Code != http.StatusOK {
		t.Fatalf("view in read-only: %d", rec.Code)
	}
	rec := f.doAuthed(t, token, http.MethodPut, "/provider/v1/tenants/tn_1/governance",
		map[string]any{"redact_export": true})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "license_read_only") {
		t.Fatalf("governance write in read-only: %d %s", rec.Code, rec.Body.String())
	}
}
