// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package provider

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/govern"
	"github.com/imfeelingtheagi/probectl/internal/license"
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

func governedFixture(t *testing.T) (*fixture, *memGovStore, string) {
	t.Helper()
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, 90*24*time.Hour))
	store := newMemGov()
	f.h.WithGovernance(&Governance{Store: store}) // Pool nil → composed PG reads skipped
	token := f.bootstrapAndLogin(t)
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
	f := newFixture(t, licenseManager(t, license.TierProvider, 0, -31*24*time.Hour)) // read_only
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
