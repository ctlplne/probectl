// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/version"
)

func auditorRequest(t *testing.T, tenant string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/compliance/auditor-bundle", nil)
	return req.WithContext(auth.WithPrincipal(req.Context(),
		&auth.Principal{Email: "auditor@example.com", TenantID: tenant}))
}

// An UNSIGNED auditor bundle is worthless for the purpose it exists for, so a
// deployment with no signing key is refused rather than served bytes nobody
// vouched for.
func TestAuditorBundleRefusedWithoutASigningKey(t *testing.T) {
	s := testServer(nil)
	rec := httptest.NewRecorder()
	err := s.handleAuditorBundle(rec, auditorRequest(t, "00000000-0000-0000-0000-000000000001"))
	if err == nil {
		t.Fatal("a deployment with no evidence signing key must refuse")
	}
	if !strings.Contains(err.Error(), "signing key") {
		t.Errorf("the refusal must name the missing key: %v", err)
	}
}

// On a deployment where the database-backed sections cannot be gathered, the
// bundle still verifies and still ACCOUNTS for every control — the sections it
// could not reach are present with their reasons. A reader must never have to
// notice an absence (CLM-UNMEASURED-NOT-CLEAN).
func TestAuditorBundleAccountsForUngatherableSections(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	s := testServer(nil).WithEvidenceSigningKey(priv)
	rec := httptest.NewRecorder()
	if err := s.handleAuditorBundle(rec, auditorRequest(t, "00000000-0000-0000-0000-000000000001")); err != nil {
		t.Fatalf("handler: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Disposition"); !strings.Contains(ct, "probectl-auditor-bundle.json") {
		t.Errorf("the response must download as a bundle, got %q", ct)
	}
	m, err := compliance.VerifyAuditorBundle(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("the served bundle must verify offline: %v", err)
	}
	if len(m.Sections) != len(compliance.AuditorSectionKinds) {
		t.Fatalf("want every section accounted for, got %d", len(m.Sections))
	}
	// Provenance and the self-test need no database, so they are gathered here.
	byKind := map[string]compliance.AuditorSection{}
	for _, sec := range m.Sections {
		byKind[sec.Kind] = sec
	}
	for _, kind := range []string{compliance.SectionProvenance, compliance.SectionSelfTest} {
		if byKind[kind].Status == compliance.StatusUnavailable {
			t.Errorf("section %q needs no database and should have been gathered", kind)
		}
	}
	// The database-backed ones are named as unavailable WITH a reason.
	for _, kind := range []string{compliance.SectionIsolation, compliance.SectionAuditChain} {
		got := byKind[kind]
		if got.Status != compliance.StatusUnavailable || got.Reason == "" {
			t.Errorf("section %q should be unavailable with a reason, got %+v", kind, got)
		}
	}
	if !strings.Contains(strings.Join(m.Caveats, " "), "NOT VERIFIED") {
		t.Error("the caveats must name the ungathered sections")
	}
}

// Guardrail 6: the bundle is an export an operator hands to an outside party, so
// no configured secret may appear in it. The values below are the same ones the
// support bundle scrubs.
func TestAuditorBundleCarriesNoConfiguredSecret(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	s := testServer(nil)
	secrets := []string{
		"envelope-key-cGxhaW50ZXh0LXNlY3JldA",
		"oidc-client-secret-9f2b1c",
		"cmdb-secret-7a3e",
		"ai-model-token-sk-test-1234",
	}
	s.cfg.EnvelopeKey = secrets[0]
	s.cfg.OIDCClientSecret = secrets[1]
	s.cfg.CMDBSecret = secrets[2]
	s.cfg.AIModelToken = secrets[3]
	s = s.WithEvidenceSigningKey(priv)

	rec := httptest.NewRecorder()
	if err := s.handleAuditorBundle(rec, auditorRequest(t, "00000000-0000-0000-0000-000000000001")); err != nil {
		t.Fatalf("handler: %v", err)
	}
	body := rec.Body.String()
	for _, sec := range secrets {
		if strings.Contains(body, sec) {
			t.Errorf("the bundle leaked a configured secret: %q", sec)
		}
	}
	// The signing PRIVATE key must never travel with the document it signed;
	// only the public half does.
	if strings.Contains(body, "PRIVATE KEY") {
		t.Error("the bundle must not carry a private key")
	}
	if !strings.Contains(body, "PUBLIC KEY") {
		t.Error("the bundle must carry the public key so it can be verified offline")
	}
	// And the tenant id is bound by digest, never serialized.
	if strings.Contains(body, "00000000-0000-0000-0000-000000000001") {
		t.Error("the bundle must not serialize the tenant id")
	}
}

// DPR-148: a signed document must not assert a commit it cannot stand behind.
// The provenance section is reported as FAILED — present, with its evidence,
// impossible to read as passing — when the binary was built from a modified tree
// or carries no usable commit, because in either case there is no published
// artifact for the reader to compare against.
func TestAuditorBundleRefusesToVouchForAnUntrustworthyBuild(t *testing.T) {
	priv, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	s := testServer(nil).WithEvidenceSigningKey(priv)
	rec := httptest.NewRecorder()
	if err := s.handleAuditorBundle(rec, auditorRequest(t, "00000000-0000-0000-0000-000000000001")); err != nil {
		t.Fatalf("handler: %v", err)
	}
	m, err := compliance.VerifyAuditorBundle(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	var prov compliance.AuditorSection
	for _, sec := range m.Sections {
		if sec.Kind == compliance.SectionProvenance {
			prov = sec
		}
	}
	// A test binary is built without the release ldflags, so its commit is
	// "unknown" — exactly the untrustworthy case this rule exists for.
	if version.Get().ProvenanceTrustworthy() {
		t.Skip("this binary carries a released commit; the untrustworthy path is not reachable here")
	}
	if prov.Status != compliance.StatusFailed {
		t.Errorf("provenance status = %q, want %q for a build that cannot be traced", prov.Status, compliance.StatusFailed)
	}
	if prov.Digest == "" {
		t.Error("a failed control must still carry its evidence, not be omitted")
	}
	if !strings.Contains(strings.Join(m.Caveats, " "), "FAILED") {
		t.Error("the caveats must name the failing control")
	}
}
