// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/version"
)

func TestAuditorBundleSegmentationStatusReflectsSeparateTenantObservations(t *testing.T) {
	lanes := []struct {
		tenant, policy, status string
		port                   int
		observed               bool
		verdict                compliance.Verdict
	}{
		{"00000000-0000-4000-8000-000000000001", "primary-boundary", compliance.StatusFailed, 443, true, compliance.VerdictViolation},
		{"00000000-0000-4000-8000-000000000002", "paired-boundary", "observed", 8443, true, compliance.VerdictObservedClean},
		{"00000000-0000-4000-8000-000000000003", "quiet-boundary", compliance.StatusUnavailable, 443, false, compliance.VerdictNotObserved},
	}
	policies := make(map[string][]compliance.Policy, len(lanes))
	for _, lane := range lanes {
		policies[lane.tenant] = []compliance.Policy{auditorBoundaryPolicy(t, lane.policy, lane.port)}
	}
	engine, err := compliance.NewTenantEngine(policies)
	if err != nil {
		t.Fatal(err)
	}
	for _, lane := range lanes {
		if lane.observed {
			engine.Observe(lane.tenant, compliance.FlowObs{Src: "192.0.2.1", Dst: "198.51.100.1", DstPort: 443, Bytes: 150, Source: "flow", At: time.Now().UTC()})
		}
	}
	private, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(private)
	s := testServer(nil).WithCompliance(engine).WithEvidenceSigningKey(private)
	for _, lane := range lanes {
		t.Run(lane.policy, func(t *testing.T) {
			rec := httptest.NewRecorder()
			if err := s.handleAuditorBundle(rec, auditorRequest(t, lane.tenant)); err != nil {
				t.Fatal(err)
			}
			manifest, err := compliance.VerifyEvidenceBundle(rec.Body.Bytes())
			if err != nil || rec.Code != http.StatusOK || manifest.Contract != compliance.AuditorBundleContract {
				t.Fatal("auditor bundle did not verify", rec.Code, manifest.Contract, err)
			}
			wantScope := hex.EncodeToString(crypto.Hash([]byte("probectl-auditor-scope/v1|" + lane.tenant)))
			if manifest.TenantScopeDigest != wantScope {
				t.Error("auditor bundle changed the requesting tenant's scope digest")
			}
			if strings.Contains(rec.Body.String(), lane.tenant) {
				t.Error("auditor bundle disclosed the raw tenant identifier")
			}
			for _, other := range lanes {
				if other.tenant != lane.tenant && (strings.Contains(rec.Body.String(), other.tenant) || strings.Contains(rec.Body.String(), other.policy)) {
					t.Fatal("auditor bundle carries another tenant's policy or evidence")
				}
			}
			for _, section := range manifest.Sections {
				if section.Kind == compliance.SectionSegmentation {
					checkAuditorSegmentationSection(t, rec.Body.Bytes(), section, lane.status, lane.policy, lane.verdict)
					return
				}
			}
			t.Fatal("auditor bundle omitted the segmentation section")
		})
	}
}

func auditorBoundaryPolicy(t *testing.T, name string, port int) compliance.Policy {
	t.Helper()
	policy, err := compliance.ParsePolicy([]byte(fmt.Sprintf(`name: %s
zones:
  - name: outside
    cidrs: ["192.0.2.0/24"]
  - name: protected
    cidrs: ["198.51.100.0/24"]
rules:
  - id: boundary
    from: outside
    to: protected
    ports: [%d]
`, name, port)))
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func checkAuditorSegmentationSection(t *testing.T, raw []byte, section compliance.AuditorSection, want, policy string, verdict compliance.Verdict) {
	t.Helper()
	if section.Status != want || section.Reason == "" {
		t.Fatal("segmentation section does not reflect the recorded observation", section.Status, "want", want)
	}
	if want == compliance.StatusUnavailable {
		if section.Digest != "" {
			t.Fatal("unavailable segmentation section claims an attachment")
		}
		return
	}
	var bundle compliance.AuditorPackage
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	for _, attachment := range bundle.Attachments {
		if attachment.Digest == section.Digest {
			var evidence compliance.Evidence
			if err := json.Unmarshal(attachment.Content, &evidence); err != nil || compliance.VerifyEvidence(evidence) != nil || evidence.Tenant != "" ||
				len(evidence.Records) != 1 || evidence.Coverage.Observations != 1 ||
				evidence.Records[0].Result.Policy != policy || evidence.Records[0].Result.Verdict != verdict {
				t.Fatal("signed segmentation attachment lost exact owned rule evidence", err)
			}
			return
		}
	}
	t.Fatal("measured segmentation section omitted its attachment")
}

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
	m, err := compliance.VerifyEvidenceBundle(rec.Body.Bytes())
	if err != nil || m.Contract != compliance.AuditorBundleContract {
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
	m, err := compliance.VerifyEvidenceBundle(rec.Body.Bytes())
	if err != nil || m.Contract != compliance.AuditorBundleContract {
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
