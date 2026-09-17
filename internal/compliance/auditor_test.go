// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package compliance

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

func auditorKey(t *testing.T) []byte {
	t.Helper()
	priv, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	return priv
}

func verifiedSections() []SectionInput {
	out := make([]SectionInput, 0, len(AuditorSectionKinds))
	for _, k := range AuditorSectionKinds {
		out = append(out, SectionInput{Kind: k, Status: StatusVerified,
			Content: map[string]any{"kind": k, "ok": true}})
	}
	return out
}

// The whole point of the format: one signed document an auditor verifies offline.
func TestAuditorBundleSignsAndVerifiesOffline(t *testing.T) {
	m, att, err := BuildAuditorBundle(AuditorInput{
		TenantID:   "00000000-0000-0000-0000-000000000001",
		CreatedAt:  time.Unix(1700000000, 0),
		Redaction:  "headers",
		Deployment: DeploymentIdentity{Version: "0.6.0", Commit: "abc1234", FIPSMode: true},
		Sections:   verifiedSections(),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(m.Sections) != len(AuditorSectionKinds) {
		t.Fatalf("want every section, got %d", len(m.Sections))
	}
	raw, err := SignAuditorBundle(m, att, auditorKey(t))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got, err := VerifyAuditorBundle(raw)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.BundleID != m.BundleID || got.TenantScopeDigest != m.TenantScopeDigest {
		t.Error("verified manifest does not match the signed one")
	}
	// The tenant id itself must never appear in the bundle — only its binding.
	if strings.Contains(string(raw), "00000000-0000-0000-0000-000000000001") {
		t.Error("the tenant id must not be serialized; only its scope digest")
	}
}

// Tampering with either half must fail, or the signature means nothing.
func TestAuditorBundleRefusesTampering(t *testing.T) {
	m, att, err := BuildAuditorBundle(AuditorInput{
		TenantID: "t1", CreatedAt: time.Unix(1700000000, 0), Sections: verifiedSections(),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	raw, err := SignAuditorBundle(m, att, auditorKey(t))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	var pkg AuditorPackage
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// 1. the manifest
	bad := pkg
	bad.Manifest = json.RawMessage(strings.Replace(string(pkg.Manifest), `"redaction":""`, `"redaction":"none"`, 1))
	if b, err := json.Marshal(bad); err == nil {
		if _, err := VerifyAuditorBundle(b); err == nil {
			t.Error("a modified manifest must not verify")
		}
	}

	// 2. an attachment's content, leaving its digest alone
	bad = pkg
	bad.Attachments = append([]Attachment(nil), pkg.Attachments...)
	bad.Attachments[0].Content = json.RawMessage(`{"kind":"isolation-posture","ok":false}`)
	b, err := json.Marshal(bad)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, err := VerifyAuditorBundle(b); err == nil {
		t.Error("an attachment whose content no longer matches its digest must not verify")
	}
}

// CLM-UNMEASURED-NOT-CLEAN, applied to the bundle itself: a control that could
// not be gathered is PRESENT and marked, never omitted, and the caveats name it.
// An auditor reading a bundle must not have to notice an absence.
func TestAuditorBundleNamesWhatItCouldNotGather(t *testing.T) {
	sections := verifiedSections()
	sections[2] = SectionInput{Kind: SectionAuditChain, Status: StatusUnavailable,
		Reason: "audit store unreachable"}
	// And one that was gathered and FAILED, which must also survive into the bundle.
	sections[0] = SectionInput{Kind: SectionIsolation, Status: StatusFailed,
		Reason:  "one table carries a policy with no grant behind it",
		Content: map[string]any{"failing_tables": []string{"break_glass_grants"}}}

	m, att, err := BuildAuditorBundle(AuditorInput{TenantID: "t1", CreatedAt: time.Unix(1, 0), Sections: sections})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var unavailable, failed *AuditorSection
	for i := range m.Sections {
		switch m.Sections[i].Kind {
		case SectionAuditChain:
			unavailable = &m.Sections[i]
		case SectionIsolation:
			failed = &m.Sections[i]
		}
	}
	if unavailable == nil || unavailable.Status != StatusUnavailable {
		t.Fatal("the ungathered section must be present and marked unavailable")
	}
	if unavailable.Digest != "" {
		t.Error("an unavailable section must carry no content digest")
	}
	if failed == nil || failed.Status != StatusFailed || failed.Digest == "" {
		t.Fatal("a failed control must be present WITH its evidence, not omitted")
	}
	joined := strings.Join(m.Caveats, " | ")
	if !strings.Contains(joined, "NOT VERIFIED") || !strings.Contains(joined, "audit store unreachable") {
		t.Errorf("caveats must name the ungathered section: %q", joined)
	}
	if !strings.Contains(joined, "FAILED") || !strings.Contains(joined, "no grant behind it") {
		t.Errorf("caveats must name the failed control: %q", joined)
	}
	// Caveats are inside the signed bytes, so tooling cannot drop them.
	raw, err := SignAuditorBundle(m, att, auditorKey(t))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !strings.Contains(string(raw), "NOT VERIFIED") {
		t.Error("the caveat must be part of the signed document")
	}
}

// A caller that forgets a section entirely gets an explicit unavailable entry,
// because the alternative is a bundle that silently covers less than it appears to.
func TestAuditorBundleAccountsForEverySectionEvenIfTheCallerForgets(t *testing.T) {
	m, _, err := BuildAuditorBundle(AuditorInput{
		TenantID: "t1", CreatedAt: time.Unix(1, 0),
		Sections: []SectionInput{{Kind: SectionSelfTest, Status: StatusVerified, Content: map[string]any{"ok": true}}},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(m.Sections) != len(AuditorSectionKinds) {
		t.Fatalf("want %d sections, got %d", len(AuditorSectionKinds), len(m.Sections))
	}
	for _, s := range m.Sections {
		if s.Kind == SectionSelfTest {
			continue
		}
		if s.Status != StatusUnavailable || s.Reason == "" {
			t.Errorf("section %q should be explicitly unavailable with a reason, got %+v", s.Kind, s)
		}
	}
}

// An unavailable section without a reason is a silent gap wearing a label, so it
// is refused at build time.
func TestAuditorBundleRefusesAnUnexplainedGap(t *testing.T) {
	_, _, err := BuildAuditorBundle(AuditorInput{
		TenantID: "t1", CreatedAt: time.Unix(1, 0),
		Sections: []SectionInput{{Kind: SectionSelfTest, Status: StatusUnavailable}},
	})
	if err == nil {
		t.Fatal("an unavailable section with no reason must be refused")
	}
}

// The mappings must state requirement AREAS and must not ship invented article
// numbers: a fabricated citation inside a signed document is worse than none.
func TestFrameworkMappingsShipNoInventedCitations(t *testing.T) {
	seen := map[string]bool{}
	frameworks := map[string]bool{}
	for _, f := range DefaultFrameworkMappings() {
		if seen[f.ID] {
			t.Errorf("duplicate mapping id %q", f.ID)
		}
		seen[f.ID] = true
		frameworks[f.Framework] = true
		if strings.TrimSpace(f.Area) == "" {
			t.Errorf("mapping %q has no requirement area", f.ID)
		}
		if f.Ref != "" {
			t.Errorf("mapping %q ships a reference (%q); references are the operator's to supply", f.ID, f.Ref)
		}
		if len(f.Sections) == 0 {
			t.Errorf("mapping %q maps to no section", f.ID)
		}
		for _, s := range f.Sections {
			valid := false
			for _, k := range AuditorSectionKinds {
				if s == k {
					valid = true
				}
			}
			if !valid {
				t.Errorf("mapping %q references unknown section %q", f.ID, s)
			}
		}
	}
	for _, want := range []string{"NIS2", "DORA", "GAIA-X"} {
		if !frameworks[want] {
			t.Errorf("no mapping for %s", want)
		}
	}
	// And the caveat about interpretation must always be present.
	m, _, err := BuildAuditorBundle(AuditorInput{TenantID: "t1", CreatedAt: time.Unix(1, 0), Sections: verifiedSections()})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(strings.Join(m.Caveats, " "), "not a legal opinion") {
		t.Error("the bundle must say in its own bytes that the mappings are an interpretation")
	}
}
