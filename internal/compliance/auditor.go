// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package compliance

// The auditor bundle (P7): ONE signed, tenant-scoped export that answers the
// questions an auditor actually asks, instead of seven separate downloads the
// reader has to correlate by hand — isolation posture, segmentation evidence,
// audit-chain verification, retention receipts, deletion proofs, the build's
// provenance identity, and the cryptographic self-test.
//
// Two properties are deliberate:
//
//   - A section that could not be gathered is present and marked unavailable
//     with its reason, never omitted. An auditor reading a bundle must be able
//     to tell "this control was verified" from "this control was not looked at",
//     and a missing section silently reads as the former
//     (CLM-UNMEASURED-NOT-CLEAN).
//   - Framework mappings are an INTERPRETATION, not a measurement. They say
//     which requirement area a section speaks to, they are operator-editable,
//     and the bundle says in its own text that the reader must confirm them
//     against their own reading of the regulation. Shipping article numbers as
//     if they were evidence would be the same dishonesty this format exists to
//     prevent.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// AuditorBundleContract identifies the export format.
const AuditorBundleContract = "probectl-auditor-bundle/v1"

// AuditorSignatureAlg is the signature suite (matches the incident evidence
// package, so an auditor verifies both the same way).
const AuditorSignatureAlg = "ed25519"

// Section kinds. Every bundle carries every kind, in this order.
const (
	SectionIsolation    = "isolation-posture"
	SectionSegmentation = "segmentation-evidence"
	SectionAuditChain   = "audit-chain-verification"
	SectionRetention    = "retention-receipts"
	SectionDeletion     = "deletion-proofs"
	SectionProvenance   = "build-provenance"
	SectionSelfTest     = "crypto-self-test"
)

// AuditorSectionKinds is the fixed, ordered set. A bundle missing a kind is
// invalid: the point of the format is that the reader knows what was asked.
var AuditorSectionKinds = []string{
	SectionIsolation,
	SectionSegmentation,
	SectionAuditChain,
	SectionRetention,
	SectionDeletion,
	SectionProvenance,
	SectionSelfTest,
}

// Section statuses.
const (
	StatusVerified    = "verified"    // gathered, and the control it evidences passed
	StatusFailed      = "failed"      // gathered, and the control FAILED — reported, not hidden
	StatusUnavailable = "unavailable" // could not be gathered; Reason says why
)

// AuditorSection is one evidence section. Content is the section's own payload,
// carried as an attachment and referenced here by digest.
type AuditorSection struct {
	Kind      string   `json:"kind"`
	Status    string   `json:"status"`
	Reason    string   `json:"reason,omitempty"` // required when Status is unavailable or failed
	Digest    string   `json:"digest,omitempty"` // sha256 of the attachment content; empty when unavailable
	MediaType string   `json:"media_type,omitempty"`
	Speaks    []string `json:"speaks_to,omitempty"` // framework requirement areas, by id
}

// FrameworkMapping is one requirement area a section speaks to. Ref is the
// framework's own identifier where the operator has supplied one; Area is the
// plain-language requirement theme, which is what the default mappings state
// because a theme can be asserted honestly and an article number cannot be
// asserted on the product's behalf.
type FrameworkMapping struct {
	ID        string   `json:"id"`
	Framework string   `json:"framework"`
	Area      string   `json:"area"`
	Ref       string   `json:"ref,omitempty"`
	Sections  []string `json:"sections"`
}

// AuditorManifest is the signed document.
type AuditorManifest struct {
	Contract          string             `json:"contract"`
	BundleID          string             `json:"bundle_id"`
	TenantScopeDigest string             `json:"tenant_scope_digest"`
	CreatedAt         time.Time          `json:"created_at"`
	Deployment        DeploymentIdentity `json:"deployment"`
	Redaction         string             `json:"redaction"`
	Sections          []AuditorSection   `json:"sections"`
	Frameworks        []FrameworkMapping `json:"frameworks"`
	// Caveats are carried IN the signed document so they cannot be dropped in
	// transit or by a reader's tooling.
	Caveats []string `json:"caveats"`
}

// DeploymentIdentity is what the bundle can say about the software that produced
// it without inventing anything: the version and commit it was built from, and
// the third-party inventory digest baked into that build. The SBOM itself is a
// RELEASE artifact (docs/releasing.md), not something a running control plane
// can regenerate, so the bundle names the build rather than pretending to
// produce a parts list at runtime.
type DeploymentIdentity struct {
	Version          string `json:"version"`
	Commit           string `json:"commit"`
	FIPSMode         bool   `json:"fips_mode"`
	SBOMArtifact     string `json:"sbom_artifact,omitempty"`
	ThirdPartyDigest string `json:"third_party_inventory_digest,omitempty"`
	IsolationModel   string `json:"isolation_model,omitempty"`
}

// AuditorPackage is the portable wire form: the manifest as the exact signed
// bytes, the attachments, and the signature.
type AuditorPackage struct {
	Manifest    json.RawMessage `json:"manifest"`
	Attachments []Attachment    `json:"attachments"`
	Signing     AuditorSigning  `json:"signing"`
}

// Attachment is one section's content, content-addressed.
type Attachment struct {
	Digest    string          `json:"digest"`
	MediaType string          `json:"media_type"`
	Content   json.RawMessage `json:"content"`
}

// AuditorSigning carries the detached signature over the manifest bytes.
type AuditorSigning struct {
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key_pem"`
	Fingerprint string `json:"public_key_fingerprint"`
	Signature   []byte `json:"signature"`
}

// SectionInput is one gathered section, or the reason it could not be gathered.
type SectionInput struct {
	Kind    string
	Status  string
	Reason  string
	Content any // marshaled to canonical JSON; nil when unavailable
}

// AuditorInput is everything the builder needs. It takes ALREADY-GATHERED
// sections so the format is testable without a database, a bus or a cluster.
type AuditorInput struct {
	TenantID   string
	CreatedAt  time.Time
	Deployment DeploymentIdentity
	Redaction  string
	Sections   []SectionInput
	Frameworks []FrameworkMapping // nil uses DefaultFrameworkMappings
}

// BuildAuditorBundle assembles a deterministic manifest and content-addressed
// attachments. TenantID is used only to derive the scope binding and is never
// serialized — the same rule the incident evidence package follows.
func BuildAuditorBundle(in AuditorInput) (AuditorManifest, []Attachment, error) {
	tenant := strings.TrimSpace(in.TenantID)
	if tenant == "" {
		return AuditorManifest{}, nil, fmt.Errorf("compliance: auditor bundle requires a tenant")
	}
	byKind := make(map[string]SectionInput, len(in.Sections))
	for _, s := range in.Sections {
		byKind[s.Kind] = s
	}

	frameworks := in.Frameworks
	if frameworks == nil {
		frameworks = DefaultFrameworkMappings()
	}
	speaks := map[string][]string{}
	for _, f := range frameworks {
		for _, kind := range f.Sections {
			speaks[kind] = append(speaks[kind], f.ID)
		}
	}

	var attachments []Attachment
	sections := make([]AuditorSection, 0, len(AuditorSectionKinds))
	for _, kind := range AuditorSectionKinds {
		got, ok := byKind[kind]
		if !ok {
			// A caller that forgot a section gets an explicit unavailable entry
			// rather than a bundle that quietly omits a control.
			got = SectionInput{Kind: kind, Status: StatusUnavailable,
				Reason: "not gathered by this deployment"}
		}
		sec := AuditorSection{Kind: kind, Status: got.Status, Reason: got.Reason}
		if ids := speaks[kind]; len(ids) > 0 {
			sort.Strings(ids)
			sec.Speaks = ids
		}
		switch got.Status {
		case StatusUnavailable:
			if strings.TrimSpace(got.Reason) == "" {
				return AuditorManifest{}, nil, fmt.Errorf("compliance: section %q is unavailable without a reason", kind)
			}
		case StatusVerified, StatusFailed:
			if got.Content == nil {
				return AuditorManifest{}, nil, fmt.Errorf("compliance: section %q is %s with no content", kind, got.Status)
			}
			raw, err := json.Marshal(got.Content)
			if err != nil {
				return AuditorManifest{}, nil, fmt.Errorf("compliance: encode section %q: %w", kind, err)
			}
			sec.Digest = "sha256:" + hex.EncodeToString(crypto.Hash(raw))
			sec.MediaType = "application/json"
			attachments = append(attachments, Attachment{Digest: sec.Digest, MediaType: sec.MediaType, Content: raw})
			if got.Status == StatusFailed && strings.TrimSpace(got.Reason) == "" {
				return AuditorManifest{}, nil, fmt.Errorf("compliance: section %q failed without a reason", kind)
			}
		default:
			return AuditorManifest{}, nil, fmt.Errorf("compliance: section %q has unknown status %q", kind, got.Status)
		}
		sections = append(sections, sec)
	}

	created := in.CreatedAt.UTC()
	scope := crypto.Hash([]byte("probectl-auditor-scope/v1|" + tenant))
	id := crypto.Hash([]byte(AuditorBundleContract + "|" + tenant + "|" + created.Format(time.RFC3339Nano)))
	return AuditorManifest{
		Contract:          AuditorBundleContract,
		BundleID:          hex.EncodeToString(id[:16]),
		TenantScopeDigest: hex.EncodeToString(scope),
		CreatedAt:         created,
		Deployment:        in.Deployment,
		Redaction:         in.Redaction,
		Sections:          sections,
		Frameworks:        frameworks,
		Caveats:           auditorCaveats(sections),
	}, attachments, nil
}

// auditorCaveats states, inside the signed document, what this bundle does and
// does not establish. The unavailable and failed sections are named explicitly
// so a reader cannot mistake an ungathered control for a passing one.
func auditorCaveats(sections []AuditorSection) []string {
	out := []string{
		"Framework mappings in this bundle are an interpretation of which requirement area each section speaks to. They are operator-editable and are not a legal opinion; confirm them against your own reading of the regulation.",
		"This bundle evidences the controls named in its sections at the time it was generated. It does not evidence anything not named here.",
	}
	var unavailable, failed []string
	for _, s := range sections {
		switch s.Status {
		case StatusUnavailable:
			unavailable = append(unavailable, s.Kind+" ("+s.Reason+")")
		case StatusFailed:
			failed = append(failed, s.Kind+" ("+s.Reason+")")
		}
	}
	if len(unavailable) > 0 {
		out = append(out, "NOT VERIFIED — these sections could not be gathered and must not be read as passing: "+strings.Join(unavailable, "; "))
	}
	if len(failed) > 0 {
		out = append(out, "FAILED — these controls did not pass and are reported here rather than omitted: "+strings.Join(failed, "; "))
	}
	return out
}

// SignAuditorBundle signs the canonical manifest bytes and returns the portable
// package. The manifest is preserved as raw bytes so offline verification checks
// exactly what was signed.
func SignAuditorBundle(manifest AuditorManifest, attachments []Attachment, privatePEM []byte) ([]byte, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("compliance: encode auditor manifest: %w", err)
	}
	sig, err := crypto.SignEd25519(privatePEM, raw)
	if err != nil {
		return nil, fmt.Errorf("compliance: sign auditor manifest: %w", err)
	}
	publicPEM, err := crypto.PublicPEMFromPrivate(privatePEM)
	if err != nil {
		return nil, fmt.Errorf("compliance: derive public key: %w", err)
	}
	fp := crypto.Hash(publicPEM)
	return json.Marshal(AuditorPackage{
		Manifest:    raw,
		Attachments: attachments,
		Signing: AuditorSigning{
			Algorithm:   AuditorSignatureAlg,
			PublicKey:   string(publicPEM),
			Fingerprint: "sha256:" + hex.EncodeToString(fp),
			Signature:   sig,
		},
	})
}

// VerifyAuditorBundle performs every offline check an auditor needs: the
// contract and signature, that each attachment matches the digest the manifest
// commits to, and that every required section is accounted for. It needs no
// server and no network.
func VerifyAuditorBundle(raw []byte) (AuditorManifest, error) {
	var pkg AuditorPackage
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return AuditorManifest{}, fmt.Errorf("compliance: decode auditor bundle: %w", err)
	}
	var m AuditorManifest
	if err := json.Unmarshal(pkg.Manifest, &m); err != nil {
		return AuditorManifest{}, fmt.Errorf("compliance: decode auditor manifest: %w", err)
	}
	if m.Contract != AuditorBundleContract {
		return AuditorManifest{}, fmt.Errorf("compliance: unexpected contract %q", m.Contract)
	}
	if pkg.Signing.Algorithm != AuditorSignatureAlg {
		return AuditorManifest{}, fmt.Errorf("compliance: unexpected signature algorithm %q", pkg.Signing.Algorithm)
	}
	ok, err := crypto.VerifyEd25519([]byte(pkg.Signing.PublicKey), pkg.Manifest, pkg.Signing.Signature)
	if err != nil {
		return AuditorManifest{}, fmt.Errorf("compliance: auditor bundle signature: %w", err)
	}
	if !ok {
		return AuditorManifest{}, fmt.Errorf("compliance: auditor bundle signature does not verify")
	}
	fp := crypto.Hash([]byte(pkg.Signing.PublicKey))
	if want := "sha256:" + hex.EncodeToString(fp); pkg.Signing.Fingerprint != want {
		return AuditorManifest{}, fmt.Errorf("compliance: signing-key fingerprint does not match its key")
	}
	byDigest := make(map[string]json.RawMessage, len(pkg.Attachments))
	for _, a := range pkg.Attachments {
		if got := "sha256:" + hex.EncodeToString(crypto.Hash(a.Content)); got != a.Digest {
			return AuditorManifest{}, fmt.Errorf("compliance: attachment content does not match its digest %s", a.Digest)
		}
		byDigest[a.Digest] = a.Content
	}
	seen := map[string]bool{}
	for _, s := range m.Sections {
		seen[s.Kind] = true
		if s.Status == StatusUnavailable {
			if s.Digest != "" {
				return AuditorManifest{}, fmt.Errorf("compliance: section %q is unavailable but carries content", s.Kind)
			}
			continue
		}
		if _, ok := byDigest[s.Digest]; !ok {
			return AuditorManifest{}, fmt.Errorf("compliance: section %q references missing attachment %s", s.Kind, s.Digest)
		}
	}
	for _, kind := range AuditorSectionKinds {
		if !seen[kind] {
			return AuditorManifest{}, fmt.Errorf("compliance: bundle does not account for section %q", kind)
		}
	}
	return m, nil
}
