// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// Package evidence defines the portable, offline-verifiable incident evidence
// package. The package deliberately contains redacted tenant evidence, not a
// live share URL: expiry or revocation of a server-hosted share cannot change a
// package that an operator already exported.
package evidence

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/incident"
)

const (
	ContractVersion = "probectl-evidence/v1"
	DigestAlgorithm = "sha256"
	SignatureAlg    = "Ed25519"
)

// State keeps absence and uncertainty explicit. These values must not
// be collapsed into one another by API, CLI, browser, or exported reports.
type State string

const (
	StateObserved    State = "observed"
	StateInferred    State = "inferred"
	StateUnknown     State = "unknown"
	StateStale       State = "stale"
	StateUnsupported State = "unsupported"
)

// MissingInterval describes a known evidence gap. An empty list means no gap
// was reported; it does not claim that the source was continuously healthy.
type MissingInterval struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Reason string    `json:"reason"`
}

// Provenance is the mandatory source/trust/independence vocabulary rendered on
// every supported surface. Unknown values remain the literal string "unknown".
type Provenance struct {
	Source               string            `json:"source"`
	VantageID            string            `json:"vantage_id"`
	VantageOwner         string            `json:"vantage_owner"`
	TrustTier            string            `json:"trust_tier"`
	Independence         string            `json:"independence"`
	CapturedAt           time.Time         `json:"captured_at"`
	Freshness            string            `json:"freshness"`
	ClockQuality         string            `json:"clock_quality"`
	SampleCadenceSeconds int               `json:"sample_cadence_seconds,omitempty"`
	MissingIntervals     []MissingInterval `json:"missing_intervals"`
}

// Record points to a content-addressed attachment containing the canonical
// redacted source record.
type Record struct {
	ID               string     `json:"id"`
	Kind             string     `json:"kind"`
	Summary          string     `json:"summary"`
	State            State      `json:"state"`
	Provenance       Provenance `json:"provenance"`
	AttachmentDigest string     `json:"attachment_digest"`
}

// Statement is either a fact grounded by at least one record, an inference
// grounded by records, or an explicit unknown. Verification rejects an
// ungrounded factual statement.
type Statement struct {
	ID          string   `json:"id"`
	Text        string   `json:"text"`
	Class       string   `json:"class"` // fact | inference | unknown
	EvidenceIDs []string `json:"evidence_ids"`
}

type Window struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

type IncidentSummary struct {
	ID               string            `json:"id"`
	Status           incident.Status   `json:"status"`
	Severity         incident.Severity `json:"severity"`
	Title            string            `json:"title"`
	Target           string            `json:"target,omitempty"`
	Prefix           string            `json:"prefix,omitempty"`
	StartedAt        time.Time         `json:"started_at"`
	LastSeenAt       time.Time         `json:"last_seen_at"`
	SignalCount      int               `json:"signal_count"`
	SignalsTruncated bool              `json:"signals_truncated"`
}

// Manifest is canonical JSON signed by the control plane. TenantScopeDigest
// binds the artifact to one tenant without exposing the raw tenant identifier.
type Manifest struct {
	Contract          string          `json:"contract"`
	PackageID         string          `json:"package_id"`
	TenantScopeDigest string          `json:"tenant_scope_digest"`
	CreatedAt         time.Time       `json:"created_at"`
	Incident          IncidentSummary `json:"incident"`
	Window            Window          `json:"window"`
	Redaction         string          `json:"redaction"`
	Statements        []Statement     `json:"statements"`
	Evidence          []Record        `json:"evidence"`
}

type Attachment struct {
	Digest    string          `json:"digest"`
	MediaType string          `json:"media_type"`
	Content   json.RawMessage `json:"content"`
}

type Signing struct {
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key_pem"`
	Fingerprint string `json:"public_key_fingerprint"`
	Signature   []byte `json:"signature"`
}

// Package is the portable wire form. Manifest is preserved as raw canonical
// bytes so offline verification checks exactly what the server signed.
type Package struct {
	Manifest    json.RawMessage `json:"manifest"`
	Attachments []Attachment    `json:"attachments"`
	Signing     Signing         `json:"signing"`
}

type BuildInput struct {
	TenantID   string
	Incident   incident.Incident
	CreatedAt  time.Time
	Conclusion string
	Grounded   bool
}

// Build creates a deterministic manifest and content-addressed attachments
// from an already-redacted incident. TenantID is used only to derive the scope
// binding and is never serialized.
func Build(in BuildInput) (Manifest, []Attachment, error) {
	if strings.TrimSpace(in.TenantID) == "" || strings.TrimSpace(in.Incident.ID) == "" {
		return Manifest{}, nil, errors.New("evidence: tenant and incident id are required")
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = time.Now().UTC()
	}
	if in.Incident.TenantID != "" {
		return Manifest{}, nil, errors.New("evidence: incident must be redacted before packaging")
	}

	records := make([]Record, 0, len(in.Incident.Signals))
	attachments := make([]Attachment, 0, len(in.Incident.Signals))
	statements := make([]Statement, 0, len(in.Incident.Signals)+1)
	for i, signal := range in.Incident.Signals {
		if signal.TenantID != "" {
			return Manifest{}, nil, fmt.Errorf("evidence: signal %d was not tenant-redacted", i)
		}
		raw, err := json.Marshal(signal)
		if err != nil {
			return Manifest{}, nil, fmt.Errorf("evidence: encode signal %d: %w", i, err)
		}
		digest := digest(raw)
		id := "evidence:" + digest
		records = append(records, Record{
			ID: id, Kind: signal.Plane + "." + signal.Kind,
			Summary: first(signal.Summary, signal.Title, "Observed signal"),
			State:   sourceState(signal.Attributes), Provenance: provenance(signal),
			AttachmentDigest: digest,
		})
		attachments = append(attachments, Attachment{Digest: digest, MediaType: "application/json", Content: raw})
		statements = append(statements, Statement{
			ID: fmt.Sprintf("statement-%03d", i+1), Text: first(signal.Title, signal.Summary, "Observed signal"),
			Class: "fact", EvidenceIDs: []string{id},
		})
	}

	allEvidence := make([]string, 0, len(records))
	for _, record := range records {
		allEvidence = append(allEvidence, record.ID)
	}
	conclusion := strings.TrimSpace(in.Conclusion)
	class := "unknown"
	refs := []string{}
	if conclusion == "" {
		conclusion = "The available evidence does not establish a root cause."
	} else if in.Grounded && len(allEvidence) > 0 {
		class = "inference"
		refs = allEvidence
	}
	statements = append(statements, Statement{ID: "conclusion", Text: conclusion, Class: class, EvidenceIDs: refs})

	tenantDigest := digest([]byte(in.TenantID))
	packageSeed, _ := json.Marshal(struct {
		Tenant   string    `json:"tenant"`
		Incident string    `json:"incident"`
		Created  time.Time `json:"created"`
	}{tenantDigest, in.Incident.ID, in.CreatedAt.UTC()})
	manifest := Manifest{
		Contract: ContractVersion, PackageID: "pkg_" + strings.TrimPrefix(digest(packageSeed), DigestAlgorithm+":")[:32],
		TenantScopeDigest: tenantDigest, CreatedAt: in.CreatedAt.UTC(),
		Incident: IncidentSummary{
			ID: in.Incident.ID, Status: in.Incident.Status, Severity: in.Incident.Severity,
			Title: in.Incident.Title, Target: in.Incident.Target, Prefix: in.Incident.Prefix,
			StartedAt: in.Incident.StartedAt, LastSeenAt: in.Incident.LastSeenAt,
			SignalCount: in.Incident.SignalCount, SignalsTruncated: in.Incident.SignalsTruncated,
		},
		Window:     Window{From: in.Incident.StartedAt, To: in.Incident.LastSeenAt},
		Redaction:  "privacy-policy-applied; raw tenant id and secrets omitted",
		Statements: statements, Evidence: records,
	}
	return manifest, attachments, nil
}

// Sign returns the JSON package signed with a stable Ed25519 private key.
func Sign(manifest Manifest, attachments []Attachment, privatePEM []byte) ([]byte, error) {
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("evidence: encode manifest: %w", err)
	}
	sig, err := crypto.SignEd25519(privatePEM, raw)
	if err != nil {
		return nil, fmt.Errorf("evidence: sign manifest: %w", err)
	}
	publicPEM, err := crypto.PublicPEMFromPrivate(privatePEM)
	if err != nil {
		return nil, fmt.Errorf("evidence: derive public key: %w", err)
	}
	out := Package{Manifest: raw, Attachments: attachments, Signing: Signing{
		Algorithm: SignatureAlg, PublicKey: string(publicPEM), Fingerprint: digest(publicPEM), Signature: sig,
	}}
	// Keep RawMessage bytes compact and byte-for-byte identical to the signed
	// canonical forms. json.MarshalIndent would reformat embedded raw JSON and
	// thereby invalidate both the signature and the content addresses.
	return json.Marshal(out)
}

// Verify performs all offline checks: schema/version, signing-key fingerprint,
// signature, attachment content addresses, reference closure, and the rule that
// every factual statement is grounded.
func Verify(raw []byte) (*Manifest, error) {
	var pkg Package
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return nil, fmt.Errorf("evidence: malformed package: %w", err)
	}
	if pkg.Signing.Algorithm != SignatureAlg {
		return nil, fmt.Errorf("evidence: unsupported signature algorithm %q", pkg.Signing.Algorithm)
	}
	if got := digest([]byte(pkg.Signing.PublicKey)); got != pkg.Signing.Fingerprint {
		return nil, errors.New("evidence: signing-key fingerprint mismatch")
	}
	ok, err := crypto.VerifyEd25519([]byte(pkg.Signing.PublicKey), pkg.Manifest, pkg.Signing.Signature)
	if err != nil {
		return nil, fmt.Errorf("evidence: public key: %w", err)
	}
	if !ok {
		return nil, errors.New("evidence: manifest signature does not verify")
	}
	var manifest Manifest
	if err := json.Unmarshal(pkg.Manifest, &manifest); err != nil {
		return nil, fmt.Errorf("evidence: malformed manifest: %w", err)
	}
	if manifest.Contract != ContractVersion || manifest.PackageID == "" || manifest.TenantScopeDigest == "" {
		return nil, errors.New("evidence: manifest contract or identity is invalid")
	}

	attachmentIDs := make(map[string]bool, len(pkg.Attachments))
	for _, attachment := range pkg.Attachments {
		if attachment.Digest == "" || attachmentIDs[attachment.Digest] {
			return nil, errors.New("evidence: missing or duplicate attachment digest")
		}
		if digest(attachment.Content) != attachment.Digest {
			return nil, fmt.Errorf("evidence: attachment %s digest mismatch", attachment.Digest)
		}
		attachmentIDs[attachment.Digest] = true
	}
	recordIDs := make(map[string]bool, len(manifest.Evidence))
	for _, record := range manifest.Evidence {
		if record.ID == "" || recordIDs[record.ID] || !attachmentIDs[record.AttachmentDigest] {
			return nil, fmt.Errorf("evidence: record %q is duplicate or has no verified attachment", record.ID)
		}
		if !validState(record.State) || !validProvenance(record.Provenance) {
			return nil, fmt.Errorf("evidence: record %q has invalid state/provenance", record.ID)
		}
		recordIDs[record.ID] = true
	}
	statementIDs := map[string]bool{}
	for _, statement := range manifest.Statements {
		if statement.ID == "" || statementIDs[statement.ID] || strings.TrimSpace(statement.Text) == "" {
			return nil, errors.New("evidence: invalid or duplicate statement")
		}
		statementIDs[statement.ID] = true
		if statement.Class != "fact" && statement.Class != "inference" && statement.Class != "unknown" {
			return nil, fmt.Errorf("evidence: statement %q has invalid class", statement.ID)
		}
		if statement.Class == "fact" && len(statement.EvidenceIDs) == 0 {
			return nil, fmt.Errorf("evidence: factual statement %q is ungrounded", statement.ID)
		}
		for _, id := range statement.EvidenceIDs {
			if !recordIDs[id] {
				return nil, fmt.Errorf("evidence: statement %q refers to unknown evidence %q", statement.ID, id)
			}
		}
	}
	return &manifest, nil
}

func digest(raw []byte) string { return DigestAlgorithm + ":" + hex.EncodeToString(crypto.Hash(raw)) }

func validState(s State) bool {
	switch s {
	case StateObserved, StateInferred, StateUnknown, StateStale, StateUnsupported:
		return true
	default:
		return false
	}
}

func sourceState(attrs map[string]string) State {
	for _, key := range []string{"evidence.state", "state", "coverage_state"} {
		switch State(strings.ToLower(strings.TrimSpace(attrs[key]))) {
		case StateObserved, StateInferred, StateUnknown, StateStale, StateUnsupported:
			return State(strings.ToLower(strings.TrimSpace(attrs[key])))
		}
	}
	return StateObserved
}

func provenance(signal incident.Signal) Provenance {
	attrs := signal.Attributes
	p := Provenance{
		Source:       first(attrs["evidence.source"], attrs["source"], signal.Plane, "unknown"),
		VantageID:    first(attrs["vantage_id"], attrs["agent_id"], "unknown"),
		VantageOwner: first(attrs["vantage_owner"], "customer-owned"),
		TrustTier:    first(attrs["trust_tier"], "tenant-authenticated"),
		Independence: first(attrs["independence"], "customer-operated"),
		CapturedAt:   signal.OccurredAt, Freshness: first(attrs["freshness"], "current-at-capture"),
		ClockQuality: first(attrs["clock_quality"], "unknown"), MissingIntervals: []MissingInterval{},
	}
	if raw := strings.TrimSpace(attrs["missing_intervals"]); raw != "" {
		_ = json.Unmarshal([]byte(raw), &p.MissingIntervals)
	}
	if raw := strings.TrimSpace(attrs["sample_cadence_seconds"]); raw != "" {
		_, _ = fmt.Sscanf(raw, "%d", &p.SampleCadenceSeconds)
	}
	return p
}

func validProvenance(p Provenance) bool {
	values := []string{p.Source, p.VantageID, p.VantageOwner, p.TrustTier, p.Independence, p.Freshness, p.ClockQuality}
	sort.Strings(values) // deterministic work; also keeps validation allocation bounded.
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return false
		}
	}
	return !p.CapturedAt.IsZero()
}

func first(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
