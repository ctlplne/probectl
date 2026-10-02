// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package compliance

// Audit-grade evidence export (the S46 watch-out: immutable, timestamped).
//
// The evidence document is a hash chain: every record is timestamped and each
// record's hash covers its canonical content + the previous hash (via the
// internal crypto provider — guardrail 3), ending in a final chain head. The
// chain alone is NOT tamper-evident against an editor who also recomputes it —
// nothing in the chain is secret, so a mutated document can be re-hashed and
// VerifyEvidence will accept the result (finding AI-04). Tamper-evidence comes
// from the SIGNATURE: Export builds the document, SignEvidence seals its exact
// bytes with the deployment's Ed25519 evidence-signing key (the same key the
// auditor bundle and incident-evidence exports use), and VerifySignedEvidence
// rejects any edited document because the detached signature no longer covers
// its bytes — recomputing the chain does not help the forger.
//
// Framework mappings (PCI DSS / NIST / zero-trust) ride each rule's declared
// tags; coverage caveats are embedded IN the evidence — an auditor sees exactly
// what was and wasn't observed.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// EvidenceRecord is one rule's audit entry.
type EvidenceRecord struct {
	Seq      int        `json:"seq"`
	Result   RuleResult `json:"result"`
	PrevHash string     `json:"prev_hash"`
	Hash     string     `json:"hash"` // sha256(canonical(seq,result,prev_hash))
}

// Evidence is the exportable, tamper-evident document.
type Evidence struct {
	Version     string           `json:"version"` // format version
	Tenant      string           `json:"tenant"`
	GeneratedAt time.Time        `json:"generated_at"`
	Policies    []string         `json:"policies"`
	Coverage    Coverage         `json:"coverage"`
	Records     []EvidenceRecord `json:"records"`
	ChainHead   string           `json:"chain_head"` // the last record's hash
}

// evidenceGenesis anchors the chain.
const evidenceGenesis = "genesis"

// EvidenceFormatVersion identifies the export format.
const EvidenceFormatVersion = "probectl-compliance-evidence/v1"

// Export builds the tenant's evidence document at the engine's current state.
func (e *Engine) Export(tenant string) (Evidence, error) {
	results := e.Results(tenant)
	cov := e.CoverageFor(tenant)

	ev := Evidence{
		Version:     EvidenceFormatVersion,
		Tenant:      tenant,
		GeneratedAt: e.clock().UTC(),
		Policies:    e.Policies(),
		Coverage:    cov,
	}
	prev := evidenceGenesis
	for i, res := range results {
		h, err := recordHash(i, res, prev)
		if err != nil {
			return Evidence{}, err
		}
		ev.Records = append(ev.Records, EvidenceRecord{Seq: i, Result: res, PrevHash: prev, Hash: h})
		prev = h
	}
	ev.ChainHead = prev
	return ev, nil
}

// VerifyEvidence re-walks the chain; any mutated record breaks it.
func VerifyEvidence(ev Evidence) error {
	prev := evidenceGenesis
	for _, rec := range ev.Records {
		if rec.PrevHash != prev {
			return fmt.Errorf("compliance: evidence record %d: chain broken (prev_hash mismatch)", rec.Seq)
		}
		h, err := recordHash(rec.Seq, rec.Result, rec.PrevHash)
		if err != nil {
			return err
		}
		if h != rec.Hash {
			return fmt.Errorf("compliance: evidence record %d: content hash mismatch (tampered)", rec.Seq)
		}
		prev = rec.Hash
	}
	if ev.ChainHead != prev {
		return fmt.Errorf("compliance: evidence chain head mismatch")
	}
	return nil
}

// recordHash hashes the canonical record content chained to prev (via the
// internal crypto provider — never raw primitives, guardrail 3).
func recordHash(seq int, res RuleResult, prev string) (string, error) {
	canonical, err := json.Marshal(struct {
		Seq    int        `json:"seq"`
		Result RuleResult `json:"result"`
		Prev   string     `json:"prev"`
	}{seq, res, prev})
	if err != nil {
		return "", fmt.Errorf("compliance: canonicalize evidence record: %w", err)
	}
	return hex.EncodeToString(crypto.Default.Hash(canonical)), nil
}

// SignedEvidenceContract identifies the signed export envelope.
const SignedEvidenceContract = "probectl-compliance-evidence-signed/v1"

// EvidenceSignatureAlg is the signature suite sealing the evidence export. It
// matches the auditor bundle and the incident-evidence package, so an auditor
// verifies all three the same way.
const EvidenceSignatureAlg = "ed25519"

// EvidenceSigning carries the detached signature over the exact evidence bytes.
type EvidenceSigning struct {
	Algorithm   string `json:"algorithm"`
	PublicKey   string `json:"public_key_pem"`
	Fingerprint string `json:"public_key_fingerprint"`
	Signature   []byte `json:"signature"`
}

// SignedEvidence is the portable wire form of the evidence export: the evidence
// document as the exact signed bytes, plus the detached signature over them. The
// document is preserved as raw bytes so offline verification checks EXACTLY what
// was signed — editing any field and re-serializing breaks the signature even
// when the inner hash chain has been recomputed (finding AI-04).
type SignedEvidence struct {
	Contract string          `json:"contract"`
	Evidence json.RawMessage `json:"evidence"`
	Signing  EvidenceSigning `json:"signing"`
}

// SignEvidence seals the exact evidence bytes with the deployment Ed25519
// evidence-signing key and returns the portable package. The hash chain alone
// is not tamper-evident against an editor who recomputes it, so the endpoint
// that serves the export refuses when no key is configured rather than vouch
// for bytes nobody signed.
func SignEvidence(ev Evidence, privatePEM []byte) ([]byte, error) {
	raw, err := json.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("compliance: encode evidence: %w", err)
	}
	sig, err := crypto.SignEd25519(privatePEM, raw)
	if err != nil {
		return nil, fmt.Errorf("compliance: sign evidence: %w", err)
	}
	publicPEM, err := crypto.PublicPEMFromPrivate(privatePEM)
	if err != nil {
		return nil, fmt.Errorf("compliance: derive public key: %w", err)
	}
	fp := crypto.Hash(publicPEM)
	return json.Marshal(SignedEvidence{
		Contract: SignedEvidenceContract,
		Evidence: raw,
		Signing: EvidenceSigning{
			Algorithm:   EvidenceSignatureAlg,
			PublicKey:   string(publicPEM),
			Fingerprint: "sha256:" + hex.EncodeToString(fp),
			Signature:   sig,
		},
	})
}

// VerifySignedEvidence performs every offline check a reader needs: the
// contract, the Ed25519 signature over the EXACT evidence bytes, that the
// signing-key fingerprint matches its key, and the inner hash chain. It returns
// the decoded evidence only when all hold. Editing any field of the document and
// recomputing the chain still fails here, because the detached signature no
// longer covers the mutated bytes (finding AI-04).
func VerifySignedEvidence(raw []byte) (Evidence, error) {
	var pkg SignedEvidence
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return Evidence{}, fmt.Errorf("compliance: decode signed evidence: %w", err)
	}
	if pkg.Contract != SignedEvidenceContract {
		return Evidence{}, fmt.Errorf("compliance: unexpected evidence contract %q", pkg.Contract)
	}
	if pkg.Signing.Algorithm != EvidenceSignatureAlg {
		return Evidence{}, fmt.Errorf("compliance: unexpected signature algorithm %q", pkg.Signing.Algorithm)
	}
	ok, err := crypto.VerifyEd25519([]byte(pkg.Signing.PublicKey), pkg.Evidence, pkg.Signing.Signature)
	if err != nil {
		return Evidence{}, fmt.Errorf("compliance: evidence signature: %w", err)
	}
	if !ok {
		return Evidence{}, fmt.Errorf("compliance: evidence signature does not verify (tampered)")
	}
	fp := crypto.Hash([]byte(pkg.Signing.PublicKey))
	if want := "sha256:" + hex.EncodeToString(fp); pkg.Signing.Fingerprint != want {
		return Evidence{}, fmt.Errorf("compliance: signing-key fingerprint does not match its key")
	}
	var ev Evidence
	if err := json.Unmarshal(pkg.Evidence, &ev); err != nil {
		return Evidence{}, fmt.Errorf("compliance: decode evidence: %w", err)
	}
	if err := VerifyEvidence(ev); err != nil {
		return Evidence{}, err
	}
	return ev, nil
}
