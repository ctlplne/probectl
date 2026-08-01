// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package compliance

// Audit-grade evidence export (the S46 watch-out: immutable, timestamped).
// The export is a self-verifying JSON document: every record is timestamped,
// the records are hash-chained (each record's hash covers its canonical
// content + the previous hash, via the internal crypto provider — guardrail
// 3), and the document carries a final chain head. Any post-export tampering
// breaks verification. Framework mappings (PCI DSS / NIST / zero-trust) ride
// each rule's declared tags; coverage caveats are embedded IN the evidence —
// an auditor sees exactly what was and wasn't observed.

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
