// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package testsync implements the SIGNED, PULL-BASED central test distribution
// from the config-push ADR (ARCH-001). The flagship loop — define a test
// centrally, have the fleet execute it — must work WITHOUT reintroducing
// config push (StreamConfig stays an explicit deny). The mechanism mirrors
// license verification: the control plane serves a tenant's test set as a
// bundle SIGNED with an Ed25519 key; agents PULL the bundle and verify the
// signature against a build-baked public key before applying it. Distribution
// authority therefore stays OUTSIDE the data plane (a compromised bus or API
// path cannot forge a bundle without the signing key), exactly as the ADR
// requires.
package testsync

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// Test is the minimal, agent-executable view of a synthetic test (the bundle
// does not carry control-plane-only metadata like timestamps).
type Test struct {
	ID              string            `json:"id"`
	Type            string            `json:"type"`
	Target          string            `json:"target"`
	IntervalSeconds int               `json:"interval_seconds"`
	TimeoutSeconds  int               `json:"timeout_seconds"`
	Params          map[string]string `json:"params,omitempty"`
}

// Bundle is the signed payload: a tenant's enabled tests at a monotonically
// increasing epoch. The agent applies a bundle only if its epoch is newer than
// the one it is running (replay/rollback protection).
type Bundle struct {
	TenantID string `json:"tenant_id"`
	Epoch    int64  `json:"epoch"` // unix-nanos of issuance; strictly increasing
	Tests    []Test `json:"tests"`
}

// Signed is the wire form: the canonical bundle bytes plus the detached
// Ed25519 signature over them.
type Signed struct {
	Bundle    json.RawMessage `json:"bundle"`    // canonical JSON of Bundle
	Signature []byte          `json:"signature"` // Ed25519 over Bundle bytes
}

// canonical marshals a bundle deterministically (Go's encoding/json sorts map
// keys, and the struct field order is fixed), so the signed bytes are stable.
func canonical(b Bundle) ([]byte, error) { return json.Marshal(b) }

// Sign builds the signed wire form of a bundle using the PKCS#8 Ed25519
// private-key PEM (the same key kind as the license/WORM signer). The control
// plane holds the private half; agents hold only the build-baked public half.
func Sign(b Bundle, privPEM []byte) ([]byte, error) {
	priv, err := crypto.ParseEd25519PrivatePEM(privPEM)
	if err != nil {
		return nil, fmt.Errorf("testsync: signing key: %w", err)
	}
	raw, err := canonical(b)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, raw)
	return json.Marshal(Signed{Bundle: raw, Signature: sig})
}

// ErrBadSignature is returned when a bundle's signature does not verify against
// the supplied public key — the agent then REFUSES the bundle (fail closed:
// keep running the last verified test set rather than apply an unsigned one).
var ErrBadSignature = errors.New("testsync: bundle signature does not verify (refusing)")

// Verify checks a signed bundle against the build-baked Ed25519 public-key PEM
// and returns the bundle only if the signature is valid. A current epoch (the
// one the agent is already running) is passed so a replayed OLDER bundle is
// refused even if correctly signed.
func Verify(signed []byte, pubPEM []byte, currentEpoch int64) (*Bundle, error) {
	pub, err := crypto.ParseEd25519PublicPEM(pubPEM)
	if err != nil {
		return nil, fmt.Errorf("testsync: verify key: %w", err)
	}
	var s Signed
	if err := json.Unmarshal(signed, &s); err != nil {
		return nil, fmt.Errorf("testsync: malformed signed bundle: %w", err)
	}
	if !ed25519.Verify(pub, s.Bundle, s.Signature) {
		return nil, ErrBadSignature
	}
	var b Bundle
	if err := json.Unmarshal(s.Bundle, &b); err != nil {
		return nil, fmt.Errorf("testsync: malformed bundle body: %w", err)
	}
	if b.Epoch <= currentEpoch {
		return nil, fmt.Errorf("testsync: bundle epoch %d not newer than current %d (refusing rollback/replay)", b.Epoch, currentEpoch)
	}
	return &b, nil
}

// NewEpoch returns a fresh monotonically-increasing epoch (issuance time in
// unix-nanos).
func NewEpoch() int64 { return time.Now().UnixNano() }
