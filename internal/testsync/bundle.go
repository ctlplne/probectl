// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package testsync is the SIGNED central test distribution (decision D-41,
// docs/adr/central-test-distribution.md; closes PLAT-13). A test defined in the
// console, the API or the CLI reaches the tenant's agents WITHOUT config push
// (StreamConfig stays an explicit deny): each agent PULLS its tenant's test set
// over the mTLS channel it already has (the FetchTestBundle RPC), Verifies the
// bundle's Ed25519 signature against the deployment's test-bundle public key it
// received at enrollment, checks the bundle names its own certificate's tenant,
// filters it through its local policy, and only then applies it.
//
// The control-plane half is Source: it reads the tenant's enabled tests and its
// test-set version under the tenant's RLS scope and signs them (Sign). The
// bundle epoch is that per-tenant version, a counter bumped in the same
// transaction as every test write, so an agent refuses a replayed or older
// bundle without trusting any clock. The agent half is internal/agent's
// test-sync loop, which calls Verify.
package testsync

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ctlplne/probectl/internal/crypto"
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
	Epoch    int64  `json:"epoch"` // the tenant's test-set version; strictly increasing
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
// plane holds the private half; agents hold only the public half, delivered at
// enrollment.
func Sign(b Bundle, privPEM []byte) ([]byte, error) {
	raw, err := canonical(b)
	if err != nil {
		return nil, err
	}
	// All crypto goes through internal/crypto (docs/guardrails.md G7-3, FIPS-swappable);
	// never call crypto/ed25519 primitives directly here.
	sig, err := crypto.SignEd25519(privPEM, raw)
	if err != nil {
		return nil, fmt.Errorf("testsync: signing key: %w", err)
	}
	return json.Marshal(Signed{Bundle: raw, Signature: sig})
}

// ErrBadSignature is returned when a bundle's signature does not verify against
// the supplied public key — the agent then REFUSES the bundle (fail closed:
// keep running the last verified test set rather than apply an unsigned one).
var ErrBadSignature = errors.New("testsync: bundle signature does not verify (refusing)")

// ErrStaleEpoch is returned for a correctly signed bundle whose epoch is not
// newer than the one the agent runs (a replay or a rollback).
var ErrStaleEpoch = errors.New("testsync: bundle epoch not newer than current (refusing rollback/replay)")

// Verify is the agent-facing verification entry point (PLAT-13): it checks a
// signed bundle against the deployment's Ed25519 public-key PEM and returns the
// bundle only if the signature is valid. currentEpoch (the version the agent is
// already running) is passed so a replayed OLDER bundle is refused even if
// correctly signed. The caller must still check the bundle's tenant against its
// own certificate's tenant before applying it.
func Verify(signed []byte, pubPEM []byte, currentEpoch int64) (*Bundle, error) {
	return verify(signed, pubPEM, currentEpoch)
}

// verify checks a signed bundle against the Ed25519 public-key PEM
// and returns the bundle only if the signature is valid. A current epoch (the
// one the agent is already running) is passed so a replayed OLDER bundle is
// refused even if correctly signed.
func verify(signed []byte, pubPEM []byte, currentEpoch int64) (*Bundle, error) {
	var s Signed
	if err := json.Unmarshal(signed, &s); err != nil {
		return nil, fmt.Errorf("testsync: malformed signed bundle: %w", err)
	}
	// All crypto goes through internal/crypto (docs/guardrails.md G7-3, FIPS-swappable).
	ok, err := crypto.VerifyEd25519(pubPEM, s.Bundle, s.Signature)
	if err != nil {
		return nil, fmt.Errorf("testsync: verify key: %w", err)
	}
	if !ok {
		return nil, ErrBadSignature
	}
	var b Bundle
	if err := json.Unmarshal(s.Bundle, &b); err != nil {
		return nil, fmt.Errorf("testsync: malformed bundle body: %w", err)
	}
	if b.Epoch <= currentEpoch {
		return nil, fmt.Errorf("%w: epoch %d, current %d", ErrStaleEpoch, b.Epoch, currentEpoch)
	}
	return &b, nil
}
