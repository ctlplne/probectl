// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package testsync is the SIGNED central test-distribution mechanism from the
// config-push ADR (ARCH-001). The intended flagship loop — define a test
// centrally, have the fleet execute it — works WITHOUT reintroducing config
// push (StreamConfig stays an explicit deny): the control plane serves a
// tenant's test set as a bundle SIGNED with an Ed25519 key, and an agent is
// meant to PULL the bundle and Verify the signature against a build-baked
// public key before applying it, so distribution authority stays OUTSIDE the
// data plane (a compromised bus or API path cannot forge a bundle without the
// signing key).
//
// SHIPPED SCOPE (ING-20/PLAT-13): the control-plane HALF is implemented — Sign,
// and GET /v1/tests/bundle serving the signed tenant-scoped bundle — and this
// package's Verify is the agent-facing verification entry point. The agent-side
// PULL loop (fetch the bundle on an interval, Verify, and apply it to the
// schedule) is NOT yet wired into any shipped agent: no cmd/probectl-agent or
// internal/agent code imports this package (asserted by
// TestAgentSideBundlePullNotYetWired). Until it is, tests reach agents through
// the agent's own configuration, not through this bundle. Wiring the pull loop
// requires choosing the agent transport (the agent speaks gRPC/mTLS while the
// bundle is a REST resource) — a design + operational decision tracked in
// design-partner-readiness/decisions-needed.md (D-28, PLAT-13).
package testsync

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

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

// Verify is the agent-facing verification entry point (PLAT-13): it checks a
// signed bundle against the build-baked Ed25519 public-key PEM and returns the
// bundle only if the signature is valid. currentEpoch (the one the agent is
// already running) is passed so a replayed OLDER bundle is refused even if
// correctly signed. The agent-side pull loop that will call this is not yet
// shipped (see the package doc); exporting it fixes the verification contract
// in place for that loop.
func Verify(signed []byte, pubPEM []byte, currentEpoch int64) (*Bundle, error) {
	return verify(signed, pubPEM, currentEpoch)
}

// verify checks a signed bundle against the build-baked Ed25519 public-key PEM
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
		return nil, fmt.Errorf("testsync: bundle epoch %d not newer than current %d (refusing rollback/replay)", b.Epoch, currentEpoch)
	}
	return &b, nil
}

// NewEpoch returns a fresh monotonically-increasing epoch (issuance time in
// unix-nanos).
func NewEpoch() int64 { return time.Now().UnixNano() }
