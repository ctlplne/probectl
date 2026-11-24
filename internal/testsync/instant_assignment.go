// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testsync

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/testspec"
)

const instantAssignmentFormat = "probectl.instant-test-assignment/v1"

// An assignment deadline covers the existing five-minute maximum test timeout
// and time for a claimed job to produce its result.
const maxInstantAssignmentLifetime = 6 * time.Minute

var (
	ErrInvalidInstantAssignment = errors.New("testsync: instant assignment is invalid")
	ErrInstantAssignmentPeer    = errors.New("testsync: instant assignment belongs to another peer")
	ErrInstantAssignmentExpired = errors.New("testsync: instant assignment expired")
)

// InstantAssignment binds a single saved definition to one enrolled agent and
// one lease. Both IDs are required when posting the result to the owning run.
type InstantAssignment struct {
	RunID          string    `json:"run_id"`
	LeaseID        string    `json:"lease_id"`
	TenantID       string    `json:"tenant_id"`
	AgentID        string    `json:"agent_id"`
	DefinitionHash string    `json:"definition_hash"`
	Test           Test      `json:"test"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type instantAssignmentDocument struct {
	Format     string            `json:"format"`
	Assignment InstantAssignment `json:"assignment"`
}

type signedInstantAssignment struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}

// SignInstantAssignment signs the same executable definition used by the
// scheduled bundle. The payload format separates these signatures from bundles.
func (s *Source) SignInstantAssignment(assignment InstantAssignment) ([]byte, error) {
	if err := assignment.validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(instantAssignmentDocument{Format: instantAssignmentFormat, Assignment: assignment})
	if err != nil {
		return nil, ErrInvalidInstantAssignment
	}
	signature, err := crypto.SignEd25519(s.priv, payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(signedInstantAssignment{Payload: payload, Signature: signature})
}

// VerifyInstantAssignment checks the exact signed bytes against the enrollment
// key before comparing the authenticated local tenant and agent identities.
// The caller still enforces local probe policy and consumes the lease once.
func VerifyInstantAssignment(encoded, publicKey []byte, localTenant, localAgent string, now time.Time) (InstantAssignment, error) {
	var wire signedInstantAssignment
	if err := json.Unmarshal(encoded, &wire); err != nil || len(wire.Payload) == 0 || len(wire.Signature) == 0 {
		return InstantAssignment{}, ErrInvalidInstantAssignment
	}
	valid, err := crypto.VerifyEd25519(publicKey, wire.Payload, wire.Signature)
	if err != nil || !valid {
		return InstantAssignment{}, ErrBadSignature
	}
	var doc instantAssignmentDocument
	if err := json.Unmarshal(wire.Payload, &doc); err != nil || doc.Format != instantAssignmentFormat {
		return InstantAssignment{}, ErrInvalidInstantAssignment
	}
	job := doc.Assignment
	if job.TenantID != localTenant || job.AgentID != localAgent {
		return InstantAssignment{}, ErrInstantAssignmentPeer
	}
	if err := job.validate(); err != nil {
		return InstantAssignment{}, err
	}
	if !now.Before(job.ExpiresAt) {
		return InstantAssignment{}, ErrInstantAssignmentExpired
	}
	if now.Add(30 * time.Second).Before(job.IssuedAt) {
		return InstantAssignment{}, ErrInvalidInstantAssignment
	}
	return job, nil
}

func (a InstantAssignment) validate() error {
	for _, id := range []string{a.RunID, a.LeaseID, a.TenantID, a.AgentID, a.Test.ID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return ErrInvalidInstantAssignment
		}
	}
	lifetime := a.ExpiresAt.Sub(a.IssuedAt)
	if a.IssuedAt.IsZero() || lifetime <= 0 || lifetime > maxInstantAssignmentLifetime {
		return ErrInvalidInstantAssignment
	}
	if err := testspec.Validate(testspec.Spec{
		Name: a.Test.ID, Type: a.Test.Type, Target: a.Test.Target, Params: a.Test.Params,
		IntervalSeconds: a.Test.IntervalSeconds, TimeoutSeconds: a.Test.TimeoutSeconds,
	}); err != nil {
		return ErrInvalidInstantAssignment
	}
	hash, err := testspec.DefinitionHash(a.Test)
	if err != nil || hash != a.DefinitionHash {
		return ErrInvalidInstantAssignment
	}
	return nil
}
