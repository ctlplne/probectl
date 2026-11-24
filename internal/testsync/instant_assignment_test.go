// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testsync

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/testspec"
)

func TestInstantAssignmentRequiresExactPeerDefinitionAndLiveLease(t *testing.T) {
	privateKey, publicKey, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	job := InstantAssignment{
		RunID: uuid.NewString(), LeaseID: uuid.NewString(), TenantID: uuid.NewString(), AgentID: uuid.NewString(),
		Test:     Test{ID: uuid.NewString(), Type: "http", Target: "https://probe.example/", IntervalSeconds: 30, TimeoutSeconds: 5},
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(20 * time.Second),
	}
	job.DefinitionHash, err = testspec.DefinitionHash(job.Test)
	if err != nil {
		t.Fatal(err)
	}
	signer := &Source{priv: privateKey}
	encoded, err := signer.SignInstantAssignment(job)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyInstantAssignment(encoded, publicKey, job.TenantID, job.AgentID, issuedAt)
	if err != nil || got.RunID != job.RunID || got.LeaseID != job.LeaseID || got.DefinitionHash != job.DefinitionHash {
		t.Fatal("assignment lost its exact run, lease or saved definition", err)
	}
	for _, peer := range [][2]string{{uuid.NewString(), job.AgentID}, {job.TenantID, uuid.NewString()}} {
		if _, err := VerifyInstantAssignment(encoded, publicKey, peer[0], peer[1], issuedAt); !errors.Is(err, ErrInstantAssignmentPeer) {
			t.Fatal("sibling tenant or agent accepted the assignment", err)
		}
	}
	if _, err := VerifyInstantAssignment(encoded, publicKey, job.TenantID, job.AgentID, job.ExpiresAt); !errors.Is(err, ErrInstantAssignmentExpired) {
		t.Fatal("the exact lease expiry admitted a run", err)
	}
	var wire signedInstantAssignment
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	job.Test.Target = "https://changed.example/"
	wire.Payload, err = json.Marshal(instantAssignmentDocument{Format: instantAssignmentFormat, Assignment: job})
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyInstantAssignment(tampered, publicKey, job.TenantID, job.AgentID, issuedAt); !errors.Is(err, ErrBadSignature) {
		t.Fatal("a modified definition survived signature verification", err)
	}
	if _, err := signer.SignInstantAssignment(job); !errors.Is(err, ErrInvalidInstantAssignment) {
		t.Fatal("the signer issued a definition whose hash did not match", err)
	}
}
