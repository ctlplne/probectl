// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package auth

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

func TestWorkerPolicySurvivesEquivalentReplicaAndRejectsChangedAuthentication(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "keyed", true: "legacy-admission"}[legacy], func(t *testing.T) {
			store := newFakeStore()
			key := bytes.Repeat([]byte{71}, 32)
			manager := NewManager(store, time.Hour, true, key)
			issuer := manager
			if legacy {
				issuer = NewManager(store, time.Hour, true, nil)
			}
			token, err := issuer.Issue(context.Background(), Session{ID: workerID, TenantID: workerTenant, UserID: workerOwner})
			if err != nil {
				t.Fatal(err)
			}
			p, err := NewAuthenticator(manager, fakePerms{}).Resolve(workerSessionRequest(token))
			if err != nil || p == nil {
				t.Fatal("ordinary authentication failed", err)
			}
			ref, err := WorkerCredentialFromPrincipal(p)
			if err != nil {
				t.Fatal(err)
			}
			accepted := issuer.hashToken(token)
			if !ref.MatchesStored(WorkerCredentialSession, workerTenant, workerOwner, workerID, accepted) || !manager.WorkerCredentialPolicyMatches(ref) {
				t.Fatal("accepted origin lost row or policy binding")
			}
			replica := NewManager(store, time.Hour, true, append([]byte{}, key...))
			if !replica.WorkerCredentialPolicyMatches(ref) {
				t.Fatal("equivalent replica rejected authenticated origin")
			}
			idle, err := replica.WorkerCredentialIdleTimeout(ref)
			if err != nil || idle != DefaultSessionIdleTimeout {
				t.Fatal("worker did not use current Manager idle policy", err)
			}

			changed := []*Manager{
				NewManager(store, time.Hour, true, bytes.Repeat([]byte{72}, 32)),
				NewManager(store, time.Hour, true, nil),
				NewManager(store, 2*time.Hour, true, key),
				NewManager(store, time.Hour, true, key).WithIdleTimeout(time.Minute),
				NewManager(store, time.Hour, false, key),
				NewManager(nil, time.Hour, true, key),
				nil,
			}
			for _, current := range changed {
				if current.WorkerCredentialPolicyMatches(ref) {
					t.Fatal("changed authentication policy accepted queued origin")
				}
				if idle, err := current.WorkerCredentialIdleTimeout(ref); err == nil || idle != 0 {
					t.Fatal("changed policy exposed a usable idle window", err)
				}
			}
			// An admitted legacy row may still support ordinary login under a new
			// HMAC key. Queued work is conservatively tied to its original policy.
			if legacy {
				next, err := changed[0].Resolve(context.Background(), token)
				if err != nil || next == nil {
					t.Fatal("policy binding changed ordinary legacy login semantics", err)
				}
			}
			encoded, err := ref.MarshalBinary()
			if err != nil || bytes.Contains(encoded, key) || bytes.Contains(encoded, []byte(token)) || bytes.Contains(encoded, accepted) {
				t.Fatal("private reference retained raw authentication material", err)
			}
			decoded, err := DecodeWorkerCredentialRef(encoded)
			if err != nil || !replica.WorkerCredentialPolicyMatches(decoded) || !decoded.MatchesStored(WorkerCredentialSession, workerTenant, workerOwner, workerID, accepted) {
				t.Fatal("private envelope codec lost policy/row binding", err)
			}
			encoded[113] ^= 1
			tampered, err := DecodeWorkerCredentialRef(encoded)
			if err != nil {
				t.Fatal("policy tamper proof must reach semantic verification", err)
			}
			if replica.WorkerCredentialPolicyMatches(tampered) || tampered.MatchesStored(WorkerCredentialSession, workerTenant, workerOwner, workerID, accepted) {
				t.Fatal("serialized policy edit survived origin verification")
			}
		})
	}
}

func TestWorkerPolicyRejectsMissingUnprofiledOrDifferentKind(t *testing.T) {
	manager := NewManager(newFakeStore(), time.Hour, true, bytes.Repeat([]byte{73}, 32))
	hash := crypto.Hash([]byte("owned accepted row hash"))
	for _, kind := range []WorkerCredentialKind{WorkerCredentialSession, WorkerCredentialMCP} {
		ref, err := CaptureWorkerCredential(kind, workerTenant, workerOwner, workerID, hash)
		if err != nil {
			t.Fatal(err)
		}
		if manager.WorkerCredentialPolicyMatches(ref) {
			t.Fatal("unprofiled or MCP metadata passed a session policy fence")
		}
	}
	if manager.WorkerCredentialPolicyMatches(WorkerCredentialRef{}) {
		t.Fatal("missing origin passed policy fence")
	}
}

func TestWorkerPolicyRotationRetainsCurrentPolicyAndUsesNewExactCredential(t *testing.T) {
	store := newFakeStore()
	manager := NewManager(store, time.Hour, true, bytes.Repeat([]byte{74}, 32))
	token, err := manager.Issue(context.Background(), Session{ID: workerID, TenantID: workerTenant, UserID: workerOwner})
	if err != nil {
		t.Fatal(err)
	}
	p, replacement, err := NewAuthenticator(manager, fakePerms{keys: []string{"flow.read"}}).ResolveAndRotate(workerSessionRequest(token))
	if err != nil || p == nil || replacement == "" {
		t.Fatal("authentication rotation failed", err)
	}
	ref, err := WorkerCredentialFromPrincipal(p)
	if err != nil || !manager.WorkerCredentialPolicyMatches(ref) || !ref.MatchesStored(WorkerCredentialSession, workerTenant, workerOwner, workerID, manager.hashToken(replacement)) || ref.MatchesStored(WorkerCredentialSession, workerTenant, workerOwner, workerID, manager.hashToken(token)) {
		t.Fatal("rotation did not preserve current policy and exact successor", err)
	}
}
