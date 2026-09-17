// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

func TestSessionsUseKeyedHMACWhenConfigured(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 3)
	}
	s := NewSessions(key)
	token := "provider-session-token"

	keyed := s.hashKey(token)
	unkeyed := NewSessions(nil).hashKey(token)
	if keyed == unkeyed {
		t.Fatal("provider session hash did not use PROBECTL_SESSION_HMAC_KEY")
	}
}

func TestSessionsIdleTimeout(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	s := NewSessions(nil).WithIdleTimeout(30 * time.Minute)
	s.now = func() time.Time { return now }
	token, err := s.Issue(Operator{ID: "op1", Email: "op@example.com"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	now = now.Add(29 * time.Minute)
	if got := s.Resolve(token); got == nil {
		t.Fatal("active provider session expired before idle timeout")
	}
	now = now.Add(31 * time.Minute)
	if got := s.Resolve(token); got != nil {
		t.Fatalf("idle provider session resolved: %+v", got)
	}
}

func TestSessionsKeyedIssueResolveRevoke(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 5)
	}
	s := NewSessions(key)
	token, err := s.Issue(Operator{ID: "op1", Email: "op@example.com"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, ok := s.byH[token]; ok {
		t.Fatal("provider token stored in clear")
	}
	if _, ok := s.byH[s.hashKey(token)]; !ok {
		t.Fatal("provider token not stored under keyed digest")
	}
	if op := s.Resolve(token); op == nil || op.ID != "op1" {
		t.Fatalf("resolve = %+v", op)
	}
	s.Revoke(token)
	if op := s.Resolve(token); op != nil {
		t.Fatalf("revoked provider session resolved: %+v", op)
	}
}

// fakeSessionStore stands in for Postgres: a map shared by several Sessions
// instances, the way replicas share one database.
type fakeSessionStore struct {
	rows      map[string]fakeSessionRow
	operators map[string]Operator
}

type fakeSessionRow struct {
	operatorID    string
	expires, last time.Time
}

func newFakeSessionStore(ops ...Operator) *fakeSessionStore {
	f := &fakeSessionStore{rows: map[string]fakeSessionRow{}, operators: map[string]Operator{}}
	for _, op := range ops {
		f.operators[op.ID] = op
	}
	return f
}

func (f *fakeSessionStore) PutSession(_ context.Context, h, operatorID string, expires, last time.Time) error {
	f.rows[h] = fakeSessionRow{operatorID: operatorID, expires: expires, last: last}
	return nil
}

func (f *fakeSessionStore) GetSession(_ context.Context, h string) (Operator, time.Time, time.Time, bool, error) {
	row, ok := f.rows[h]
	if !ok {
		return Operator{}, time.Time{}, time.Time{}, false, nil
	}
	return f.operators[row.operatorID], row.expires, row.last, true, nil
}

func (f *fakeSessionStore) TouchSession(_ context.Context, h string, last time.Time) error {
	row := f.rows[h]
	row.last = last
	f.rows[h] = row
	return nil
}

func (f *fakeSessionStore) DeleteSession(_ context.Context, h string) error {
	delete(f.rows, h)
	return nil
}

func (f *fakeSessionStore) DeleteOperatorSessions(_ context.Context, operatorID string) error {
	for h, row := range f.rows {
		if row.operatorID == operatorID {
			delete(f.rows, h)
		}
	}
	return nil
}

// DPR-033: with a shared store, a session issued by one replica is honored
// by another, a revocation on any replica reaches all of them, disabling the
// operator kills the session everywhere, and the idle timeout still applies.
func TestSessionsSharedStoreServesEveryReplica(t *testing.T) {
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 7)
	}
	op := Operator{ID: "op-1", Email: "ops@example.com", Role: RoleAdmin, Status: "active"}
	store := newFakeSessionStore(op)
	now := time.Unix(1_700_000_000, 0)
	replica := func() *Sessions {
		s := NewSessions(key).WithIdleTimeout(30 * time.Minute).WithStore(store)
		s.now = func() time.Time { return now }
		return s
	}
	a, b := replica(), replica()

	token, err := a.Issue(op)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, inMemory := a.byH[a.hashKey(token)]; inMemory {
		t.Fatal("a stored session must not also live in the issuing replica's memory")
	}
	if got := b.Resolve(token); got == nil || got.ID != op.ID {
		t.Fatalf("replica B must honor a session issued by replica A, got %+v", got)
	}
	// The operator row is read fresh: disabling it ends the session at once.
	store.operators[op.ID] = Operator{ID: "op-1", Email: op.Email, Role: RoleAdmin, Status: "disabled"}
	if got := b.Resolve(token); got == nil || got.Status != "disabled" {
		t.Fatalf("resolution must surface the CURRENT operator status, got %+v", got)
	}
	store.operators[op.ID] = op
	// Idle timeout is judged from the shared last-activity timestamp.
	now = now.Add(31 * time.Minute)
	if got := a.Resolve(token); got != nil {
		t.Fatalf("idle session must expire across replicas, got %+v", got)
	}
	if _, still := store.rows[a.hashKey(token)]; still {
		t.Fatal("an expired session must be removed from the shared store")
	}
	// Revocation on one replica is revocation everywhere.
	now = now.Add(time.Minute)
	token2, _ := a.Issue(op)
	b.Revoke(token2)
	if got := a.Resolve(token2); got != nil {
		t.Fatal("a session revoked on replica B still resolved on replica A")
	}
	token3, _ := a.Issue(op)
	b.RevokeOperator(op.ID)
	if got := a.Resolve(token3); got != nil {
		t.Fatal("disabling an operator on replica B left its session alive on replica A")
	}
}
