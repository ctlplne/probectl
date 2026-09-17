// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Commercial code; see ee/LICENSE.

//go:build integration

package provider

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// DPR-033: with the Postgres-backed store, a session issued by one control
// replica authenticates on another, the raw token is never stored, disabling
// the operator kills the session on every replica, and revocation from any
// replica is global.
func TestPGSessionsAreSharedAcrossReplicasAndDieWithTheOperator(t *testing.T) {
	pool := pgPool(t)
	ctx := context.Background()
	st := NewPGStore(pool)
	op, err := st.CreateOperator(ctx, Operator{
		Email: fmt.Sprintf("sess-%d@example.com", time.Now().UnixNano()), Name: "Session Test", Role: RoleAdmin,
	}, crypto.Hash([]byte("enroll-"+fmt.Sprint(time.Now().UnixNano()))))
	if err != nil {
		t.Fatalf("create operator: %v", err)
	}
	if err := st.SetOperatorStatus(ctx, op.ID, "active"); err != nil {
		t.Fatalf("activate: %v", err)
	}
	op.Status = "active"
	key := make([]byte, crypto.KeySize)
	for i := range key {
		key[i] = byte(i + 11)
	}
	replicaA := NewSessions(key).WithStore(st)
	replicaB := NewSessions(key).WithStore(st)

	token, err := replicaA.IssueContext(ctx, op)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	var stored int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM provider_sessions WHERE token_hash = $1`, token).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("the raw token must never be stored (rows=%d err=%v)", stored, err)
	}
	got := replicaB.ResolveContext(ctx, token)
	if got == nil || got.ID != op.ID || got.Status != "active" {
		t.Fatalf("replica B must honor replica A's session, got %+v", got)
	}
	if err := st.SetOperatorStatus(ctx, op.ID, "disabled"); err != nil {
		t.Fatal(err)
	}
	if got := replicaB.ResolveContext(ctx, token); got == nil || got.Status != "disabled" {
		t.Fatalf("a disabled operator must surface as disabled on every replica, got %+v", got)
	}
	if err := st.SetOperatorStatus(ctx, op.ID, "active"); err != nil {
		t.Fatal(err)
	}
	replicaB.RevokeContext(ctx, token)
	if got := replicaA.ResolveContext(ctx, token); got != nil {
		t.Fatal("a session revoked on replica B still resolved on replica A")
	}
	token2, _ := replicaA.IssueContext(ctx, op)
	token3, _ := replicaB.IssueContext(ctx, op)
	replicaA.RevokeOperatorContext(ctx, op.ID)
	if replicaB.ResolveContext(ctx, token2) != nil || replicaA.ResolveContext(ctx, token3) != nil {
		t.Fatal("revoking the operator must end every session on every replica")
	}
	// A replica with a different session HMAC key cannot resolve the token:
	// the keyed hash is part of the trust boundary, not just a lookup key.
	otherKey := make([]byte, crypto.KeySize)
	token4, _ := replicaA.IssueContext(ctx, op)
	if NewSessions(otherKey).WithStore(st).ResolveContext(ctx, token4) != nil {
		t.Fatal("a replica without the shared HMAC key must not resolve the session")
	}
}
