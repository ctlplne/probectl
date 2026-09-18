// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Commercial component. See ee/LICENSE. Not covered by the MPL-2.0 core
// license; use requires a probectl commercial license.

package provider

import (
	"context"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// DPR-178: an unredeemed operator enrollment token used to be valid forever.
// The hash is single-use and never stored in plaintext, but until someone
// redeemed it the message carrying it stayed a live credential for the
// product's highest-privilege domain. The agent side of the same idea has
// always been an hour.
func TestOperatorEnrollmentTokenExpires(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	token := "enroll-token-under-test"
	hash := crypto.Hash([]byte(token))

	op, err := store.CreateOperator(ctx, Operator{Email: "noc@example.com", Role: RoleOperator}, hash)
	if err != nil {
		t.Fatal(err)
	}

	// Inside the window it is a token.
	if _, err := store.OperatorByEnrollHash(ctx, hash); err != nil {
		t.Fatalf("a freshly minted enrollment token was refused: %v", err)
	}

	// Past the window it is not, and the refusal is the same "no such token"
	// every wrong hash gets — an expired token must not be distinguishable from
	// an invented one.
	store.mu.Lock()
	store.operators[op.ID].enrollExpires = time.Now().Add(-time.Second)
	store.mu.Unlock()
	if _, err := store.OperatorByEnrollHash(ctx, hash); err == nil {
		t.Fatal("an expired enrollment token was still accepted")
	} else if err != ErrNotFound {
		t.Fatalf("an expired token must be refused as not-found, got %v", err)
	}

	// A token with no recorded window is refused too: rows written before the
	// window existed are not immortal credentials.
	store.mu.Lock()
	store.operators[op.ID].enrollExpires = time.Time{}
	store.mu.Unlock()
	if _, err := store.OperatorByEnrollHash(ctx, hash); err == nil {
		t.Fatal("an enrollment token with no expiry was accepted")
	}
}

// The window has to be long enough to install an authenticator and short enough
// that a forgotten invitation stops being a way in.
func TestOperatorEnrollTTLIsBounded(t *testing.T) {
	if OperatorEnrollTTL < time.Hour {
		t.Fatalf("OperatorEnrollTTL = %s: too short for a person who must install an authenticator", OperatorEnrollTTL)
	}
	if OperatorEnrollTTL > 7*24*time.Hour {
		t.Fatalf("OperatorEnrollTTL = %s: a week-old invitation is not a credential anyone is still watching", OperatorEnrollTTL)
	}
}
