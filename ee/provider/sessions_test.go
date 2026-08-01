// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package provider

import (
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
