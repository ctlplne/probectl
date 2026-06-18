// SPDX-License-Identifier: LicenseRef-probectl-Commercial-TBD

package provider

import (
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
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
