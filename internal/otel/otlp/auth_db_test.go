// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otlp

import (
	"context"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

type fakeOTLPTokenStore struct {
	byHash  map[string]string
	revoked map[string]bool
	calls   int
}

func newFakeOTLPTokenStore(tokens map[string]string) *fakeOTLPTokenStore {
	f := &fakeOTLPTokenStore{byHash: map[string]string{}, revoked: map[string]bool{}}
	for tok, tenant := range tokens {
		f.byHash[string(crypto.Hash([]byte(tok)))] = tenant
	}
	return f
}

func (f *fakeOTLPTokenStore) Authenticate(_ context.Context, tokenHash []byte) (string, error) {
	f.calls++
	k := string(tokenHash)
	if f.revoked[k] {
		return "", ErrUnauthenticated
	}
	tenant, ok := f.byHash[k]
	if !ok {
		return "", ErrUnauthenticated
	}
	return tenant, nil
}

func (f *fakeOTLPTokenStore) revoke(token string) {
	f.revoked[string(crypto.Hash([]byte(token)))] = true
}

func TestDBTokenAuthenticatorKeepsConfigTokensWorking(t *testing.T) {
	db := newFakeOTLPTokenStore(nil)
	auth := NewDBTokenAuthenticator(db, map[string]string{"config-token": "tenant-config"}, nil)

	got, err := auth.Authenticate("config-token")
	if err != nil {
		t.Fatalf("config token should authenticate without DB row: %v", err)
	}
	if got != "tenant-config" {
		t.Fatalf("tenant = %q, want tenant-config", got)
	}
	if db.calls != 0 {
		t.Fatalf("config token should not require DB lookup, got %d calls", db.calls)
	}
}

func TestDBTokenAuthenticatorCachesAndHotRevokesDBTokens(t *testing.T) {
	db := newFakeOTLPTokenStore(map[string]string{"db-token": "tenant-db"})
	auth := NewDBTokenAuthenticator(db, nil, nil)

	got, err := auth.Authenticate("db-token")
	if err != nil {
		t.Fatalf("db token first auth: %v", err)
	}
	if got != "tenant-db" {
		t.Fatalf("tenant = %q, want tenant-db", got)
	}
	if db.calls != 1 {
		t.Fatalf("first DB token auth should query DB once, got %d", db.calls)
	}

	got, err = auth.Authenticate("db-token")
	if err != nil {
		t.Fatalf("db token cached auth: %v", err)
	}
	if got != "tenant-db" {
		t.Fatalf("tenant = %q, want tenant-db", got)
	}
	if db.calls != 2 {
		t.Fatalf("cached DB token must still verify DB for hot revocation, got %d calls", db.calls)
	}

	db.revoke("db-token")
	if _, err := auth.Authenticate("db-token"); err != ErrUnauthenticated {
		t.Fatalf("revoked DB token err = %v, want ErrUnauthenticated", err)
	}
	if _, err := auth.Authenticate("db-token"); err != ErrUnauthenticated {
		t.Fatalf("revoked DB token should stay evicted, got %v", err)
	}
}
