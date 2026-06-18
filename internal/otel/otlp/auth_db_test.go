// SPDX-License-Identifier: LicenseRef-probectl-TBD

package otlp

import (
	"context"
	"errors"
	"testing"
	"time"

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

type cancelAwareOTLPTokenStore struct {
	called chan struct{}
	done   chan error
}

func (s *cancelAwareOTLPTokenStore) Authenticate(ctx context.Context, _ []byte) (string, error) {
	close(s.called)
	<-ctx.Done()
	s.done <- ctx.Err()
	return "", ctx.Err()
}

func TestDBTokenAuthenticatorKeepsConfigTokensWorking(t *testing.T) {
	db := newFakeOTLPTokenStore(nil)
	auth := NewDBTokenAuthenticator(db, map[string]string{"config-token": "tenant-config"}, nil)

	got, err := auth.Authenticate(context.Background(), "config-token")
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

	got, err := auth.Authenticate(context.Background(), "db-token")
	if err != nil {
		t.Fatalf("db token first auth: %v", err)
	}
	if got != "tenant-db" {
		t.Fatalf("tenant = %q, want tenant-db", got)
	}
	if db.calls != 1 {
		t.Fatalf("first DB token auth should query DB once, got %d", db.calls)
	}

	got, err = auth.Authenticate(context.Background(), "db-token")
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
	if _, err := auth.Authenticate(context.Background(), "db-token"); err != ErrUnauthenticated {
		t.Fatalf("revoked DB token err = %v, want ErrUnauthenticated", err)
	}
	if _, err := auth.Authenticate(context.Background(), "db-token"); err != ErrUnauthenticated {
		t.Fatalf("revoked DB token should stay evicted, got %v", err)
	}
}

func TestDBTokenAuthenticatorUsesRequestContext(t *testing.T) {
	db := &cancelAwareOTLPTokenStore{
		called: make(chan struct{}),
		done:   make(chan error, 1),
	}
	auth := NewDBTokenAuthenticator(db, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := make(chan error, 1)
	go func() {
		_, err := auth.Authenticate(ctx, "db-token")
		result <- err
	}()

	select {
	case <-db.called:
	case <-time.After(time.Second):
		t.Fatal("DB auth store was not called")
	}
	cancel()

	select {
	case err := <-db.done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("store saw context error %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DB auth store did not observe request cancellation")
	}
	select {
	case err := <-result:
		if err != ErrUnauthenticated {
			t.Fatalf("auth error = %v, want ErrUnauthenticated", err)
		}
	case <-time.After(time.Second):
		t.Fatal("auth did not return after request cancellation")
	}
}
