// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otlp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/tenancy"
)

type quarantinedTokens struct{ quarantined bool }

func (q *quarantinedTokens) Authenticate(context.Context, []byte) (string, error) {
	if q.quarantined {
		return "", fmt.Errorf("auth: %w", &tenancy.QuarantinedError{})
	}
	return "t-q", nil
}

// D-62: a quarantined tenant's collector is told to retry (HTTP 503 +
// Retry-After, gRPC UNAVAILABLE) and its token stays cached — a quarantine is
// not a revocation; once released the same token works again.
func TestOTLPAuthAnswersRetryLaterForAQuarantinedTenant(t *testing.T) {
	store := &quarantinedTokens{}
	auth := NewDBTokenAuthenticator(store, nil, nil)
	if tenant, err := auth.Authenticate(context.Background(), "tok"); err != nil || tenant != "t-q" {
		t.Fatalf("warm-up = %q %v", tenant, err)
	}
	store.quarantined = true
	_, err := auth.Authenticate(context.Background(), "tok")
	if !errors.Is(err, tenancy.ErrTenantQuarantined) {
		t.Fatalf("quarantined Authenticate = %v, want the quarantine refusal", err)
	}
	rec := httptest.NewRecorder()
	writeHTTPAuthError(rec, err)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("HTTP = %d (Retry-After %q), want a retryable 503", rec.Code, rec.Header().Get("Retry-After"))
	}
	if code := status.Code(grpcAuthError(err)); code != codes.Unavailable {
		t.Fatalf("gRPC = %v, want Unavailable", code)
	}
	if code := status.Code(grpcAuthError(ErrUnauthenticated)); code != codes.Unauthenticated {
		t.Fatalf("a bad token = %v, want Unauthenticated", code)
	}
	store.quarantined = false
	if _, _, err := auth.mem.authenticateEntry("tok"); err != nil {
		t.Fatalf("the quarantine evicted the cached token: %v", err)
	}
	if tenant, err := auth.Authenticate(context.Background(), "tok"); err != nil || tenant != "t-q" {
		t.Fatalf("after release = %q %v", tenant, err)
	}
}
