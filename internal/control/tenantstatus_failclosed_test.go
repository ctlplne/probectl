// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ctlplne/probectl/internal/apierror"
)

type failingTenantStatus struct{}

func (failingTenantStatus) TenantStatus(context.Context, string) (string, error) {
	return "", errors.New("tenant status store unavailable")
}

type fixedTenantStatus string

func (f fixedTenantStatus) TenantStatus(context.Context, string) (string, error) {
	return string(f), nil
}

// TestCheckTenantLifecycleFailsClosedOnStatusError proves AUTHZ-22: when the
// tenant lifecycle status cannot be determined (the source errors and there is
// no cached value), the gate FAILS CLOSED with a retryable 503 instead of
// degrading open to "active" — a suspended tenant on a fresh replica whose
// status read fails must not be served. Readable states still behave: active
// passes, suspended is refused with 403.
func TestCheckTenantLifecycleFailsClosedOnStatusError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)

	err := testServer(nil).WithTenantStatus(failingTenantStatus{}).checkTenantLifecycle(req, "tenant-a")
	var ae *apierror.Error
	if !errors.As(err, &ae) || ae.Kind != apierror.KindUnavailable {
		t.Fatalf("an unreadable tenant status must fail closed with 503 Unavailable, got %v", err)
	}
	if ae.Code != string(apierror.CodeUnavailable) {
		t.Fatalf("code=%q, want %q (registered)", ae.Code, apierror.CodeUnavailable)
	}

	// Non-vacuity: a readable "active" status is allowed through.
	if err := testServer(nil).WithTenantStatus(fixedTenantStatus("active")).checkTenantLifecycle(req, "tenant-a"); err != nil {
		t.Fatalf("an active tenant must pass the lifecycle gate, got %v", err)
	}

	// A readable "suspended" status is refused with 403 (not 503).
	err = testServer(nil).WithTenantStatus(fixedTenantStatus("suspended")).checkTenantLifecycle(req, "tenant-a")
	if !errors.As(err, &ae) || ae.Kind != apierror.KindForbidden {
		t.Fatalf("a suspended tenant must be refused with 403 Forbidden, got %v", err)
	}
}

// TestTerminalStatusPersists proves suspended/offboarding/deleted are treated as
// terminal (cached without aging out, AUTHZ-22) while active is not.
func TestTerminalStatusPersists(t *testing.T) {
	for _, s := range []string{"suspended", "offboarding", "deleted"} {
		if !terminalStatus(s) {
			t.Errorf("%q must be terminal (cached persistently)", s)
		}
	}
	if terminalStatus("active") {
		t.Error("active must not be terminal")
	}
}
