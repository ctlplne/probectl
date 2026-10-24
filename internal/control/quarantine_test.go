// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func withQuarantine(t *testing.T, entries ...tenancy.QuarantineEntry) *tenancy.Quarantine {
	t.Helper()
	prev := tenancy.CurrentQuarantine()
	t.Cleanup(func() { tenancy.SetQuarantine(prev) })
	q := tenancy.NewQuarantine()
	for _, e := range entries {
		q.Enter(e)
	}
	tenancy.SetQuarantine(q)
	return q
}

// D-62: a quarantined tenant's users get the stable 503 tenant_quarantined on
// every authenticated /v1 route, with the failed precondition and plane named
// and no operator-side detail; every other tenant is served.
func TestQuarantinedTenantIsRefusedAtTheAPIWithAnActionableError(t *testing.T) {
	quarantined := "33333333-3333-3333-3333-333333333333"
	q := withQuarantine(t, tenancy.QuarantineEntry{TenantID: quarantined, Reason: tenancy.QuarantinePlaneUnreachable,
		Plane: "eu", Detail: "dial tcp 10.1.2.3:8443: connection refused", Remedy: "restore connectivity"})
	srv := testServer(fakePinger{})

	if rec := do(srv, http.MethodGet, "/v1/editions"); rec.Code != http.StatusOK {
		t.Fatalf("the default tenant must be served: %d %s", rec.Code, rec.Body.String())
	}
	rec := doAsTenant(srv, http.MethodGet, "/v1/editions", quarantined)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("quarantined tenant: %d %s", rec.Code, rec.Body.String())
	}
	var body errorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != string(apierror.CodeTenantQuarantined) ||
		!strings.Contains(body.Error.Message, `"eu" is unreachable`) ||
		!strings.Contains(body.Error.Message, "operator") {
		t.Fatalf("error = %+v, want tenant_quarantined naming the plane and who fixes it", body.Error)
	}
	if strings.Contains(rec.Body.String(), "10.1.2.3") {
		t.Fatalf("the operator-side detail reached the tenant: %s", rec.Body.String())
	}
	q.Release(quarantined)
	if rec := doAsTenant(srv, http.MethodGet, "/v1/editions", quarantined); rec.Code != http.StatusOK {
		t.Fatalf("released tenant: %d %s", rec.Code, rec.Body.String())
	}
}

// A handler that returns a store error — even one wrapped in another domain
// error — still surfaces the quarantine as the actionable 503, not a 500.
func TestWriteErrorMapsAWrappedQuarantineRefusal(t *testing.T) {
	qerr := &tenancy.QuarantinedError{Entry: tenancy.QuarantineEntry{TenantID: "t", Reason: tenancy.QuarantinePlaneMissing, Plane: "mars"}}
	for _, err := range []error{
		fmt.Errorf("flowstore: route tenant t: %w", qerr),
		apierror.Internal("query flows").Wrap(qerr),
	} {
		rec := httptest.NewRecorder()
		writeError(rec, httptest.NewRequest(http.MethodGet, "/v1/flows", nil), err)
		if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "tenant_quarantined") ||
			!strings.Contains(rec.Body.String(), "PROBECTL_DATAPLANES") {
			t.Fatalf("writeError(%v) = %d %s", err, rec.Code, rec.Body.String())
		}
	}
}

// A quarantined tenant's own valid credential (API token or session) cannot
// resolve — its storage is refused — and the edge says why with the 503,
// while any other resolution failure stays a plain 401.
func TestQuarantinedCredentialGetsTheQuarantineErrorNotA401(t *testing.T) {
	srv := testServer(fakePinger{})
	qerr := &tenancy.QuarantinedError{Entry: tenancy.QuarantineEntry{TenantID: "t", Reason: tenancy.QuarantineSchemaCatchUpFailed}}
	for _, tc := range []struct {
		cause error
		want  string
	}{
		{fmt.Errorf("resolve api token: %w", qerr), string(apierror.CodeTenantQuarantined)},
		{errors.New("token revoked"), string(apierror.CodeUnauthorized)},
	} {
		r := httptest.NewRequest(http.MethodGet, "/v1/tests", nil)
		r.Header.Set("Authorization", "Bearer pat_whatever")
		r = r.WithContext(withPrincipalFailure(r.Context()))
		p := srv.resolvePrincipalSessionWith(nil, r,
			func(*http.Request, string) (*auth.Principal, error) { return nil, tc.cause }, nil)
		if p != nil {
			t.Fatal("a failed resolution produced a principal")
		}
		got, _ := apierror.As(unauthenticated(r))
		if got == nil || got.Code != tc.want {
			t.Fatalf("cause %v: edge error = %+v, want %s", tc.cause, got, tc.want)
		}
	}
}
