// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
)

// TestCollectorRegistrationDuplicateNameIsA409 (DPR-048): the registry's
// conflict for a reused collector name reaches the API caller as 409 with
// the actionable message, not as an opaque 500.
func TestCollectorRegistrationDuplicateNameIsA409(t *testing.T) {
	srv, db := setupSessionAPI(t, auth.Identity{})
	h := srv.Handler()
	tenant := freshTenant(t, db, "collconf")
	uid := createUserWithPerm(t, db, tenant, "ops@x.com", nil, "agent.write")
	sess, err := srv.sessions.Issue(context.Background(), auth.Session{TenantID: tenant, UserID: uid, Email: "ops@x.com", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv.enrollSvc = forensicEnrollmentService{collectorErr: apierror.Conflict(`an agent or collector named "helm-flow-1" is already registered in this tenant: reuse its agent_id, or register with another name`)}
	rec := sessionReq(t, h, http.MethodPost, "/v1/collectors/register",
		&http.Cookie{Name: auth.SessionCookie, Value: sess},
		`{"token":"pjt_test-token","plane":"flow","hostname":"helm-flow-1"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"conflict"`) || !strings.Contains(rec.Body.String(), "helm-flow-1") {
		t.Fatalf("body must carry the conflict and the name: %s", rec.Body.String())
	}
}
