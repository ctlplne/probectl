// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

//go:build integration

package control

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func abacDenialRows(t *testing.T, db *store.DB, tenant string) []audit.Event {
	t.Helper()
	var rows []audit.Event
	ctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenant))
	if err := tenancy.InTenant(ctx, db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		rows, err = audit.ListFiltered(ctx, sc, 0, 100, audit.Filter{Action: "abac.denied"})
		return err
	}); err != nil {
		t.Fatalf("list denial rows: %v", err)
	}
	return rows
}

// TestABACDenialIsAuditedOncePerWindow (DPR-043): a policy denial lands on the
// tenant's tamper-evident stream naming the actor and the permission, repeats
// inside the window fold into that row, a later denial is a new row, and an
// ordinary RBAC miss is not mislabelled as a policy denial.
func TestABACDenialIsAuditedOncePerWindow(t *testing.T) {
	srv, db := setupSessionAPI(t, auth.Identity{})
	h := srv.Handler()
	testBody := `{"name":"t","type":"icmp","target":"1.1.1.1"}`
	tenant := freshTenant(t, db, "abacaudit")
	uid := createUserWithPerm(t, db, tenant, "con@x.com", map[string]string{"department": "contractor"}, "test.write")
	createDenyPolicy(t, db, tenant, "test.write", map[string]string{"department": "contractor"})
	sess, err := srv.sessions.Issue(context.Background(), auth.Session{TenantID: tenant, UserID: uid, Email: "con@x.com", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	deny := func() {
		t.Helper()
		rec := sessionReq(t, h, http.MethodPost, "/v1/tests", &http.Cookie{Name: auth.SessionCookie, Value: sess}, testBody)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("policy must deny: %d %s", rec.Code, rec.Body)
		}
		// The control plane rotates the session cookie when effective
		// authorization changes; keep following the replacement like a browser.
		for _, c := range rec.Result().Cookies() {
			if c.Name == auth.SessionCookie && c.Value != "" {
				sess = c.Value
			}
		}
	}
	deny()
	deny()
	rows := abacDenialRows(t, db, tenant)
	if len(rows) != 1 {
		t.Fatalf("two denials inside the window must produce one audit row, got %d", len(rows))
	}
	if rows[0].Actor != "con@x.com" || rows[0].Target != "test.write" || rows[0].Data["permission"] != "test.write" || rows[0].Data["user_id"] != uid {
		t.Fatalf("denial row must name actor, permission and user: %+v", rows[0])
	}

	// The window elapsed: the next denial is a new row.
	srv.abacDenials.Delete(tenant + "|" + uid + "|test.write")
	deny()
	if rows = abacDenialRows(t, db, tenant); len(rows) != 2 {
		t.Fatalf("a denial after the window must append again, got %d rows", len(rows))
	}

	// An RBAC miss (no test.write at all) is a different 403 and not a policy denial.
	viewer := createUserWithPerm(t, db, tenant, "viewer@x.com", nil, "test.read")
	vsess, err := srv.sessions.Issue(context.Background(), auth.Session{TenantID: tenant, UserID: viewer, Email: "viewer@x.com", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if rec := sessionReq(t, h, http.MethodPost, "/v1/tests", &http.Cookie{Name: auth.SessionCookie, Value: vsess}, testBody); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer write: %d", rec.Code)
	}
	if rows = abacDenialRows(t, db, tenant); len(rows) != 2 {
		t.Fatalf("an RBAC miss must not be recorded as a policy denial, got %d rows", len(rows))
	}
}
