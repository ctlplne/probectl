// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestOneShotCredentialCommandsAreAudited is the AUD-09 regression. The one-shot
// probectl-control credential commands minted/revoked tokens with no audit
// record (only a slog line), while the equivalent API routes audited. Each such
// command must now append exactly one tenant audit event carrying the token id
// (never the secret) plus a provider-stream event. Covered here end-to-end:
// scim-token and mcp-token (the two with no agent-CA/global-state dependency);
// enroll-token, register-collector and revoke-agent route through the same
// auditCredentialOneShot helper.
func TestOneShotCredentialCommandsAreAudited(t *testing.T) {
	db := setupEnvelopeRewrapDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	tn, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("aud09-%d", time.Now().UnixNano()), "AUD-09")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	var userID string
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tn.ID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		u, e := store.Users{}.Create(ctx, sc, fmt.Sprintf("aud09-%d@example.test", time.Now().UnixNano()), "AUD-09 User")
		if e == nil {
			userID = u.ID
		}
		return e
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	type auditRow struct{ action, target, actor, data string }
	tenantEvents := func(t *testing.T, action string) []auditRow {
		t.Helper()
		rows, err := db.Pool().Query(ctx,
			`SELECT action, target, actor, data::text FROM audit_events WHERE tenant_id = $1::uuid AND action = $2 ORDER BY seq`,
			tn.ID, action)
		if err != nil {
			t.Fatalf("query tenant audit events: %v", err)
		}
		defer rows.Close()
		var out []auditRow
		for rows.Next() {
			var a auditRow
			if err := rows.Scan(&a.action, &a.target, &a.actor, &a.data); err != nil {
				t.Fatalf("scan: %v", err)
			}
			out = append(out, a)
		}
		return out
	}
	providerCount := func(t *testing.T, action, target string) int {
		t.Helper()
		var n int
		if err := db.Pool().QueryRow(ctx,
			`SELECT count(*) FROM provider_audit_events WHERE action = $1 AND target = $2`, action, target).Scan(&n); err != nil {
			t.Fatalf("query provider audit events: %v", err)
		}
		return n
	}
	// runCapture redirects stdout so the once-shown secret is captured and can be
	// asserted absent from the audit record. The logger is already /dev/null.
	runCapture := func(t *testing.T, fn func() error) string {
		t.Helper()
		old := os.Stdout
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		os.Stdout = w
		runErr := fn()
		_ = w.Close()
		os.Stdout = old
		out, _ := io.ReadAll(r)
		if runErr != nil {
			t.Fatalf("command: %v", runErr)
		}
		return strings.TrimSpace(string(out))
	}

	assertAudited := func(t *testing.T, action, secret string) {
		t.Helper()
		ev := tenantEvents(t, action)
		if len(ev) != 1 {
			t.Fatalf("AUD-09: %s must produce exactly one tenant audit event, got %d", action, len(ev))
		}
		if ev[0].target == "" {
			t.Fatalf("AUD-09: %s audit event has no token id (target)", action)
		}
		if !strings.HasPrefix(ev[0].actor, "cli:") {
			t.Fatalf("AUD-09: %s audit actor = %q, want cli:<user>@<host>", action, ev[0].actor)
		}
		if secret != "" && (strings.Contains(ev[0].target, secret) || strings.Contains(ev[0].data, secret)) {
			t.Fatalf("AUD-09: %s leaked the secret into the audit event", action)
		}
		if n := providerCount(t, action, ev[0].target); n != 1 {
			t.Fatalf("AUD-09: %s must produce exactly one provider audit event for token %s, got %d", action, ev[0].target, n)
		}
	}

	scimSecret := runCapture(t, func() error {
		return runSCIMToken(log, db, []string{"--tenant", tn.ID, "--name", "aud09-scim"})
	})
	assertAudited(t, "directory.scim_token_create", scimSecret)

	mcpSecret := runCapture(t, func() error {
		return runMCPToken(log, db, []string{"--tenant", tn.ID, "--user", userID, "--name", "aud09-mcp"})
	})
	assertAudited(t, "mcp.token_create", mcpSecret)
}
