// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package e2e

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type releaseCoreReportConsent struct{ pool *pgxpool.Pool }

// Core operators set consent in their own database (docs/ai-egress.md).
// Reuse the scoped store and its atomic tenant audit; the Enterprise-only
// management API must stay hidden in this core release image.
func newReleaseCoreReportConsent(t *testing.T, stack composeStack, ca string) *releaseCoreReportConsent {
	t.Helper()
	uri := url.URL{Scheme: "postgres", User: url.User("probectl_runtime"),
		Host: net.JoinHostPort("localhost", stack.envValue("PROBECTL_DEV_POSTGRES_PORT")), Path: "/probectl",
		RawQuery: url.Values{"sslmode": {"verify-full"}, "sslrootcert": {ca}}.Encode()}
	cfg, err := pgxpool.ParseConfig(uri.String())
	if err != nil {
		t.Fatal("parse release core consent database configuration:", err)
	}
	cfg.ConnConfig.Password = e2eRuntimePassword
	cfg.ConnConfig.ConnectTimeout = 10 * time.Second
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal("open release core consent database:", err)
	}
	t.Cleanup(pool.Close)
	return &releaseCoreReportConsent{pool: pool}
}

func (c *releaseCoreReportConsent) set(t *testing.T, p *releaseFlowReport, allowed bool) {
	t.Helper()
	p.api.json(t, http.StatusNotFound, http.MethodPut, "/v1/governance/policy",
		map[string]any{"ai_remote_egress": allowed, "redact_export": true}, nil)
	var me struct {
		TenantID string `json:"tenant_id"`
		UserID   string `json:"user_id"`
	}
	p.api.json(t, http.StatusOK, http.MethodGet, "/v1/me", nil, &me)
	if me.TenantID != p.tenant || me.UserID == "" {
		t.Fatal("core operator consent fixture requires the actual report tenant and user")
	}
	store := govern.NewPolicyStore(c.pool)
	prior, found, err := store.TenantPolicy(t.Context(), p.tenant)
	if err != nil {
		t.Fatal("read prior core report consent:", err)
	}
	policy := prior
	policy.AIRemoteEgress, policy.RedactExport = allowed, true
	actor := "core-operator:" + me.UserID
	var receipt audit.Event
	err = store.SetTenantPolicy(t.Context(), p.tenant, policy, actor, func(ctx context.Context, sc tenancy.Scope) error {
		var appendErr error
		receipt, appendErr = audit.TenantAppend(ctx, sc, actor, "governance.policy_set", p.tenant, map[string]any{
			"ai_remote_egress": allowed, "redact_export": true,
			"prior_ai_remote_egress": prior.AIRemoteEgress, "prior_policy_existed": found,
			"fixture": "documented-core-operator",
		})
		return appendErr
	})
	if err != nil {
		t.Fatal("set scoped core report consent and atomic tenant audit:", err)
	}
	current, ok, err := store.TenantPolicy(t.Context(), p.tenant)
	if err != nil || !ok || current.AIRemoteEgress != allowed || !current.RedactExport {
		t.Fatal("core report consent did not commit for the owned tenant:", err)
	}
	c.verifyReceipt(t, p.tenant, actor, receipt)
}

func (c *releaseCoreReportConsent) verifyReceipt(t *testing.T, tenant, actor string, receipt audit.Event) {
	t.Helper()
	if receipt.Seq <= 0 || receipt.Hash == "" {
		t.Fatal("core report consent requires a tenant audit receipt")
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	err := tenancy.InTenant(ctx, c.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var count int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events
			WHERE tenant_id = $1 AND seq = $2 AND actor = $3
			  AND action = 'governance.policy_set' AND target = $5 AND hash = $4`,
			tenant, receipt.Seq, actor, receipt.Hash, tenant).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			t.Fatal("core report consent tenant audit did not commit with the policy")
		}
		return nil
	})
	if err != nil {
		t.Fatal("verify committed core report consent tenant audit:", err)
	}
}
