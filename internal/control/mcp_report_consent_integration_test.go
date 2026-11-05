// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"testing"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Configure the owned operator fixture through the existing scoped store;
// the real MCP gate, credential and source checks remain in the request path.
func consentCapturedReportMCP(t *testing.T, f *tagImportSubjectFixture, proof *reportDownloadProof) {
	t.Helper()
	store := govern.NewPolicyStore(f.db.Pool())
	policy, found, err := store.TenantPolicy(t.Context(), proof.tenant)
	if err != nil || policy.AIRemoteEgress {
		t.Fatal("report MCP fixture requires its original unconsented tenant:", err)
	}
	policy.AIRemoteEgress, policy.RedactExport = true, true
	actor := "core-operator:" + proof.user
	var receipt audit.Event
	err = store.SetTenantPolicy(t.Context(), proof.tenant, policy, actor, func(ctx context.Context, sc tenancy.Scope) error {
		var appendErr error
		receipt, appendErr = audit.TenantAppend(ctx, sc, actor, "governance.policy_set", proof.tenant, map[string]any{
			"ai_remote_egress": true, "redact_export": true,
			"prior_ai_remote_egress": false, "prior_policy_existed": found,
			"fixture": "documented-core-operator",
		})
		return appendErr
	})
	if err != nil || receipt.Seq <= 0 || receipt.Hash == "" {
		t.Fatal("report MCP scoped consent requires its atomic tenant audit:", err)
	}
	current, ok, err := store.TenantPolicy(t.Context(), proof.tenant)
	if err != nil || !ok || !current.AIRemoteEgress || !current.RedactExport {
		t.Fatal("report MCP operator consent did not commit for its owned tenant:", err)
	}
}
