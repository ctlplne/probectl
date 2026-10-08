// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package govern

import (
	"context"

	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TenantPolicyStore is the tenant-scoped policy surface behind the /v1
// governance routes; *PolicyStore implements it.
type TenantPolicyStore interface {
	TenantPolicy(ctx context.Context, tenantID string) (Policy, bool, error)
	SetTenantPolicy(ctx context.Context, tenantID string, pol Policy, by string, auditTx func(context.Context, tenancy.Scope) error) error
}

// GatePolicyWrites keeps a tenant's governance policy readable but refuses to
// change it once the license is read-only (past its grace period: "no new
// tenants or config", docs/editions.md), before the change reaches the store.
// One change is always allowed: withdrawing the remote-AI egress consent with
// nothing else changed. Refusing that would keep the tenant's telemetry
// flowing to a remote model it no longer consents to, which is the open
// direction (docs/guardrails.md G7-2); every other edit degrades closed.
func GatePolicyWrites(delegate TenantPolicyStore, writes license.WriteCapability) TenantPolicyStore {
	if delegate == nil {
		return nil
	}
	return writeGatedPolicyStore{delegate: delegate, writes: writes}
}

type writeGatedPolicyStore struct {
	delegate TenantPolicyStore
	writes   license.WriteCapability
}

func (g writeGatedPolicyStore) TenantPolicy(ctx context.Context, tenantID string) (Policy, bool, error) {
	return g.delegate.TenantPolicy(ctx, tenantID)
}

func (g writeGatedPolicyStore) SetTenantPolicy(ctx context.Context, tenantID string, pol Policy, by string, auditTx func(context.Context, tenancy.Scope) error) error {
	if !g.writes.Enabled() {
		prior, _, err := g.delegate.TenantPolicy(ctx, tenantID)
		if err != nil {
			return err
		}
		if !withdrawsEgressOnly(prior, pol) {
			return license.ErrReadOnly
		}
	}
	return g.delegate.SetTenantPolicy(ctx, tenantID, pol, by, auditTx)
}

// withdrawsEgressOnly reports whether next differs from prior only by turning
// the remote-AI egress consent off: every category keeps its effective class
// and redaction strategy, and the redaction floor and export redaction are
// unchanged.
func withdrawsEgressOnly(prior, next Policy) bool {
	if !prior.AIRemoteEgress || next.AIRemoteEgress {
		return false
	}
	if prior.RedactExport != next.RedactExport || prior.redactFrom() != next.redactFrom() {
		return false
	}
	for _, cat := range Categories() {
		if prior.ClassOf(cat) != next.ClassOf(cat) || prior.StrategyFor(cat) != next.StrategyFor(cat) {
			return false
		}
	}
	return true
}
