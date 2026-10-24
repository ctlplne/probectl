// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package govern

import (
	"context"

	"github.com/ctlplne/probectl/internal/l7redact"
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
// Changes in the closed direction are always allowed, alone or together, with
// nothing else changed: withdrawing the remote-AI egress consent, and
// tightening the L7 capture redaction floor (D-43). Refusing either would keep
// data flowing in a way the tenant no longer consents to, which is the open
// direction (docs/guardrails.md G7-2); every other edit — loosening the L7
// floor included — degrades closed.
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
		if !closesOnly(prior, pol) {
			return license.ErrReadOnly
		}
	}
	return g.delegate.SetTenantPolicy(ctx, tenantID, pol, by, auditTx)
}

// closesOnly reports whether next differs from prior only in the closed
// direction: the remote-AI egress consent turned off and/or the L7 capture
// redaction floor made stricter, with at least one of them changed, and every
// category keeping its effective class and redaction strategy, and the
// redaction floor and export redaction unchanged.
func closesOnly(prior, next Policy) bool {
	egressSame := prior.AIRemoteEgress == next.AIRemoteEgress
	egressWithdrawn := prior.AIRemoteEgress && !next.AIRemoteEgress
	l7Same := l7redact.Normalize(prior.L7CaptureRedaction) == l7redact.Normalize(next.L7CaptureRedaction)
	l7Tightened := l7redact.ValidMode(l7redact.Normalize(next.L7CaptureRedaction)) &&
		l7redact.Looser(prior.L7CaptureRedaction, next.L7CaptureRedaction)
	egressOK := egressSame || egressWithdrawn
	l7OK := l7Same || l7Tightened
	if !egressOK || !l7OK || (egressSame && l7Same) {
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
