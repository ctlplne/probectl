// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"net/netip"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// SubscriberOwnsProtectedPrefixInScope requires one explicit assignment that
// covers the entire protected network with no conflicting more-specific one.
func SubscriberOwnsProtectedPrefixInScope(ctx context.Context, sc tenancy.Scope, contextID, tagID, subscriber string, prefix netip.Prefix) (bool, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok || tenant != sc.Tenant || sc.Q == nil || !prefix.IsValid() || prefix.Bits() < 1 || prefix != prefix.Masked() || prefix.Addr().Is4In6() {
		return false, entity.ErrScopeMismatch
	}
	if err := requireRoutingCaptureReadSnapshot(ctx, sc); err != nil {
		return false, err
	}
	var owned bool
	err := sc.Q.QueryRow(ctx, `WITH covering AS (
 SELECT MAX(masklen(e.network_prefix)) AS specificity
 FROM entities e JOIN tenant_tag_assignments a ON a.tenant_id=$1 AND a.context_id=$2
 AND a.entity_id=e.id AND a.target_kind='prefix' AND a.tag_id=$3 AND a.value=$4
 WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.kind='prefix' AND e.network_prefix >>= $5::cidr
 )
 SELECT covering.specificity IS NOT NULL AND NOT EXISTS (
 SELECT 1 FROM entities e JOIN tenant_tag_assignments a ON a.tenant_id=$1 AND a.context_id=$2
 AND a.entity_id=e.id AND a.target_kind='prefix' AND a.tag_id=$3 AND a.value<>$4
 WHERE e.tenant_id=$1 AND e.context_id=$2 AND e.kind='prefix' AND e.network_prefix && $5::cidr
 AND masklen(e.network_prefix)>=covering.specificity
 ) FROM covering`, tenant.String(), contextID, tagID, subscriber, prefix.String()).Scan(&owned)
	return owned, err
}
