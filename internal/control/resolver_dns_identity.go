// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/incident"
)

// The dedicated resolver window was authenticated before publication.
// Recheck its current operator-owned canonical device under the same
// transaction that publishes the signal.
func (p pgIncidentTxStore) resolveResolverDNSAnchor(ctx context.Context, identity incident.IdentityResolution, anchorID, target string) (incident.IdentityResolution, error) {
	if anchorID == "" || target != "resolver:"+anchorID {
		return incident.IdentityResolution{}, incident.ErrFaultSourceInactive
	}
	err := p.scope.Q.QueryRow(ctx, `SELECT id::text FROM entities
		WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND kind='device' FOR SHARE`,
		p.scope.Tenant.String(), identity.ContextID, anchorID).Scan(&identity.EntityID)
	if errors.Is(err, pgx.ErrNoRows) {
		return incident.IdentityResolution{}, incident.ErrFaultSourceInactive
	}
	return identity, err
}
