// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// CMDBKeys answers one question: does this tenant have anything of its own by
// that name or address?
//
// The CMDB is deployment-level infrastructure shared by every tenant on an
// MSP-hosted install, so a lookup key must be something the CALLER already
// owns — an agent it enrolled, a device it collects, or a target on one of its
// own incidents. Without that check a tenant could read the operator's whole
// CMDB by guessing hostnames, which is how tenant B's device inventory leaks
// to tenant A (DPR-118). Ownership is decided against the AUTHORITATIVE tenant
// (s.Tenant, taken from the authenticated request principal), never a
// self-asserted agent name or hostname from the payload: every statement below
// carries an explicit tenant_id predicate so a name that collides across
// tenants (an agent renamed to match another tenant's agent) can never make
// one tenant "own" another tenant's key. RLS already confines each statement
// to the caller's tenant; the predicate makes the storage-layer boundary hold
// independently of it (docs/guardrails.md G7-1; AUTHZ-17). Fail closed when
// there is no tenant in scope.
type CMDBKeys struct{}

// TenantOwns reports whether key matches an agent, a device or an incident
// target belonging to the scope's tenant. The tenant is s.Tenant (the
// authenticated principal's tenant), bound as an explicit predicate on every
// table so the boundary does not depend on RLS context alone (AUTHZ-17).
func (CMDBKeys) TenantOwns(ctx context.Context, s tenancy.Scope, key string) (bool, error) {
	if key == "" || s.Tenant == "" {
		return false, nil
	}
	var owns bool
	err := s.Q.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM agents WHERE tenant_id = $2 AND (hostname = $1 OR name = $1))
		    OR EXISTS (SELECT 1 FROM incidents WHERE tenant_id = $2 AND target = $1)
		    OR EXISTS (SELECT 1 FROM incident_signals WHERE tenant_id = $2 AND target = $1)
		    OR EXISTS (SELECT 1 FROM device_collection_outcomes WHERE tenant_id = $2 AND configured_target = $1)`,
		key, s.Tenant.String()).Scan(&owns)
	if err != nil {
		// A handler must not have to re-decide this: the caller's question
		// cannot be answered right now, which is a 503, not a 500.
		return false, apierror.Unavailable("cmdb key ownership lookup failed")
	}
	return owns, nil
}
