// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"fmt"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

// RewrapEnvelopeSecrets re-seals the tenant's OIDC client secret
// (tenant_idp.client_secret_sealed) from a retired deployment-envelope KEK to
// the active one (PLAT-04). The documented rotation originally walked only
// alert_rules.channels and agent_ca.key_sealed, so after `envelope-rewrap
// --from-key-id=old` every tenant's SSO secret was still stamped with the
// retired key; `--verify-retired-key-id=old` reported matched=0/verified=1 and
// exited 0, and removing the retired opener then returned 503 on every tenant's
// /auth/login. Registering this column in the rewrap set makes execute rewrap
// it and makes verify fail closed while it still carries the retired id.
//
// It runs inside a tenant scope so forced RLS stays the outer boundary even
// though this is an operator maintenance job. tenant_idp holds at most one row
// per tenant (ON CONFLICT (tenant_id)); the LIKE prefilter skips tenants whose
// secret is not envelope-sealed (keyless-dev passthrough stores nothing).
func (TenantIDPs) RewrapEnvelopeSecrets(ctx context.Context, s tenancy.Scope, activeKeyID, fromKeyID string, dryRun bool, verifyOpen bool) (EnvelopeRewrapStats, error) {
	stats := EnvelopeRewrapStats{Store: "tenant_idp.client_secret_sealed"}
	rows, err := s.Q.Query(ctx, `SELECT tenant_id::text, client_secret_sealed FROM tenant_idp WHERE client_secret_sealed LIKE '%dv1:%' ORDER BY tenant_id`)
	if err != nil {
		return stats, err
	}
	type row struct{ tenant, sealed string }
	var candidates []row
	for rows.Next() {
		var tn, sealed string
		if err := rows.Scan(&tn, &sealed); err != nil {
			rows.Close()
			return stats, err
		}
		candidates = append(candidates, row{tenant: tn, sealed: sealed})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return stats, err
	}

	for _, candidate := range candidates {
		stats.RowsScanned++
		secret := candidate.sealed
		keyID, ok := tenantcrypto.DeploymentEnvelopeKeyID(secret)
		if !ok {
			continue
		}
		stats.ValuesScanned++
		if keyID == activeKeyID {
			stats.Active++
			if verifyOpen {
				if _, err := tenantcrypto.Open(ctx, s.Tenant.String(), secret, []byte(tenantIDPSecretAAD)); err != nil {
					return stats, err
				}
				stats.Verified++
			}
			continue
		}
		if fromKeyID != "" && keyID != fromKeyID {
			continue
		}
		stats.Matched++
		if dryRun {
			continue
		}
		rewrapped, err := tenantcrypto.RewrapDeploymentEnvelope(ctx, s.Tenant.String(), secret, []byte(tenantIDPSecretAAD))
		if err != nil {
			return stats, err
		}
		newKeyID, ok := tenantcrypto.DeploymentEnvelopeKeyID(rewrapped)
		if !ok || newKeyID != activeKeyID {
			return stats, apierror.Internal("key rotation could not complete").
				Wrap(fmt.Errorf("tenant_idp: rewrap produced key id %q (want active %q)", newKeyID, activeKeyID))
		}
		if _, err := s.Q.Exec(ctx, `UPDATE tenant_idp SET client_secret_sealed = $2, updated_at = clock_timestamp() WHERE tenant_id = $1`, candidate.tenant, rewrapped); err != nil {
			return stats, err
		}
		stats.Rewrapped++
	}
	return stats, nil
}
