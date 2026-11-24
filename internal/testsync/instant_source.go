// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package testsync

import (
	"context"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// InstantLeaseAuthority checks the initiating actor and exact definition
// under the same tenant transaction that commits the signed lease.
type InstantLeaseAuthority func(context.Context, tenancy.Scope, store.InstantTestLease, string) error

// PullInstantAssignment reserves and signs one pending job for the verified
// agent. Signing and the issuer's current authority are checked before commit.
func (s *Source) PullInstantAssignment(ctx context.Context, tenant, agent, serial string, authorize InstantLeaseAuthority) ([]byte, error) {
	if s == nil || authorize == nil || tenant == "" || agent == "" || serial == "" {
		return nil, ErrInvalidInstantAssignment
	}
	if bound, present := tenancy.FromContext(ctx); present && bound.String() != tenant {
		return nil, ErrInstantAssignmentPeer
	}
	leaseID, err := crypto.UUIDv4()
	if err != nil {
		return nil, err
	}
	var response []byte
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		lease, err := (store.InstantTestRuns{}).LeaseNext(ctx, sc, agent, serial, leaseID)
		if err != nil || lease == nil {
			return err
		}
		if err := authorize(ctx, sc, *lease, agent); err != nil {
			return err
		}
		response, err = s.SignInstantAssignment(InstantAssignment{
			RunID: lease.RunID, LeaseID: lease.LeaseID, TenantID: tenant, AgentID: agent,
			DefinitionHash: lease.DefinitionHash, IssuedAt: lease.IssuedAt, ExpiresAt: lease.ExpiresAt,
			Test: Test{
				ID: lease.Test.ID, Type: lease.Test.Type, Target: lease.Test.Target, Params: lease.Test.Params,
				IntervalSeconds: lease.Test.IntervalSeconds, TimeoutSeconds: lease.Test.TimeoutSeconds,
			},
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	return response, nil
}
