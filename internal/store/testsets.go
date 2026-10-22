// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestSets is the tenant's central test-set version (G9, D-41,
// docs/adr/central-test-distribution.md). Every write to the tenant's tests
// bumps it in the same transaction, so the signed bundle an agent pulls carries
// a counter that only increases: the agent refuses a bundle whose version is
// not newer than the one it runs. RLS (FORCE, migration 0125) confines the row
// to the caller's tenant.
type TestSets struct{}

// InitialTestSetVersion is the version of a tenant whose tests were never
// written since migration 0125: tests that already existed are still delivered
// to an agent that has applied nothing (version 0).
const InitialTestSetVersion uint64 = 1

// Version returns the caller's tenant's current test-set version.
func (TestSets) Version(ctx context.Context, s tenancy.Scope) (uint64, error) {
	var v int64
	err := s.Q.QueryRow(ctx,
		`SELECT COALESCE((SELECT version FROM tenant_test_set_versions WHERE tenant_id = $1), $2)`,
		s.Tenant.String(), int64(InitialTestSetVersion)).Scan(&v)
	if err != nil {
		return 0, err
	}
	return uint64(v), nil
}

// bump advances the caller's tenant's version by one. It runs in the same
// transaction as the test write it records, so a reader that sees the new test
// also sees the new version, and concurrent writers serialize on the row lock.
func (TestSets) bump(ctx context.Context, s tenancy.Scope) error {
	_, err := s.Q.Exec(ctx,
		`INSERT INTO tenant_test_set_versions AS v (tenant_id, version, changed_at)
		 VALUES ($1, $2, now())
		 ON CONFLICT (tenant_id) DO UPDATE SET version = v.version + 1, changed_at = now()`,
		s.Tenant.String(), int64(InitialTestSetVersion)+1)
	return err
}

// EnabledTests returns the tenant's enabled tests, the set a signed bundle
// distributes. Read it AFTER Version in the same transaction: a test committed
// in between then rides a bundle labeled with the older version, which the
// agent replaces on its next pull, never the reverse (a newer label on older
// content would hide the test until the next change).
func (TestSets) EnabledTests(ctx context.Context, s tenancy.Scope, maxRows int) ([]Test, error) {
	all, err := (Tests{}).ListAll(ctx, s, maxRows)
	if err != nil {
		return nil, err
	}
	out := make([]Test, 0, len(all))
	for _, t := range all {
		if t.Enabled {
			out = append(out, t)
		}
	}
	return out, nil
}
