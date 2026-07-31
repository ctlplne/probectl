// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tenancy

import (
	"context"
	"fmt"
)

// LockTenantWrites acquires the canonical transaction-scoped exclusive tenant
// writer lock. Full erasure takes this lock before committing the durable
// offboarding fence, so storage writers that already hold the matching shared
// lock finish first and later writers observe the committed fence.
func LockTenantWrites(
	ctx context.Context,
	q Querier,
	tenantID string,
) error {
	_, err := q.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock(
		     hashtextextended('tenant-write:' || $1::uuid::text, 0)
		 )`,
		tenantID,
	)
	if err != nil {
		return fmt.Errorf("lock tenant writers: %w", err)
	}
	return nil
}
