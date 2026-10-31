// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package audit

import (
	"context"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// TenantRecord is the error-only transactional append seam for repositories
// that must not depend on the audit event representation. It has exactly the
// same immutable append/failure behavior as TenantAppend, in the caller's scope.
func TenantRecord(ctx context.Context, scope tenancy.Scope, actor, action, target string, data map[string]any) error {
	_, err := TenantAppend(ctx, scope, actor, action, target, data)
	return err
}
