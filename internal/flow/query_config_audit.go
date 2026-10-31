// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// QueryConfigAudit appends immutable configuration audit in the SAME tenant
// transaction. Trusted wiring supplies the recorder; request data cannot choose
// it. Missing/failed append rolls back the mutation, never silently skips audit.
type QueryConfigAudit func(context.Context, tenancy.Scope, string, string, string, map[string]any) error

func recordQueryConfig(ctx context.Context, scope tenancy.Scope, record QueryConfigAudit, actor, action, target string, data map[string]any) error {
	if record == nil {
		return errors.New("flow configuration audit is unavailable")
	}
	return record(ctx, scope, actor, action, target, data)
}
