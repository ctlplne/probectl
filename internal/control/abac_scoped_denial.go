// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"

	"github.com/ctlplne/probectl/internal/auth"
)

type scopedABACDenialKey struct{}

type scopedABACDenialRecord struct {
	principal  *auth.Principal
	permission string
}

// Keep the ordinary authorization/denial door while one tenant connection is
// held. The owning operation synchronously flushes its first denial through the
// existing durable audit door AFTER its transaction has rolled back. There is
// no background queue, second connection inside the scope, or successful write
// on a denied operation. The callback must be deferred by the transaction owner.
func scopedABACDenial(ctx context.Context) (context.Context, func(*Server)) {
	record := &scopedABACDenialRecord{}
	return context.WithValue(ctx, scopedABACDenialKey{}, record), func(s *Server) {
		if record.principal != nil {
			s.auditABACDenial(ctx, record.principal, record.permission)
		}
	}
}
