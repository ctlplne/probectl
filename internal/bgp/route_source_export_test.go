// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
)

// SourcePeerUpForTest exposes only the decoder to the external real-router
// fixture. Production callers still need the authenticated source service.
func SourcePeerUpForTest(ctx context.Context, raw []byte, budget PeerMessageBudget) (PeerUp, error) {
	return parseBMPPeerUp(ctx, raw, budget)
}

// SourceChangesForTest exposes complete interpreted source data only to the
// real-router fixture; it establishes no transport or storage authority.
func SourceChangesForTest(ctx context.Context, raw []byte, peer PeerUp, budget UpdateFrameBudget) (RoutingChanges, error) {
	return decodeBMPRouteChanges(ctx, raw, peer, budget)
}
