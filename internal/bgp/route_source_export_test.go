// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import "context"

// SourcePeerUpForTest exposes only the decoder to the external real-router
// fixture. Production callers still need the authenticated source service.
func SourcePeerUpForTest(ctx context.Context, raw []byte, budget PeerMessageBudget) (PeerUp, error) {
	return parseBMPPeerUp(ctx, raw, budget)
}

// SourceRouteForTest is a test-only bridge for actual pinned FRR wire input.
func SourceRouteForTest(ctx context.Context, raw []byte, peer PeerUp, budget UpdateFrameBudget) (sourceRouteFrame, error) {
	return parseBMPSourceRoute(ctx, raw, peer, budget)
}
