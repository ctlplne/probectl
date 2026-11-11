// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

// PeeringRoutingMatch is operation-local original-path classification, never
// query JSON, retained authority or evidence of an actual peering session.
type PeeringRoutingMatch struct {
	RouterID            string
	PeerASN             uint32
	Source, Destination string
}
