// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"errors"
	"testing"
)

func TestPublicRoutingAssignmentCannotAuthorizeEntityObservations(t *testing.T) {
	source := SourceKey{AgentID: "collector", Kind: PublicBGP, SourceRef: "ris/mrt_table_dump_v2/rrc00"}
	if got, err := source.Normalize(); err != nil || got != source {
		t.Fatal("public collector assignment was refused", got, err)
	}
	for _, alias := range []AliasKind{AddressAlias, PrefixAlias, SNMPDeviceAlias, SNMPInterfaceAlias, PhysicalNeighborAlias, FlowExporterAlias, BMPPeerAlias, PathHopAlias, AgentSiteAlias} {
		if err := validateObservationFamily(Observation{Source: source, Alias: AliasKey{Kind: alias}}); !errors.Is(err, ErrInvalidClaim) {
			t.Fatal("public collector assignment authorized an entity observation", alias, err)
		}
	}
}
