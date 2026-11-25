// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package rmm

import (
	"context"
	"encoding/hex"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/nmsimport"
)

func publishSiteInventory(ctx context.Context, scope SiteMapping, candidates []Candidate,
	store nmsimport.CaptureStore) (nmsimport.DiscoveryPlan, error) {
	var devices []nmsimport.DiscoveryDevice
	for _, device := range candidates {
		devices = append(devices, nmsimport.DiscoveryDevice{
			ExternalID: device.ExternalID, Hostname: device.Hostname, Address: device.Address,
		})
	}
	sourceHash := crypto.Default.Hash([]byte("probectl:rmm-site:v1\x00" + scope.Account + "\x00" + scope.ID))
	instance := string(scope.Vendor) + "-" + hex.EncodeToString(sourceHash)
	return store.PublishDiscovery(ctx, scope.ContextID, instance, devices)
}
