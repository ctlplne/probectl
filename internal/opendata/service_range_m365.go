// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
)

const m365RangeTermsURL = "https://learn.microsoft.com/en-us/microsoft-365/enterprise/microsoft-365-ip-web-service"

var m365RangeInstances = map[string]string{
	"m365_worldwide":    "Worldwide",
	"m365_china":        "China",
	"m365_usgovdod":     "USGovDoD",
	"m365_usgovgcchigh": "USGovGCCHigh",
}

// ServiceRangeFetchOptions contains operator-only public source configuration.
// The client association is not a tenant ID or an authentication credential.
type ServiceRangeFetchOptions struct {
	Microsoft365ClientRequestID string
}

func validateServiceRangeFetchOptions(publishers []string, options ServiceRangeFetchOptions) error {
	for _, publisher := range publishers {
		if _, microsoft365 := m365RangeInstances[publisher]; !microsoft365 {
			continue
		}
		value := options.Microsoft365ClientRequestID
		id, err := uuid.Parse(value)
		if err != nil || id == uuid.Nil || id.String() != strings.ToLower(value) {
			return errors.New("Microsoft365 bulk fetch requires a valid operator-supplied machine client GUID")
		}
	}
	return nil
}

func parseM365ServiceRanges(ctx context.Context, raw []byte, dataset *serviceRangeDataset, remaining *int64) error {
	var endpoints []struct {
		ServiceArea string          `json:"serviceArea"`
		IPs         json.RawMessage `json:"ips"`
	}
	if err := json.Unmarshal(raw, &endpoints); err != nil || endpoints == nil {
		return serviceRangeDecodeError("Microsoft365 endpoints")
	}
	// The endpoints response has no publisher version or generation clock.
	// Keep its complete original JSON and use an explicitly local content ID.
	dataset.status.Version = "sha256:" + dataset.status.Digest
	dataset.status.TermsURL = m365RangeTermsURL
	for _, endpoint := range endpoints {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !validServiceRangeLabel(endpoint.ServiceArea) {
			return serviceRangeDecodeError("Microsoft365 service area")
		}
		if endpoint.IPs == nil {
			continue // URL-only entries remain in the original; never resolve them
		}
		var addresses []string
		if err := json.Unmarshal(endpoint.IPs, &addresses); err != nil || addresses == nil {
			return serviceRangeDecodeError("Microsoft365 address list")
		}
		for _, address := range addresses {
			prefix, err := serviceRangeAddressPrefix(address)
			if err != nil {
				return err
			}
			if err := dataset.add(ctx, prefix, "Microsoft 365 "+endpoint.ServiceArea, "", remaining); err != nil {
				return err
			}
		}
	}
	return nil
}
