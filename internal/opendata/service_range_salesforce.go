// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"encoding/json"
	"time"
)

type salesforceRangeGroup struct {
	Provider string   `json:"provider"`
	Region   string   `json:"region"`
	IPv4     []string `json:"ip_prefix"`
	IPv6     []string `json:"ipv6_prefix"`
}

func parseSalesforceServiceRanges(ctx context.Context, raw []byte, dataset *serviceRangeDataset, remaining *int64) error {
	var document struct {
		Token    string                 `json:"syncToken"`
		Created  string                 `json:"createDate"`
		Prefixes []salesforceRangeGroup `json:"prefixes"`
		IPv6     []salesforceRangeGroup `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || document.Prefixes == nil || document.IPv6 == nil {
		return serviceRangeDecodeError("Salesforce")
	}
	// The publisher's calendar text does not state its offset. Keep it and
	// syncToken literally; original bulk-fetch time governs freshness.
	if _, err := time.Parse("2006-01-02-15-04-05", document.Created); err != nil {
		return serviceRangeDecodeError("Salesforce publication calendar")
	}
	dataset.status.Version, dataset.status.PublishedTime = document.Token, document.Created
	dataset.status.TermsURL = "https://help.salesforce.com/s/articleView?id=xcloud.hf_ip_ranges_to_allow.htm&language=en_US&type=5"
	for _, family := range []struct {
		groups []salesforceRangeGroup
		ipv4   bool
	}{{document.Prefixes, true}, {document.IPv6, false}} {
		for _, group := range family.groups {
			prefixes, other := group.IPv4, group.IPv6
			if !family.ipv4 {
				prefixes, other = group.IPv6, group.IPv4
			}
			if prefixes == nil || other != nil || !validServiceRangeLabel(group.Provider) {
				return serviceRangeDecodeError("Salesforce provider/address family")
			}
			for _, prefix := range prefixes {
				if !serviceRangeFamily(prefix, family.ipv4) {
					return serviceRangeDecodeError("Salesforce prefix family")
				}
				// The hosting provider does not turn these into generic AWS/GCP
				// traffic or identify another Salesforce product such as Slack.
				if err := dataset.add(ctx, prefix, "Salesforce", group.Region, remaining); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
