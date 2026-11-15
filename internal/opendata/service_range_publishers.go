// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"encoding/json"
	"net/netip"
	"time"
)

func parseAWSServiceRanges(ctx context.Context, raw []byte, dataset *serviceRangeDataset, remaining *int64) error {
	var document struct {
		Token    string `json:"syncToken"`
		Created  string `json:"createDate"`
		Prefixes []struct {
			Prefix  string `json:"ip_prefix"`
			Region  string `json:"region"`
			Service string `json:"service"`
		} `json:"prefixes"`
		IPv6 []struct {
			Prefix  string `json:"ipv6_prefix"`
			Region  string `json:"region"`
			Service string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || document.Prefixes == nil || document.IPv6 == nil {
		return serviceRangeDecodeError("AWS")
	}
	published, err := time.Parse("2006-01-02-15-04-05", document.Created)
	if err != nil {
		return serviceRangeDecodeError("AWS")
	}
	dataset.status.Version, dataset.status.PublishedAt = document.Token, published
	dataset.status.TermsURL = "https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html"
	for _, row := range document.Prefixes {
		if !serviceRangeFamily(row.Prefix, true) {
			return serviceRangeDecodeError("AWS IPv4")
		}
		if err := dataset.add(ctx, row.Prefix, row.Service, row.Region, remaining); err != nil {
			return err
		}
	}
	for _, row := range document.IPv6 {
		if !serviceRangeFamily(row.Prefix, false) {
			return serviceRangeDecodeError("AWS IPv6")
		}
		if err := dataset.add(ctx, row.Prefix, row.Service, row.Region, remaining); err != nil {
			return err
		}
	}
	return nil
}

func parseGoogleServiceRanges(ctx context.Context, raw []byte, dataset *serviceRangeDataset, remaining *int64) error {
	var document struct {
		Token    string    `json:"syncToken"`
		Created  time.Time `json:"creationTime"`
		Prefixes []struct {
			IPv4    string `json:"ipv4Prefix"`
			IPv6    string `json:"ipv6Prefix"`
			Service string `json:"service"`
			Scope   string `json:"scope"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || document.Prefixes == nil {
		return serviceRangeDecodeError("Google")
	}
	dataset.status.Version, dataset.status.PublishedAt = document.Token, document.Created.UTC()
	dataset.status.TermsURL = "https://cloud.google.com/vpc/docs/configure-private-google-access"
	for _, row := range document.Prefixes {
		if (row.IPv4 == "") == (row.IPv6 == "") {
			return serviceRangeDecodeError("Google")
		}
		cidr := row.IPv4
		if row.IPv6 != "" {
			cidr = row.IPv6
		}
		if !serviceRangeFamily(cidr, row.IPv4 != "") {
			return serviceRangeDecodeError("Google address family")
		}
		service, region := row.Service, row.Scope
		if dataset.status.Publisher == "google" {
			// goog.json publishes ownership, not a particular API or region.
			if service != "" || region != "" {
				return serviceRangeDecodeError("Google global")
			}
			service, region = "Google", "global"
		}
		if err := dataset.add(ctx, cidr, service, region, remaining); err != nil {
			return err
		}
	}
	return nil
}

func serviceRangeFamily(cidr string, ipv4 bool) bool {
	prefix, err := netip.ParsePrefix(cidr)
	return err == nil && !prefix.Addr().Is4In6() && prefix.Addr().Is4() == ipv4
}
