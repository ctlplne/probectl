// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"bytes"
	"context"
	"encoding/json"
)

func parseCloudflareServiceRanges(ctx context.Context, raw []byte, dataset *serviceRangeDataset, remaining *int64) error {
	var document struct {
		Success *bool             `json:"success"`
		Errors  []json.RawMessage `json:"errors"`
		Result  *struct {
			ETag    string          `json:"etag"`
			IPv4    json.RawMessage `json:"ipv4_cidrs"`
			IPv6    json.RawMessage `json:"ipv6_cidrs"`
			JDCloud json.RawMessage `json:"jdcloud_cidrs"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &document); err != nil || document.Success == nil || !*document.Success || len(document.Errors) != 0 || document.Result == nil {
		return serviceRangeDecodeError("Cloudflare")
	}
	result := document.Result
	if result.IPv4 == nil && result.IPv6 == nil && result.JDCloud == nil {
		return serviceRangeDecodeError("Cloudflare prefix families")
	}
	dataset.status.TermsURL = "https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/"
	dataset.status.Version = result.ETag
	if dataset.status.Version == "" {
		// No invented publisher version or publication clock. Freshness uses
		// the preserved bulk fetch time; this explicit ID is local content identity.
		dataset.status.Version = "sha256:" + dataset.status.Digest
	}
	for _, family := range []struct {
		raw     json.RawMessage
		bits    int
		service string
	}{
		{result.IPv4, 32, "Cloudflare"}, {result.IPv6, 128, "Cloudflare"}, {result.JDCloud, 0, "JD Cloud"},
	} {
		if family.raw == nil {
			continue
		}
		var prefixes []string
		if bytes.Equal(bytes.TrimSpace(family.raw), []byte("null")) || json.Unmarshal(family.raw, &prefixes) != nil {
			return serviceRangeDecodeError("Cloudflare prefix family")
		}
		for _, prefix := range prefixes {
			if family.bits != 0 && !serviceRangeFamily(prefix, family.bits == 32) {
				return serviceRangeDecodeError("Cloudflare address family")
			}
			// The publisher does not locate an anycast address in one region.
			// Empty region explicitly means unknown; it never becomes a guessed site.
			if err := dataset.add(ctx, prefix, family.service, "", remaining); err != nil {
				return err
			}
		}
	}
	return nil
}
