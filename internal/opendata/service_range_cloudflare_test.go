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
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestCloudflarePublishedRangesKeepAllFamiliesWithoutInventedRegionOrClock(t *testing.T) {
	at := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	body := `{"success":true,"errors":[],"result":{"etag":"original-publisher-etag","ipv4_cidrs":["192.0.2.0/24"],"ipv6_cidrs":["2001:db8::/32"],"jdcloud_cidrs":["198.51.100.0/24","2001:db8:abcd::/48"]}}`
	wrap := func(body string) string {
		return fmt.Sprintf(`{"version":1,"sources":[{"publisher":"cloudflare","fetched_at":%q,"complete":true,"data":%s}]}`, at.Format(time.RFC3339Nano), body)
	}
	source, err := LoadServiceRanges(context.Background(), serviceRangeFile(t, wrap(body)), time.Hour, 16<<20, at)
	if err != nil {
		t.Fatal(err)
	}
	for address, service := range map[string]string{"192.0.2.7": "Cloudflare", "2001:db8::7": "Cloudflare", "198.51.100.7": "JD Cloud", "2001:db8:abcd::7": "JD Cloud"} {
		status := source.lookup(netip.MustParseAddr(address), at, true)[0]
		if status.Status != "matched" || status.Version != "original-publisher-etag" || !status.PublishedAt.IsZero() {
			t.Fatal("original identity was lost or an unknown clock invented", status)
		}
		found := false
		for _, match := range status.Matches {
			found = found || (match.Service == service && match.Region == "")
		}
		if !found {
			t.Fatal("family was omitted or an anycast region invented", address, status)
		}
		encoded, err := json.Marshal(status)
		if err != nil || bytes.Contains(encoded, []byte(`"published_at"`)) {
			t.Fatal("unknown publisher clock became a fabricated date", string(encoded), err)
		}
	}
	for _, complete := range []string{
		`{"success":true,"result":{"ipv4_cidrs":["192.0.2.0/24"]}}`,
		`{"success":true,"result":{"ipv6_cidrs":["2001:db8::/32"]}}`,
		`{"success":true,"result":{"ipv4_cidrs":[],"ipv6_cidrs":[]}}`,
	} {
		value, err := LoadServiceRanges(context.Background(), serviceRangeFile(t, wrap(complete)), time.Hour, 16<<20, at)
		if err != nil || value == nil || !strings.HasPrefix(value.datasets[0].status.Version, "sha256:") {
			t.Fatal("documented optional families or absent etag were narrowed", err)
		}
	}
	for _, invalid := range []string{
		strings.Replace(body, `"success":true`, `"success":false`, 1),
		strings.Replace(body, `"success":true`, `"success":null`, 1),
		strings.Replace(body, `"errors":[]`, `"errors":[{"code":1000}]`, 1),
		strings.Replace(body, `"192.0.2.0/24"`, `"2001:db8::/32"`, 1),
		`{"success":true,"result":{"ipv4_cidrs":null}}`,
		`{"success":true,"result":null}`,
		`{"success":true,"result":{"etag":"without-complete-prefix-families"}}`,
	} {
		if value, err := LoadServiceRanges(context.Background(), serviceRangeFile(t, wrap(invalid)), time.Hour, 16<<20, at); err == nil || value != nil {
			t.Fatal("incomplete Cloudflare data partially admitted", value, err)
		}
	}
}
