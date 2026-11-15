// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package opendata

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestGooglePublishedRangeClockKeepsTimezoneLessOriginalWithoutGuessing(t *testing.T) {
	at := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	// Metadata shape reproduced from the actual public export. The prefix is
	// QA-authored; this does not redistribute a publisher's range dataset.
	for _, clock := range []string{"2026-11-15T00:04:21.649665", "2026-07-15T00:04:21.649665", "2026-11-15T00:04:21.649665-08:00", "2026-11-15T08:04:21.649665Z"} {
		raw := fmt.Sprintf(`{"version":1,"sources":[{"publisher":"google_cloud","fetched_at":"2026-11-15T09:00:00Z","complete":true,"data":{"syncToken":"1794729861649","creationTime":%q,"prefixes":[{"ipv4Prefix":"192.0.2.0/24","service":"Google Cloud","scope":"us-west1"}]}}]}`, clock)
		source, err := LoadServiceRanges(context.Background(), serviceRangeFile(t, raw), 24*time.Hour, 16<<20, at)
		if err != nil {
			t.Fatal("valid publisher calendar clock was narrowed to a timezone-bearing format", clock, err)
		}
		status := source.lookup(netip.MustParseAddr("192.0.2.7"), at, true)[0]
		if status.Status != "matched" || status.Version != "1794729861649" || status.PublishedTime != clock || len(status.Matches) != 1 || status.Matches[0].Region != "us-west1" {
			t.Fatal("original metadata or golden attribution changed", status)
		}
		_, offsetErr := time.Parse(time.RFC3339Nano, clock)
		if offsetErr == nil && !status.PublishedAt.Equal(time.Date(2026, 11, 15, 8, 4, 21, 649665000, time.UTC)) {
			t.Fatal("explicit offset lost original precision", status)
		}
		if offsetErr != nil && !status.PublishedAt.IsZero() {
			t.Fatal("timezone-less clock was assigned an invented absolute time", status)
		}
		encoded, err := json.Marshal(status)
		if err != nil {
			t.Fatal(err)
		}
		var value map[string]any
		if err = json.Unmarshal(encoded, &value); err != nil {
			t.Fatal(err)
		}
		if value["published_time"] != clock {
			t.Fatal("public metadata dropped original calendar clock", value)
		}
		if _, present := value["published_at"]; offsetErr != nil && present {
			t.Fatal("public metadata invented a timezone", value)
		}
	}
	for _, invalid := range []string{"2026-02-30T00:04:21.649665", "00:04:21", "not-a-clock"} {
		if _, err := googleServicePublicationClock(invalid); err == nil {
			t.Fatal("malformed source clock accepted", invalid)
		}
	}
}
