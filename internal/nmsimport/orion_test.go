// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestOrionSWISPagesPreserveIDsAndKeepSourcePolicyInert(t *testing.T) {
	pages := []struct {
		name string
		raw  string
		read func(io.Reader) (Snapshot, error)
		kind string
		id   string
	}{
		{"nodes", `{"results":[{"NodeID":17,"Caption":"Edge R1","IPAddress":"10.0.0.1","Location":"East","PollInterval":120,"Community":"secret-community-123"}]}`,
			parseOrionNodes, "device", "17"},
		{"groups", `{"results":[{"ContainerID":23,"Name":"WAN","Owner":"secret-owner-456"}]}`,
			parseOrionGroups, "group", "23"},
		{"rules", `{"results":[{"AlertID":31,"Name":"Down","NotifyEnabled":true,"Trigger":"secret-trigger-789","Reset":"secret-reset-111","NotificationSettings":"https://secret.invalid/hook"}]}`,
			parseOrionRules, "rule", "31"},
	}
	for _, tc := range pages {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.read(strings.NewReader(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if got.Source != Orion || len(got.Rows) != 1 || got.Rows[0].Kind != tc.kind || got.Rows[0].ExternalID != tc.id {
				t.Fatalf("source identity lost: %+v", got)
			}
			if tc.name == "nodes" && (got.Rows[0].Address != "10.0.0.1" || got.Rows[0].LocationLabel != "East" ||
				got.Rows[0].PollSeconds != 120 || !contains(got.Rows[0].UnmappedCodes, "site_unmapped") ||
				!contains(got.Rows[0].UnmappedCodes, "poll_settings_unmapped")) {
				t.Fatalf("node mapping lost: %+v", got.Rows[0])
			}
			if tc.name == "groups" && !contains(got.Rows[0].UnmappedCodes, "membership_not_captured") {
				t.Fatalf("group membership silently assumed: %+v", got.Rows[0])
			}
			if tc.name == "rules" && (!contains(got.Rows[0].UnmappedCodes, "expression_unmapped") ||
				!contains(got.Rows[0].UnmappedCodes, "delivery_unmapped")) {
				t.Fatalf("source alert policy silently mapped: %+v", got.Rows[0])
			}
			wire, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"secret-community-123", "secret-owner-456", "secret-trigger-789", "secret-reset-111", "https://secret.invalid/hook"} {
				if strings.Contains(string(wire), forbidden) {
					t.Fatalf("source-only field %q escaped into preview", forbidden)
				}
			}
		})
	}
}

func TestOrionSWISPagesRejectAmbiguousNodeAndRuleIDs(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		read func(io.Reader) (Snapshot, error)
	}{
		{`{"results":[{"NodeID":17},{"NodeID":"017"}]}`, parseOrionNodes},
		{`{"results":[{"AlertID":0}]}`, parseOrionRules},
		{`{"results":null}`, parseOrionGroups},
	} {
		_, err := tc.read(strings.NewReader(tc.raw))
		if !errors.Is(err, ErrInvalidPage) {
			t.Fatalf("ambiguous SWIS source accepted: %v", err)
		}
	}
}
