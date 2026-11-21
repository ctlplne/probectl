// SPDX-License-Identifier: BUSL-1.1
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import "testing"

func TestDDoSAssessmentPinsCanonicalNetworkAndDecimalThresholds(t *testing.T) {
	base := DDoSAssessmentInput{Version: "9007199254740993", Prefix: "192.0.2.0/24", Direction: "ingress", PeriodSeconds: 60,
		BytesFloor: "9007199254740993", PacketsFloor: "9007199254740995", GrowthBasisPoints: 15000, VectorShareBasisPoints: 8000,
		MinObservedRecords: 11, MinObservedAddresses: 12}
	limits := base.Thresholds()
	if limits.BytesFloor != base.BytesFloor || limits.PacketsFloor != base.PacketsFloor || limits.GrowthBasisPoints != 15000 ||
		limits.VectorShareBasisPoints != 8000 || limits.MinObservedRecords != 11 || limits.MinObservedAddresses != 12 {
		t.Fatal("the assessment rounded or replaced its evidence thresholds", limits)
	}
	for _, tc := range []struct {
		name      string
		configure func(*DDoSAssessmentInput)
		accepted  bool
	}{
		{"canonical IPv4", func(*DDoSAssessmentInput) {}, true},
		{"canonical IPv6", func(in *DDoSAssessmentInput) {
			in.Prefix, in.Direction, in.PeriodSeconds = "2001:db8::/64", "egress", 300
		}, true},
		{"host bits present", func(in *DDoSAssessmentInput) { in.Prefix = "192.0.2.1/24" }, false},
		{"IPv4-mapped IPv6", func(in *DDoSAssessmentInput) { in.Prefix = "::ffff:192.0.2.0/120" }, false},
		{"revision not canonical", func(in *DDoSAssessmentInput) { in.Version = "+1" }, false},
		{"direction not selected", func(in *DDoSAssessmentInput) { in.Direction = "both" }, false},
		{"window not supported", func(in *DDoSAssessmentInput) { in.PeriodSeconds = 30 }, false},
		{"no packet floor", func(in *DDoSAssessmentInput) { in.PacketsFloor = "0" }, false},
		{"dual stack exporters", func(in *DDoSAssessmentInput) {
			in.RequiredExporters = []string{"2001:db8::2", "192.0.2.1"}
		}, true},
		{"noncanonical exporter", func(in *DDoSAssessmentInput) { in.RequiredExporters = []string{"2001:DB8::2"} }, false},
		{"duplicate exporter", func(in *DDoSAssessmentInput) { in.RequiredExporters = []string{"192.0.2.1", "192.0.2.1"} }, false},
		{"scoped exporter address", func(in *DDoSAssessmentInput) { in.RequiredExporters = []string{"fe80::1%eth0"} }, false},
		{"unspecified exporter address", func(in *DDoSAssessmentInput) { in.RequiredExporters = []string{"0.0.0.0"} }, false},
		{"too many exporters", func(in *DDoSAssessmentInput) {
			in.RequiredExporters = []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7", "192.0.2.8", "192.0.2.9"}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := base
			tc.configure(&in)
			prefix, err := in.ValidatedPrefix()
			if (err == nil) != tc.accepted || (tc.accepted && prefix.String() != in.Prefix) {
				t.Fatal("wrong protected network verdict", prefix, err)
			}
		})
	}
}
