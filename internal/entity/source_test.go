// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"errors"
	"strings"
	"testing"
)

func TestSourceKeyRequiresAuthenticatedConfiguredIdentity(t *testing.T) {
	base := SourceKey{AgentID: "collector-a", Kind: DeviceTarget, SourceRef: "10.42.0.1"}
	if got, err := base.Normalize(); err != nil || got != base {
		t.Fatalf("valid configured source: %+v err=%v", got, err)
	}
	for _, tc := range []struct {
		name string
		key  SourceKey
	}{
		{"missing agent", SourceKey{Kind: base.Kind, SourceRef: base.SourceRef}},
		{"missing target", SourceKey{AgentID: base.AgentID, Kind: base.Kind}},
		{"unknown producer", SourceKey{AgentID: base.AgentID, Kind: "packet", SourceRef: base.SourceRef}},
		{"control character", SourceKey{AgentID: base.AgentID, Kind: base.Kind, SourceRef: "target\nforged"}},
		{"unbounded agent", SourceKey{AgentID: strings.Repeat("x", 129), Kind: base.Kind, SourceRef: base.SourceRef}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.key.Normalize(); !errors.Is(err, ErrInvalidSource) {
				t.Fatalf("invalid source accepted: %v", err)
			}
		})
	}
}
