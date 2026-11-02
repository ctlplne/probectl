// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"testing"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tags"
)

func TestMCPTagAssignmentHidesExporterSourceReference(t *testing.T) {
	exporter := store.TagAssignmentRecord{ID: "assignment", Assignment: tags.Assignment{
		TagID: "tag", TargetKind: "exporter",
		TargetID: "encoded-agent-and-configured-source", Value: "blue", Source: "manual"},
		ExporterAgentID: "agent-secret", ExporterSourceRef: "configured-source-secret"}
	if got := mcpTagAssignment(exporter); got.TargetID != "" || got.ID != "assignment" ||
		got.Value != "blue" || got.Source != "manual" {
		t.Fatalf("MCP exporter projection leaked source or lost value: %+v", got)
	}
	device := store.TagAssignmentRecord{Assignment: tags.Assignment{
		TargetKind: "device", TargetID: "canonical-device-id", Value: "green"}}
	if got := mcpTagAssignment(device); got.TargetID != "canonical-device-id" {
		t.Fatalf("MCP canonical subject ID was removed: %+v", got)
	}
}
