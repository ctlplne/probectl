// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"strings"
	"testing"
	"time"
)

func TestFlowQueryCostConfigRejectsUnlimitedAndPreservesDefaults(t *testing.T) {
	cfg, err := Load(envFunc(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FlowQueryExecutionLimit != 5*time.Second || cfg.FlowQueryReadBytes != 256<<20 || cfg.FlowQueryReadRows != 5000000 || cfg.FlowQueryResponseBytes != 64<<20 || cfg.FlowQueryMemoryBytes != 512<<20 || cfg.FlowQueryIntermediateGroups != 500000 || cfg.FlowQueryInterfaceItems != 10000 || cfg.FlowQueryThreads != 2 {
		t.Fatal("operator query defaults changed")
	}
	if cfg.FlowSnapshotLifetime != 15*time.Minute || cfg.FlowSnapshotTenantBytes != 512<<20 || cfg.FlowSnapshotBytes != 128<<20 || cfg.FlowSnapshotObjectBytes != 64<<20 || cfg.FlowSnapshotExportBytes != 256<<20 {
		t.Fatal("snapshot cache defaults changed")
	}
	if cfg.FlowMCPSourceBytes != 32<<20 || cfg.FlowMCPWireBytes != 128<<20 || cfg.FlowMCPResultNodes != 4<<20 || cfg.FlowMCPCSVPageBytes != 2<<20 {
		t.Fatal("native rendering defaults changed")
	}
	for _, key := range []string{"PROBECTL_FLOW_MCP_SOURCE_BYTES", "PROBECTL_FLOW_MCP_WIRE_BYTES", "PROBECTL_FLOW_MCP_RESULT_NODES", "PROBECTL_FLOW_MCP_CSV_PAGE_BYTES"} {
		for _, invalid := range []string{"0", "-1", "999999999999999999999999999999"} {
			if _, err := Load(envFunc(map[string]string{key: invalid})); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatal("invalid render cost did not refuse startup", key)
			}
		}
	}
	for _, key := range []string{"PROBECTL_FLOW_QUERY_TIMEOUT", "PROBECTL_FLOW_QUERY_MAX_READ_BYTES", "PROBECTL_FLOW_QUERY_MAX_READ_ROWS", "PROBECTL_FLOW_QUERY_MAX_RESPONSE_BYTES", "PROBECTL_FLOW_QUERY_MAX_MEMORY_BYTES", "PROBECTL_FLOW_QUERY_MAX_INTERMEDIATE_GROUPS", "PROBECTL_FLOW_QUERY_MAX_INTERFACE_ITEMS", "PROBECTL_FLOW_QUERY_MAX_THREADS", "PROBECTL_FLOW_SNAPSHOT_LIFETIME", "PROBECTL_FLOW_SNAPSHOT_TENANT_BYTES", "PROBECTL_FLOW_SNAPSHOT_MAX_BYTES", "PROBECTL_FLOW_SNAPSHOT_OBJECT_BYTES", "PROBECTL_FLOW_SNAPSHOT_EXPORT_BYTES"} {
		t.Run(key, func(t *testing.T) {
			for _, invalid := range []string{"0", "-1", "999999999999999999999999999999"} {
				if _, err := Load(envFunc(map[string]string{key: invalid})); err == nil || !strings.Contains(err.Error(), key) {
					t.Fatal("invalid operator budget did not refuse configuration")
				}
			}
		})
	}
	cfg, err = Load(envFunc(map[string]string{"PROBECTL_FLOW_QUERY_TIMEOUT": "1.25s", "PROBECTL_FLOW_QUERY_MAX_READ_ROWS": "12345678", "PROBECTL_FLOW_QUERY_MAX_MEMORY_BYTES": "1073741824"}))
	if err != nil || cfg.FlowQueryExecutionLimit != 1250*time.Millisecond || cfg.FlowQueryReadRows != 12345678 || cfg.FlowQueryMemoryBytes != 1<<30 {
		t.Fatal("valid operator query policy was not retained", err)
	}
}
