// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import "time"

func loadFlowQueryConfig(l *loader, cfg *Config) {
	maxInt := int(^uint(0)>>1) - 1
	cfg.FlowQueryExecutionLimit = l.dur("PROBECTL_FLOW_QUERY_TIMEOUT", 5*time.Second)
	if cfg.FlowQueryExecutionLimit <= 0 || cfg.FlowQueryExecutionLimit > time.Duration(1<<63-1)/6 {
		l.errf("PROBECTL_FLOW_QUERY_TIMEOUT: must be positive and fit the six-pass comparison envelope")
	}
	cfg.FlowQueryReadBytes = l.intRange("PROBECTL_FLOW_QUERY_MAX_READ_BYTES", 256<<20, 1, maxInt)
	cfg.FlowQueryReadRows = l.intRange("PROBECTL_FLOW_QUERY_MAX_READ_ROWS", 5000000, 1, maxInt)
	cfg.FlowQueryResponseBytes = l.intRange("PROBECTL_FLOW_QUERY_MAX_RESPONSE_BYTES", 64<<20, 1, maxInt)
	cfg.FlowQueryMemoryBytes = l.intRange("PROBECTL_FLOW_QUERY_MAX_MEMORY_BYTES", 2<<30, 1, maxInt)
	cfg.FlowQueryIntermediateGroups = l.intRange("PROBECTL_FLOW_QUERY_MAX_INTERMEDIATE_GROUPS", 500000, 1, maxInt)
	cfg.FlowQueryInterfaceItems = l.intRange("PROBECTL_FLOW_QUERY_MAX_INTERFACE_ITEMS", 10000, 1, maxInt/10)
	cfg.FlowQueryThreads = l.intRange("PROBECTL_FLOW_QUERY_MAX_THREADS", 2, 1, maxInt)
	cfg.FlowQueryLibraryBytes = l.intRange("PROBECTL_FLOW_QUERY_LIBRARY_BYTES", 256<<20, 1, maxInt)
	cfg.FlowSnapshotLifetime = l.dur("PROBECTL_FLOW_SNAPSHOT_LIFETIME", 15*time.Minute)
	if cfg.FlowSnapshotLifetime <= 0 {
		l.errf("PROBECTL_FLOW_SNAPSHOT_LIFETIME: must be positive")
	}
	cfg.FlowSnapshotTenantBytes = l.intRange("PROBECTL_FLOW_SNAPSHOT_TENANT_BYTES", 512<<20, 1, maxInt)
	cfg.FlowSnapshotBytes = l.intRange("PROBECTL_FLOW_SNAPSHOT_MAX_BYTES", 128<<20, 1, maxInt)
	cfg.FlowSnapshotObjectBytes = l.intRange("PROBECTL_FLOW_SNAPSHOT_OBJECT_BYTES", 64<<20, 1, maxInt)
	cfg.FlowSnapshotExportBytes = l.intRange("PROBECTL_FLOW_SNAPSHOT_EXPORT_BYTES", 256<<20, 1, maxInt)
	cfg.FlowMCPSourceBytes = l.intRange("PROBECTL_FLOW_MCP_SOURCE_BYTES", 32<<20, 1, maxInt)
	cfg.FlowMCPWireBytes = l.intRange("PROBECTL_FLOW_MCP_WIRE_BYTES", 128<<20, 1, maxInt)
	cfg.FlowMCPResultNodes = l.intRange("PROBECTL_FLOW_MCP_RESULT_NODES", 4<<20, 1, maxInt)
	cfg.FlowMCPCSVPageBytes = l.intRange("PROBECTL_FLOW_MCP_CSV_PAGE_BYTES", 2<<20, 1, maxInt)
	cfg.FlowQuestionMaxBytes = l.intRange("PROBECTL_FLOW_QUESTION_MAX_BYTES", 8<<20, 1, maxInt)
	cfg.FlowQuestionMaxTokens = l.intRange("PROBECTL_FLOW_QUESTION_MAX_TOKENS", 1<<20, 1, maxInt)
	cfg.FlowQuestionMaxNesting = l.intRange("PROBECTL_FLOW_QUESTION_MAX_NESTING", 32, 1, maxInt)
	cfg.FlowQuestionModelResponseBytes = l.intRange("PROBECTL_FLOW_QUESTION_MODEL_MAX_RESPONSE_BYTES", 16<<20, 1, maxInt)
	cfg.FlowQuestionModelOutputTokens = l.intRange("PROBECTL_FLOW_QUESTION_MODEL_MAX_OUTPUT_TOKENS", 16384, 1, maxInt)
	cfg.FlowQuestionModelTokenParameter = l.enum("PROBECTL_FLOW_QUESTION_MODEL_OPENAI_TOKEN_PARAMETER", "max_completion_tokens", "max_completion_tokens", "max_tokens")
}
