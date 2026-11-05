// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import "time"

func loadReportOutputConfig(l *loader, cfg *Config) {
	maxInt := int(^uint(0)>>1) - 1
	cfg.ReportRenderMemoryBytes = l.intRange("PROBECTL_REPORT_RENDER_MEMORY_BYTES", 1<<30, 1, maxInt)
	cfg.ReportOperationTimeout = l.dur("PROBECTL_REPORT_OPERATION_TIMEOUT", time.Minute)
	if cfg.ReportOperationTimeout <= 0 {
		l.errf("PROBECTL_REPORT_OPERATION_TIMEOUT: must be positive")
	}
	cfg.ReportCSVRows = l.intRange("PROBECTL_REPORT_CSV_ROWS", 500000, 1, maxInt/2)
	cfg.ReportPDFRows = l.intRange("PROBECTL_REPORT_PDF_ROWS", 4000, 1, maxInt/2)
	// The existing integer chunk ordinal addresses at most 2^47 body bytes.
	// Keep config independent of the renderer and its embedded font assets.
	cfg.ReportMaxBytes = l.intRange("PROBECTL_REPORT_MAX_BYTES", 256<<20, 1, int(min(int64(maxInt), int64(1)<<47)))
}
