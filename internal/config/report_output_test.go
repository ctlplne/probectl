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

func TestReportOutputCapacityConfiguration(t *testing.T) {
	defaults, err := Load(envFunc(nil))
	if err != nil || defaults.ReportCSVRows != 500000 || defaults.ReportPDFRows != 4000 || defaults.ReportMaxBytes != 256<<20 {
		t.Fatal("report admission defaults missing", err)
	}
	cfg, err := Load(envFunc(map[string]string{
		"PROBECTL_REPORT_CSV_ROWS":  "2000000",
		"PROBECTL_REPORT_PDF_ROWS":  "25000",
		"PROBECTL_REPORT_MAX_BYTES": "536870912",
	}))
	if err != nil || cfg.ReportCSVRows != 2000000 || cfg.ReportPDFRows != 25000 || cfg.ReportMaxBytes != 512<<20 {
		t.Fatal("larger finite report capacity refused", err)
	}
	if diagnostic, ok := cfg.Redacted()["report_output_cost"].(map[string]any); !ok || diagnostic["csv_rows"] != 2000000 || diagnostic["pdf_rows"] != 25000 || diagnostic["bytes"] != 512<<20 {
		t.Fatal("effective report admission missing from diagnostics")
	}
	for _, key := range []string{"PROBECTL_REPORT_CSV_ROWS", "PROBECTL_REPORT_PDF_ROWS", "PROBECTL_REPORT_MAX_BYTES"} {
		for _, value := range []string{"0", "-1", "999999999999999999999999"} {
			if _, err := Load(envFunc(map[string]string{key: value})); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatal("invalid report capacity admitted", key, value)
			}
		}
	}
}

func TestStaticReportOperationCapacityProfilesAreRaiseable(t *testing.T) {
	defaults, err := Load(envFunc(nil))
	if err != nil || defaults.ReportRenderMemoryBytes != 1<<30 || defaults.ReportOperationTimeout != time.Minute {
		t.Fatal("static report operation defaults missing", err)
	}
	configured, err := Load(envFunc(map[string]string{"PROBECTL_REPORT_RENDER_MEMORY_BYTES": "2147483648", "PROBECTL_REPORT_OPERATION_TIMEOUT": "25h"}))
	if err != nil || configured.ReportRenderMemoryBytes != 2<<30 || configured.ReportOperationTimeout != 25*time.Hour {
		t.Fatal("larger finite static operation profile refused", err)
	}
	diagnostic, ok := configured.Redacted()["report_output_cost"].(map[string]any)
	if !ok || diagnostic["render_memory_bytes"] != 2<<30 || diagnostic["operation_timeout"] != "25h0m0s" {
		t.Fatal("static operation admission missing from safe diagnostics")
	}
	for _, item := range []struct{ key, value string }{{"PROBECTL_REPORT_RENDER_MEMORY_BYTES", "0"}, {"PROBECTL_REPORT_RENDER_MEMORY_BYTES", "-1"}, {"PROBECTL_REPORT_RENDER_MEMORY_BYTES", "999999999999999999999"}, {"PROBECTL_REPORT_OPERATION_TIMEOUT", "0s"}, {"PROBECTL_REPORT_OPERATION_TIMEOUT", "-1s"}, {"PROBECTL_REPORT_OPERATION_TIMEOUT", "999999999999999h"}} {
		if _, err := Load(envFunc(map[string]string{item.key: item.value})); err == nil || !strings.Contains(err.Error(), item.key) {
			t.Fatal("invalid static operation profile admitted", item.key, item.value)
		}
	}
}
