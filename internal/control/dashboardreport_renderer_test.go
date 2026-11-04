// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestDashboardReportRendererStagesOwnedCompleteInlineBodies(t *testing.T) {
	definition := validDashboardRequest().Definition
	doc := reporting.Document{
		Title: "Owned report", TenantName: "Tenant A", TenantScope: "tenant-a",
		AbsoluteFrom: definition.AbsoluteFrom, AbsoluteTo: definition.AbsoluteTo,
		GeneratedAt: time.Now().UTC(), GeneratedBy: "owner@example.invalid",
		Provenance: definition.Provenance, RedactionState: definition.RedactionState,
		CoverageLimitations: definition.CoverageLimitations, Metrics: definition.Metrics,
	}
	own := tenancy.WithTenant(t.Context(), tenancy.ID(doc.TenantScope))
	for _, format := range []string{"csv", "pdf"} {
		t.Run(format, func(t *testing.T) {
			expected, err := reporting.RenderCSVContext(own, doc)
			media := "text/csv"
			if format == "pdf" {
				expected, err = reporting.RenderPDFContext(own, doc)
				media = "application/pdf"
			}
			if err != nil {
				t.Fatal(err)
			}
			content, actualMedia, err := renderDashboardReport(own, format, doc)
			if err != nil || !bytes.Equal(content, expected) || actualMedia != media || len(content) > maxInlineReportBytes {
				t.Fatal("staged inline body lost complete renderer bytes", err)
			}
			canceled, cancel := context.WithCancel(own)
			cancel()
			for _, ctx := range []context.Context{t.Context(), tenancy.WithTenant(t.Context(), tenancy.ID("tenant-b")), canceled} {
				content, media, err := renderDashboardReport(ctx, format, doc)
				if err == nil || content != nil || media != "" {
					t.Fatal("unbound, foreign or canceled body became publishable")
				}
			}
		})
	}
	// Complete CSV data over the legacy storage constraint is refused, never
	// silently truncated or returned as a partially successful artifact.
	doc.Metrics = map[string]string{"large": strings.Repeat("x", maxInlineReportBytes)}
	content, media, err := renderDashboardReport(own, "csv", doc)
	if err == nil || content != nil || media != "" {
		t.Fatal("over-limit inline report returned a partial artifact")
	}
}
