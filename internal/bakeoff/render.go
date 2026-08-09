// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bakeoff

import (
	"fmt"
	"strings"
)

func RenderMarkdown(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Buyer bake-off report\n\nCatalog: `%s` · profile: `%s` · archetype: `%s`\n\n", report.CatalogRevision, report.ProfileRevision, report.BuyerArchetype)
	b.WriteString("## Buyer-owned volumes\n\n| Input | Value | Note |\n|---|---:|---|\n")
	volumeNames := sortedVolumeNames(report.Volumes)
	for _, name := range volumeNames {
		volume := report.Volumes[name]
		fmt.Fprintf(&b, "| %s | %.2f %s | %s |\n", name, volume.Value, volume.Unit, volume.Note)
	}
	b.WriteString("\n## Scenario cells\n\n| Scenario | Candidate | Weight | Status | Evidence | Notes |\n|---|---|---:|---|---|---|\n")
	for _, row := range report.Rows {
		fmt.Fprintf(&b, "| %s | %s | %.2f | **%s** | %s | %s |\n", row.Title, row.Candidate, row.Weight, row.Status, renderEvidence(row.Evidence), row.Notes)
	}
	b.WriteString("\n## Score eligibility\n\n| Candidate | Known coverage | Weighted pass rate | Ranking | Blocking cells |\n|---|---:|---:|---|---|\n")
	for _, summary := range report.Summaries {
		passRate := "UNKNOWN"
		if summary.WeightedPassRate != nil {
			passRate = fmt.Sprintf("%.2f%%", *summary.WeightedPassRate*100)
		}
		ranking := "INELIGIBLE"
		if summary.RankingEligible {
			ranking = "ELIGIBLE"
		}
		fmt.Fprintf(&b, "| %s | %.2f%% | %s | %s | %s |\n", summary.Candidate, summary.KnownCoverage*100, passRate, ranking, strings.Join(summary.BlockingCells, ", "))
	}
	b.WriteString("\nUnknown and unsupported cells are never scored as zero. A candidate is ranking-eligible only when every weighted scenario is an evidence-backed pass or fail. Change the separate buyer profile to change volumes or weights; do not rewrite catalog facts.\n")
	return b.String()
}

func renderEvidence(items []Evidence) string {
	if len(items) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("[%s](../../%s)", item.Claim, strings.TrimPrefix(item.Location, "./")))
	}
	return strings.Join(parts, "; ")
}

func sortedVolumeNames(volumes map[string]Volume) []string {
	names := make([]string, 0, len(volumes))
	for name := range volumes {
		names = append(names, name)
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}
