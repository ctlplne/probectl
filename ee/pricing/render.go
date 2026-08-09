// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.

package pricing

import (
	"fmt"
	"strings"
)

// RenderMarkdown renders the human-review summary. JSON remains the canonical
// result because it carries the complete formula, input, and unknown trace.
func RenderMarkdown(report Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# probectl offline TCO report\n\nInput revision: `%s` · currency: `%s` · offline: `%t`\n\n", report.InputRevision, report.Currency, report.Offline)
	b.WriteString("| Scenario | Sensitivity | Plan | License / month | TCO / month | Per tenant / month | Cap |\n")
	b.WriteString("|---|---|---|---:|---:|---:|---|\n")
	for _, scenario := range report.ScenarioResults {
		for _, plan := range scenario.Packages {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s |\n",
				scenario.Scenario, scenario.Sensitivity, plan.Name,
				formatMoney(plan.MonthlyLicenseUSD.Value), formatMoney(plan.MonthlyTCOUSD.Value),
				formatMoney(plan.EffectiveTenantMonthUSD.Value), plan.CapStatus)
		}
	}
	b.WriteString("\n`UNKNOWN` means at least one named input is null; inspect JSON output for the exact formula and unknown inputs. This planning report is not a quote or legal term.\n")
	return b.String()
}

func formatMoney(value *float64) string {
	if value == nil {
		return "UNKNOWN"
	}
	return fmt.Sprintf("$%.2f", *value)
}
