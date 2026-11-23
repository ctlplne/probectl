// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestDeviceNVDFeedRetainsScopedApplicabilityAndProvenance(t *testing.T) {
	row := func(id, product, state, node string) string {
		return fmt.Sprintf(`{"cve":{"id":"%s","vulnStatus":"%s","published":"2026-09-10T00:00:00.000","lastModified":"2026-10-01T00:00:00.000","descriptions":[{"lang":"en","value":"synthetic"}],"configurations":[{"operator":"%s","nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:o:reviewed:%s:*:*:*:*:*:*:*:*","versionStartIncluding":"1.2.0","versionEndExcluding":"1.3.0","matchCriteriaId":"11111111-1111-4111-8111-111111111111"}]}]}]}}`, id, state, node, product)
	}
	input := fmt.Sprintf(`{"resultsPerPage":4,"startIndex":0,"totalResults":4,"format":"NVD_CVE","version":"2.0","timestamp":"2026-10-06T10:30:00.123","vulnerabilities":[%s,%s,%s,%s]}`,
		row("CVE-2026-99101", "owned-firmware", "Analyzed", "OR"),
		row("CVE-2026-99102", "unbound-firmware", "Analyzed", "OR"),
		row("CVE-2026-99103", "owned-firmware", "Rejected", "OR"),
		row("CVE-2026-99104", "owned-firmware", "Analyzed", "AND"),
	)
	products := []nvdProductKey{{"o", "reviewed", "owned-firmware"}}
	catalog, err := readDeviceNVDCatalog(t.Context(), strings.NewReader(input), products)
	wantClock := time.Date(2026, time.October, 6, 10, 30, 0, 123_000_000, time.UTC)
	if err != nil || !catalog.observedAt.Equal(wantClock) || len(catalog.byProduct) != 1 {
		t.Fatal("the feed lost its original timestamp or scoped product selection", catalog, err)
	}
	at := wantClock.Add(time.Hour)
	cpe := deviceCPE{part: "o", vendor: "reviewed", product: "owned-firmware", version: "1.2.3", numericOrder: true}
	matches, comparable := catalog.lookup(cpe, at, 24*time.Hour)
	if comparable || len(matches) != 1 || matches[0].ID != "CVE-2026-99101" ||
		matches[0].Published != "2026-09-10T00:00:00.000" || matches[0].LastModified != "2026-10-01T00:00:00.000" {
		t.Fatal("a partial dependency, wrong product or rejected record gained an applicability flag", matches, comparable)
	}
	cpe.version = "1.3.0"
	if matches, _ := catalog.lookup(cpe, at, 24*time.Hour); len(matches) != 0 {
		t.Fatal("an exclusive upper firmware boundary matched a disclosed record", matches)
	}
	cpe.version = "1.2.3"
	if matches, comparable := catalog.lookup(cpe, at.Add(48*time.Hour), 24*time.Hour); comparable || len(matches) != 0 {
		t.Fatal("an expired reference produced a current vulnerability result", matches, comparable)
	}
	for _, bad := range []string{
		strings.Replace(input, `"totalResults":4`, `"totalResults":5`, 1),
		strings.Replace(input, `"startIndex":0`, `"startIndex":4`, 1),
		strings.Replace(input, `"version":"2.0"`, `"version":"2.0","version":"2.0"`, 1),
		input[:len(input)-8],
	} {
		if broken, err := readDeviceNVDCatalog(t.Context(), strings.NewReader(bad), products); err == nil || broken != nil {
			t.Fatal("a partial or conflicting snapshot was published", err)
		}
	}
}
