// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pathstore

import (
	"strings"
	"testing"
)

func TestPathRollupDDLShape(t *testing.T) {
	hops := createHopsRollupsFor(hopsRollupsTable)
	for _, want := range []string{
		"ENGINE = SummingMergeTree",
		"PARTITION BY (tenant_id, toYYYYMMDD(bucket))",
		"ORDER BY (tenant_id, bucket, target, mode, ttl, responder)",
	} {
		if !strings.Contains(hops, want) {
			t.Fatalf("hops rollup DDL missing %q:\n%s", want, hops)
		}
	}
	links := createLinksRollupsFor(linksRollupsTable)
	for _, want := range []string{
		"ENGINE = SummingMergeTree",
		"PARTITION BY (tenant_id, toYYYYMMDD(bucket))",
		"ORDER BY (tenant_id, bucket, target, ttl, from_ip, to_ip)",
	} {
		if !strings.Contains(links, want) {
			t.Fatalf("links rollup DDL missing %q:\n%s", want, links)
		}
	}
	hopMV := createHopsRollupsMVFor(hopsRollupsMV, hopsTable, hopsRollupsTable)
	for _, want := range []string{
		"CREATE MATERIALIZED VIEW IF NOT EXISTS probectl_path_hops_rollups_hour_mv",
		"TO probectl_path_hops_rollups_hour",
		"FROM probectl_path_hops2",
		"GROUP BY tenant_id, bucket, target, mode, ttl, responder",
	} {
		if !strings.Contains(hopMV, want) {
			t.Fatalf("hops rollup MV missing %q:\n%s", want, hopMV)
		}
	}
	linkMV := createLinksRollupsMVFor(linksRollupsMV, linksTable, linksRollupsTable)
	for _, want := range []string{
		"CREATE MATERIALIZED VIEW IF NOT EXISTS probectl_path_links_rollups_hour_mv",
		"TO probectl_path_links_rollups_hour",
		"FROM probectl_path_links2",
		"GROUP BY tenant_id, bucket, target, ttl, from_ip, to_ip",
	} {
		if !strings.Contains(linkMV, want) {
			t.Fatalf("links rollup MV missing %q:\n%s", want, linkMV)
		}
	}
}
