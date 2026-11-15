// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestClickHousePublishedServiceFieldsKeepRawRetainedTotalsAndTwoTenantPolicy(t *testing.T) {
	store := explorerIntegrationStore(t)
	tenants := []string{uuid.NewString(), uuid.NewString()}
	t.Cleanup(func() {
		for _, tenant := range tenants {
			cleanupExplorerFixtureTenant(t, store, tenant)
		}
	})
	at := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	for lane, tenant := range tenants {
		row := explorerFixtureRow(tenant)
		row.TS = at
		row.StartTS = at.Add(-time.Second)
		row.SrcService, row.SrcServiceRegion, row.SrcServiceProvider, row.SrcServiceStatus = "S3", "us-east-1", "aws", "known"
		row.DstService, row.DstServiceProvider, row.DstServiceStatus = "Cloudflare", "cloudflare", "known"
		row.ServiceClassifiedAt = at.Format(time.RFC3339Nano)
		row.ServiceEvidence = `{"version":1,"source":{"original":"retained"}}`
		row.BytesScaled = uint64(100 * (lane + 1))
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := store.Insert(ctx, []Row{row, row}); err != nil {
			t.Fatal(err)
		}
	}
	for lane, tenant := range tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		for _, series := range []string{"raw", "rollup"} {
			plan := flow.QueryPlan{From: at.Add(-time.Second), To: at.Add(time.Second), DataSeries: series, GroupBy: []string{"src_service", "src_service_region", "dst_service", "dst_service_region"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}, View: "table"}
			result, err := store.ExplorePlan(ctx, PlanQuery{TenantID: tenant, Plan: plan})
			if err != nil || len(result.Rows) != 1 || result.Totals["bytes:total"] != fmt.Sprint(100*(lane+1)) {
				t.Fatal("raw/retained service fields crossed scope or changed original volume", series, result, err)
			}
			group := result.Rows[0].Group
			if group["src_service"] != "S3" || group["src_service_region"] != "us-east-1" || group["dst_service"] != "Cloudflare" || group["dst_service_region"] != "" {
				t.Fatal("raw/retained source labels changed", series, group)
			}
		}
	}
}
