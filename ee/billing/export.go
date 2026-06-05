// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package billing

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
	"time"
)

// The billing-export feed (the ratified first target: GENERIC, vendor-neutral
// CSV + JSON Lines any PSA/billing system imports). The column set is a
// CONTRACT — additive changes only:
//
//	tenant_id, tenant_slug, meter, kind, period_start, period_end, value, unit
//
// Timestamps are RFC 3339 UTC. Counters sum across periods; gauges are
// point-in-time snapshots (peak when rolled up). One row per
// (tenant, meter, period).

// ExportCSVHeader is the stable column order.
var ExportCSVHeader = []string{
	"tenant_id", "tenant_slug", "meter", "kind", "period_start", "period_end", "value", "unit",
}

// WriteCSV streams records as the documented CSV contract.
func WriteCSV(w io.Writer, records []UsageRecord) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(ExportCSVHeader); err != nil {
		return err
	}
	for _, r := range records {
		if err := cw.Write([]string{
			r.TenantID, r.TenantSlug, r.Meter, r.Kind,
			r.PeriodStart.UTC().Format(time.RFC3339),
			r.PeriodEnd.UTC().Format(time.RFC3339),
			strconv.FormatInt(r.Value, 10), r.Unit,
		}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// WriteJSONL streams records as JSON Lines (one UsageRecord object per line,
// the same field names as the JSON API).
func WriteJSONL(w io.Writer, records []UsageRecord) error {
	enc := json.NewEncoder(w)
	for i := range records {
		r := records[i]
		r.PeriodStart = r.PeriodStart.UTC()
		r.PeriodEnd = r.PeriodEnd.UTC()
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	return nil
}
