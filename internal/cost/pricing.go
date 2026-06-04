package cost

// Pricing: USD per GiB by traffic class, with provenance (the S44 AUP/
// freshness watch-out). The embedded defaults are representative PUBLIC list
// rates gathered from cloud providers' published pricing pages — they exist
// so the engine is useful out of the box, and they are deliberately
// conservative ballparks, NOT a billing source. Operators override them with
// their provider's current (or negotiated) rates via configuration; the
// as-of date is always surfaced so staleness is visible, never hidden.

import (
	"encoding/json"
	"fmt"
	"os"
)

// PriceTable prices traffic classes in USD per GiB.
type PriceTable struct {
	// PerGiB maps traffic class → USD per GiB. Absent classes price at 0
	// (same-zone traffic is free on the major clouds).
	PerGiB map[TrafficClass]float64 `json:"per_gib"`

	// Provenance (surfaced in the API/UI — freshness is the operator's call).
	Source  string `json:"source"`
	AsOf    string `json:"as_of"`   // YYYY-MM-DD the rates were captured
	License string `json:"license"` // AUP note for the rate source
}

// DefaultPriceTable is the embedded public-list ballpark (see file comment).
func DefaultPriceTable() *PriceTable {
	return &PriceTable{
		PerGiB: map[TrafficClass]float64{
			ClassSameZone:    0,
			ClassInterAZ:     0.01, // typical published intra-region cross-AZ rate
			ClassInterRegion: 0.02, // typical published inter-region floor
			ClassInternet:    0.09, // typical published internet-egress first tier
		},
		Source:  "public cloud pricing pages (representative list rates)",
		AsOf:    "2026-06-01",
		License: "publicly published rates; verify against your provider/agreement",
	}
}

// LoadPriceTable reads an operator override (JSON, the PriceTable shape) from
// path. path "" → the embedded defaults. A malformed file is an ERROR (fail
// closed: silently mispriced cost data is worse than none); a deployment that
// wants NO pricing sets PROBECTL_COST_PRICED=false instead.
func LoadPriceTable(path string) (*PriceTable, error) {
	if path == "" {
		return DefaultPriceTable(), nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cost: read price table: %w", err)
	}
	var t PriceTable
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("cost: parse price table %s: %w", path, err)
	}
	if len(t.PerGiB) == 0 {
		return nil, fmt.Errorf("cost: price table %s declares no rates", path)
	}
	for class, rate := range t.PerGiB {
		if rate < 0 {
			return nil, fmt.Errorf("cost: price table %s: negative rate for %s", path, class)
		}
	}
	return &t, nil
}

// Price returns the USD cost for byteCount of a class; ok=false when the
// table is nil (the volume-only degraded mode).
func (t *PriceTable) Price(class TrafficClass, byteCount uint64) (usd float64, ok bool) {
	if t == nil {
		return 0, false
	}
	rate, present := t.PerGiB[class]
	if !present {
		return 0, true // class explicitly unpriced (e.g. same-zone, unknown)
	}
	return float64(byteCount) / (1 << 30) * rate, true
}
