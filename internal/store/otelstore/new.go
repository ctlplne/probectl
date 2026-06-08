package otelstore

import (
	"errors"
	"fmt"
)

// New selects the Store backend (the flowstore convention): "" or "memory"
// for the in-process store (lightweight mode), "clickhouse" for production.
func New(mode, url string, retentionDays int) (Store, error) {
	switch mode {
	case "", "memory":
		return NewMemory(), nil
	case "clickhouse":
		if url == "" {
			return nil, errors.New("otelstore: clickhouse mode requires PROBECTL_OTELSTORE_URL")
		}
		return NewClickHouse(url, retentionDays)
	default:
		return nil, fmt.Errorf("otelstore: unknown mode %q (want memory|clickhouse)", mode)
	}
}
