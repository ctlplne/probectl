package tsdb

import (
	"context"
	"errors"
	"fmt"
)

// Series is one metric data point: a metric name + labels + a value at a time.
type Series struct {
	Metric     string
	Labels     map[string]string
	Value      float64
	TimeMillis int64 // Unix milliseconds
}

// Writer persists time series. Prometheus remote-write is the default; an
// in-memory writer backs the lightweight mode and tests.
type Writer interface {
	Write(ctx context.Context, series []Series) error
	Close() error
}

// New builds a Writer for the given mode. "memory" (or empty) is in-process;
// "prometheus" remote-writes to url (e.g. http://localhost:9090).
func New(mode, url string) (Writer, error) {
	switch mode {
	case "", "memory":
		return NewMemory(), nil
	case "prometheus":
		if url == "" {
			return nil, errors.New("tsdb: prometheus mode requires PROBECTL_TSDB_URL")
		}
		return NewPrometheus(url), nil
	default:
		return nil, fmt.Errorf("tsdb: unknown mode %q (want memory|prometheus)", mode)
	}
}
