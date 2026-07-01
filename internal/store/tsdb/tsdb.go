// SPDX-License-Identifier: LicenseRef-probectl-TBD

package tsdb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TenantLabel is the storage-layer boundary label every tenant-owned series
// must carry. Query code may use package-local aliases, but writes validate this
// canonical label before a sample can reach any backing TSDB.
const TenantLabel = "tenant_id"

var (
	// ErrTenantRequired is returned before write when tenant-owned telemetry is
	// missing its storage/query-layer tenant boundary. This is fail-closed: the
	// whole caller write is rejected, rather than preserving an unlabeled series
	// that no tenant deletion or tenant-scoped query can reason about.
	ErrTenantRequired = errors.New("tsdb: tenant-owned series missing tenant_id")
	// ErrGlobalTenantLabel is returned by the explicit global metrics path when
	// a caller tries to sneak tenant-owned telemetry through it.
	ErrGlobalTenantLabel = errors.New("tsdb: global series must not carry tenant_id")
	// ErrGlobalWriterUnsupported means a wrapper/fake Writer has not exposed the
	// explicit global metrics path required for non-tenant control-plane series.
	ErrGlobalWriterUnsupported = errors.New("tsdb: writer does not support explicit global metrics")
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

// GlobalWriter is the explicit non-tenant control-plane metrics path. Normal
// Writer.Write is tenant-owned and requires tenant_id; global health/build
// gauges must opt into this separate method so unlabeled tenant telemetry cannot
// be stored by accident.
type GlobalWriter interface {
	WriteGlobal(ctx context.Context, series []Series) error
}

// ValidateTenantSeries enforces the default tenant-owned TSDB write contract.
func ValidateTenantSeries(series []Series) error {
	for i, s := range series {
		if s.Labels == nil || strings.TrimSpace(s.Labels[TenantLabel]) == "" {
			return fmt.Errorf("%w: series[%d] metric %q", ErrTenantRequired, i, s.Metric)
		}
	}
	return nil
}

// ValidateGlobalSeries enforces the explicit non-tenant metrics contract.
func ValidateGlobalSeries(series []Series) error {
	for i, s := range series {
		if s.Labels != nil {
			if _, ok := s.Labels[TenantLabel]; ok {
				return fmt.Errorf("%w: series[%d] metric %q", ErrGlobalTenantLabel, i, s.Metric)
			}
		}
	}
	return nil
}

// WriteGlobal writes non-tenant control-plane metrics through the explicit
// escape hatch. It refuses wrappers/fakes that have not made that choice
// visible in their type.
func WriteGlobal(ctx context.Context, w Writer, series []Series) error {
	if len(series) == 0 || w == nil {
		return nil
	}
	gw, ok := w.(GlobalWriter)
	if !ok {
		return ErrGlobalWriterUnsupported
	}
	return gw.WriteGlobal(ctx, series)
}

// New builds a Writer for the given mode. "memory" (or empty) is in-process
// (bounded by retention + max bytes, U-018); "prometheus" remote-writes to
// url (e.g. http://localhost:9090).
func New(mode, url string) (Writer, error) { return NewWithLimits(mode, url, 0, 0) }

// NewWithLimits is New with explicit in-memory bounds (non-positive = defaults).
func NewWithLimits(mode, url string, retention time.Duration, maxBytes int64) (Writer, error) {
	switch mode {
	case "", "memory":
		return NewMemoryWithLimits(retention, maxBytes), nil
	case "prometheus":
		if url == "" {
			return nil, errors.New("tsdb: prometheus mode requires PROBECTL_TSDB_URL")
		}
		return NewPrometheus(url), nil
	default:
		return nil, fmt.Errorf("tsdb: unknown mode %q (want memory|prometheus)", mode)
	}
}
