// SPDX-License-Identifier: LicenseRef-probectl-TBD

package endpoint

import (
	"context"
	"fmt"
	"strings"
)

// ViewReader is the tenant-first read-model seam used by the API. Both the
// in-memory snapshot and durable read-through repository implement it.
type ViewReader interface {
	ListFilteredContext(ctx context.Context, tenant string, f ListFilter) ([]View, error)
}

// ListFilter is the server-side endpoint inventory filter. It is intentionally
// small and explicit so list UX does not turn into an unbounded query language.
type ListFilter struct {
	Query string
	Cause string
}

// Normalize validates and trims the filter.
func (f ListFilter) Normalize() (ListFilter, error) {
	f.Query = strings.TrimSpace(f.Query)
	f.Cause = strings.ToLower(strings.TrimSpace(f.Cause))
	if f.Cause == "" {
		f.Cause = "all"
	}
	switch f.Cause {
	case "all", "impaired", "wifi", "local", "isp", "network", "none":
	default:
		return ListFilter{}, fmt.Errorf("unknown endpoint cause filter %q", f.Cause)
	}
	return f, nil
}

// ListFiltered assembles and filters the tenant's endpoint views. Tenant
// selection still happens first via List(tenant); filters only shrink that set.
func (s *SnapshotStore) ListFiltered(tenant string, f ListFilter) ([]View, error) {
	f, err := f.Normalize()
	if err != nil {
		return nil, err
	}
	return FilterViews(s.List(tenant), f), nil
}

// ListFilteredContext is the context-aware ViewReader method. The snapshot
// itself performs no I/O, so cancellation does not change its behavior.
func (s *SnapshotStore) ListFilteredContext(_ context.Context, tenant string, f ListFilter) ([]View, error) {
	return s.ListFiltered(tenant, f)
}

// FilterViews applies a normalized filter to already tenant-scoped views.
func FilterViews(items []View, f ListFilter) []View {
	f, err := f.Normalize()
	if err != nil {
		return nil
	}
	if f.Query == "" && f.Cause == "all" {
		return items
	}
	q := strings.ToLower(f.Query)
	out := make([]View, 0, len(items))
	for _, v := range items {
		if !matchesCause(v, f.Cause) {
			continue
		}
		if q != "" && !strings.Contains(endpointSearchText(v), q) {
			continue
		}
		out = append(out, v)
	}
	return out
}

func matchesCause(v View, cause string) bool {
	switch cause {
	case "all":
		return true
	case "impaired":
		return v.Slow
	case "none":
		return !v.Slow || v.Cause == "none"
	default:
		return v.Cause == cause
	}
}

func endpointSearchText(v View) string {
	parts := []string{v.AgentID, v.Cause, v.Summary}
	addResult := func(r *ResultView) {
		if r == nil {
			return
		}
		parts = append(parts, r.Target, r.Error)
		for k, value := range r.Attributes {
			parts = append(parts, k, value)
		}
	}
	addResult(v.Attribution)
	addResult(v.WiFi)
	addResult(v.Gateway)
	addResult(v.LastMile)
	for i := range v.Sessions {
		r := v.Sessions[i]
		addResult(&r)
	}
	return strings.ToLower(strings.Join(parts, " "))
}
