// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

const (
	// ExplorerExecutionLimit covers the complete operation, including current
	// metadata and original routing references for full-size query populations.
	// Operators may lower or raise it; fairness and the other budgets still apply.
	ExplorerExecutionLimit = time.Minute
	// ExplorerReadBytes is a hard read budget, not a response truncation threshold.
	ExplorerReadBytes = 256 * 1024 * 1024
	// ExplorerReadRows bounds rows examined by either backend.
	ExplorerReadRows = 5000000
	// ExplorerInterfaceLimit bounds the tenant-local device-name lookup.
	ExplorerInterfaceLimit = 10000
)

// ErrExplorerBudget refuses expensive queries without returning partial rows.
var ErrExplorerBudget = errors.New("flow query resource budget exceeded; narrow the time window, filters, or grouping")

// ExplorerInterface is a tenant-owned device interface read from telemetry.
// TenantID stays attached until the flow store validates the lookup response.
type ExplorerInterface struct {
	TenantID string
	Exporter string
	Index    uint32
	Name     string
}

// ExplorerInterfaceSource must scope its underlying storage read before RBAC.
// A missing lookup yields explicit unmapped identities; a failed lookup refuses.
type ExplorerInterfaceSource interface {
	FlowInterfaces(context.Context, string) ([]ExplorerInterface, error)
}

func explorerInterfaceNames(ctx context.Context, source ExplorerInterfaceSource, tenant string, q flow.QueryPlan, budgets ...ExplorerBudget) (map[string]map[uint32]string, error) {
	budget, err := selectExplorerBudget(budgets)
	if err != nil {
		return nil, err
	}
	needed := false
	fields := append(append(append([]string{}, q.GroupBy...), q.MatrixWith...), flow.QueryFilterFields(q.Filter)...)
	for _, name := range fields {
		needed = needed || name == "in_if_name" || name == "out_if_name"
	}
	names := map[string]map[uint32]string{}
	if !needed || source == nil {
		return names, nil
	}
	items, err := source.FlowInterfaces(ctx, tenant)
	if err != nil {
		return nil, err
	}
	if len(items) > budget.InterfaceItems {
		return nil, ErrExplorerBudget
	}
	for _, item := range items {
		if item.TenantID != tenant {
			return nil, ErrNoTenant
		}
		if item.Name == "" {
			continue
		}
		if names[item.Exporter] == nil {
			names[item.Exporter] = map[uint32]string{}
		}
		if previous, ok := names[item.Exporter][item.Index]; ok && previous != item.Name {
			// Ambiguous telemetry must not silently pick an arbitrary interface label.
			return nil, errors.New("flow interface name is ambiguous; group by numeric interface instead")
		}
		names[item.Exporter][item.Index] = item.Name
	}
	return names, nil
}

// AttachExplorerInterfaces configures metadata once during server construction,
// preserving the mutation fence and its optional erasure capability.
func AttachExplorerInterfaces(store Store, source ExplorerInterfaceSource) {
	for {
		switch current := store.(type) {
		case *writeFencedStore:
			store = current.next
		case *subjectDeletingWriteFencedStore:
			store = current.next
		case *Memory:
			current.WithExplorerInterfaces(source)
			return
		case *ClickHouse:
			current.WithExplorerInterfaces(source)
			return
		default:
			return
		}
	}
}
