// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

type explorerDeviceInterfaces struct{ server *Server }
type tenantMetricSnapshotter interface {
	TenantSnapshot(context.Context, string, string, int) ([]tsdb.Series, error)
}

// FlowInterfaces uses tenant-scoped storage reads, never a deployment-wide
// snapshot. Labels from a bad/misrouted upstream are rejected as a second lock.
func (source explorerDeviceInterfaces) FlowInterfaces(ctx context.Context, tenant string) ([]flowstore.ExplorerInterface, error) {
	if tenant == "" {
		return nil, flowstore.ErrNoTenant
	}
	budget := flowstore.ExplorerOperationBudget(ctx, source.server.flowStore)
	if err := budget.Validate(); err != nil {
		return nil, err
	}
	type named struct {
		item      flowstore.ExplorerInterface
		at        float64
		ambiguous bool
	}
	latest := map[string]named{}
	consume := func(labels map[string]string, at float64) error {
		if labels[tsdb.TenantLabel] != tenant {
			return flowstore.ErrNoTenant
		}
		exporter, name := labels["device"], labels["if_name"]
		if exporter == "" || name == "" || labels["if_index"] == "" {
			return nil
		}
		if len(exporter) > 256 || len(name) > flow.MaxQueryValueBytes {
			return flowstore.ErrExplorerBudget
		}
		index, err := strconv.ParseUint(labels["if_index"], 10, 32)
		if err != nil {
			return errors.New("invalid interface index in device telemetry")
		}
		key := fmt.Sprintf("%d:%s:%d", len(exporter), exporter, index)
		item := flowstore.ExplorerInterface{TenantID: tenant, Exporter: exporter, Index: uint32(index), Name: name}
		previous, ok := latest[key]
		if ok && previous.at == at && previous.item.Name != name {
			previous.ambiguous = true
			latest[key] = previous
		}
		if !ok || previous.at < at {
			latest[key] = named{item: item, at: at, ambiguous: false}
		}
		if len(latest) > budget.InterfaceItems {
			return flowstore.ErrExplorerBudget
		}
		return nil
	}
	if memory, ok := source.server.tsdbWriter.(tenantMetricSnapshotter); ok {
		// The underlying memory store applies tenant scope before copying any data.
		series, err := memory.TenantSnapshot(ctx, tenant, deviceMetricPrefix, budget.InterfaceItems*10)
		if err != nil {
			return nil, err
		}
		for _, item := range series {
			if err := consume(item.Labels, float64(item.TimeMillis)); err != nil {
				return nil, err
			}
		}
	} else if query, ok := source.server.tsdbWriter.(deviceMetricQuerier); ok {
		if strings.ContainsAny(tenant, "\"\\\n") {
			return nil, flowstore.ErrNoTenant
		}
		// Select one tenant before aggregation. The extra row detects overflow;
		// timestamp chooses the most recent actual observation across metric names.
		selector := `{__name__=~"probectl_device_.+",tenant_id="` + tenant + `",if_index!="",if_name!=""}`
		promql := fmt.Sprintf("topk(%d,max by (tenant_id,device,if_index,if_name) (timestamp(%s)))", budget.InterfaceItems+1, selector)
		samples, err := query.InstantVector(ctx, promql)
		if err != nil {
			return nil, err
		}
		if len(samples) > budget.InterfaceItems {
			return nil, flowstore.ErrExplorerBudget
		}
		for _, item := range samples {
			if err := consume(item.Labels, item.Value); err != nil {
				return nil, err
			}
		}
	}
	out := make([]flowstore.ExplorerInterface, 0, len(latest))
	for _, entry := range latest {
		if entry.ambiguous {
			return nil, errors.New("ambiguous current interface name in device telemetry")
		}
		out = append(out, entry.item)
	}
	return out, nil
}
