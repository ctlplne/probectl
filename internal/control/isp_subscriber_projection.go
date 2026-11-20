// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"cmp"
	"context"
	"math/big"
	"slices"
	"strconv"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type subscriberTrafficCounters struct {
	bytes, packets big.Int
}

func (c *subscriberTrafficCounters) add(bytes, packets *big.Int) {
	c.bytes.Add(&c.bytes, bytes)
	c.packets.Add(&c.packets, packets)
}

func (c *subscriberTrafficCounters) value() flow.SubscriberTraffic {
	return flow.SubscriberTraffic{Bytes: c.bytes.String(), Packets: c.packets.String()}
}

type subscriberServiceKey struct{ direction, status, provider, service string }

type subscriberServiceGroup struct {
	key     subscriberServiceKey
	traffic *subscriberTrafficCounters
}

func projectSubscriberUsage(ctx context.Context, input flow.SubscriberUsageRequest, original capturedReportFlow) (flow.SubscriberUsageReport, error) {
	result := original.Result
	out := flow.SubscriberUsageReport{ViewID: original.ID, ViewVersion: original.Version, TagID: input.TagID, TagKey: input.TagKey,
		Subscriber: input.Subscriber, TagRevision: strconv.FormatInt(result.TagRevision, 10), TagAsOf: original.TagAsOf,
		From: result.Query.From, To: result.Query.To, Source: result.Source, ResolutionSeconds: result.ResolutionSeconds,
		TopServices: []flow.SubscriberServiceUsage{}}
	source, destination := input.TagFields()
	if original.ID != input.ViewID || original.Version != input.Version || original.Period != "current" || original.TagAsOf.IsZero() ||
		result.TagTenantID != original.TenantID || result.TagRevision <= 0 || result.TagIDs[source] != input.TagID || result.TagIDs[destination] != input.TagID ||
		result.Source != "raw" || !out.From.Before(out.To) || result.Coverage == nil || !result.Coverage.CompleteInputs ||
		result.DetailLimited || result.Other != nil || result.TotalGroups != len(result.Rows) {
		return flow.SubscriberUsageReport{}, subscriberCoverageError()
	}
	var total, downloaded, uploaded, internal subscriberTrafficCounters
	services := make(map[subscriberServiceKey]*subscriberTrafficCounters)
	for _, row := range result.Rows {
		if err := ctx.Err(); err != nil {
			return flow.SubscriberUsageReport{}, err
		}
		bytes, byteOK := ddosWindowCounter(row.Metrics["bytes:total"])
		packets, packetOK := ddosWindowCounter(row.Metrics["packets:total"])
		if row.Other || !byteOK || !packetOK {
			return flow.SubscriberUsageReport{}, subscriberCoverageError()
		}
		src, dst := row.Group[source] == input.Subscriber, row.Group[destination] == input.Subscriber
		total.add(bytes, packets)
		switch {
		case src && dst:
			internal.add(bytes, packets)
		case src:
			uploaded.add(bytes, packets)
			addSubscriberService(services, row, "upload", "dst_service", bytes, packets)
		case dst:
			downloaded.add(bytes, packets)
			addSubscriberService(services, row, "download", "src_service", bytes, packets)
		default:
			return flow.SubscriberUsageReport{}, subscriberCoverageError()
		}
	}
	if total.bytes.String() != result.Totals["bytes:total"] || total.packets.String() != result.Totals["packets:total"] {
		return flow.SubscriberUsageReport{}, subscriberCoverageError()
	}
	out.Total, out.Download, out.Upload, out.Internal = total.value(), downloaded.value(), uploaded.value(), internal.value()
	out.TopServices, out.OtherServices = rankSubscriberServices(services)
	return out, ctx.Err()
}

func addSubscriberService(services map[subscriberServiceKey]*subscriberTrafficCounters, row flowstore.PlanRow, direction, field string, bytes, packets *big.Int) {
	key := subscriberServiceKey{direction: direction, status: row.Group[field+"_status"]}
	switch key.status {
	case "known":
		key.provider, key.service = row.Group[field+"_provider"], row.Group[field]
		if key.provider == "" || key.service == "" {
			key = subscriberServiceKey{direction: direction, status: "unknown"}
		}
	case "ambiguous":
	default:
		key.status = "unknown"
	}
	counter := services[key]
	if counter == nil {
		counter = &subscriberTrafficCounters{}
		services[key] = counter
	}
	counter.add(bytes, packets)
}

func rankSubscriberServices(services map[subscriberServiceKey]*subscriberTrafficCounters) ([]flow.SubscriberServiceUsage, flow.SubscriberTraffic) {
	var values []subscriberServiceGroup
	for key, traffic := range services {
		values = append(values, subscriberServiceGroup{key: key, traffic: traffic})
	}
	slices.SortFunc(values, func(a, b subscriberServiceGroup) int {
		return cmp.Or(b.traffic.bytes.Cmp(&a.traffic.bytes), b.traffic.packets.Cmp(&a.traffic.packets),
			cmp.Compare(a.key.direction, b.key.direction), cmp.Compare(a.key.status, b.key.status),
			cmp.Compare(a.key.provider, b.key.provider), cmp.Compare(a.key.service, b.key.service))
	})
	const limit = 20
	split := min(limit, len(values))
	out := make([]flow.SubscriberServiceUsage, 0, split)
	for _, value := range values[:split] {
		out = append(out, flow.SubscriberServiceUsage{Direction: value.key.direction, Status: value.key.status,
			Provider: value.key.provider, Service: value.key.service, Traffic: value.traffic.value()})
	}
	var other subscriberTrafficCounters
	for _, value := range values[split:] {
		other.add(&value.traffic.bytes, &value.traffic.packets)
	}
	return out, other.value()
}

func subscriberCoverageError() error {
	return apierror.Conflict("complete subscriber flow groups are unavailable for this interval")
}
