// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/ctlplne/probectl/internal/tags"
)

// SubscriberUsageRequest selects an immutable view and a tenant-owned prefix
// tag. The server resolves the current binding before querying observations.
type SubscriberUsageRequest struct {
	ViewID     string     `json:"-"`
	Version    string     `json:"version"`
	TagID      string     `json:"tag_id"`
	TagKey     string     `json:"tag_key"`
	Subscriber string     `json:"subscriber"`
	End        *time.Time `json:"end,omitempty"`
}

type SubscriberTraffic struct {
	Bytes   string `json:"bytes"`
	Packets string `json:"packets"`
}

type SubscriberServiceUsage struct {
	Direction string            `json:"direction"`
	Provider  string            `json:"provider,omitempty"`
	Service   string            `json:"service,omitempty"`
	Status    string            `json:"status"`
	Traffic   SubscriberTraffic `json:"traffic"`
}

// SubscriberUsageReport keeps exact observed counters, the current assignment
// receipt and the attribution basis for remote service rows.
type SubscriberUsageReport struct {
	ViewID            string                   `json:"view_id"`
	ViewVersion       string                   `json:"view_version"`
	TagID             string                   `json:"tag_id"`
	TagKey            string                   `json:"tag_key"`
	Subscriber        string                   `json:"subscriber"`
	TagRevision       string                   `json:"tag_revision"`
	TagAsOf           time.Time                `json:"tag_as_of"`
	From              time.Time                `json:"from"`
	To                time.Time                `json:"to"`
	Source            string                   `json:"source"`
	ResolutionSeconds int                      `json:"resolution_seconds"`
	Total             SubscriberTraffic        `json:"total"`
	Download          SubscriberTraffic        `json:"download"`
	Upload            SubscriberTraffic        `json:"upload"`
	Internal          SubscriberTraffic        `json:"internal"`
	TopServices       []SubscriberServiceUsage `json:"top_services"`
	OtherServices     SubscriberTraffic        `json:"other_services"`
}

func (r SubscriberUsageRequest) TagFields() (string, string) {
	return "tag.src_prefix." + r.TagKey, "tag.dst_prefix." + r.TagKey
}

func (r SubscriberUsageRequest) Validate() error {
	if err := tags.ValidateKey(r.TagKey); err != nil {
		return errors.New("select a current subscriber prefix tag")
	}
	if r.Subscriber == "" || len(r.Subscriber) > 128 || strings.TrimSpace(r.Subscriber) != r.Subscriber || strings.IndexFunc(r.Subscriber, unicode.IsControl) >= 0 {
		return errors.New("enter one exact subscriber tag value")
	}
	if _, err := QueryViewVersion(r.Version); err != nil {
		return errors.New("select the exact saved flow view revision")
	}
	return nil
}

func (r SubscriberUsageRequest) Plan(base QueryPlan) QueryPlan {
	source, destination := r.TagFields()
	member := QueryFilterGroup{Match: "any", Mode: "include", Conditions: []QueryPredicate{
		{Field: source, Op: QueryEqual, Values: []string{r.Subscriber}},
		{Field: destination, Op: QueryEqual, Values: []string{r.Subscriber}},
	}}
	if base.Filter == nil {
		base.Filter = &member
	} else {
		base.Filter = &QueryFilterGroup{Match: "all", Mode: "include", Groups: []QueryFilterGroup{*base.Filter, member}}
	}
	base.GroupBy = []string{source, destination, "src_service_status", "src_service_provider", "src_service", "dst_service_status", "dst_service_provider", "dst_service"}
	base.View, base.DataSeries, base.Cursor = "table", "raw", ""
	base.MatrixWith, base.MatrixDepth, base.SeriesDepth = nil, 0, 0
	base.IPv4PrefixLength, base.IPv6PrefixLength = nil, nil
	base.Metrics = []QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "packets", Calculation: "total", Role: "secondary"}}
	base.RowLimit, base.PageSize = 1000, 1000
	return base
}
