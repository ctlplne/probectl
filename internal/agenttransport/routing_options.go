// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"errors"
	"math"
	"time"

	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store"
)

type routingTransportLimits struct {
	public            store.BGPRoutingBudget
	maxAge            time.Duration
	receiveBytes      int
	captureStateBytes int64
	rpki              *opendata.Enricher
}

// Option configures finite transport/source admission before listeners start.
type Option func(*routingTransportLimits) error

// WithRPKIEnrichment supplies independent local validator evidence for
// authenticated ingestion-time capture. It adds no sender-supplied authority.
func WithRPKIEnrichment(source *opendata.Enricher) Option {
	return func(limits *routingTransportLimits) error {
		limits.rpki = source
		return nil
	}
}

func defaultRoutingTransportLimits() routingTransportLimits {
	return routingTransportLimits{public: store.BGPRoutingBudget{MemoryBytes: 512 << 20, WorkUnits: 2 << 30, StateBytes: 64 << 30, LeaseDuration: 12 * time.Hour}, maxAge: 12 * time.Hour, receiveBytes: maxRecvBytes, captureStateBytes: 64 << 30}
}

// WithRoutingLimits sets public-source operation admission, the shared tenant
// BMP/public state allowance, original-file freshness and listener wire budget.
func WithRoutingLimits(profile store.BGPRoutingBudget, maxAge time.Duration, receiveBytes int) Option {
	return func(limits *routingTransportLimits) error {
		if profile.MemoryBytes <= 0 || profile.WorkUnits <= 0 || profile.StateBytes <= 0 || profile.LeaseDuration <= 0 || maxAge <= 0 || receiveBytes <= 0 || receiveBytes > math.MaxInt32 {
			return errors.New("routing transport requires positive finite resource and freshness admission")
		}
		limits.public, limits.maxAge, limits.receiveBytes = profile, maxAge, receiveBytes
		return nil
	}
}

// WithRoutingCaptureStateBytes sets the separate tenant admission for retained
// immutable flow capture facts, clocks and intents. No state is preallocated.
func WithRoutingCaptureStateBytes(bytes int64) Option {
	return func(limits *routingTransportLimits) error {
		if bytes <= 0 {
			return errors.New("routing capture state admission must be positive")
		}
		limits.captureStateBytes = bytes
		return nil
	}
}

func (svc *service) routingCaptureBudget() store.BGPRoutingBudget {
	limits := svc.routingLimits
	if limits.public.MemoryBytes <= 0 || limits.public.WorkUnits <= 0 || limits.captureStateBytes <= 0 || limits.maxAge <= 0 {
		limits = defaultRoutingTransportLimits()
	}
	return store.BGPRoutingBudget{MemoryBytes: limits.public.MemoryBytes, WorkUnits: limits.public.WorkUnits, StateBytes: limits.captureStateBytes, LeaseDuration: time.Minute, PublicSourceMaxAge: limits.maxAge}
}

func (svc *service) routingStateLimit() int64 {
	if svc.routingLimits.public.StateBytes > 0 {
		return svc.routingLimits.public.StateBytes
	}
	return defaultRoutingTransportLimits().public.StateBytes
}
