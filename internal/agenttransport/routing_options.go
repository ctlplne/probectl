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

	"github.com/ctlplne/probectl/internal/store"
)

type routingTransportLimits struct {
	public       store.BGPRoutingBudget
	maxAge       time.Duration
	receiveBytes int
}

// Option configures finite transport/source admission before listeners start.
type Option func(*routingTransportLimits) error

func defaultRoutingTransportLimits() routingTransportLimits {
	return routingTransportLimits{public: store.BGPRoutingBudget{MemoryBytes: 512 << 20, WorkUnits: 2 << 30, StateBytes: 64 << 30, LeaseDuration: 12 * time.Hour}, maxAge: 12 * time.Hour, receiveBytes: maxRecvBytes}
}

// WithRoutingLimits sets public-source operation admission, the shared tenant
// BMP/public state allowance, original-file freshness and listener wire budget.
func WithRoutingLimits(profile store.BGPRoutingBudget, maxAge time.Duration, receiveBytes int) Option {
	return func(limits *routingTransportLimits) error {
		if profile.MemoryBytes <= 0 || profile.WorkUnits <= 0 || profile.StateBytes <= 0 || profile.LeaseDuration <= 0 || maxAge <= 0 || receiveBytes <= 0 || receiveBytes > math.MaxInt32 {
			return errors.New("routing transport requires positive finite resource and freshness admission")
		}
		*limits = routingTransportLimits{public: profile, maxAge: maxAge, receiveBytes: receiveBytes}
		return nil
	}
}

func (svc *service) routingStateLimit() int64 {
	if svc.routingLimits.public.StateBytes > 0 {
		return svc.routingLimits.public.StateBytes
	}
	return defaultRoutingTransportLimits().public.StateBytes
}
