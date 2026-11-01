// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// FaultKind is a bounded observation made by an evidence-plane collector.
// It is a signal for human triage, never an inline action or routing authority.
type FaultKind string

const (
	FaultDevicePollFailed   FaultKind = "device.poll_failed"
	FaultFlowExporterSilent FaultKind = "flow.exporter_silent"
	AttrFaultObservationID            = "probectl.entity.fault.observation_id"
	AttrFaultKind                     = "probectl.entity.fault.kind"
	AttrSourceKind                    = "probectl.entity.source.kind"
)

type FaultObservation struct {
	ID         string
	Source     SourceKey
	Target     string // observed IP; never chooses the context
	Kind       FaultKind
	ObservedAt time.Time
}

// Normalize rejects unbounded or cross-family claims before RPC admission.
// The server still derives tenant/agent from mTLS and context/entity from RLS.
func (f FaultObservation) Normalize(now time.Time) (FaultObservation, error) {
	id, err := uuid.Parse(f.ID)
	if err != nil || id == uuid.Nil || id.Version() != 4 {
		return FaultObservation{}, ErrInvalidClaim
	}
	f.ID = id.String()
	f.Source, err = f.Source.Normalize()
	if err != nil {
		return FaultObservation{}, err
	}
	switch f.Kind {
	case FaultDevicePollFailed:
		if f.Source.Kind != DeviceTarget {
			return FaultObservation{}, ErrInvalidClaim
		}
	case FaultFlowExporterSilent:
		if f.Source.Kind != FlowExporter {
			return FaultObservation{}, ErrInvalidClaim
		}
	default:
		return FaultObservation{}, ErrInvalidClaim
	}
	addr, err := netip.ParseAddr(f.Target)
	if err != nil || addr.Zone() != "" || addr.IsUnspecified() || addr.IsMulticast() {
		return FaultObservation{}, ErrInvalidClaim
	}
	f.Target = addr.Unmap().String()
	if f.Kind == FaultDevicePollFailed || f.Kind == FaultFlowExporterSilent {
		configured, err := netip.ParseAddr(f.Source.SourceRef)
		if err != nil || configured.Zone() != "" ||
			configured.Unmap().String() != f.Target {
			return FaultObservation{}, ErrInvalidClaim
		}
	}
	if f.ObservedAt.IsZero() || f.ObservedAt.After(now.Add(5*time.Minute)) ||
		f.ObservedAt.Before(now.Add(-7*24*time.Hour)) {
		return FaultObservation{}, ErrInvalidClaim
	}
	f.ObservedAt = f.ObservedAt.UTC().Truncate(time.Microsecond)
	return f, nil
}
