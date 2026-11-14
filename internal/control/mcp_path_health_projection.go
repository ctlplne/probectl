// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/entity"
)

type nativePathHealthScope struct {
	TenantID  mcp.NativeRoleUUID `json:"tenant_id"`
	ContextID mcp.NativeRoleUUID `json:"context_id"`
}

type nativePathHealthClaim struct {
	entity.Claim
	Scope             nativePathHealthScope `json:"scope"`
	EntityID          mcp.NativeRoleUUID    `json:"entity_id"`
	EvidenceID        mcp.NativeRoleUUID    `json:"evidence_id"`
	SupportEvidenceID mcp.NativeRoleUUID    `json:"support_evidence_id,omitempty"`
}

type nativePathHealthResolution struct {
	entity.Resolution
	Scope      nativePathHealthScope   `json:"scope"`
	EntityID   mcp.NativeRoleUUID      `json:"entity_id,omitempty"`
	Candidates []nativePathHealthClaim `json:"candidates,omitempty"`
}

// A fixed server metric vocabulary is not arbitrary source hostname text.
// All aliases, labels, addresses and sender prose retain full redaction.
type nativePathHealthMetric string

func (metric nativePathHealthMetric) MarshalJSON() ([]byte, error) {
	if !slices.Contains(pathHealthMetricNames, string(metric)) {
		return nil, errors.New("invalid server path health metric")
	}
	raw, err := json.Marshal(string(metric))
	if err != nil {
		return nil, err
	}
	return []byte(strings.ReplaceAll(string(raw), ".", `\u002e`)), nil
}

// Only validated original numeric words, computed nonnegative rationals and
// server-verified SHA-256 receipt identities receive structural encoding.
type nativePathHealthCounter struct {
	pathHealthCounter
	Metric                 nativePathHealthMetric   `json:"metric"`
	Value                  mcp.NativePeeringCounter `json:"value,omitempty"`
	PreviousValue          mcp.NativePeeringCounter `json:"previous_value,omitempty"`
	SpeedBPS               mcp.NativePeeringCounter `json:"interface_speed_bps,omitempty"`
	PreviousSpeedBPS       mcp.NativePeeringCounter `json:"previous_interface_speed_bps,omitempty"`
	MinimumDelta           mcp.NativePeeringCounter `json:"minimum_delta,omitempty"`
	RateNumerator          mcp.NativePeeringCounter `json:"rate_numerator,omitempty"`
	RateDenominator        mcp.NativePeeringCounter `json:"rate_denominator,omitempty"`
	UtilizationNumerator   mcp.NativePeeringCounter `json:"utilization_numerator,omitempty"`
	UtilizationDenominator mcp.NativePeeringCounter `json:"utilization_denominator,omitempty"`
	CaptureKey             mcp.NativeRoleDigest     `json:"capture_key,omitempty"`
	PreviousCaptureKey     mcp.NativeRoleDigest     `json:"previous_capture_key,omitempty"`
	RawDigest              mcp.NativeRoleDigest     `json:"raw_digest,omitempty"`
	PreviousRawDigest      mcp.NativeRoleDigest     `json:"previous_raw_digest,omitempty"`
}

type nativePathInterfaceHealth struct {
	pathInterfaceHealth
	ContextID      mcp.NativeRoleUUID          `json:"context_id,omitempty"`
	InterfaceID    mcp.NativeRoleUUID          `json:"interface_id,omitempty"`
	DeviceID       mcp.NativeRoleUUID          `json:"device_id,omitempty"`
	PhysicalMaxBPS mcp.NativePeeringCounter    `json:"physical_max_bps,omitempty"`
	Counters       []nativePathHealthCounter   `json:"counters"`
	ConfigChanges  []nativePathConfigReference `json:"config_changes,omitempty"`
}

type nativePathConfigBinding struct {
	device.ConfigArchiveBinding
	ContextID      mcp.NativeRoleUUID `json:"context_id"`
	DeviceEntityID mcp.NativeRoleUUID `json:"device_entity_id"`
}

type nativePathConfigReference struct {
	device.ConfigArchiveReference
	ID           mcp.NativeRoleUUID      `json:"id"`
	PreviousID   mcp.NativeRoleUUID      `json:"previous_id,omitempty"`
	ContentHash  mcp.NativeRoleDigest    `json:"content_hash"`
	PreviousHash mcp.NativeRoleDigest    `json:"previous_hash,omitempty"`
	Binding      nativePathConfigBinding `json:"binding"`
}

type nativePathHealthHop struct {
	pathEntityHop
	Resolution nativePathHealthResolution `json:"resolution"`
	Health     *nativePathInterfaceHealth `json:"health,omitempty"`
}

func marshalNativePathHealth(result pathHealthResult) (json.RawMessage, error) {
	native := struct {
		pathHealthResult
		TestID    mcp.NativeRoleUUID    `json:"test_id"`
		ContextID mcp.NativeRoleUUID    `json:"context_id,omitempty"`
		Items     []nativePathHealthHop `json:"items"`
	}{pathHealthResult: result, TestID: mcp.NativeRoleUUID(result.TestID), ContextID: mcp.NativeRoleUUID(result.ContextID), Items: make([]nativePathHealthHop, 0, len(result.Items))}
	scope := func(value entity.Scope) nativePathHealthScope {
		return nativePathHealthScope{mcp.NativeRoleUUID(value.TenantID), mcp.NativeRoleUUID(value.ContextID)}
	}
	for _, item := range result.Items {
		resolution := nativePathHealthResolution{Resolution: item.Resolution, Scope: scope(item.Resolution.Scope), EntityID: mcp.NativeRoleUUID(item.Resolution.EntityID)}
		for _, claim := range item.Resolution.Candidates {
			resolution.Candidates = append(resolution.Candidates, nativePathHealthClaim{Claim: claim, Scope: scope(claim.Scope), EntityID: mcp.NativeRoleUUID(claim.EntityID), EvidenceID: mcp.NativeRoleUUID(claim.EvidenceID), SupportEvidenceID: mcp.NativeRoleUUID(claim.SupportEvidenceID)})
		}
		hop := nativePathHealthHop{pathEntityHop: item, Resolution: resolution}
		if item.Health != nil {
			health := item.Health
			hop.Health = &nativePathInterfaceHealth{pathInterfaceHealth: *health, ContextID: mcp.NativeRoleUUID(health.ContextID), InterfaceID: mcp.NativeRoleUUID(health.InterfaceID), DeviceID: mcp.NativeRoleUUID(health.DeviceID), PhysicalMaxBPS: mcp.NativePeeringCounter(health.PhysicalMaxBPS), Counters: make([]nativePathHealthCounter, 0, len(health.Counters))}
			for _, counter := range health.Counters {
				hop.Health.Counters = append(hop.Health.Counters, nativePathHealthCounter{pathHealthCounter: counter, Metric: nativePathHealthMetric(counter.Metric),
					Value: mcp.NativePeeringCounter(counter.Value), PreviousValue: mcp.NativePeeringCounter(counter.PreviousValue), SpeedBPS: mcp.NativePeeringCounter(counter.SpeedBPS), PreviousSpeedBPS: mcp.NativePeeringCounter(counter.PreviousSpeedBPS),
					MinimumDelta: mcp.NativePeeringCounter(counter.MinimumDelta), RateNumerator: mcp.NativePeeringCounter(counter.RateNumerator), RateDenominator: mcp.NativePeeringCounter(counter.RateDenominator), UtilizationNumerator: mcp.NativePeeringCounter(counter.UtilizationNumerator), UtilizationDenominator: mcp.NativePeeringCounter(counter.UtilizationDenominator),
					CaptureKey: mcp.NativeRoleDigest(counter.CaptureKey), PreviousCaptureKey: mcp.NativeRoleDigest(counter.PreviousCaptureKey), RawDigest: mcp.NativeRoleDigest(counter.RawDigest), PreviousRawDigest: mcp.NativeRoleDigest(counter.PreviousRawDigest)})
			}
			for _, ref := range health.ConfigChanges {
				hop.Health.ConfigChanges = append(hop.Health.ConfigChanges, nativePathConfigReference{ConfigArchiveReference: ref, ID: mcp.NativeRoleUUID(ref.ID), PreviousID: mcp.NativeRoleUUID(ref.PreviousID), ContentHash: mcp.NativeRoleDigest(ref.ContentHash), PreviousHash: mcp.NativeRoleDigest(ref.PreviousHash), Binding: nativePathConfigBinding{ConfigArchiveBinding: ref.Binding, ContextID: mcp.NativeRoleUUID(ref.Binding.ContextID), DeviceEntityID: mcp.NativeRoleUUID(ref.Binding.DeviceEntityID)}})
			}
		}
		native.Items = append(native.Items, hop)
	}
	return json.Marshal(native)
}
