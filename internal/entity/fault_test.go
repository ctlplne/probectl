// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"testing"
	"time"
)

func TestFaultObservationRefusesCrossFamilyAndNonAddressTargets(t *testing.T) {
	now := time.Now().UTC()
	valid := FaultObservation{
		ID:     "55e143c5-c63c-4e0e-974a-f29631bb5233",
		Source: SourceKey{AgentID: "collector-a", Kind: DeviceTarget, SourceRef: "10.42.0.1"},
		Target: "10.42.0.1", Kind: FaultDevicePollFailed, ObservedAt: now,
	}
	if _, err := valid.Normalize(now); err != nil {
		t.Fatalf("valid device fault: %v", err)
	}
	for name, mutate := range map[string]func(*FaultObservation){
		"flow source claiming device kind": func(f *FaultObservation) { f.Source.Kind = FlowExporter },
		"unknown fault kind":               func(f *FaultObservation) { f.Kind = "device.reboot_network" },
		"BMP without router-origin proof": func(f *FaultObservation) {
			f.Kind, f.Source.Kind = "bgp.peer_down", BMPPeer
		},
		"DNS name as identity target": func(f *FaultObservation) { f.Target = "router.internal" },
		"multicast target":            func(f *FaultObservation) { f.Target = "239.1.2.3" },
		"different device target":     func(f *FaultObservation) { f.Target = "10.42.0.2" },
		"stale observation":           func(f *FaultObservation) { f.ObservedAt = now.Add(-8 * 24 * time.Hour) },
	} {
		t.Run(name, func(t *testing.T) {
			f := valid
			mutate(&f)
			if _, err := f.Normalize(now); err == nil {
				t.Fatal("accepted a fault without bounded sender-family/address evidence")
			}
		})
	}
}
