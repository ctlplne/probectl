// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"errors"
	"net"
	"net/netip"
	"runtime"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/testspec"
)

// ProbeEgressConfig is a local trust root for one centrally assigned test.
// The signed bundle can still disable the test or change its schedule within
// agent policy. It cannot replace the pinned destination or forwarding lane.
type ProbeEgressConfig struct {
	Target    string `yaml:"target"`
	HandoffID string `yaml:"handoff_id"`
	Peer      string `yaml:"peer_address"`
	Interface string `yaml:"interface"`
	Source    string `yaml:"source"`
	PeerMAC   string `yaml:"peer_mac"`
}

func (e ProbeEgressConfig) binding(testID string) (*testspec.RoutingProbeBinding, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("ICMP egress witnessing requires Linux")
	}
	id, err := uuid.Parse(testID)
	if err != nil || id == uuid.Nil || id.String() != testID {
		return nil, errors.New("egress binding requires the registered test UUID")
	}
	return testspec.ParseRoutingProbeBinding("icmp", e.Target, map[string]string{
		testspec.RoutingProbeHandoffParam: e.HandoffID, testspec.RoutingProbePeerParam: e.Peer,
		testspec.RoutingProbeInterfaceParam: e.Interface, testspec.RoutingProbeSourceParam: e.Source,
		testspec.RoutingProbePeerMACParam: e.PeerMAC,
	})
}

func (s *testSyncer) newTestCanary(testID string, cfg canary.Config) (canary.Canary, error) {
	declared, err := testspec.ParseRoutingProbeBinding(cfg.Type, cfg.Target, cfg.Params)
	if err != nil {
		return nil, err
	}
	egress, exists := s.cfg.ICMPEgress[testID]
	if !exists && declared == nil {
		return s.reg.New(cfg)
	}
	if !exists || declared == nil || cfg.Target != egress.Target {
		return nil, errors.New("routing probe requires the same locally pinned ICMP destination")
	}
	pinned, err := egress.binding(testID)
	if err != nil {
		return nil, err
	}
	if *pinned != *declared {
		return nil, errors.New("routing probe must match the locally provisioned handoff and first hop")
	}
	// The matched operator binding has already validated source and MAC.
	source, _ := netip.ParseAddr(pinned.Egress.Source)
	mac, _ := net.ParseMAC(pinned.Egress.PeerMAC)
	binding := canary.ICMPEgress{Interface: pinned.Egress.Interface, Source: source}
	copy(binding.PeerMAC[:], mac)
	return canary.NewICMPWithEgress(cfg, binding)
}
