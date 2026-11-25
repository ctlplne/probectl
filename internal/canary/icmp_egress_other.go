// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build !linux

package canary

import (
	"errors"
	"net/netip"
)

func openICMPEgressWitness(ICMPEgress, netip.Addr, []byte) (icmpEgressWitness, error) {
	return nil, errors.New("icmp: egress witnessing is only available on Linux")
}
