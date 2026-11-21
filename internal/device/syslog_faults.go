// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package device

import (
	"encoding/hex"
	"strings"

	"github.com/ctlplne/probectl/internal/crypto"
)

// SyslogPatternSource carries source binding from the authenticated receiver.
type SyslogPatternSource struct {
	Family          string
	Name            string
	FaultDevice     string
	RoutingInstance string
}

type syslogFaultCandidate struct {
	target, subject string
}

func syslogFaultForPattern(row SyslogEvent, pattern SyslogPattern, source SyslogPatternSource) syslogFaultCandidate {
	if source.Name == "" || source.FaultDevice == "" || row.Hostname != source.FaultDevice ||
		row.Device != source.FaultDevice || pattern.Subject == "" {
		return syslogFaultCandidate{}
	}
	instance := ""
	switch pattern.Kind {
	case SyslogPatternLinkDown, SyslogPatternSupplyFault:
	case SyslogPatternBGPDown:
		instance = source.RoutingInstance
		if instance == "" || (pattern.RoutingContext != "" && pattern.RoutingContext != instance) {
			return syslogFaultCandidate{}
		}
	default:
		return syslogFaultCandidate{}
	}
	// Scope the exact original subject to the admitted sender, configured
	// device and routing instance. Addresses or interface names can repeat.
	key := strings.Join([]string{row.TenantID, source.Name, source.FaultDevice, instance, string(pattern.Kind), pattern.Subject}, "\x00")
	digest := crypto.Hash([]byte("device-syslog-fault-v1\x00" + key))
	if len(digest) != 32 {
		return syslogFaultCandidate{}
	}
	return syslogFaultCandidate{target: "device-syslog:" + hex.EncodeToString(digest), subject: pattern.Subject}
}
