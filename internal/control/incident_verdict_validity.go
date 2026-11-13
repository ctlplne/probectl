// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/store"
)

func incidentVerdictRoleInputSize(inputs store.InterfaceRoleInputs) (int64, error) {
	body, err := json.Marshal(inputs)
	if err != nil {
		return 0, err
	}
	return 4096 + 8*int64(len(body)), nil
}

func incidentVerdictSnapshotStillCurrent(snapshot incidentVerdictSnapshot) error {
	now := time.Now().UTC()
	include := func(until *time.Time) error {
		if until != nil && !until.After(now) {
			return apierror.Unavailable("incident verdict source authority expired; retry")
		}
		return nil
	}
	for _, source := range snapshot.sources {
		if source.Current {
			if err := include(source.ValidUntil); err != nil {
				return err
			}
		}
	}
	for _, source := range snapshot.tests {
		for _, until := range []*time.Time{source.ValidUntil, source.MeasurementIdentityUntil} {
			if err := include(until); err != nil {
				return err
			}
		}
	}
	for _, inputs := range snapshot.roles {
		clocks := []store.InterfaceRoleEvidenceClock{}
		if inputs.SNMP != nil {
			clocks = append(clocks, inputs.SNMP.InterfaceRoleEvidenceClock)
			if inputs.SNMP.Prefixes != nil {
				clocks = append(clocks, inputs.SNMP.PrefixClock)
			}
			for _, binding := range inputs.SNMP.Bindings {
				clocks = append(clocks, binding.InterfaceRoleEvidenceClock)
			}
		}
		for _, peer := range inputs.Peers {
			clocks = append(clocks, peer.InterfaceRoleEvidenceClock)
		}
		for _, clock := range clocks {
			if !roleInputClock(clock).current(now) {
				return apierror.Unavailable("incident verdict role evidence expired; retry")
			}
		}
	}
	return nil
}
