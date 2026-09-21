// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"fmt"

	"github.com/ctlplne/probectl/internal/bus"
	bgpv1 "github.com/ctlplne/probectl/internal/gen/probectl/bgp/v1"
)

var (
	errBGPMissingTenantEnvelope  = errors.New("bgp event missing authenticated tenant envelope")
	errBGPTenantEnvelopeMismatch = errors.New("bgp event tenant envelope/payload mismatch")
)

func bindBGPEventAuthenticatedTenant(ev *bgpv1.BGPEvent, msg bus.Message, laneTenant string) (string, error) {
	if ev == nil {
		return "", errBGPMissingTenantEnvelope
	}
	keyTenant := bus.TenantFromKey(msg.Key)
	envelopeTenant := laneTenant
	if envelopeTenant != "" && keyTenant != "" && keyTenant != envelopeTenant {
		return "", fmt.Errorf("%w: key tenant %q != lane tenant %q", errBGPTenantEnvelopeMismatch, keyTenant, envelopeTenant)
	}
	if envelopeTenant == "" {
		envelopeTenant = keyTenant
	}
	if envelopeTenant == "" {
		return "", errBGPMissingTenantEnvelope
	}
	payloadTenant := ev.GetTenantId()
	if payloadTenant != "" && payloadTenant != envelopeTenant {
		return "", fmt.Errorf("%w: envelope tenant %q != payload tenant %q", errBGPTenantEnvelopeMismatch, envelopeTenant, payloadTenant)
	}
	ev.TenantId = envelopeTenant
	return envelopeTenant, nil
}
