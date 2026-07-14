// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"errors"
	"fmt"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	bgpv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/bgp/v1"
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
