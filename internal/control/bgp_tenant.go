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
	"github.com/ctlplne/probectl/internal/pipeline"
)

var (
	errBGPMissingTenantEnvelope  = errors.New("bgp event missing authenticated tenant envelope")
	errBGPTenantEnvelopeMismatch = errors.New("bgp event tenant envelope/payload mismatch")
)

// bindBGPEventAuthenticatedTenant reconciles the lane envelope, message-key and
// payload tenant for a BGP event and rewrites the payload to the authenticated
// value (RED-005, fail closed on any disagreement).
//
// strict (RTP-02, WIRE-001, AUTHZ-11): on the SHARED pooled lane (laneTenant
// == "") the tenant is carried only by the producer-set message key, which a
// bus actor can forge. In a strict (regulated / multi-tenant) profile the
// shared lane is refused outright — the only authoritative path is a
// tenant-namespaced lane (broker-ACL isolated, single-tenant by construction) —
// so a forged key cannot drive a BGP-derived incident/SIEM/routing record under
// a victim tenant. Non-strict deployments keep the key-envelope reconciliation.
func bindBGPEventAuthenticatedTenant(ev *bgpv1.BGPEvent, msg bus.Message, laneTenant string, strict bool) (string, error) {
	if ev == nil {
		return "", errBGPMissingTenantEnvelope
	}
	if strict && laneTenant == "" {
		return "", pipeline.ErrSharedLaneForbidden
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
