// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/pipeline"
)

// ndrFakeBinding verifies only the (tenant, agent) pairs it was told about;
// everything else is "not bound" — the injection case.
type ndrFakeBinding map[string]string // agent -> its real tenant

func (b ndrFakeBinding) Verify(_ context.Context, tenantID, agentID string) error {
	if boundTenant, ok := b[agentID]; ok && boundTenant == tenantID {
		return nil
	}
	return errors.New("agent not bound to tenant")
}

// ARCH-012 (CLAUDE.md §7.1 accompanying isolation test): the NDR consumer must
// reject a flow batch whose claimed tenant the sending agent does not belong
// to. Before the fix it trusted the payload tenant, so a bus actor could raise
// a detection against any victim tenant. rejectFlows must return true (drop)
// for the cross-tenant batch and false for a correctly-bound one.
func TestNDRRejectsCrossTenantInjection(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	binding := ndrFakeBinding{"agent-1": "tenant-real"}
	cs := (&NDRConsumer{log: log}).WithTenantBinding(binding)

	// agent-1 really belongs to tenant-real but the payload claims tenant-victim.
	inject := []pipeline.Identity{{Tenant: "tenant-victim", Agent: "agent-1"}}
	if !cs.rejectFlows(context.Background(), "flow", inject) {
		t.Fatal("cross-tenant injection was NOT rejected — NDR would raise a detection against the victim tenant")
	}

	// The honest batch (agent in its own tenant) is admitted.
	ok := []pipeline.Identity{{Tenant: "tenant-real", Agent: "agent-1"}}
	if cs.rejectFlows(context.Background(), "flow", ok) {
		t.Fatal("a correctly-bound batch was rejected")
	}

	// With no binding installed (unit-test/legacy mode) nothing is rejected —
	// production must always install one (asserted by wiring in main.go).
	noBind := &NDRConsumer{log: log}
	if noBind.rejectFlows(context.Background(), "flow", inject) {
		t.Fatal("nil-binding consumer should not reject (legacy/test mode)")
	}
}
