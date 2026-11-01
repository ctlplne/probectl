// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package enroll_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/enroll"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The second SVID is issued only with a one-use token pinned to the existing
// agent. It keeps that agent's bus registration and meter slot intact, and its
// serial is tenant-scoped for revocation/rotation.
func TestEvidenceSVIDRequiresExistingPinnedCollector(t *testing.T) {
	ctx := context.Background()
	pool, svc, tenantID := setup(ctx, t)
	defer pool.Close()
	baseToken, _, err := svc.MintToken(ctx, tenantID, "", "flow-source", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	base, err := svc.RegisterCollectorForTenant(ctx, tenantID, baseToken,
		"flow-source", "flow", "")
	if err != nil {
		t.Fatal(err)
	}
	var originalSPIFFE string
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			agent, err := (store.Agents{}).Get(ctx, sc, base.AgentID)
			if err == nil {
				originalSPIFFE = agent.SPIFFEID
			}
			return err
		}); err != nil {
		t.Fatal(err)
	}
	csr, key, err := crypto.CreateCSR("flow-source-evidence")
	if err != nil {
		t.Fatal(err)
	}
	unpinned, _, err := svc.MintToken(ctx, tenantID, "", "unbound-evidence", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterCollectorForTenant(ctx, tenantID, unpinned,
		"unbound-evidence", "entity", string(csr)); !errors.Is(err, enroll.ErrEvidencePinRequired) {
		t.Fatalf("unpinned evidence token issued an SVID: %v", err)
	}
	pinned, _, err := svc.MintToken(ctx, tenantID, base.AgentID, "flow-source", "test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := svc.RegisterCollectorForTenant(ctx, tenantID, pinned,
		"flow-source", "entity", string(csr))
	if err != nil || identity.SVID == nil || identity.AgentID != base.AgentID ||
		identity.SVID.SPIFFEID != crypto.EntitySPIFFEID(tenantID, base.AgentID) {
		t.Fatalf("evidence SVID = %+v, err=%v", identity, err)
	}
	if known, err := store.NewAgentIdentities(pool).KnownIssuedIdentity(ctx, tenantID,
		base.AgentID, identity.SVID.SPIFFEID, identity.SVID.Serial); err != nil || !known {
		t.Fatalf("evidence serial not bound to original tenant/agent: %v, %v", known, err)
	}
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			agent, err := (store.Agents{}).Get(ctx, sc, base.AgentID)
			if err == nil && agent.SPIFFEID != originalSPIFFE {
				t.Fatalf("evidence issuance replaced raw collector SPIFFE: %s", agent.SPIFFEID)
			}
			return err
		}); err != nil {
		t.Fatal(err)
	}
	csr2, _, err := crypto.CreateCSR("flow-source-evidence-rotation")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := crypto.ECDSASignPEM(key, csr2)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := svc.Rotate(ctx, enroll.RotateRequest{
		CertPEM: leafOnly(identity.SVID.CertPEM), CSRPEM: string(csr2),
		ProofHex: fmt.Sprintf("%x", proof),
	})
	if err != nil || rotated.Plane != "entity" || rotated.AgentID != base.AgentID ||
		rotated.Serial == identity.SVID.Serial {
		t.Fatalf("evidence rotation = %+v, err=%v", rotated, err)
	}
}
