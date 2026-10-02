// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsync"
)

// WithTestSyncKey installs the Ed25519 PKCS#8 private-key PEM the control plane
// signs test bundles with (ARCH-001). Agents verify against the matching
// build-baked public key. nil/empty leaves GET /v1/tests/bundle reporting 503
// (central test distribution not configured).
func (s *Server) WithTestSyncKey(privPEM []byte) *Server {
	s.testSyncKey = privPEM
	return s
}

// handleTestBundle serves GET /v1/tests/bundle — the caller's tenant's enabled
// tests as a SIGNED, pull-able bundle (ARCH-001). This is the control-plane
// half of central test distribution; it is implemented and signed. An agent is
// MEANT to poll this, Verify the signature against the build-baked public key,
// and apply it only if the epoch is newer — so central test definition reaches
// the fleet WITHOUT config push (StreamConfig stays denied; distribution
// authority is the signing key, outside the data plane). The agent-side pull
// loop is NOT yet shipped (ING-20/PLAT-13): no agent imports internal/testsync,
// so today this endpoint is served but not consumed, and tests reach agents via
// their own config. See internal/testsync's package doc + D-28 (PLAT-13).
func (s *Server) handleTestBundle(w http.ResponseWriter, r *http.Request) error {
	if len(s.testSyncKey) == 0 {
		return apierror.Unavailable("central test distribution is not configured (no signing key)")
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	var tests []store.Test
	if err := s.inTenant(r, func(ctx context.Context, sc tenancy.Scope) error {
		t, e := store.Tests{}.ListAll(ctx, sc, 0)
		tests = t
		return e
	}); err != nil {
		return err
	}
	bundle := testsync.Bundle{TenantID: tid, Epoch: testsync.NewEpoch()}
	for _, t := range tests {
		if !t.Enabled {
			continue // only enabled tests are distributed to the fleet
		}
		bundle.Tests = append(bundle.Tests, testsync.Test{
			ID: t.ID, Type: t.Type, Target: t.Target,
			IntervalSeconds: t.IntervalSeconds, TimeoutSeconds: t.TimeoutSeconds,
			Params: t.Params,
		})
	}
	signed, err := testsync.Sign(bundle, s.testSyncKey)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(signed)
	return nil
}
