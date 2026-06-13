// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"net/http"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsync"
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
// tests as a SIGNED, pull-able bundle (ARCH-001). Agents poll this, verify the
// signature against the build-baked public key, and apply it only if the epoch
// is newer — so central test definition reaches the fleet WITHOUT config push
// (StreamConfig stays denied; distribution authority is the signing key, which
// lives outside the data plane).
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
		t, e := store.Tests{}.List(ctx, sc)
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
