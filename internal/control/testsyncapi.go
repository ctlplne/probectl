// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"errors"
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/testsync"
)

// WithTestSync installs the central test-distribution source (G9, D-41): the
// signer of the tenant's test set. nil leaves GET /v1/tests/bundle reporting
// 503 (central test distribution not configured).
func (s *Server) WithTestSync(src *testsync.Source) *Server {
	s.testSync = src
	return s
}

// handleTestBundle serves GET /v1/tests/bundle — the caller's tenant's enabled
// tests as the SAME signed bundle its agents pull over mTLS (FetchTestBundle,
// docs/adr/central-test-distribution.md). It lets an operator inspect exactly
// what the fleet will verify and run: the epoch is the tenant's test-set
// version, and the signature verifies against `probectl-control testsync
// public-key`. The tenant is the authenticated principal's, read under RLS.
func (s *Server) handleTestBundle(w http.ResponseWriter, r *http.Request) error {
	if s.testSync == nil {
		return apierror.Unavailable("central test distribution is not configured (no signing key)")
	}
	tid, err := s.principalTenant(r)
	if err != nil {
		return err
	}
	_, signed, err := s.testSync.Bundle(r.Context(), tid)
	if errors.Is(err, testsync.ErrTestSetTooLarge) {
		return apierror.TooLarge("the tenant's enabled tests exceed the distributable maximum")
	}
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(signed)
	return nil
}
