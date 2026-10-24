// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// DPR-363 (D-62): the alert supervisor runs no evaluator for a quarantined
// tenant (its rules and notification state are unreadable, so an evaluator
// built during the quarantine would re-page everything on release); the
// healthy tenant's evaluator is untouched.
func TestAlertSupervisorStopsAQuarantinedTenantsEvaluator(t *testing.T) {
	quarantined, healthy := "44444444-4444-4444-4444-444444444444", "55555555-5555-5555-5555-555555555555"
	withQuarantine(t, tenancy.QuarantineEntry{TenantID: quarantined, Reason: tenancy.QuarantineReaderScopeUnproven})
	var stopped []string
	s := &AlertEvaluatorSupervisor{
		evaluators: map[string]*tenantEvaluator{quarantined: {tenant: tenancy.ID(quarantined)}, healthy: {tenant: tenancy.ID(healthy)}},
		unregister: func(id string) { stopped = append(stopped, id) },
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		listTenants: func(context.Context) ([]store.Tenant, error) {
			return []store.Tenant{{ID: quarantined, Status: "active"}, {ID: healthy, Status: "active"}}, nil
		},
	}
	if err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.evaluators[quarantined]; ok || len(stopped) != 1 || stopped[0] != quarantined {
		t.Fatalf("evaluators = %v stopped = %v; want only the quarantined tenant's evaluator stopped", s.evaluators, stopped)
	}
	if _, ok := s.evaluators[healthy]; !ok {
		t.Fatal("the healthy tenant's evaluator was stopped")
	}
}
