// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) loadIncidentImpactTestsInScope(ctx context.Context, principal *auth.Principal, sc tenancy.Scope, id string, snapshot *incidentImpactSnapshot, selection incidentImpactTestSelection, maxBytes int64) error {
	authorize := func(ctx context.Context, record entity.ContextRecord, member store.IncidentImpactEntity, testID string) error {
		if record.TenantID != principal.TenantID || record.ContextID != member.ContextID {
			return entity.ErrScopeMismatch
		}
		resource := entityContextResource(record)
		resource["incident_id"], resource["entity_id"], resource["test_id"] = id, member.EntityID, testID
		if err := s.authorizeIncidentImpact(ctx, principal, resource); err != nil {
			return err
		}
		return s.authorize(ctx, principal, permTestRead, auth.RBACGlobal, resource)
	}
	tests, err := (store.Incidents{}).ConfiguredImpactTestsInScope(ctx, sc, snapshot.inputs, maxBytes, authorize)
	if err != nil {
		return err
	}
	digest, err := hex.DecodeString(snapshot.sourceDigest)
	if err != nil {
		return err
	}
	digest, err = hashFlowRoleInputs(ctx, digest, tests, maxBytes)
	if err != nil {
		return err
	}
	snapshot.tests, snapshot.sourceDigest = tests, hex.EncodeToString(digest)
	if s.sloEngine != nil {
		snapshot.sloEnabled = true
		snapshot.sloDefinitions = s.sloEngine.SLOsFor(principal.TenantID)
	}
	digest, err = hashFlowRoleInputs(ctx, digest, struct {
		Enabled     bool
		Definitions any
	}{snapshot.sloEnabled, snapshot.sloDefinitions}, maxBytes)
	if err != nil {
		return err
	}
	snapshot.sourceDigest = hex.EncodeToString(digest)
	if selection.history {
		snapshot.testReads, err = (store.Incidents{}).IncidentTestMeasurementsInScope(ctx, sc, tests, selection.input.From, selection.input.To, maxBytes)
		return err
	}
	// Final publication checks only the original retained selectors. A newly
	// arriving probe does not turn the original read into an endless retry.
	if selection.original != nil {
		return (store.Incidents{}).RecheckIncidentTestMeasurementsInScope(ctx, sc, selection.original, maxBytes)
	}
	return nil
}

func bindIncidentImpactValidUntil(result *incident.ImpactResponse, snapshot incidentImpactSnapshot) error {
	now := time.Now().UTC()
	include := func(until time.Time) error {
		if until.IsZero() {
			return nil
		}
		if !until.After(now) {
			return apierror.Unavailable("current incident source authority expired; retry")
		}
		if result.ValidUntil == nil || until.Before(*result.ValidUntil) {
			value := until
			result.ValidUntil = &value
		}
		return nil
	}
	for _, source := range snapshot.sources {
		if err := include(source.ValidUntil); err != nil {
			return err
		}
	}
	for _, source := range snapshot.tests {
		for _, until := range []*time.Time{source.ValidUntil, source.MeasurementIdentityUntil} {
			if until != nil {
				if err := include(*until); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
