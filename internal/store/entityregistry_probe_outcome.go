// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

// The digest supplies no authority. Lock the exact current enabled test and
// its explicit metadata context beside the authenticated sender/source locks.
func currentProbeOutcomeDefinition(ctx context.Context, sc tenancy.Scope, claim entity.Observation, contextID string) (bool, error) {
	if claim.Outcome == nil {
		return true, nil
	}
	var definition testspec.ExecutableDefinition
	var params []byte
	var updated, assigned time.Time
	err := sc.Q.QueryRow(ctx, `SELECT t.id::text,t.type,t.target,t.interval_seconds,t.timeout_seconds,t.params,t.updated_at,c.assigned_at
 FROM tests t JOIN entity_test_contexts c ON (c.tenant_id,c.test_id)=(t.tenant_id,t.id)
 WHERE t.tenant_id=$1 AND t.id=$2 AND t.enabled AND c.context_id=$3
 FOR SHARE OF t,c`, sc.Tenant.String(), claim.Source.SourceRef, contextID).Scan(&definition.ID, &definition.Type, &definition.Target, &definition.IntervalSeconds, &definition.TimeoutSeconds, &params, &updated, &assigned)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(params, &definition.Params); err != nil {
		return false, err
	}
	return matchesProbeOutcomeDefinition(claim, definition, updated, assigned)
}

func matchesProbeOutcomeDefinition(claim entity.Observation, definition testspec.ExecutableDefinition, updated, assigned time.Time) (bool, error) {
	m := claim.Outcome
	if m == nil || definition.Type == "icmp" || definition.Type != m.CanaryType || definition.ID != claim.Source.SourceRef || claim.Alias.Value != definition.ID || m.StartedAt.Before(updated) || m.StartedAt.Before(assigned) {
		return false, nil
	}
	digest, err := testspec.DefinitionHash(definition)
	return err == nil && digest == m.DefinitionHash, err
}

func evidenceStartedAt(claim entity.Observation) time.Time {
	if claim.Outcome != nil {
		return claim.Outcome.StartedAt
	}
	if claim.ICMP != nil {
		return claim.ICMP.StartedAt
	}
	return claim.ObservedAt
}

func probeOutcomeDocument(claim entity.Observation) ([]byte, error) {
	if claim.Outcome == nil {
		return nil, nil
	}
	return json.Marshal(claim.Outcome)
}
