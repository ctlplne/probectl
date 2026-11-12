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
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

// Current definition and explicit test contexts are locked in the same tenant
// transaction as the issued sender and source/anchor. An old digest, same-hash
// disable/re-enable or later context binding cannot revive an earlier sample.
func currentICMPDefinition(ctx context.Context, sc tenancy.Scope, claim entity.Observation, contextID string) (bool, error) {
	if claim.ICMP == nil {
		return true, nil
	}
	var test testspec.ExecutableDefinition
	var params []byte
	var updated, pathAssigned, contextAssigned time.Time
	var pathTarget string
	err := sc.Q.QueryRow(ctx, `SELECT t.id::text,t.type,t.target,t.interval_seconds,t.timeout_seconds,t.params,
		t.updated_at,p.path_target,p.assigned_at,c.assigned_at
		FROM tests t JOIN entity_path_test_contexts p ON (p.tenant_id,p.test_id)=(t.tenant_id,t.id)
		JOIN entity_test_contexts c ON (c.tenant_id,c.test_id,c.context_id)=(p.tenant_id,p.test_id,p.context_id)
		WHERE t.tenant_id=$1 AND t.id=$2 AND t.enabled AND t.type='icmp' AND p.context_id=$3
		FOR SHARE OF t,p,c`, sc.Tenant.String(), claim.Source.SourceRef, contextID).
		Scan(&test.ID, &test.Type, &test.Target, &test.IntervalSeconds, &test.TimeoutSeconds, &params,
			&updated, &pathTarget, &pathAssigned, &contextAssigned)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(params, &test.Params); err != nil {
		return false, err
	}
	return matchesICMPDefinition(claim, test, updated, pathTarget, pathAssigned, contextAssigned)
}

func matchesICMPDefinition(claim entity.Observation, test testspec.ExecutableDefinition, updated time.Time, pathTarget string, pathAssigned, contextAssigned time.Time) (bool, error) {
	if path.TargetHost(test.Target) != pathTarget || claim.ICMP.StartedAt.Before(updated) ||
		claim.ICMP.StartedAt.Before(pathAssigned) || claim.ICMP.StartedAt.Before(contextAssigned) {
		return false, nil
	}
	if target, err := netip.ParseAddr(test.Target); err == nil && target.Unmap().WithZone("").String() != claim.Alias.Value {
		return false, nil
	}
	digest, err := testspec.DefinitionHash(test)
	if err != nil || digest != claim.ICMP.DefinitionHash {
		return false, err
	}
	// Reuse the compiled-in probe's defaults/validation rather than accepting
	// a collector-selected requested population as the current profile.
	probe, err := canary.NewICMP(canary.Config{Type: test.Type, Target: test.Target,
		Interval: time.Duration(test.IntervalSeconds) * time.Second,
		Timeout:  time.Duration(test.TimeoutSeconds) * time.Second, Params: test.Params})
	if err != nil {
		return false, nil
	}
	return canary.ICMPRequestedPackets(probe) == uint64(claim.ICMP.Requested), nil
}

func icmpMeasurementDocument(claim entity.Observation) ([]byte, error) {
	if claim.ICMP == nil {
		return nil, nil
	}
	return json.Marshal(claim.ICMP)
}
