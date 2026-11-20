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

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/threat/dnstap"
)

var (
	ErrResolverDNSUnavailable = errors.New("resolver DNS source unavailable")
	ErrResolverDNSConflict    = errors.New("resolver DNS capture overlaps different evidence")
	ErrResolverDNSBudget      = errors.New("resolver DNS interval state admission exhausted")
)

type ResolverDNSIdentity struct {
	ContextID, DeviceID, AgentID, SourceRef string
	SourceAssignedAt, AgentAssignedAt       time.Time
}

type ResolverDNSCaptureInput struct {
	AgentID, CertificateSerial, SourceRef string
	Digest                                [32]byte
	Capture                               dnstap.ClosedCapture
	Policy                                dnstap.PressurePolicy
}

type ResolverDNSCaptureResult struct {
	Identity ResolverDNSIdentity
	Previous []dnstap.ResolverIntervalCounts
	Policy   dnstap.PressurePolicy
}

// CaptureResolverDNS locks the exact current mTLS identity and operator
// assignment before accepting the clocks and counters under tenant RLS.
func (s *EntityRegistry) CaptureResolverDNS(ctx context.Context, input ResolverDNSCaptureInput) (ResolverDNSCaptureResult, error) {
	if s == nil || s.pool == nil || !dnstap.ValidSourceRef(input.SourceRef) ||
		input.AgentID == "" || input.CertificateSerial == "" || input.Digest == [32]byte{} ||
		input.Capture.Validate(time.Now()) != nil || input.Policy.Rule.Validate() != nil {
		return ResolverDNSCaptureResult{}, ErrResolverDNSUnavailable
	}
	var result ResolverDNSCaptureResult
	ctx = tenancy.WithSiloTableLock(ctx)
	err := tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sourceepoch.SourceGenerationInScope(ctx, sc); err != nil {
			return err
		}
		if err := tenancy.LockTenantAuditStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		start := input.Capture.Intervals[0].From
		end := input.Capture.Intervals[len(input.Capture.Intervals)-1].To
		var admitted bool
		if err := sc.Q.QueryRow(ctx, `SELECT NOT invalidating AND observation_not_before<=$2
			FROM flow_snapshot_epochs WHERE tenant_id=$1 FOR SHARE`, sc.Tenant.String(), start).Scan(&admitted); err != nil {
			return err
		}
		if !admitted {
			return ErrResolverDNSUnavailable
		}
		identity, err := currentResolverDNSIdentity(ctx, sc, input, start, end)
		if err != nil {
			return err
		}
		result, err = writeResolverDNSIntervals(ctx, sc, identity, input, start)
		return err
	})
	if err != nil {
		return ResolverDNSCaptureResult{}, err
	}
	return result, nil
}

func currentResolverDNSIdentity(ctx context.Context, sc tenancy.Scope, input ResolverDNSCaptureInput, from, to time.Time) (ResolverDNSIdentity, error) {
	tenant := sc.Tenant.String()
	var active int
	err := sc.Q.QueryRow(ctx, `SELECT 1 FROM agent_identities
		WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3 AND spiffe_id=$4
		  AND revoked_at IS NULL AND issued_at<=$5 AND not_after>$6
		  AND not_after>statement_timestamp() FOR SHARE`, tenant, input.AgentID, input.CertificateSerial,
		crypto.EntitySPIFFEID(tenant, input.AgentID), from, to).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) {
		return ResolverDNSIdentity{}, ErrEvidenceIdentityInactive
	}
	if err != nil {
		return ResolverDNSIdentity{}, err
	}
	identity := ResolverDNSIdentity{AgentID: input.AgentID, SourceRef: input.SourceRef}
	err = sc.Q.QueryRow(ctx, `SELECT m.context_id::text,n.id::text,m.assigned_at,a.assigned_at
		FROM entity_source_contexts m
		JOIN entity_agent_contexts a ON (a.tenant_id,a.agent_id,a.context_id)=(m.tenant_id,m.agent_id,m.context_id)
		JOIN entities n ON (n.tenant_id,n.context_id,n.id)=(m.tenant_id,m.context_id,m.anchor_entity_id) AND n.kind='device'
		WHERE m.tenant_id=$1 AND m.agent_id=$2 AND m.source_kind='dns_resolver' AND m.source_ref=$3
		  AND m.assigned_at<=$4 AND a.assigned_at<=$4
		  AND (m.expires_at IS NULL OR m.expires_at>GREATEST($5,statement_timestamp()))
		  AND (a.expires_at IS NULL OR a.expires_at>GREATEST($5,statement_timestamp()))
		  AND NOT EXISTS (SELECT 1 FROM agent_identities i WHERE i.tenant_id=m.tenant_id AND i.agent_id=m.agent_id
		      AND i.revoked_at IS NOT NULL AND i.revoked_by IS DISTINCT FROM 'entity_registry_delete')
		FOR SHARE OF m,a,n`, tenant, input.AgentID, input.SourceRef, from, to).
		Scan(&identity.ContextID, &identity.DeviceID, &identity.SourceAssignedAt, &identity.AgentAssignedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ResolverDNSIdentity{}, ErrResolverDNSUnavailable
	}
	return identity, err
}

const maximumResolverIntervalsPerTenant = 100_000

func writeResolverDNSIntervals(ctx context.Context, sc tenancy.Scope, identity ResolverDNSIdentity,
	input ResolverDNSCaptureInput, start time.Time) (ResolverDNSCaptureResult, error) {
	tenant := sc.Tenant.String()
	policy, err := json.Marshal(input.Policy)
	if err != nil {
		return ResolverDNSCaptureResult{}, err
	}
	if _, err := sc.Q.Exec(ctx, `DELETE FROM resolver_dns_intervals
		WHERE tenant_id=$1 AND minute_start<statement_timestamp()-interval '24 hours 1 minute'`, tenant); err != nil {
		return ResolverDNSCaptureResult{}, err
	}
	var last time.Time
	err = sc.Q.QueryRow(ctx, `SELECT minute_start FROM resolver_dns_intervals
		WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='dns_resolver' AND source_ref=$3
		  AND source_assigned_at=$4 AND agent_assigned_at=$5
		ORDER BY minute_start DESC LIMIT 1`, tenant, identity.AgentID, identity.SourceRef,
		identity.SourceAssignedAt, identity.AgentAssignedAt).Scan(&last)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ResolverDNSCaptureResult{}, err
	}
	if last.Before(start) {
		var full bool
		err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM resolver_dns_intervals
			WHERE tenant_id=$1 LIMIT 1 OFFSET $2)`, tenant,
			maximumResolverIntervalsPerTenant-len(input.Capture.Intervals)).Scan(&full)
		if err != nil {
			return ResolverDNSCaptureResult{}, err
		}
		if full {
			return ResolverDNSCaptureResult{}, ErrResolverDNSBudget
		}
		for _, window := range input.Capture.Intervals {
			if err := insertResolverDNSInterval(ctx, sc, identity, input.Digest, window, policy); err != nil {
				return ResolverDNSCaptureResult{}, err
			}
		}
	} else {
		policy, err = verifyResolverDNSReplay(ctx, sc, identity, input)
		if err != nil {
			return ResolverDNSCaptureResult{}, err
		}
	}
	var retainedPolicy dnstap.PressurePolicy
	if json.Unmarshal(policy, &retainedPolicy) != nil || retainedPolicy.Rule.Validate() != nil {
		return ResolverDNSCaptureResult{}, ErrResolverDNSUnavailable
	}
	previous, err := readResolverDNSPrior(ctx, sc, identity, start, policy)
	return ResolverDNSCaptureResult{Identity: identity, Previous: previous, Policy: retainedPolicy}, err
}

func insertResolverDNSInterval(ctx context.Context, sc tenancy.Scope, identity ResolverDNSIdentity,
	digest [32]byte, window dnstap.ResolverIntervalCounts, policy []byte) error {
	_, err := sc.Q.Exec(ctx, `INSERT INTO resolver_dns_intervals
		(tenant_id,context_id,device_id,agent_id,source_ref,source_assigned_at,agent_assigned_at,
		 minute_start,client_responses,name_errors,server_failures,truncated,capture_digest,pressure_policy)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		sc.Tenant.String(), identity.ContextID, identity.DeviceID, identity.AgentID, identity.SourceRef,
		identity.SourceAssignedAt, identity.AgentAssignedAt, window.From, window.Responses,
		window.NameErrors, window.ServerFailure, window.Truncated, digest[:], policy)
	return err
}

func verifyResolverDNSReplay(ctx context.Context, sc tenancy.Scope, identity ResolverDNSIdentity, input ResolverDNSCaptureInput) ([]byte, error) {
	from := input.Capture.Intervals[0].From
	to := input.Capture.Intervals[len(input.Capture.Intervals)-1].To
	var admitted int
	var policy []byte
	err := sc.Q.QueryRow(ctx, `SELECT count(*),pressure_policy FROM resolver_dns_intervals
		WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='dns_resolver' AND source_ref=$3
		  AND source_assigned_at=$4 AND agent_assigned_at=$5 AND minute_start>=$6 AND minute_start<$7
		  AND capture_digest=$8 GROUP BY pressure_policy LIMIT 1`, sc.Tenant.String(), identity.AgentID, identity.SourceRef,
		identity.SourceAssignedAt, identity.AgentAssignedAt, from, to, input.Digest[:]).Scan(&admitted, &policy)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && admitted != len(input.Capture.Intervals) {
		return nil, ErrResolverDNSConflict
	}
	return policy, err
}

func readResolverDNSPrior(ctx context.Context, sc tenancy.Scope, identity ResolverDNSIdentity, start time.Time, policy []byte) ([]dnstap.ResolverIntervalCounts, error) {
	rows, err := sc.Q.Query(ctx, `SELECT minute_start,client_responses,name_errors,server_failures,truncated
		FROM resolver_dns_intervals
		WHERE tenant_id=$1 AND agent_id=$2 AND source_kind='dns_resolver' AND source_ref=$3
		  AND source_assigned_at=$4 AND agent_assigned_at=$5 AND minute_start>=$6 AND minute_start<$7
		  AND pressure_policy=$8
		ORDER BY minute_start LIMIT 2`, sc.Tenant.String(), identity.AgentID, identity.SourceRef,
		identity.SourceAssignedAt, identity.AgentAssignedAt, start.Add(-2*dnstap.ResolverInterval), start, policy)
	if err != nil {
		return nil, err
	}
	return scanResolverDNSIntervals(rows)
}

func scanResolverDNSIntervals(rows pgx.Rows) ([]dnstap.ResolverIntervalCounts, error) {
	defer rows.Close()
	results := []dnstap.ResolverIntervalCounts{}
	for rows.Next() {
		var window dnstap.ResolverIntervalCounts
		if err := rows.Scan(&window.From, &window.Responses, &window.NameErrors, &window.ServerFailure, &window.Truncated); err != nil {
			return nil, err
		}
		window.From = window.From.UTC()
		window.To = window.From.Add(dnstap.ResolverInterval)
		results = append(results, window)
	}
	return results, rows.Err()
}

// ResolverDNSCoverage retains only completed minute counters selected by an
// exact current resolver assignment. Empty minutes have no synthetic sample.
type ResolverDNSCoverage struct {
	From         time.Time                       `json:"from"`
	To           time.Time                       `json:"to"`
	Status       string                          `json:"status"`
	Expected     int                             `json:"expected_intervals"`
	Observations []dnstap.ResolverIntervalCounts `json:"observations"`
}

func (s *EntityRegistry) ReadResolverDNSCoverage(ctx context.Context, scope entity.Scope, deviceID, agentID, sourceRef string, minutes int) (ResolverDNSCoverage, error) {
	const maxMinutes = 120
	if s == nil || s.pool == nil || !dnstap.ValidSourceRef(sourceRef) || minutes < 1 || minutes > maxMinutes {
		return ResolverDNSCoverage{}, ErrResolverDNSUnavailable
	}
	tenant, bound := tenancy.FromContext(ctx)
	if !bound || tenant.String() != scope.TenantID {
		return ResolverDNSCoverage{}, entity.ErrScopeMismatch
	}
	contextID, err := validRegistryUUID(scope.ContextID)
	if err != nil {
		return ResolverDNSCoverage{}, err
	}
	deviceID, err = validRegistryUUID(deviceID)
	if err != nil {
		return ResolverDNSCoverage{}, err
	}
	agentID, err = validRegistryUUID(agentID)
	if err != nil {
		return ResolverDNSCoverage{}, err
	}
	to := time.Now().UTC().Truncate(dnstap.ResolverInterval)
	result := ResolverDNSCoverage{From: to.Add(-time.Duration(minutes) * dnstap.ResolverInterval), To: to,
		Expected: minutes, Observations: []dnstap.ResolverIntervalCounts{}, Status: "no_recent_capture"}
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		result.Observations, err = resolverDNSCoverageInScope(ctx, sc, contextID, deviceID, agentID, sourceRef, result)
		return err
	})
	if err != nil {
		return ResolverDNSCoverage{}, err
	}
	switch {
	case len(result.Observations) == minutes:
		result.Status = "closed_file_intervals_present"
	case len(result.Observations) > 0:
		result.Status = "missing_closed_file_intervals"
	}
	return result, nil
}

func resolverDNSCoverageInScope(ctx context.Context, sc tenancy.Scope, contextID, deviceID, agentID, sourceRef string,
	request ResolverDNSCoverage) ([]dnstap.ResolverIntervalCounts, error) {
	var sourceAt, agentAt time.Time
	err := sc.Q.QueryRow(ctx, `SELECT m.assigned_at,a.assigned_at
		FROM entity_source_contexts m
		JOIN entity_agent_contexts a ON (a.tenant_id,a.agent_id,a.context_id)=(m.tenant_id,m.agent_id,m.context_id)
		JOIN entities n ON (n.tenant_id,n.context_id,n.id)=(m.tenant_id,m.context_id,m.anchor_entity_id) AND n.kind='device'
		WHERE m.tenant_id=$1 AND m.context_id=$2 AND n.id=$3 AND m.agent_id=$4
		  AND m.source_kind='dns_resolver' AND m.source_ref=$5
		  AND m.assigned_at<=statement_timestamp() AND a.assigned_at<=statement_timestamp()
		  AND (m.expires_at IS NULL OR m.expires_at>statement_timestamp())
		  AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())
		  AND NOT EXISTS (SELECT 1 FROM agent_identities i WHERE i.tenant_id=m.tenant_id AND i.agent_id=m.agent_id
		      AND i.revoked_at IS NOT NULL AND i.revoked_by IS DISTINCT FROM 'entity_registry_delete')`,
		sc.Tenant.String(), contextID, deviceID, agentID, sourceRef).Scan(&sourceAt, &agentAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrResolverDNSUnavailable
	}
	if err != nil {
		return nil, err
	}
	rows, err := sc.Q.Query(ctx, `SELECT minute_start,client_responses,name_errors,server_failures,truncated
		FROM resolver_dns_intervals
		WHERE tenant_id=$1 AND context_id=$2 AND device_id=$3 AND agent_id=$4 AND source_kind='dns_resolver'
		  AND source_ref=$5 AND source_assigned_at=$6 AND agent_assigned_at=$7 AND minute_start>=$8 AND minute_start<$9
		ORDER BY minute_start LIMIT $10`, sc.Tenant.String(), contextID, deviceID, agentID, sourceRef,
		sourceAt, agentAt, request.From, request.To, request.Expected)
	if err != nil {
		return nil, err
	}
	return scanResolverDNSIntervals(rows)
}
