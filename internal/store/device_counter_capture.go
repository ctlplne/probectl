// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store/sourceepoch"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var (
	ErrCounterCaptureUnavailable = errors.New("device counter source witness unavailable")
	ErrCounterCaptureBudget      = errors.New("device counter witness state admission exhausted")
)

// DeviceCounterCaptures accepts write witnesses only from the restricted
// authenticated evidence RPC. A bus payload can look up a witness, never create
// one. Neither operation grants an outward reader access to the counter history.
type DeviceCounterCaptures struct{ pool *pgxpool.Pool }

func NewDeviceCounterCaptures(pool *pgxpool.Pool) *DeviceCounterCaptures {
	return &DeviceCounterCaptures{pool: pool}
}

// DeviceCounterCapture retains server-selected identity and its exact authority
// interval. Clock/width/continuity interpretation still belongs to the history
// adapter; this witness attests original bytes, not an inferred billing rate.
type DeviceCounterCapture struct {
	entity.CounterCaptureReference
	Scope                             entity.Scope
	DeviceID, SenderSerial            string
	SourceAssignedAt, AgentAssignedAt time.Time
}

func (s *DeviceCounterCaptures) key(ctx context.Context, sender string, digest [32]byte, input entity.CounterCaptureInput) ([32]byte, error) {
	if err := ctx.Err(); err != nil {
		return [32]byte{}, err
	}
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return [32]byte{}, entity.ErrScopeMismatch
	}
	if s == nil || s.pool == nil {
		return [32]byte{}, ErrCounterCaptureUnavailable
	}
	return entity.CounterCaptureKey(tenant.String(), sender, digest, input)
}

// CaptureAuthenticated must receive sender/serial from the verified, issued
// evidence mTLS identity. Assignment rows and that exact certificate are locked
// until commit. A lifecycle fence and hash-only first receipt prevent replay
// from recreating an erased payload or selecting a later source incarnation.
func (s *DeviceCounterCaptures) CaptureAuthenticated(ctx context.Context, sender, serial string, digest [32]byte, input entity.CounterCaptureInput, stateBytes int64) (entity.CounterCaptureReference, error) {
	key, err := s.key(ctx, sender, digest, input)
	if err != nil {
		return entity.CounterCaptureReference{}, err
	}
	if serial == "" {
		return entity.CounterCaptureReference{}, ErrEvidenceIdentityInactive
	}
	if stateBytes < 4352 {
		return entity.CounterCaptureReference{}, ErrCounterCaptureBudget
	}
	var result entity.CounterCaptureReference
	ctx = tenancy.WithSiloTableLock(ctx)
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sourceepoch.SourceGenerationInScope(ctx, sc); err != nil {
			return err
		}
		if err := tenancy.LockTenantAuditStream(ctx, sc.Q, sc.Tenant.String()); err != nil {
			return err
		}
		var admitted bool
		if err := sc.Q.QueryRow(ctx, `SELECT NOT invalidating
                AND observation_not_before<=$2 AND $3<=clock_timestamp()+interval '5 minutes'
                FROM flow_snapshot_epochs WHERE tenant_id=$1 FOR SHARE`,
			sc.Tenant.String(), input.PollStartedAt, input.PollCompletedAt).Scan(&admitted); err != nil {
			return err
		}
		if !admitted {
			return ErrCounterCaptureUnavailable
		}
		var active int
		if err := sc.Q.QueryRow(ctx, `SELECT 1 FROM agent_identities
                WHERE tenant_id=$1 AND agent_id=$2 AND serial=$3 AND spiffe_id=$4
                  AND revoked_at IS NULL AND issued_at<=$5 AND not_after>$6
                  AND not_after>clock_timestamp() FOR SHARE`, sc.Tenant.String(), sender, serial,
			crypto.EntitySPIFFEID(sc.Tenant.String(), sender), input.PollStartedAt, input.PollCompletedAt).Scan(&active); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrEvidenceIdentityInactive
			}
			return err
		}
		var contextID, deviceID string
		var sourceAt, agentAt time.Time
		if err := sc.Q.QueryRow(ctx, `SELECT m.context_id::text,n.id::text,m.assigned_at,a.assigned_at
                FROM entity_source_contexts m
                JOIN entity_agent_contexts a ON (a.tenant_id,a.agent_id,a.context_id)=(m.tenant_id,m.agent_id,m.context_id)
                JOIN entities n ON (n.tenant_id,n.context_id,n.id)=(m.tenant_id,m.context_id,m.anchor_entity_id) AND n.kind='device'
                WHERE m.tenant_id=$1 AND m.agent_id=$2 AND m.source_kind='device_target' AND m.source_ref=$3
                  AND m.assigned_at<=$4 AND a.assigned_at<=$4
                  AND m.assigned_at<=clock_timestamp() AND a.assigned_at<=clock_timestamp()
                  AND (m.expires_at IS NULL OR m.expires_at>GREATEST($5,clock_timestamp()))
                  AND (a.expires_at IS NULL OR a.expires_at>GREATEST($5,clock_timestamp()))
                  AND NOT EXISTS (SELECT 1 FROM agent_identities i WHERE i.tenant_id=m.tenant_id AND i.agent_id=m.agent_id
                      AND i.revoked_at IS NOT NULL AND i.revoked_by IS DISTINCT FROM 'entity_registry_delete')
                FOR SHARE OF m,a,n`, sc.Tenant.String(), sender, input.ConfiguredTarget, input.PollStartedAt, input.PollCompletedAt).
			Scan(&contextID, &deviceID, &sourceAt, &agentAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrCounterCaptureUnavailable
			}
			return err
		}
		var exists bool
		if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM device_counter_captures WHERE tenant_id=$1 AND capture_key=$2)`, sc.Tenant.String(), key[:]).Scan(&exists); err != nil {
			return err
		}
		if exists {
			capture, err := lookupDeviceCounterWitness(ctx, sc, key)
			result = capture.CounterCaptureReference
			return err // missing erased payload is never refilled
		}
		var used string
		if err := sc.Q.QueryRow(ctx, `SELECT (COALESCE((SELECT sum(charged_bytes) FROM device_counter_captures WHERE tenant_id=$1),0)
                +COALESCE((SELECT sum(charged_bytes) FROM device_counter_capture_sources WHERE tenant_id=$1),0))::text`, sc.Tenant.String()).Scan(&used); err != nil {
			return err
		}
		// Numeric SUM avoids signed overflow. Compare inside PostgreSQL rather
		// than converting a potentially exhausted tenant total through float64.
		if err := sc.Q.QueryRow(ctx, `SELECT $1::numeric <= $2::bigint-4352`, used, stateBytes).Scan(&admitted); err != nil {
			return err
		}
		if !admitted {
			return ErrCounterCaptureBudget
		}
		result.Key = key
		if err := sc.Q.QueryRow(ctx, `INSERT INTO device_counter_captures(tenant_id,capture_key) VALUES($1,$2) RETURNING captured_at`, sc.Tenant.String(), key[:]).Scan(&result.CapturedAt); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx, `INSERT INTO device_counter_capture_sources
                (tenant_id,capture_key,context_id,device_id,agent_id,source_ref,sender_serial,source_assigned_at,agent_assigned_at,
                 raw_digest,poll_started_unix_nanos,poll_completed_unix_nanos,point_count)
                VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, sc.Tenant.String(), key[:], contextID, deviceID, sender,
			input.ConfiguredTarget, serial, sourceAt, agentAt, digest[:], input.PollStartedAt.UnixNano(), input.PollCompletedAt.UnixNano(), int64(input.PointCount))
		return err
	})
	if err != nil {
		return entity.CounterCaptureReference{}, err
	}
	return result, nil
}

// LookupWitness checks the same tenant and current source incarnation. The
// claimed bus sender selects an existing independently authenticated receipt;
// it cannot create a receipt. A later storage write must recheck this authority
// under its own publication fence, and outward reads must authorize their actor.
func (s *DeviceCounterCaptures) LookupWitness(ctx context.Context, claimedSender string, digest [32]byte, input entity.CounterCaptureInput) (DeviceCounterCapture, error) {
	key, err := s.key(ctx, claimedSender, digest, input)
	if err != nil {
		return DeviceCounterCapture{}, err
	}
	var capture DeviceCounterCapture
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		capture, err = lookupDeviceCounterWitness(ctx, sc, key)
		return err
	})
	return capture, err
}

func lookupDeviceCounterWitness(ctx context.Context, sc tenancy.Scope, key [32]byte) (DeviceCounterCapture, error) {
	result := DeviceCounterCapture{CounterCaptureReference: entity.CounterCaptureReference{Key: key}, Scope: entity.Scope{TenantID: sc.Tenant.String()}}
	err := sc.Q.QueryRow(ctx, `SELECT c.captured_at,p.context_id::text,p.device_id::text,p.sender_serial,p.source_assigned_at,p.agent_assigned_at
        FROM device_counter_captures c JOIN device_counter_capture_sources p USING(tenant_id,capture_key)
        JOIN entity_source_contexts m ON (m.tenant_id,m.agent_id,m.source_kind,m.source_ref)=(p.tenant_id,p.agent_id,p.source_kind,p.source_ref)
          AND m.context_id=p.context_id AND m.anchor_entity_id=p.device_id AND m.assigned_at=p.source_assigned_at
        JOIN entity_agent_contexts a ON (a.tenant_id,a.agent_id,a.context_id)=(p.tenant_id,p.agent_id,p.context_id) AND a.assigned_at=p.agent_assigned_at
        JOIN entities n ON (n.tenant_id,n.context_id,n.id,n.kind)=(p.tenant_id,p.context_id,p.device_id,p.device_kind)
        JOIN agent_identities origin ON (origin.tenant_id,origin.agent_id,origin.serial)=(p.tenant_id,p.agent_id,p.sender_serial)
        JOIN flow_snapshot_epochs epoch ON epoch.tenant_id=p.tenant_id AND NOT epoch.invalidating
        WHERE c.tenant_id=$1 AND c.capture_key=$2
          AND m.assigned_at<=statement_timestamp() AND a.assigned_at<=statement_timestamp()
          AND (m.expires_at IS NULL OR m.expires_at>statement_timestamp())
          AND (a.expires_at IS NULL OR a.expires_at>statement_timestamp())
          AND origin.revoked_at IS NULL AND origin.spiffe_id='spiffe://probectl/tenant/' || p.tenant_id::text || '/entity/' || p.agent_id
          AND EXISTS(SELECT 1 FROM agent_identities live WHERE live.tenant_id=p.tenant_id AND live.agent_id=p.agent_id
              AND live.spiffe_id=origin.spiffe_id AND live.revoked_at IS NULL AND live.not_after>statement_timestamp())
          AND NOT EXISTS(SELECT 1 FROM agent_identities revoked WHERE revoked.tenant_id=p.tenant_id AND revoked.agent_id=p.agent_id
              AND revoked.revoked_at IS NOT NULL AND revoked.revoked_by IS DISTINCT FROM 'entity_registry_delete')`, sc.Tenant.String(), key[:]).
		Scan(&result.CapturedAt, &result.Scope.ContextID, &result.DeviceID, &result.SenderSerial, &result.SourceAssignedAt, &result.AgentAssignedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DeviceCounterCapture{}, ErrCounterCaptureUnavailable
	}
	if err != nil {
		return DeviceCounterCapture{}, err
	}
	return result, nil
}
