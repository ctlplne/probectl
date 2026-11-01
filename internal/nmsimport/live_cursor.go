// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var ErrCaptureBusy = errors.New("nmsimport: capture step busy")

// LiveCaptureStep is one server-selected endpoint. Its secret stays in this
// process, and only its digest is stored on the tenant's FORCE-RLS plan row.
// A caller must finish or release it and zero the secret when done.
type LiveCaptureStep struct {
	Stage     string
	GroupID   string
	StartPage int64
	StartRow  int64
	secret    []byte
}

func (step *LiveCaptureStep) Zeroize() {
	crypto.Zeroize(step.secret)
	step.secret = nil
}

func (step LiveCaptureStep) leaseHash() string {
	return hex.EncodeToString(crypto.Default.Hash(step.secret))
}

func validCaptureIDs(contextID, planID string) (string, string, error) {
	contextUUID, contextErr := uuid.Parse(contextID)
	planUUID, planErr := uuid.Parse(planID)
	if contextErr != nil || planErr != nil || contextUUID == uuid.Nil || planUUID == uuid.Nil {
		return "", "", ErrPlanUnavailable
	}
	return contextUUID.String(), planUUID.String(), nil
}

// AcquireConfiguredLibreNMSStage claims one configured source step for a
// context-authorized actor. It changes only the tenant plan lease; source data
// remains inert, and a failed audit rolls the lease back in the same txn.
func (s CaptureStore) AcquireConfiguredLibreNMSStage(ctx context.Context,
	contextID, planID string) (LiveCaptureStep, error) {
	if s.pool == nil || s.audit == nil {
		return LiveCaptureStep{}, ErrCaptureAuditUnavailable
	}
	contextID, planID, err := validCaptureIDs(contextID, planID)
	if err != nil {
		return LiveCaptureStep{}, err
	}
	secret, err := crypto.Random(32)
	if err != nil {
		return LiveCaptureStep{}, err
	}
	step := LiveCaptureStep{secret: secret}
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		meta, err := loadCaptureMeta(ctx, sc, contextID, planID, true)
		if err != nil {
			return err
		}
		if meta.source != LibreNMS || meta.configVersion == 0 || meta.state != "capturing" {
			return ErrPlanUnavailable
		}
		var enabled bool
		var leaseBusy bool
		err = sc.Q.QueryRow(ctx, `SELECT s.fetch_enabled,p.capture_stage,p.capture_group_cursor,
			p.capture_start_page,p.capture_start_row,
			coalesce(p.capture_lease_until>clock_timestamp(),false)
			FROM nms_import_plans p JOIN nms_import_sources s
			  ON s.tenant_id=p.tenant_id AND s.context_id=p.context_id AND s.id=p.source_id
			WHERE p.tenant_id=$1 AND p.context_id=$2 AND p.id=$3`,
			sc.Tenant.String(), contextID, planID).Scan(&enabled, &step.Stage, &step.GroupID,
			&step.StartPage, &step.StartRow, &leaseBusy)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPlanUnavailable
		}
		if err != nil {
			return err
		}
		if !enabled || step.Stage == "complete" {
			return ErrPlanUnavailable
		}
		if leaseBusy {
			return ErrCaptureBusy
		}
		if _, err := sc.Q.Exec(ctx, `UPDATE nms_import_plans SET
			capture_lease_hash=$4,capture_lease_until=clock_timestamp()+interval '60 seconds'
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
			sc.Tenant.String(), contextID, planID, step.leaseHash()); err != nil {
			return err
		}
		return s.audit(ctx, sc, "nms_import.capture_step_acquired", planID,
			map[string]any{"context_id": contextID, "stage": step.Stage,
				"group_external_id": step.GroupID})
	})
	if err != nil {
		step.Zeroize()
		return LiveCaptureStep{}, err
	}
	return step, nil
}

// ReleaseConfiguredLibreNMSStage clears only this exact lease after an
// incomplete read. A later caller can retry the same endpoint and must replay
// every already committed page hash before its completion marker can advance.
func (s CaptureStore) ReleaseConfiguredLibreNMSStage(ctx context.Context,
	contextID, planID string, step LiveCaptureStep) error {
	if s.pool == nil || s.audit == nil {
		return ErrCaptureAuditUnavailable
	}
	if len(step.secret) != 32 {
		return ErrPlanUnavailable
	}
	contextID, planID, err := validCaptureIDs(contextID, planID)
	if err != nil {
		return err
	}
	return tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		updated, err := sc.Q.Exec(ctx, `UPDATE nms_import_plans SET
			capture_lease_hash=NULL,capture_lease_until=NULL
			WHERE tenant_id=$1 AND context_id=$2 AND id=$3
			  AND capture_lease_hash=$4 AND state='capturing'`,
			sc.Tenant.String(), contextID, planID, step.leaseHash())
		if err != nil {
			return err
		}
		if updated.RowsAffected() == 0 {
			return ErrPlanUnavailable
		}
		return s.audit(ctx, sc, "nms_import.capture_step_released", planID,
			map[string]any{"context_id": contextID, "stage": step.Stage})
	})
}
