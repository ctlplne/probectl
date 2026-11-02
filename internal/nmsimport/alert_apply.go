// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package nmsimport

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// AppliedAlertTarget reports an atomic disabled-rule creation or an exact
// source-keyed no-op. A later operator action may enable a rule through the
// regular alert API; an import never changes that decision.
type AppliedAlertTarget struct {
	AlertRuleID string `json:"alert_rule_id"`
	Created     bool   `json:"created"`
}

// ApplyLibreNMSAlertTarget is a distinct, reviewed write after inventory
// apply. The caller authorizes nms.import.write and entities.read in the
// selected context. A live source is re-read against its frozen rules-page
// receipts before the tenant transaction; a file import uses its sealed
// snapshot. Both recheck the current exact sender target under row locks.
func (s CaptureStore) ApplyLibreNMSAlertTarget(ctx context.Context,
	contextID, sourceID, ruleID, agentID, targetAddress,
	expectedPlanID, expectedSnapshotHash, expectedEntityID string,
	policy LibreNMSFetchPolicy) (AppliedAlertTarget, error) {
	if s.pool == nil || s.audit == nil {
		return AppliedAlertTarget{}, ErrCaptureAuditUnavailable
	}
	contextID, expectedPlanID, err := reviewPlanIDs(contextID, expectedPlanID)
	if err != nil || len(expectedSnapshotHash) != 64 || !lowerHex(expectedSnapshotHash) {
		return AppliedAlertTarget{}, ErrInvalidReview
	}
	preview, err := s.PreviewLibreNMSAlertTarget(ctx, contextID, sourceID,
		ruleID, agentID, targetAddress)
	if err != nil {
		return AppliedAlertTarget{}, err
	}
	if preview.PlanID != expectedPlanID ||
		preview.SnapshotHash != expectedSnapshotHash ||
		preview.EntityID != expectedEntityID {
		return AppliedAlertTarget{}, ErrReviewStale
	}
	sourceID = preview.SourceID
	var live bool
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		meta, err := loadCaptureMeta(ctx, sc, contextID, expectedPlanID, false)
		if err != nil {
			return err
		}
		if meta.state != "applied" ||
			meta.snapshotHash != expectedSnapshotHash || meta.source != LibreNMS {
			return ErrPlanUnavailable
		}
		live = meta.configVersion != 0
		return nil
	})
	if err != nil {
		return AppliedAlertTarget{}, err
	}
	var proof appliedAlertRuleProof
	if live {
		proof, err = s.verifyAppliedLibreNMSRules(ctx, contextID,
			expectedPlanID, expectedSnapshotHash, ruleID, policy)
		if err != nil {
			return AppliedAlertTarget{}, err
		}
	}
	result := AppliedAlertTarget{}
	err = tenancy.InTenant(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		meta, err := loadCaptureMeta(ctx, sc, contextID, expectedPlanID, true)
		if err != nil {
			return err
		}
		if meta.state != "applied" ||
			meta.snapshotHash != expectedSnapshotHash || meta.source != LibreNMS ||
			(meta.configVersion != 0) != live {
			return ErrPlanUnavailable
		}
		if live && (proof.tenantID != sc.Tenant.String() ||
			proof.contextID != contextID || proof.planID != expectedPlanID ||
			proof.sourceID != sourceID || proof.snapshotHash != expectedSnapshotHash ||
			proof.configVersion != meta.configVersion ||
			proof.verifiedAt.IsZero() || time.Since(proof.verifiedAt) > time.Minute) {
			return ErrReviewStale
		}
		current := LibreNMSAlertTargetPreview{
			ContextID: contextID, SourceID: sourceID, RuleID: ruleID,
			AgentID: agentID, TargetAddress: targetAddress,
			RuleKind: "port_down", Enabled: false,
		}
		if err := loadLibreNMSAlertTarget(ctx, sc, &current, true); err != nil {
			return err
		}
		if current != preview {
			return ErrReviewStale
		}
		if live {
			var reviewHash string
			if err := sc.Q.QueryRow(ctx, `SELECT review_hash FROM nms_import_plans
				WHERE tenant_id=$1 AND context_id=$2 AND id=$3`,
				sc.Tenant.String(), contextID, expectedPlanID).Scan(&reviewHash); err != nil {
				return err
			}
			if reviewHash != proof.reviewHash {
				return ErrReviewStale
			}
		}
		rule, err := nativeLibreNMSPortDownRule(current)
		if err != nil {
			return err
		}
		if id, found, err := existingImportedAlert(ctx, sc, current, rule.Match); err != nil {
			return err
		} else if found {
			result.AlertRuleID = id
			return nil
		}
		var alertID string
		err = sc.Q.QueryRow(ctx, `INSERT INTO alert_rules
			(tenant_id,name,enabled,metric,match_labels,type,comparison,threshold,
			 window_n,sensitivity,for_n,renotify_seconds,severity,channels)
			VALUES ($1,$2,false,$3,$4::jsonb,'threshold','eq',0,0,0,1,0,$5,'[]'::jsonb)
			RETURNING id::text`, sc.Tenant.String(), rule.Name, rule.Metric,
			marshalAlertMatch(rule.Match), string(rule.Severity)).Scan(&alertID)
		if err != nil {
			return importedAlertWriteError(err)
		}
		command, err := sc.Q.Exec(ctx, `INSERT INTO nms_import_alert_bindings
			(tenant_id,context_id,source_id,rule_external_id,device_external_id,
			 agent_id,target_address,plan_id,alert_rule_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
			sc.Tenant.String(), contextID, sourceID, ruleID, current.DeviceID,
			agentID, targetAddress, expectedPlanID, alertID)
		if err != nil {
			return importedAlertWriteError(err)
		}
		if command.RowsAffected() != 1 {
			return ErrReviewStale
		}
		if err := s.audit(ctx, sc, "nms_import.alert_applied", alertID,
			map[string]any{"context_id": contextID, "source_id": sourceID,
				"source_rule_id": ruleID, "plan_id": expectedPlanID,
				"enabled": false}); err != nil {
			return err
		}
		result.AlertRuleID, result.Created = alertID, true
		return nil
	})
	if err != nil {
		return AppliedAlertTarget{}, importedAlertWriteError(err)
	}
	return result, nil
}

func marshalAlertMatch(match map[string]string) string {
	wire, _ := json.Marshal(match)
	return string(wire)
}

// A repeated source rule is inert only when its native rule still has every
// mapped field. Its enabled bit is deliberately excluded: only a separate
// human-authorized alert mutation may change that bit.
func existingImportedAlert(ctx context.Context, sc tenancy.Scope,
	p LibreNMSAlertTargetPreview, match map[string]string) (string, bool, error) {
	var id string
	err := sc.Q.QueryRow(ctx, `SELECT alert_rule_id::text FROM nms_import_alert_bindings
		WHERE tenant_id=$1 AND context_id=$2 AND source_id=$3
		  AND rule_external_id=$4 FOR SHARE`, sc.Tenant.String(), p.ContextID,
		p.SourceID, p.RuleID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	var exact bool
	err = sc.Q.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM nms_import_alert_bindings b JOIN alert_rules a
		  ON (a.tenant_id,a.id)=(b.tenant_id,b.alert_rule_id)
		WHERE b.tenant_id=$1 AND b.context_id=$2 AND b.source_id=$3
		  AND b.rule_external_id=$4 AND b.device_external_id=$5
		  AND b.agent_id=$6 AND b.target_address=$7 AND b.alert_rule_id=$8
		  AND a.name=$9 AND a.metric='probectl_device_if_oper_status'
		  AND a.match_labels=$10::jsonb AND a.type='threshold'
		  AND a.comparison='eq' AND a.threshold=0 AND a.window_n=0
		  AND a.sensitivity=0 AND a.for_n=1 AND a.renotify_seconds=0
		  AND a.severity=$11 AND a.channels='[]'::jsonb
		  AND a.trap_match IS NULL)`, sc.Tenant.String(), p.ContextID,
		p.SourceID, p.RuleID, p.DeviceID, p.AgentID, p.TargetAddress,
		id, p.Name, marshalAlertMatch(match), p.Severity).Scan(&exact)
	if err != nil {
		return "", false, err
	}
	if !exact {
		return "", false, ErrReviewStale
	}
	return id, true, nil
}

func importedAlertWriteError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) &&
		(pgErr.Code == "23503" || pgErr.Code == "23505" || pgErr.Code == "23514") {
		return ErrReviewStale
	}
	return err
}
