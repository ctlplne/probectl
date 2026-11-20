// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
// Licensed under the probectl Commercial Source License. See ee/LICENSE.
// Production use requires a valid commercial agreement. Resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	rem "github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *PGStore) InsertDiversionAudited(ctx context.Context, tenant string, proposal rem.Proposal, review []byte,
	current rem.RTBHImpactPublication, sink AuditSink, event AuditEvent) (rem.Proposal, error) {
	if current.Publish == nil || proposal.Kind != rem.KindDiversionPreview || len(review) == 0 || len(review) > maxDiversionReviewBytes {
		return rem.Proposal{}, rem.ErrUnknownBlastRadius
	}
	return s.insertAuditedWithReview(ctx, tenant, proposal, review, current, sink, event)
}

func (s *PGStore) ActiveDiversionStart(ctx context.Context, tenant, id string) (rem.DiversionReceipt, error) {
	scoped, err := remediationTenantContext(ctx, tenant)
	if err != nil {
		return rem.DiversionReceipt{}, err
	}
	var receipt rem.DiversionReceipt
	err = tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(scoped), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var raw []byte
		if err := sc.Q.QueryRow(ctx, `SELECT diversion_receipt FROM remediation_proposals
			WHERE tenant_id=$1 AND id=$2 AND kind='diversion_preview' AND state='approved'
			  AND diversion_receipt->>'action'='start' AND diversion_stopped_at IS NULL`, tenant, id).Scan(&raw); err != nil {
			return err
		}
		return json.Unmarshal(raw, &receipt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return rem.DiversionReceipt{}, rem.Error{Code: "not_found", Message: "active local diversion preview not found"}
	}
	if err != nil {
		return rem.DiversionReceipt{}, err
	}
	if receipt.Connector != rem.LocalDiversionPreview || receipt.Action != rem.DiversionStart || receipt.StartPreviewID != id || receipt.Prefix == "" || receipt.RecordedAt.IsZero() {
		return rem.DiversionReceipt{}, rem.ErrUnknownBlastRadius
	}
	return receipt, nil
}

type loadedDiversionReview struct {
	Proposal       rem.Proposal
	Raw            []byte
	Receipt        *rem.DiversionReceipt
	StartStoppedAt *time.Time
}

func (s *PGStore) loadDiversionReview(ctx context.Context, tenant, id string) (loadedDiversionReview, error) {
	scoped, err := remediationTenantContext(ctx, tenant)
	if err != nil {
		return loadedDiversionReview{}, err
	}
	var out loadedDiversionReview
	var saved []byte
	var prefix string
	err = tenancy.InTenantReadSnapshot(tenancy.WithSiloTableLock(scoped), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		const owned = ` FROM remediation_proposals WHERE tenant_id=$1 AND id=$2 AND kind='diversion_preview'`
		var err error
		out.Proposal, err = scanProposal(sc.Q.QueryRow(ctx, `SELECT `+cols+owned, tenant, id))
		if err != nil {
			return err
		}
		return sc.Q.QueryRow(ctx, `SELECT diversion_review, diversion_receipt, diversion_stopped_at, diversion_review #>> '{review,candidate,prefix}'`+owned, tenant, id).Scan(&out.Raw, &saved, &out.StartStoppedAt, &prefix)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return loadedDiversionReview{}, rem.Error{Code: "not_found", Message: "local diversion proposal not found"}
	}
	if err != nil || len(saved) == 0 {
		return out, err
	}
	var receipt rem.DiversionReceipt
	if err := json.Unmarshal(saved, &receipt); err != nil {
		return loadedDiversionReview{}, err
	}
	if receipt.Connector != rem.LocalDiversionPreview || receipt.Prefix != prefix || receipt.StartPreviewID == "" || receipt.RecordedAt.IsZero() ||
		(receipt.Action != rem.DiversionStart && receipt.Action != rem.DiversionStop) || (receipt.Action == rem.DiversionStart && receipt.StartPreviewID != id) {
		return loadedDiversionReview{}, rem.ErrUnknownBlastRadius
	}
	out.Receipt = &receipt
	return out, nil
}

// This interface is the local connector boundary. A connector receives only
// an already approved, scoped action and records its acknowledgement. The
// attached stand-in does not accept any provider address or credential.
type diversionPreviewConnector interface {
	RecordApproved(context.Context, tenancy.Scope, string, time.Time, rem.DiversionPreview) (rem.DiversionReceipt, error)
}

type localDiversionPreview struct{}

func (s *PGStore) ApproveDiversionAudited(ctx context.Context, tenant, id, actor, note string, at time.Time, expected []byte,
	preview rem.DiversionPreview, current rem.RTBHImpactPublication, sink AuditSink, event AuditEvent) (rem.DiversionReceipt, error) {
	if s.diversion == nil || current.Publish == nil || len(expected) == 0 || len(expected) > maxDiversionReviewBytes || preview.Connector != rem.LocalDiversionPreview {
		return rem.DiversionReceipt{}, rem.ErrUnknownBlastRadius
	}
	var receipt rem.DiversionReceipt
	publish := current.Publish
	current.Publish = func(ctx context.Context, sc tenancy.Scope, permission string, mutate func(context.Context, tenancy.Scope) error) error {
		return publish(ctx, sc, permission, func(ctx context.Context, sc tenancy.Scope) error {
			if err := mutate(ctx, sc); err != nil {
				return err
			}
			var err error
			receipt, err = s.diversion.RecordApproved(ctx, sc, id, at, preview)
			return err
		})
	}
	_, err := s.decideAuditedWithReview(ctx, tenant, id, rem.StateApproved, actor, note, at, rem.KindDiversionPreview, expected, current, sink, event)
	if err != nil {
		return rem.DiversionReceipt{}, err
	}
	return receipt, nil
}

func (localDiversionPreview) RecordApproved(ctx context.Context, sc tenancy.Scope, id string, at time.Time, preview rem.DiversionPreview) (rem.DiversionReceipt, error) {
	var empty rem.DiversionReceipt
	if sc.Tenant == "" || sc.Q == nil || preview.Connector != rem.LocalDiversionPreview {
		return empty, rem.ErrUnknownBlastRadius
	}
	tenant := sc.Tenant.String()
	start := id
	switch preview.Action {
	case rem.DiversionStart:
		if preview.StartPreviewID != "" {
			return empty, rem.ErrUnknownBlastRadius
		}
	case rem.DiversionStop:
		start = preview.StartPreviewID
		tag, err := sc.Q.Exec(ctx, `UPDATE remediation_proposals SET diversion_stopped_at=$4
			WHERE tenant_id=$1 AND id=$2 AND diversion_review #>> '{review,candidate,prefix}'=$3
			  AND kind='diversion_preview' AND state='approved'
			  AND diversion_receipt->>'action'='start' AND diversion_receipt->>'start_preview_id'=($2::uuid)::text
			  AND diversion_stopped_at IS NULL`, tenant, start, preview.Prefix, at)
		if err != nil {
			return empty, err
		}
		if tag.RowsAffected() != 1 {
			return empty, changedRTBHReview()
		}
	default:
		return empty, rem.ErrUnknownBlastRadius
	}
	receipt := rem.DiversionReceipt{Connector: preview.Connector, Action: preview.Action, Prefix: preview.Prefix, StartPreviewID: start, RecordedAt: at.UTC()}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return empty, err
	}
	tag, err := sc.Q.Exec(ctx, `UPDATE remediation_proposals SET diversion_receipt=$5::jsonb
		WHERE tenant_id=$1 AND id=$2 AND diversion_review #>> '{review,candidate,prefix}'=$3
			  AND kind='diversion_preview' AND state='approved'
		  AND diversion_review #>> '{review,candidate,action}'=$4 AND diversion_receipt IS NULL`, tenant, id, preview.Prefix, preview.Action, raw)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return empty, rem.Error{Code: "review_changed", Message: "this prefix already has an active local diversion preview"}
		}
		return empty, err
	}
	if tag.RowsAffected() != 1 {
		return empty, rem.ErrNotProposed
	}
	return receipt, nil
}
