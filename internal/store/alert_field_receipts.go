// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"time"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/alert"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type AlertFlowReceipt struct {
	ObservedAt time.Time
	Body       []byte
}

// AlertFlowReceiptKind selects a fixed, private receipt column. Each kind uses
// the same tenant predicate, expiry and bounded transfer contract.
type AlertFlowReceiptKind uint8

const (
	AlertFieldChangeReceipt AlertFlowReceiptKind = iota + 1
	AlertDDoSReceipt
)

// AppendFlowReceipt publishes a complete window on the existing ledger. The
// incident, evidence and new state share the caller's tenant transaction.
func (r AlertEvaluations) AppendFlowReceipt(ctx context.Context, sc tenancy.Scope, kind AlertFlowReceiptKind, revision time.Time, receipt alert.EvaluationReceipt, body []byte, maxBytes int64) error {
	if kind != AlertFieldChangeReceipt && kind != AlertDDoSReceipt {
		return alert.ErrQueryGroups
	}
	if err := alertQueryScope(ctx, sc, revision, maxBytes); err != nil {
		return err
	}
	if !alert.ValidFieldDigest(receipt.Fingerprint) || receipt.RuleID == "" || receipt.ObservedAt.IsZero() ||
		receipt.RuleRevision != revision.UTC().Format(time.RFC3339Nano) || receipt.State != alert.EvaluationFiring ||
		receipt.ObservedValue != nil || receipt.Expectation.Seasonal != nil ||
		len(body) == 0 || int64(len(body)) > maxBytes || !utf8.Valid(body) || !json.Valid(body) {
		return alert.ErrQueryGroups
	}
	if err := r.Append(ctx, sc, receipt); err != nil {
		return err
	}
	updated, err := sc.Q.Exec(ctx, `UPDATE alert_evaluation_receipts SET
 field_change_receipt=CASE WHEN $7::int=1 THEN $6::bytea ELSE field_change_receipt END,
 ddos_receipt=CASE WHEN $7::int=2 THEN $6::bytea ELSE ddos_receipt END
 WHERE tenant_id=$1 AND rule_id=$2 AND fingerprint=$3 AND observed_at=$4 AND rule_revision=$5
 AND evaluation_state='firing'`, sc.Tenant.String(), receipt.RuleID, receipt.Fingerprint, receipt.ObservedAt, receipt.RuleRevision, body, int(kind))
	if err != nil {
		return err
	}
	if updated.RowsAffected() != 1 {
		return ErrAlertQueryChanged
	}
	return ctx.Err()
}

// GetFlowReceipt bounds the private PostgreSQL value before transfer. The
// caller checks all retained source requirements before publishing its body.
func (AlertEvaluations) GetFlowReceipt(ctx context.Context, sc tenancy.Scope, kind AlertFlowReceiptKind, ruleID, fingerprint string, revision time.Time, maxBytes int64) (AlertFlowReceipt, error) {
	var out AlertFlowReceipt
	if kind != AlertFieldChangeReceipt && kind != AlertDDoSReceipt {
		return out, alert.ErrQueryGroups
	}
	if err := alertQueryScope(ctx, sc, revision, maxBytes); err != nil {
		return out, err
	}
	if !alert.ValidFieldDigest(fingerprint) || ruleID == "" {
		return out, alert.ErrQueryGroups
	}
	var size int64
	err := sc.Q.QueryRow(ctx, `SELECT observed_at, octet_length(proof.body)::bigint,
 CASE WHEN octet_length(proof.body) <= $5 THEN proof.body END
 FROM alert_evaluation_receipts, LATERAL (SELECT CASE $6::int
 WHEN 1 THEN field_change_receipt WHEN 2 THEN ddos_receipt END) AS proof(body) WHERE tenant_id=$1 AND rule_id=$2 AND fingerprint=$3 AND rule_revision=$4
 AND evaluation_state='firing' AND expires_at>clock_timestamp() AND proof.body IS NOT NULL
 ORDER BY observed_at DESC LIMIT 1`, sc.Tenant.String(), ruleID, fingerprint, revision.UTC().Format(time.RFC3339Nano), maxBytes, int(kind)).
		Scan(&out.ObservedAt, &size, &out.Body)
	if err != nil {
		return AlertFlowReceipt{}, err
	}
	if size < 1 || size > maxBytes || int64(len(out.Body)) != size {
		return AlertFlowReceipt{}, alert.ErrQueryGroups
	}
	return out, ctx.Err()
}
