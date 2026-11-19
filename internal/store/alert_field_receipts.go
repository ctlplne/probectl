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

type AlertFieldReceipt struct {
	ObservedAt time.Time
	Body       []byte
}

// AppendFieldReceipt retains one complete window on the existing alert
// ledger. The incident, exact observations and new state share the caller's
// publication transaction. The ordinary receipt list omits the private body.
func (r AlertEvaluations) AppendFieldReceipt(ctx context.Context, sc tenancy.Scope, revision time.Time, receipt alert.EvaluationReceipt, body []byte, maxBytes int64) error {
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
	updated, err := sc.Q.Exec(ctx, `UPDATE alert_evaluation_receipts SET field_change_receipt=$6
 WHERE tenant_id=$1 AND rule_id=$2 AND fingerprint=$3 AND observed_at=$4 AND rule_revision=$5
 AND evaluation_state='firing'`, sc.Tenant.String(), receipt.RuleID, receipt.Fingerprint, receipt.ObservedAt, receipt.RuleRevision, body)
	if err != nil {
		return err
	}
	if updated.RowsAffected() != 1 {
		return ErrAlertQueryChanged
	}
	return ctx.Err()
}

// GetFieldReceipt bounds the private PostgreSQL value before transfer. The
// caller checks the retained source requirements before publishing its body.
func (AlertEvaluations) GetFieldReceipt(ctx context.Context, sc tenancy.Scope, ruleID, fingerprint string, revision time.Time, maxBytes int64) (AlertFieldReceipt, error) {
	var out AlertFieldReceipt
	if err := alertQueryScope(ctx, sc, revision, maxBytes); err != nil {
		return out, err
	}
	if !alert.ValidFieldDigest(fingerprint) || ruleID == "" {
		return out, alert.ErrQueryGroups
	}
	var size int64
	err := sc.Q.QueryRow(ctx, `SELECT observed_at, octet_length(field_change_receipt)::bigint,
 CASE WHEN octet_length(field_change_receipt) <= $5 THEN field_change_receipt END
 FROM alert_evaluation_receipts WHERE tenant_id=$1 AND rule_id=$2 AND fingerprint=$3 AND rule_revision=$4
 AND evaluation_state='firing' AND expires_at>clock_timestamp() AND field_change_receipt IS NOT NULL
 ORDER BY observed_at DESC LIMIT 1`, sc.Tenant.String(), ruleID, fingerprint, revision.UTC().Format(time.RFC3339Nano), maxBytes).
		Scan(&out.ObservedAt, &size, &out.Body)
	if err != nil {
		return AlertFieldReceipt{}, err
	}
	if size < 1 || size > maxBytes || int64(len(out.Body)) != size {
		return AlertFieldReceipt{}, alert.ErrQueryGroups
	}
	return out, ctx.Err()
}
